# ANALYSIS: 4-state verdict emoji map; _log_interaction always writes to
#           logs/telegram_queries_YYYY-MM.jsonl regardless of privacy mode.
# CHANGES:  Collapsed to 3-state traffic-light mapping (SCAM/SUSPICIOUS both
#           kept, LIKELY_SAFE and SAFE both → 🟢 SAFE); gated the JSONL write
#           with Config.ZERO_RETENTION_MODE.
"""NovaGuard Telegram bot.

Front-end for users on Telegram. Accepts text messages, links, and
screenshots; routes each through the same NovaGuard backend as the web
app; replies with a formatted investigation report.

Run:
    python bot/novaguard_bot.py
"""

from __future__ import annotations

import sys
from pathlib import Path

# When launched as `python bot/novaguard_bot.py`, Python sets sys.path[0] to
# the `bot/` directory; make the project root importable too.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

import asyncio
import hashlib
import json
import logging
import re
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Deque

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ParseMode
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)
from telegram.request import HTTPXRequest

import requests as _req

from agent.llm_factory import active_model_id
from agent.novaguard_agent import NovaGuardAgent
from config import Config
from tools.vision_tool import VisionInspector

_BACKEND_URL      = "http://localhost:8000"
_QR_SCAN_ENDPOINT = f"{_BACKEND_URL}/api/v1/qr/scan"
_QR_PDF_ENDPOINT  = f"{_BACKEND_URL}/api/v1/qr/scan-pdf"

logging.basicConfig(
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger("novaguard.bot")

_URL_REGEX = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_RATE_LIMIT_WINDOW_SECONDS = 60
_RATE_LIMIT_MAX_REQUESTS = 5

_VERDICT_EMOJI = {
    "SCAM": "🔴 DANGEROUS",
    "SUSPICIOUS": "🟡 SUSPICIOUS",
    "LIKELY_SAFE": "🟢 SAFE",
    "SAFE": "🟢 SAFE",
}

_NOVAGUARD_FOOTER = "\n\n—\nNovaGuard 🛡️ | Forward suspicious messages to this bot"


# --------------------------------------------------------------- shared state
class _BotState:
    """Singleton-ish container for the agent, vision inspector, and rate limiter."""

    def __init__(self) -> None:
        self.agent: NovaGuardAgent | None = None
        self.vision: VisionInspector | None = None
        self.user_history: dict[int, Deque[float]] = defaultdict(
            lambda: deque(maxlen=_RATE_LIMIT_MAX_REQUESTS * 2)
        )

    def get_agent(self) -> NovaGuardAgent:
        if self.agent is None:
            self.agent = NovaGuardAgent()
        return self.agent

    def get_vision(self) -> VisionInspector:
        if self.vision is None:
            self.vision = VisionInspector()
        return self.vision


STATE = _BotState()


# --------------------------------------------------------------- helpers
def _hash_user_id(user_id: int) -> str:
    return hashlib.sha256(str(user_id).encode("utf-8")).hexdigest()[:16]


def _log_interaction(
    user_id: int,
    input_type: str,
    predicted_label: str | None,
    latency_seconds: float,
) -> None:
    if Config.ZERO_RETENTION_MODE:
        return
    log_dir = Path(Config.LOG_DIR)
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"telegram_queries_{datetime.now(timezone.utc).strftime('%Y-%m')}.jsonl"
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "user_id": _hash_user_id(user_id),
        "input_type": input_type,
        "predicted_label": predicted_label,
        "latency_seconds": round(float(latency_seconds or 0.0), 3),
    }
    try:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError as exc:
        logger.warning("Failed to write telemetry log: %s", exc)


def _check_rate_limit(user_id: int) -> bool:
    now = time.time()
    history = STATE.user_history[user_id]
    while history and now - history[0] > _RATE_LIMIT_WINDOW_SECONDS:
        history.popleft()
    if len(history) >= _RATE_LIMIT_MAX_REQUESTS:
        return False
    history.append(now)
    return True


def _format_verdict_header(predicted_label: str | None) -> str:
    return _VERDICT_EMOJI.get((predicted_label or "").upper(), "ℹ️ Investigation Result")


async def _safe_reply(update: Update, text: str) -> None:
    try:
        await update.message.reply_text(text, disable_web_page_preview=True)
    except Exception as exc:
        logger.warning("Failed to send reply: %s", exc)


# --------------------------------------------------------------- commands
async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await _safe_reply(
        update,
        "👋 Welcome to NovaGuard 🛡️\n\n"
        "I investigate suspicious SMS, WhatsApp messages, emails, and links — "
        "with a focus on scams targeting Sri Lankan users.\n\n"
        "How to use me:\n"
        "• Forward any suspicious message as text\n"
        "• Send a link directly\n"
        "• Or send a screenshot of the message\n\n"
        "Type /help for more details or /about for project info."
        + _NOVAGUARD_FOOTER,
    )


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await _safe_reply(
        update,
        "🧭 How NovaGuard works:\n\n"
        "1) You send a message, link, or screenshot.\n"
        "2) I check for known scam patterns (fake BOC / Sampath / Dialog "
        "alerts, overseas job lures, investment scams).\n"
        "3) For links, I open them in a sandboxed browser to inspect for "
        "phishing forms, redirects, and brand impersonation.\n"
        "4) You get a verdict (SCAM / SUSPICIOUS / LIKELY_SAFE / SAFE), "
        "evidence, and a recommended action.\n\n"
        "Rate limit: up to 5 investigations per minute per user.\n"
        "I do not store your message content — only hashed query telemetry."
        + _NOVAGUARD_FOOTER,
    )


async def cmd_about(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await _safe_reply(
        update,
        "About NovaGuard 🛡️\n\n"
        "NovaGuard is an LLM-powered agent for detecting scam links and "
        "messages aimed at Sri Lankan users. It is the system component of a "
        "final-year research project on agentic scam detection in low-resource "
        "languages and local threat patterns.\n\n"
        f"Tech: {Config.LLM_PROVIDER}/{active_model_id()}, "
        "LangChain ReAct agent, Selenium headless Chrome, Streamlit + Telegram front-ends."
        + _NOVAGUARD_FOOTER,
    )


# --------------------------------------------------------------- handlers
def _contains_url(text: str) -> bool:
    return bool(_URL_REGEX.search(text or ""))


async def handle_text_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id if update.effective_user else 0
    text = (update.message.text or "").strip()
    if not text:
        return

    if not _check_rate_limit(user_id):
        await _safe_reply(
            update,
            "⏳ Please wait a moment before sending another request.",
        )
        return

    has_url = _contains_url(text)
    if has_url and len(text.split()) < 4:
        await _safe_reply(update, "🔗 Investigating link...")
        input_type = "url"
    else:
        await _safe_reply(update, "🔍 Investigating your message...")
        input_type = "url" if has_url else "text"

    try:
        agent = STATE.get_agent()
        result = await asyncio.to_thread(agent.investigate, text)
        report = result.get("response") or "(no report generated)"
        header = _format_verdict_header(result.get("predicted_label"))
        message = f"{header}\n\n{report}{_NOVAGUARD_FOOTER}"
        await _send_long(update, message)
        _log_interaction(
            user_id=user_id,
            input_type=input_type,
            predicted_label=result.get("predicted_label"),
            latency_seconds=result.get("latency_seconds", 0.0),
        )
    except Exception as exc:
        logger.exception("Text-handler error: %s", exc)
        await _safe_reply(
            update,
            "❌ Investigation failed. Please try again or visit our web app.",
        )


async def handle_photo(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Receive a photo and show an inline menu asking what to do with it."""
    user_id = update.effective_user.id if update.effective_user else 0
    if not _check_rate_limit(user_id):
        await _safe_reply(update, "⏳ Please wait a moment before sending another request.")
        return

    # Store the file_id so the callback handler can retrieve it
    photo = update.message.photo[-1]
    context.user_data["pending_photo_file_id"] = photo.file_id

    keyboard = InlineKeyboardMarkup([
        [
            InlineKeyboardButton("📷 Scan for QR Code (Quishing)", callback_data="action:qr"),
        ],
        [
            InlineKeyboardButton("🔍 Analyse Screenshot (Vision)", callback_data="action:vision"),
        ],
    ])
    await update.message.reply_text(
        "What would you like to do with this image?",
        reply_markup=keyboard,
    )


async def handle_photo_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle the inline button press after a photo is sent."""
    query = update.callback_query
    await query.answer()

    action = query.data.split(":", 1)[-1]  # "qr" or "vision"
    file_id = context.user_data.get("pending_photo_file_id")

    if not file_id:
        await query.edit_message_text("❌ No image found. Please send the image again.")
        return

    # Download the photo
    try:
        file       = await context.bot.get_file(file_id)
        img_bytes  = bytes(await file.download_as_bytearray())
    except Exception as exc:
        logger.exception("Photo download error: %s", exc)
        await query.edit_message_text("❌ Could not download the image. Please try again.")
        return

    if action == "qr":
        await query.edit_message_text("🔍 Scanning for QR codes…")
        try:
            resp = await asyncio.to_thread(
                _req.post,
                _QR_SCAN_ENDPOINT,
                files={"file": ("photo.jpg", img_bytes, "image/jpeg")},
                timeout=60,
            )
            resp.raise_for_status()
            result_text = _format_qr_reply(resp.json())
        except Exception as exc:
            logger.exception("QR scan error: %s", exc)
            result_text = "❌ QR scan failed. Make sure the backend is running."
        await context.bot.send_message(chat_id=query.message.chat_id, text=result_text)

    elif action == "vision":
        await query.edit_message_text("🔍 Analysing screenshot with AI vision…")
        try:
            vision  = STATE.get_vision()
            outcome = await asyncio.to_thread(vision.analyze_screenshot, img_bytes)
        except Exception as exc:
            logger.exception("Vision pipeline error: %s", exc)
            await context.bot.send_message(
                chat_id=query.message.chat_id,
                text="❌ Investigation failed. Please try again.",
            )
            return

        if outcome.get("status") != "ok":
            await context.bot.send_message(
                chat_id=query.message.chat_id,
                text="❌ Could not read the screenshot. Try pasting the message text directly.",
            )
            return

        extraction     = outcome.get("extraction") or {}
        extracted_text = extraction.get("message_text", "")
        report         = outcome.get("investigation_report") or "(no report)"
        predicted_label = _extract_label(report)
        header         = _format_verdict_header(predicted_label)

        await context.bot.send_message(
            chat_id=query.message.chat_id,
            text=f"📝 Extracted text:\n{extracted_text}",
        )
        await _send_long(update, f"{header}\n\n{report}{_NOVAGUARD_FOOTER}")


async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    logger.error("Unhandled bot error: %s", context.error)
    if isinstance(update, Update) and update.message:
        try:
            await update.message.reply_text(
                "❌ Investigation failed. Please try again or visit our web app."
            )
        except Exception:
            pass


# --------------------------------------------------------------- output helpers
_TELEGRAM_MAX_LEN = 3800


async def _send_long(update: Update, text: str) -> None:
    """Split long messages so Telegram does not reject them."""
    if len(text) <= _TELEGRAM_MAX_LEN:
        await _safe_reply(update, text)
        return
    chunks: list[str] = []
    buf = ""
    for line in text.split("\n"):
        if len(buf) + len(line) + 1 > _TELEGRAM_MAX_LEN:
            chunks.append(buf)
            buf = line
        else:
            buf = f"{buf}\n{line}" if buf else line
    if buf:
        chunks.append(buf)
    for chunk in chunks:
        await _safe_reply(update, chunk)


_LABEL_RE = re.compile(
    r"\*\*\s*Verdict\s*:\s*\*\*\s*\[?\s*([A-Z_]+)", re.IGNORECASE
)

_RISK_EMOJI = {"green": "🟢 SAFE", "yellow": "🟡 SUSPICIOUS", "red": "🔴 DANGEROUS"}


def _format_qr_reply(data: dict) -> str:
    results = data.get("results", [])
    total   = data.get("total_qr_found", 0)
    if total == 0 or not results:
        return "📷 No QR codes found in the image."
    lines = [f"📷 {total} QR code(s) detected:\n"]
    for i, r in enumerate(results, 1):
        emoji  = _RISK_EMOJI.get(r.get("risk_level", "green"), "🟢")
        url    = r.get("decoded_url", "—")
        score  = r.get("risk_score", 0)
        reason = r.get("explanation", "")
        lines.append(f"{i}. {emoji} (risk {score}/100)")
        lines.append(f"   URL: {url[:120]}")
        if reason:
            lines.append(f"   ↳ {reason[:200]}")
    return "\n".join(lines) + _NOVAGUARD_FOOTER


async def on_document(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle PDF documents — scan every page for QR codes via the backend."""
    user_id = update.effective_user.id if update.effective_user else 0
    if not _check_rate_limit(user_id):
        await _safe_reply(update, "⏳ Please wait before sending another request.")
        return

    doc = update.message.document
    if not doc or not doc.file_name.lower().endswith(".pdf"):
        return

    await _safe_reply(update, "📄 Scanning PDF for QR codes…")
    try:
        file      = await context.bot.get_file(doc.file_id)
        pdf_bytes = bytes(await file.download_as_bytearray())
        resp      = await asyncio.to_thread(
            _req.post,
            _QR_PDF_ENDPOINT,
            files={"file": (doc.file_name, pdf_bytes, "application/pdf")},
            timeout=60,
        )
        resp.raise_for_status()
        await _send_long(update, _format_qr_reply(resp.json()))
    except Exception as exc:
        logger.exception("PDF QR scan error: %s", exc)
        await _safe_reply(update, "❌ Could not scan the PDF. Is the backend running?")


def _extract_label(report: str) -> str | None:
    if not report:
        return None
    m = _LABEL_RE.search(report)
    if not m:
        return None
    candidate = m.group(1).upper().replace(" ", "_")
    return candidate if candidate in _VERDICT_EMOJI else None


# --------------------------------------------------------------- main
def build_application() -> Application:
    if not Config.is_configured("telegram"):
        raise RuntimeError(
            "TELEGRAM_BOT_TOKEN is not configured. Set it in .env before starting the bot."
        )

    request = HTTPXRequest(connect_timeout=30, read_timeout=30, write_timeout=30)
    app = Application.builder().token(Config.TELEGRAM_BOT_TOKEN).request(request).build()
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("help", cmd_help))
    app.add_handler(CommandHandler("about", cmd_about))
    app.add_handler(MessageHandler(filters.PHOTO, handle_photo))
    app.add_handler(CallbackQueryHandler(handle_photo_callback, pattern=r"^action:"))
    app.add_handler(MessageHandler(filters.Document.PDF, on_document))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text_message))
    app.add_error_handler(error_handler)
    return app


def main() -> None:
    print("NovaGuard Telegram Bot starting...")
    app = build_application()

    async def _print_bot_name(application: Application) -> None:
        try:
            me = await application.bot.get_me()
            print(f"Bot is online as @{me.username}")
        except Exception as exc:
            logger.warning("Could not fetch bot identity: %s", exc)

    app.post_init = _print_bot_name
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
