"""Flask webhook server for the NovaGuard Telegram bot.

Polling (`novaguard_bot.py`) is the simplest way to run the bot locally.
For cloud deployment on Render / Railway / Fly, a webhook is cheaper and
faster: Telegram POSTs updates to `/webhook` instead of the bot long-polling.

Usage:
    # 1. Configure env: TELEGRAM_BOT_TOKEN, WEBHOOK_URL (e.g. https://novaguard.example.com)
    # 2. Start the server:
    python bot/webhook_server.py
    # 3. Register the webhook with Telegram (one-time, or use ?action=set_webhook):
    curl -X POST "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/setWebhook" \
        -d "url=$WEBHOOK_URL/webhook"
"""

from __future__ import annotations

import sys
from pathlib import Path

# Same path-fix as novaguard_bot.py: ensure the project root is importable
# when this script is launched directly.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

import asyncio
import logging
import os
import threading
from typing import Any

from flask import Flask, abort, jsonify, request
from telegram import Update

from bot.novaguard_bot import build_application
from config import Config

logging.basicConfig(
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger("novaguard.webhook")


def _start_event_loop() -> asyncio.AbstractEventLoop:
    """Start a dedicated asyncio loop in a background thread for the bot Application."""
    loop = asyncio.new_event_loop()

    def _runner() -> None:
        asyncio.set_event_loop(loop)
        loop.run_forever()

    thread = threading.Thread(target=_runner, name="bot-loop", daemon=True)
    thread.start()
    return loop


def create_app() -> Flask:
    if not Config.is_configured("telegram"):
        raise RuntimeError("TELEGRAM_BOT_TOKEN is not configured.")

    flask_app = Flask("novaguard-webhook")
    bot_app = build_application()
    loop = _start_event_loop()

    async def _initialise() -> None:
        await bot_app.initialize()
        await bot_app.start()
        logger.info("Telegram Application initialised in background loop.")

    asyncio.run_coroutine_threadsafe(_initialise(), loop).result(timeout=30)

    @flask_app.get("/")
    def health() -> Any:
        return jsonify({"status": "ok", "service": "novaguard-webhook"})

    @flask_app.post("/webhook")
    def webhook() -> Any:
        if not request.is_json:
            abort(400, "Expected JSON body")
        payload = request.get_json(silent=True) or {}
        try:
            update = Update.de_json(payload, bot_app.bot)
        except Exception as exc:
            logger.warning("Could not parse update: %s", exc)
            return jsonify({"ok": False, "reason": "invalid update"}), 400

        asyncio.run_coroutine_threadsafe(
            bot_app.process_update(update), loop
        )
        return jsonify({"ok": True})

    @flask_app.post("/admin/set_webhook")
    def set_webhook() -> Any:
        target_url = request.args.get("url") or os.getenv("WEBHOOK_URL")
        if not target_url:
            abort(400, "Provide ?url=... or set WEBHOOK_URL env var.")
        future = asyncio.run_coroutine_threadsafe(
            bot_app.bot.set_webhook(url=f"{target_url.rstrip('/')}/webhook"), loop
        )
        ok = future.result(timeout=15)
        return jsonify({"ok": bool(ok), "webhook_url": f"{target_url.rstrip('/')}/webhook"})

    return flask_app


def main() -> None:
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8080"))
    print(f"NovaGuard Telegram webhook server starting on {host}:{port}...")
    create_app().run(host=host, port=port)


if __name__ == "__main__":
    main()
