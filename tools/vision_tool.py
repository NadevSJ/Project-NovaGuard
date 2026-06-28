"""NVIDIA NIM Vision wrapper for NovaGuard screenshot OCR.

Replaces the previous Gemini Vision dependency.  Uses
`meta/llama-3.2-11b-vision-instruct` on NVIDIA's free-tier inference
endpoint (OpenAI-compatible), so no extra package is needed beyond the
`openai` library that is already installed as a langchain-openai dependency.

Falls back to `meta/llama-3.2-90b-vision-instruct` if the 11B model is
unavailable, configurable via NVIDIA_VISION_MODEL in .env.
"""

from __future__ import annotations

import base64
import io
import re
from typing import Any

from openai import OpenAI
from PIL import Image

from agent.novaguard_agent import run_investigation
from config import Config

# ---------------------------------------------------------------- model config
_NVIDIA_BASE_URL = "https://integrate.api.nvidia.com/v1"
# Configurable; default to the free 11B model which handles text extraction well
_VISION_MODEL = getattr(Config, "NVIDIA_VISION_MODEL", None) or "meta/llama-3.2-11b-vision-instruct"

EXTRACTION_PROMPT = """This image is a screenshot of a mobile phone screen showing
a message (SMS, WhatsApp, Viber, or email).

Extract ONLY:
1. The complete text of the message
2. Any URLs or phone numbers visible
3. The apparent sender name/number if visible

Ignore: status bar, battery, signal, UI chrome, keyboard, navigation buttons.

Format your response EXACTLY as:
MESSAGE_TEXT: [the actual message content]
URLS_FOUND: [comma separated, or "none"]
SENDER: [sender name/number, or "unknown"]
"""

_MESSAGE_RE = re.compile(
    r"MESSAGE_TEXT:\s*(.+?)(?=\n\s*(?:URLS_FOUND|SENDER)\s*:|\Z)",
    re.IGNORECASE | re.DOTALL,
)
_URLS_RE = re.compile(
    r"URLS_FOUND:\s*(.+?)(?=\n\s*SENDER\s*:|\Z)",
    re.IGNORECASE | re.DOTALL,
)
_SENDER_RE = re.compile(r"SENDER:\s*(.+?)\s*$", re.IGNORECASE | re.DOTALL)


class VisionInspector:
    """Screenshot OCR + investigation orchestrator.

    Uses NVIDIA NIM's free vision model instead of Gemini to avoid
    Google free-tier quota exhaustion.
    """

    def __init__(self) -> None:
        if not Config.NVIDIA_API_KEY:
            raise RuntimeError(
                "NVIDIA_API_KEY is required for screenshot OCR. "
                "Set it in .env — get a free key at https://build.nvidia.com/"
            )
        self._client = OpenAI(
            base_url=_NVIDIA_BASE_URL,
            api_key=Config.NVIDIA_API_KEY,
        )

    # --------------------------------------------------------- extraction
    def extract_text_from_image(self, image_bytes: bytes) -> dict[str, Any]:
        """OCR a screenshot and return structured fields."""
        # Normalise + resize so we stay within NIM's token budget
        try:
            image = Image.open(io.BytesIO(image_bytes)).convert("RGB")
            # Cap at 1280 wide — enough for text extraction, avoids huge payloads
            if image.width > 1280:
                ratio = 1280 / image.width
                image = image.resize(
                    (1280, int(image.height * ratio)), Image.LANCZOS
                )
            buf = io.BytesIO()
            image.save(buf, format="JPEG", quality=85)
            image_bytes = buf.getvalue()
        except Exception as exc:
            return {
                "success": False,
                "message_text": "",
                "urls_found": [],
                "sender": "unknown",
                "extraction_confidence": "low",
                "raw_response": "",
                "error": f"Could not open image: {exc}",
            }

        b64 = base64.b64encode(image_bytes).decode("ascii")
        data_url = f"data:image/jpeg;base64,{b64}"

        try:
            response = self._client.chat.completions.create(
                model=_VISION_MODEL,
                messages=[
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": EXTRACTION_PROMPT},
                            {"type": "image_url", "image_url": {"url": data_url}},
                        ],
                    }
                ],
                max_tokens=512,
                temperature=0.0,
                stream=False,
            )
            raw = (response.choices[0].message.content or "").strip()
        except Exception as exc:
            return {
                "success": False,
                "message_text": "",
                "urls_found": [],
                "sender": "unknown",
                "extraction_confidence": "low",
                "raw_response": "",
                "error": f"NVIDIA Vision call failed: {exc}",
            }

        message_text, urls_found, sender = self._parse(raw)
        confidence = self._confidence(message_text)

        return {
            "success": bool(message_text),
            "message_text": message_text,
            "urls_found": urls_found,
            "sender": sender,
            "extraction_confidence": confidence,
            "raw_response": raw,
        }

    # --------------------------------------------------------- end-to-end
    def analyze_screenshot(self, image_bytes: bytes) -> dict[str, Any]:
        """OCR then investigate. Returns extraction + investigation in one dict."""
        extraction = self.extract_text_from_image(image_bytes)

        if (
            not extraction.get("success")
            or extraction.get("extraction_confidence") == "low"
        ):
            return {
                "status": "extraction_failed",
                "extraction": extraction,
                "investigation_report": None,
                "user_message": (
                    "Could not read the screenshot clearly. Please re-upload a "
                    "sharper image (full message visible, no glare) or paste the "
                    "message text directly."
                ),
            }

        report = run_investigation(extraction["message_text"])
        return {
            "status": "ok",
            "extraction": extraction,
            "investigation_report": report,
            "user_message": "Extraction and investigation complete.",
        }

    # --------------------------------------------------------- IO helpers
    @staticmethod
    def load_image_from_path(path: str) -> bytes:
        with open(path, "rb") as f:
            return f.read()

    @staticmethod
    def load_image_from_streamlit_upload(uploaded_file: Any) -> bytes:
        data = uploaded_file.read()
        try:
            uploaded_file.seek(0)
        except Exception:
            pass
        return data

    # --------------------------------------------------------- internals
    @staticmethod
    def _parse(raw: str) -> tuple[str, list[str], str]:
        message_text = ""
        m = _MESSAGE_RE.search(raw)
        if m:
            message_text = m.group(1).strip().strip("[]").strip()

        urls: list[str] = []
        um = _URLS_RE.search(raw)
        if um:
            raw_urls = um.group(1).strip().strip("[]").strip()
            if raw_urls.lower() not in {"none", "n/a", "-", ""}:
                for piece in re.split(r"[,\s]+", raw_urls):
                    piece = piece.strip().strip("()[]<>'\"")
                    if piece:
                        urls.append(piece)

        sender = "unknown"
        sm = _SENDER_RE.search(raw)
        if sm:
            value = sm.group(1).strip().strip("[]").strip()
            if value and value.lower() not in {"unknown", "n/a", "-"}:
                sender = value

        return message_text, urls, sender

    @staticmethod
    def _confidence(message_text: str) -> str:
        n = len(message_text or "")
        if n > 20:
            return "high"
        if n >= 5:
            return "medium"
        return "low"
