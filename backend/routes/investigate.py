"""Investigation endpoints: text/URL auto-detect, email, and screenshot."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import threading
from typing import Any

from cachetools import TTLCache
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from sqlalchemy.orm import Session

from backend.database import Investigation, get_db
from backend.dependencies import (
    _make_optional_user_dep,
    get_agent,
    get_vision,
    require_api_key,
    traffic_light_for,
)
from backend.schemas import (
    EmailInvestigateRequest,
    InvestigateRequest,
    InvestigationResponse,
    ScreenshotInvestigationResponse,
)
from config import Config

logger = logging.getLogger("novaguard.investigate")

get_optional_user = _make_optional_user_dep(get_db)

router = APIRouter(prefix="/investigate", tags=["investigate"])

# ------------------------------------------------------------------ result cache
# Keyed on SHA-256 of the normalised input text; TTL = 1 hour.
# Disabled when ZERO_RETENTION_MODE is on (user has opted out of any persistence).
_CACHE_MAXSIZE = 500
_CACHE_TTL_SECONDS = 3600

_cache: TTLCache = TTLCache(maxsize=_CACHE_MAXSIZE, ttl=_CACHE_TTL_SECONDS)
_cache_lock = threading.Lock()


def _cache_key(text: str) -> str:
    return hashlib.sha256(text.strip().lower().encode("utf-8")).hexdigest()


def _cache_get(key: str) -> InvestigationResponse | None:
    if Config.ZERO_RETENTION_MODE:
        return None
    with _cache_lock:
        return _cache.get(key)


def _cache_set(key: str, value: InvestigationResponse) -> None:
    if Config.ZERO_RETENTION_MODE:
        return
    with _cache_lock:
        _cache[key] = value


# --------------------------------------------------------------- helpers
def _to_response(result: dict, fallback_input_type: str = "text") -> InvestigationResponse:
    label = (result.get("predicted_label") or "SUSPICIOUS").upper()
    tl = traffic_light_for(label)
    recommended_action = _extract_recommended_action(result.get("response", ""))
    return InvestigationResponse(
        predicted_label=label,
        predicted_score=int(result.get("predicted_score") or 50),
        input_type=result.get("input_type") or fallback_input_type,
        latency_seconds=float(result.get("latency_seconds") or 0.0),
        report=result.get("response") or "",
        traffic_light=tl["color"],  # type: ignore[arg-type]
        traffic_light_label=tl["label"],
        recommended_action=recommended_action or tl["action"],
    )


def _save_to_history(
    db: Session,
    user_id: int,
    input_text: str,
    response: InvestigationResponse,
) -> None:
    """Non-blocking fire-and-forget DB write; errors are logged but not raised."""
    try:
        row = Investigation(
            user_id=user_id,
            input_preview=input_text[:200],
            input_type=response.input_type,
            predicted_label=response.predicted_label,
            predicted_score=response.predicted_score,
            report=response.report,
            traffic_light=response.traffic_light,
            recommended_action=response.recommended_action,
            latency_seconds=response.latency_seconds,
        )
        db.add(row)
        db.commit()
    except Exception as exc:
        logger.warning("History save failed: %s", exc)
        try:
            db.rollback()
        except Exception:
            pass


def _extract_recommended_action(report: str) -> str:
    if not report:
        return ""
    marker = "**Recommended Action:**"
    idx = report.find(marker)
    if idx < 0:
        return ""
    tail = report[idx + len(marker):].strip()
    cut = tail.find("\n---")
    if cut >= 0:
        tail = tail[:cut]
    return tail.strip()


# --------------------------------------------------------------- POST /investigate
@router.post(
    "",
    response_model=InvestigationResponse,
    dependencies=[Depends(require_api_key)],
    summary="Investigate text, link, or pre-formatted email blob",
)
async def investigate(
    request: InvestigateRequest,
    current_user: Any = Depends(get_optional_user),
    db: Session = Depends(get_db),
) -> InvestigationResponse:
    agent = get_agent()
    cleaned = request.input.strip()
    if not cleaned:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="`input` must not be empty.",
        )

    key = _cache_key(cleaned)
    cached = _cache_get(key)
    if cached is not None:
        return cached

    try:
        result = await asyncio.to_thread(agent.investigate, cleaned)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Investigation failed: {exc}",
        )
    fallback = (
        "url"
        if cleaned.lower().startswith(("http://", "https://"))
        else "text"
    )
    response = _to_response(result, fallback_input_type=fallback)
    _cache_set(key, response)
    if current_user is not None:
        _save_to_history(db, current_user.id, cleaned, response)
    return response


# --------------------------------------------------------------- POST /investigate/email
@router.post(
    "/email",
    response_model=InvestigationResponse,
    dependencies=[Depends(require_api_key)],
    summary="Investigate an email — sender + subject + body",
)
async def investigate_email(
    request: EmailInvestigateRequest,
    current_user: Any = Depends(get_optional_user),
    db: Session = Depends(get_db),
) -> InvestigationResponse:
    agent = get_agent()
    sender = (request.sender or "").strip()
    subject = (request.subject or "").strip()
    body = (request.body or "").strip()
    if not body:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="`body` must not be empty.",
        )
    composed = "EMAIL INPUT\n"
    if sender:
        composed += f"Sender: {sender}\n"
    if subject:
        composed += f"Subject: {subject}\n"
    composed += f"Body:\n{body}"

    key = _cache_key(composed)
    cached = _cache_get(key)
    if cached is not None:
        return cached

    try:
        result = await asyncio.to_thread(agent.investigate, composed)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Email investigation failed: {exc}",
        )
    response = _to_response(result, fallback_input_type="email")
    _cache_set(key, response)
    if current_user is not None:
        _save_to_history(db, current_user.id, f"Email: {subject or body[:80]}", response)
    return response


# --------------------------------------------------------------- POST /investigate/screenshot
@router.post(
    "/screenshot",
    response_model=ScreenshotInvestigationResponse,
    dependencies=[Depends(require_api_key)],
    summary="OCR a screenshot of a message and investigate the extracted text",
)
async def investigate_screenshot(
    file: UploadFile = File(..., description="PNG / JPEG / WEBP screenshot"),
    current_user: Any = Depends(get_optional_user),
    db: Session = Depends(get_db),
) -> ScreenshotInvestigationResponse:
    if file.content_type and not file.content_type.startswith("image/"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported content type: {file.content_type}. Upload an image.",
        )
    image_bytes = await file.read()
    if not image_bytes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Empty file upload.",
        )

    vision = get_vision()
    try:
        outcome = await asyncio.to_thread(vision.analyze_screenshot, image_bytes)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Vision pipeline failed: {exc}",
        )

    if outcome.get("status") != "ok":
        return ScreenshotInvestigationResponse(
            status="extraction_failed",
            extraction=outcome.get("extraction", {}),
            investigation=None,
            user_message=outcome.get("user_message", "Could not read the screenshot clearly."),
        )

    # Re-run through the agent so we get structured fields (label, score, latency)
    # rather than only the report string the vision flow returns.
    extraction = outcome["extraction"]
    agent = get_agent()
    try:
        result = await asyncio.to_thread(agent.investigate, extraction["message_text"])
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Investigation after OCR failed: {exc}",
        )
    inv_resp = _to_response(result, fallback_input_type="text")
    if current_user is not None:
        _save_to_history(
            db, current_user.id,
            f"Screenshot: {extraction.get('message_text', '')[:80]}",
            inv_resp,
        )
    return ScreenshotInvestigationResponse(
        status="ok",
        extraction=extraction,
        investigation=inv_resp,
        user_message="Extraction and investigation complete.",
    )
