"""
backend/routes/qr_scan.py
NovaGuard QR Scanner — API Endpoints

POST /api/v1/qr/scan        — Upload image, decode QR, analyse for quishing
POST /api/v1/qr/scan-pdf    — Upload PDF, scan all pages for QR codes
POST /api/v1/qr/scan-url    — Provide image URL, decode + analyse
GET  /api/v1/qr/history     — List past QR scans
GET  /api/v1/qr/report/{id} — Full result for a single scan
"""
from __future__ import annotations

import json
import logging
import os

import requests as req
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.database import Investigation, SessionLocal, get_db
from tools.qr_scanner import run_qr_scan_bytes, scan_pdf_images
from tools.quishing_detector import analyse_quishing

router = APIRouter(prefix="/qr", tags=["QR Scanner"])
log = logging.getLogger(__name__)

ALLOWED_IMAGE_TYPES = {"image/jpeg", "image/png", "image/webp", "image/gif", "image/bmp"}
MAX_IMAGE_MB = int(os.getenv("QR_MAX_FILE_SIZE_MB", "10"))
MAX_PDF_MB   = 20
MAX_CODES    = int(os.getenv("QR_MAX_CODES_PER_IMAGE", "5"))

_LEVEL_TO_LABEL = {"green": "SAFE", "yellow": "SUSPICIOUS", "red": "SCAM"}
_LEVEL_TO_TL    = {"green": "green", "yellow": "yellow", "red": "red"}


class ScanUrlRequest(BaseModel):
    image_url: str
    user_id:   str = ""


def _save_qr_investigation(analysis, qr_url: str, db: Session) -> Investigation:
    """Save a QuishingResult as an Investigation row using the existing schema."""
    label = _LEVEL_TO_LABEL.get(analysis.risk_level, "SUSPICIOUS")
    tl    = _LEVEL_TO_TL.get(analysis.risk_level, "yellow")
    inv   = Investigation(
        user_id          = None,
        input_preview    = qr_url[:200],
        input_type       = "qr_code",
        predicted_label  = label,
        predicted_score  = analysis.risk_score,
        report           = json.dumps(analysis.to_dict()),
        traffic_light    = tl,
        recommended_action = (
            "Do not open this QR code URL — it shows signs of quishing (QR phishing)."
            if analysis.risk_level == "red"
            else "Treat with caution — scan the URL before proceeding."
            if analysis.risk_level == "yellow"
            else "URL appears safe based on available signals."
        ),
        latency_seconds  = 0.0,
    )
    db.add(inv)
    db.commit()
    db.refresh(inv)
    return inv


async def _analyse_qr_list(qr_list, db: Session) -> list[dict]:
    """Run quishing analysis on a list of QRResult objects. Returns result dicts."""
    results = []
    for qr in qr_list[:MAX_CODES]:
        try:
            analysis = analyse_quishing(
                url              = qr.url,
                label_text       = qr.label_text,
                overlay_detected = qr.overlay_detected,
            )
            inv = _save_qr_investigation(analysis, qr.url, db)
            result_dict = analysis.to_dict()
            result_dict["investigation_id"] = inv.id
            result_dict["page_number"]      = qr.page_number
            results.append(result_dict)
        except Exception as exc:
            log.warning("[QR] Analysis failed for URL %s: %s", qr.url[:60], exc)
    return results


@router.post("/scan")
async def scan_image(
    file:    UploadFile = File(...),
    user_id: str        = Form(""),
    db:      Session    = Depends(get_db),
):
    """Upload an image file. Decode all QR codes. Analyse each for quishing."""
    content_type = file.content_type or ""
    if content_type not in ALLOWED_IMAGE_TYPES:
        raise HTTPException(400, f"Unsupported file type: {content_type}.")

    file_bytes = await file.read()
    if len(file_bytes) > MAX_IMAGE_MB * 1024 * 1024:
        raise HTTPException(413, f"File too large. Max {MAX_IMAGE_MB}MB.")

    try:
        qr_results = run_qr_scan_bytes(file_bytes)
    except Exception as exc:
        raise HTTPException(422, f"Could not process image: {exc}")

    if not qr_results:
        return {"results": [], "total_qr_found": 0, "message": "No QR codes detected in this image."}

    results = await _analyse_qr_list(qr_results, db)
    return {"results": results, "total_qr_found": len(qr_results)}


@router.post("/scan-pdf")
async def scan_pdf(
    file:    UploadFile = File(...),
    user_id: str        = Form(""),
    db:      Session    = Depends(get_db),
):
    """Upload a PDF file. Scan all pages for QR codes."""
    if file.content_type != "application/pdf":
        raise HTTPException(400, "Only PDF files accepted on this endpoint.")

    file_bytes = await file.read()
    if len(file_bytes) > MAX_PDF_MB * 1024 * 1024:
        raise HTTPException(413, f"PDF too large. Max {MAX_PDF_MB}MB.")

    try:
        qr_results = scan_pdf_images(file_bytes)
    except Exception as exc:
        raise HTTPException(422, f"Could not process PDF: {exc}")

    if not qr_results:
        return {"results": [], "total_qr_found": 0, "message": "No QR codes detected in this PDF."}

    results = await _analyse_qr_list(qr_results, db)
    pages = {qr.page_number for qr in qr_results if qr.page_number}
    return {"results": results, "total_qr_found": len(qr_results), "pages_with_qr": sorted(pages)}


@router.post("/scan-url")
async def scan_url(body: ScanUrlRequest, db: Session = Depends(get_db)):
    """Provide an HTTPS image URL. Image downloaded server-side. Same pipeline as /qr/scan."""
    if not body.image_url.startswith("https://"):
        raise HTTPException(400, "image_url must be HTTPS.")
    try:
        response = req.get(body.image_url, timeout=10, stream=True)
        response.raise_for_status()
        content_type = response.headers.get("content-type", "")
        if not any(t in content_type for t in ("image/", "application/octet")):
            raise HTTPException(422, f"URL does not point to an image.")
        file_bytes = response.content
    except req.Timeout:
        raise HTTPException(408, "Image download timed out.")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(422, f"Failed to download image: {exc}")

    try:
        qr_results = run_qr_scan_bytes(file_bytes)
    except Exception as exc:
        raise HTTPException(422, f"Could not decode image: {exc}")

    if not qr_results:
        return {"results": [], "total_qr_found": 0, "message": "No QR codes detected."}

    results = await _analyse_qr_list(qr_results, db)
    return {"results": results, "total_qr_found": len(qr_results)}


@router.get("/history")
async def qr_history(
    limit:  int     = 20,
    offset: int     = 0,
    db:     Session = Depends(get_db),
):
    """Return recent QR scan investigations."""
    q = (
        db.query(Investigation)
        .filter(Investigation.input_type == "qr_code")
        .order_by(Investigation.created_at.desc())
        .offset(offset)
        .limit(min(limit, 100))
    )
    items = q.all()
    total = db.query(Investigation).filter(Investigation.input_type == "qr_code").count()
    return {
        "scans": [
            {
                "investigation_id": i.id,
                "scanned_at":       i.created_at.isoformat() if i.created_at else None,
                "decoded_url":      i.input_preview,
                "risk_level":       i.traffic_light,
            }
            for i in items
        ],
        "total":  total,
        "limit":  limit,
        "offset": offset,
    }


@router.get("/report/{investigation_id}")
async def qr_report(investigation_id: int, db: Session = Depends(get_db)):
    """Return the full QuishingResult for a past QR scan."""
    inv = db.query(Investigation).filter(
        Investigation.id         == investigation_id,
        Investigation.input_type == "qr_code",
    ).first()
    if not inv:
        raise HTTPException(404, "QR scan report not found.")
    report_data = {}
    if inv.report:
        try:
            report_data = json.loads(inv.report)
        except Exception:
            pass
    return {
        "investigation_id": inv.id,
        "scanned_at":       inv.created_at.isoformat() if inv.created_at else None,
        "decoded_url":      inv.input_preview,
        **report_data,
    }
