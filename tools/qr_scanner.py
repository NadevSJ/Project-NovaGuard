"""
tools/qr_scanner.py
NovaGuard QR Scanner — Core QR Decode Module

Decodes QR codes from images, PDFs, and email attachments.
Runs image preprocessing to handle low-quality photos.

Dependencies (add to requirements.txt):
    pyzbar>=0.1.9
    Pillow>=10.0.0
    pytesseract>=0.3.10
    pymupdf>=1.24.0   (for PDF scanning)

System packages:
    sudo apt install libzbar0 libzbar-dev tesseract-ocr libtesseract-dev -y
"""
from __future__ import annotations

import base64
import email
import io
import logging
import os
import tempfile
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger(__name__)

# ── optional dependency guards ────────────────────────────────────────────────
try:
    from pyzbar import pyzbar
    from PIL import Image, ImageEnhance, ImageFilter, ImageChops
    PYZBAR_OK = True
except ImportError:
    PYZBAR_OK = False
    log.warning("pyzbar/Pillow not installed. Run: pip install pyzbar Pillow")

try:
    import pytesseract
    TESSERACT_OK = True
except ImportError:
    TESSERACT_OK = False
    log.warning("pytesseract not installed. Run: pip install pytesseract")

try:
    import fitz  # PyMuPDF
    FITZ_OK = True
except ImportError:
    FITZ_OK = False
    log.warning("PyMuPDF not installed. Run: pip install pymupdf")


# ─── DATA CLASSES ─────────────────────────────────────────────────────────────
@dataclass
class QRResult:
    """Result from decoding one QR code in an image."""
    url:              str
    raw_data:         str              # same as url for URL-type QRs; might differ for other types
    qr_type:         str = "QRCODE"   # pyzbar type string
    rect:            tuple = (0, 0, 0, 0)  # (left, top, width, height) in pixel space
    page_number:     Optional[int] = None  # set when scanning a PDF
    label_text:      str = ""              # OCR text around the QR (for mismatch detection)
    overlay_detected:bool = False          # True if QR appears pasted over another image

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "raw_data": self.raw_data,
            "qr_type": self.qr_type,
            "rect": list(self.rect),
            "page_number": self.page_number,
            "label_text": self.label_text,
            "overlay_detected": self.overlay_detected,
        }


# ─── IMAGE PREPROCESSING ──────────────────────────────────────────────────────
def preprocess_image(pil_image: "Image.Image") -> "Image.Image":
    """
    Enhance an image to improve QR code decode success rate.
    - Convert to RGB
    - Boost contrast 1.6×
    - Sharpen filter
    Returns enhanced PIL Image.
    """
    if not PYZBAR_OK:
        raise RuntimeError("Pillow not installed")
    img = pil_image.convert("RGB")
    img = ImageEnhance.Contrast(img).enhance(1.6)
    img = img.filter(ImageFilter.SHARPEN)
    return img


def _pil_from_path(image_path: str) -> "Image.Image":
    img = Image.open(image_path)
    return img


def _pil_from_bytes(data: bytes) -> "Image.Image":
    return Image.open(io.BytesIO(data))


# ─── DECODE QR CODES FROM A PIL IMAGE ────────────────────────────────────────
def decode_qr_codes(
    pil_image: "Image.Image",
    page_number: Optional[int] = None,
) -> list[QRResult]:
    """
    Decode all QR codes (and barcodes) from a PIL Image.
    Tries once at original size, then at 2× upscale if none found.
    Returns a list of QRResult (may be empty).
    """
    if not PYZBAR_OK:
        log.warning("pyzbar not available — skipping QR decode")
        return []

    results = []

    def _decode(img: "Image.Image") -> list:
        try:
            return pyzbar.decode(img)
        except Exception as exc:
            log.debug("pyzbar decode error: %s", exc)
            return []

    found = _decode(pil_image)
    if not found:
        # Try enhanced version
        try:
            enhanced = preprocess_image(pil_image)
            found = _decode(enhanced)
        except Exception:
            pass
    if not found:
        # Try 2× upscale for tiny QR codes
        try:
            w, h = pil_image.size
            big = pil_image.resize((w * 2, h * 2), Image.LANCZOS)
            found = _decode(big)
        except Exception:
            pass

    for item in found:
        try:
            raw = item.data.decode("utf-8", errors="replace").strip()
            if not raw:
                continue
            rect = (item.rect.left, item.rect.top, item.rect.width, item.rect.height)
            results.append(QRResult(
                url=raw,
                raw_data=raw,
                qr_type=item.type.decode("utf-8") if isinstance(item.type, bytes) else str(item.type),
                rect=rect,
                page_number=page_number,
            ))
        except Exception as exc:
            log.debug("QR result parse error: %s", exc)

    return results


# ─── OCR LABEL EXTRACTION ─────────────────────────────────────────────────────
def extract_label_text(
    pil_image: "Image.Image",
    rect: tuple,
    border_px: int = 100,
) -> str:
    """
    OCR the area around a QR bounding box to detect label/brand mismatches.
    Returns lowercase stripped string.
    """
    if not TESSERACT_OK or not PYZBAR_OK:
        return ""
    try:
        left, top, width, height = rect
        img_w, img_h = pil_image.size
        crop_left   = max(0, left - border_px)
        crop_top    = max(0, top  - border_px)
        crop_right  = min(img_w, left + width  + border_px)
        crop_bottom = min(img_h, top  + height + border_px)
        crop = pil_image.crop((crop_left, crop_top, crop_right, crop_bottom))
        text = pytesseract.image_to_string(crop, config="--psm 11")
        return text.strip().lower()
    except Exception as exc:
        log.debug("OCR label extraction failed: %s", exc)
        return ""


# ─── OVERLAY DETECTION ────────────────────────────────────────────────────────
def detect_overlay(pil_image: "Image.Image", rect: tuple, border_px: int = 12) -> bool:
    """
    Detect if a QR code has been printed/pasted over another image (swap attack).
    Compares colour variance inside the QR rect vs. immediately outside it.
    Returns True if a significant colour discontinuity suggests an overlay.
    """
    if not PYZBAR_OK:
        return False
    try:
        left, top, width, height = rect
        img_w, img_h = pil_image.size
        img_rgb = pil_image.convert("RGB")

        # Inner region (the QR itself)
        inner = img_rgb.crop((
            max(0, left),
            max(0, top),
            min(img_w, left + width),
            min(img_h, top + height),
        ))

        # Outer ring (border_px wide band around the QR)
        outer = img_rgb.crop((
            max(0, left - border_px),
            max(0, top  - border_px),
            min(img_w, left + width  + border_px),
            min(img_h, top  + height + border_px),
        ))
        diff = ImageChops.difference(inner.resize(outer.size, Image.LANCZOS), outer)
        import numpy as np
        arr = np.array(diff)
        if arr.size == 0:
            return False
        mean_diff = float(arr.max(axis=2).mean())
        return mean_diff > 60  # threshold: significant colour jump at boundary
    except Exception as exc:
        log.debug("Overlay detection failed: %s", exc)
        return False


# ─── FULL IMAGE SCAN ──────────────────────────────────────────────────────────
def run_qr_scan(image_path: str) -> list[QRResult]:
    """
    Full pipeline for a single image file:
    load → preprocess → decode QR codes → extract labels → detect overlays.

    Returns list of QRResult (empty if no QR codes found).
    """
    if not PYZBAR_OK:
        return []
    try:
        img = _pil_from_path(image_path)
    except Exception as exc:
        log.warning("Failed to open image %s: %s", image_path, exc)
        return []

    results = decode_qr_codes(img)
    for qr in results:
        qr.label_text     = extract_label_text(img, qr.rect)
        qr.overlay_detected = detect_overlay(img, qr.rect)
    return results


def run_qr_scan_bytes(image_bytes: bytes) -> list[QRResult]:
    """Same as run_qr_scan() but accepts raw image bytes."""
    if not PYZBAR_OK:
        return []
    try:
        img = _pil_from_bytes(image_bytes)
    except Exception as exc:
        log.warning("Failed to open image bytes: %s", exc)
        return []
    results = decode_qr_codes(img)
    for qr in results:
        qr.label_text      = extract_label_text(img, qr.rect)
        qr.overlay_detected = detect_overlay(img, qr.rect)
    return results


# ─── PDF SCANNING ─────────────────────────────────────────────────────────────
def scan_pdf_images(pdf_bytes: bytes) -> list[QRResult]:
    """
    Extract all images from a PDF and scan each for QR codes.
    Requires PyMuPDF (pip install pymupdf).

    Returns list of QRResult with page_number set.
    """
    if not FITZ_OK:
        log.warning("PyMuPDF not installed — PDF QR scan unavailable")
        return []
    if not PYZBAR_OK:
        return []

    results: list[QRResult] = []
    try:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        for pno in range(doc.page_count):
            page = doc.load_page(pno)
            for img_info in page.get_images(full=True):
                xref = img_info[0]
                try:
                    pix = fitz.Pixmap(doc, xref)
                    if pix.n > 4:           # CMYK or other
                        pix = fitz.Pixmap(fitz.csRGB, pix)
                    img_bytes = pix.tobytes("png")
                    for qr in run_qr_scan_bytes(img_bytes):
                        qr.page_number = pno + 1
                        results.append(qr)
                except Exception as exc:
                    log.debug("PDF image extract failed (page %d, xref %d): %s", pno+1, xref, exc)
        doc.close()
    except Exception as exc:
        log.warning("PDF scan failed: %s", exc)
    return results


# ─── EMAIL ATTACHMENT SCANNING ────────────────────────────────────────────────
def scan_email_attachments(raw_email_bytes: bytes) -> list[QRResult]:
    """
    Parse a raw email and scan all image/* attachments (inline or attached)
    for QR codes.

    Returns list of QRResult across all attachments.
    """
    if not PYZBAR_OK:
        return []

    results: list[QRResult] = []
    try:
        msg = email.message_from_bytes(raw_email_bytes)
        for part in msg.walk():
            ct = part.get_content_type()
            if not ct.startswith("image/"):
                continue
            try:
                payload = part.get_payload(decode=True)
                if payload:
                    found = run_qr_scan_bytes(payload)
                    results.extend(found)
            except Exception as exc:
                log.debug("Attachment scan failed: %s", exc)
    except Exception as exc:
        log.warning("Email parse failed in scan_email_attachments: %s", exc)
    return results
