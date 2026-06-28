"""
tests/test_qr_scanner.py
Tests for tools/qr_scanner.py

Run with: pytest tests/test_qr_scanner.py -v
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import io
import pytest
from unittest.mock import patch, MagicMock


# ── HELPERS ───────────────────────────────────────────────────────────────────
def make_qr_image_bytes(url: str = "https://example.com") -> bytes:
    """
    Generate a real QR code PNG if qrcode library is available,
    otherwise return a minimal white PNG (so decode returns empty list).
    """
    try:
        import qrcode
        qr = qrcode.make(url)
        buf = io.BytesIO()
        qr.save(buf, format="PNG")
        return buf.getvalue()
    except ImportError:
        # Minimal 1×1 white PNG
        return (
            b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00'
            b'\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8'
            b'\x0f\x00\x00\x01\x01\x00\x18\xdd\x8d\xb4\x00\x00\x00\x00IEND\xaeB`\x82'
        )

def make_white_png() -> bytes:
    """A plain white 10×10 PNG (no QR code)."""
    try:
        from PIL import Image
        img = Image.new("RGB", (10, 10), (255, 255, 255))
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()
    except ImportError:
        return make_qr_image_bytes("placeholder")


# ── TESTS ─────────────────────────────────────────────────────────────────────
class TestQrScannerImport:
    def test_module_imports(self):
        from tools import qr_scanner
        assert hasattr(qr_scanner, "run_qr_scan_bytes")
        assert hasattr(qr_scanner, "scan_email_attachments")
        assert hasattr(qr_scanner, "scan_pdf_images")


class TestPreprocessImage:
    @pytest.mark.skipif(not __import__("importlib").util.find_spec("PIL"), reason="Pillow not installed")
    def test_preprocess_returns_image(self):
        from PIL import Image
        from tools.qr_scanner import preprocess_image
        img = Image.new("RGB", (100, 100), (200, 200, 200))
        result = preprocess_image(img)
        assert result.mode == "RGB"
        assert result.size == (100, 100)


class TestDecodeQrCodes:
    @patch("tools.qr_scanner.PYZBAR_OK", False)
    def test_no_pyzbar_returns_empty(self):
        from tools.qr_scanner import decode_qr_codes
        from PIL import Image
        img = Image.new("RGB", (10, 10))
        result = decode_qr_codes(img)
        assert result == []

    @pytest.mark.skipif(not __import__("importlib").util.find_spec("pyzbar"), reason="pyzbar not installed")
    def test_no_qr_in_white_image(self):
        from tools.qr_scanner import run_qr_scan_bytes
        result = run_qr_scan_bytes(make_white_png())
        assert result == []

    @pytest.mark.skipif(
        not __import__("importlib").util.find_spec("pyzbar") or
        not __import__("importlib").util.find_spec("qrcode"),
        reason="pyzbar or qrcode not installed",
    )
    def test_real_qr_decoded(self):
        from tools.qr_scanner import run_qr_scan_bytes
        img_bytes = make_qr_image_bytes("https://boc.lk/login")
        results = run_qr_scan_bytes(img_bytes)
        assert len(results) >= 1
        assert results[0].url == "https://boc.lk/login"


class TestRunQrScanBytes:
    def test_invalid_bytes(self):
        from tools.qr_scanner import run_qr_scan_bytes
        result = run_qr_scan_bytes(b"not an image")
        assert result == []  # graceful — not an exception

    def test_empty_bytes(self):
        from tools.qr_scanner import run_qr_scan_bytes
        result = run_qr_scan_bytes(b"")
        assert result == []

    def test_returns_list(self):
        from tools.qr_scanner import run_qr_scan_bytes
        result = run_qr_scan_bytes(make_white_png())
        assert isinstance(result, list)


class TestExtractLabelText:
    @patch("tools.qr_scanner.TESSERACT_OK", False)
    def test_no_tesseract_returns_empty(self):
        from tools.qr_scanner import extract_label_text
        from PIL import Image
        img = Image.new("RGB", (100, 100))
        result = extract_label_text(img, (10, 10, 50, 50))
        assert result == ""


class TestDetectOverlay:
    @patch("tools.qr_scanner.PYZBAR_OK", False)
    def test_no_pyzbar_returns_false(self):
        from tools.qr_scanner import detect_overlay
        from PIL import Image
        img = Image.new("RGB", (100, 100))
        result = detect_overlay(img, (10, 10, 50, 50))
        assert result is False

    @pytest.mark.skipif(not __import__("importlib").util.find_spec("PIL"), reason="Pillow not installed")
    def test_white_image_no_overlay(self):
        from tools.qr_scanner import detect_overlay
        from PIL import Image
        img = Image.new("RGB", (200, 200), (255, 255, 255))
        result = detect_overlay(img, (50, 50, 100, 100))
        assert result is False


class TestScanEmailAttachments:
    def test_empty_email(self):
        from tools.qr_scanner import scan_email_attachments
        result = scan_email_attachments(b"From: test\n\nBody only")
        assert result == []

    def test_no_image_attachments(self):
        raw = (
            b"From: test@example.com\n"
            b"Content-Type: text/plain\n\n"
            b"Just text, no images"
        )
        from tools.qr_scanner import scan_email_attachments
        result = scan_email_attachments(raw)
        assert result == []


class TestScanPdfImages:
    @patch("tools.qr_scanner.FITZ_OK", False)
    def test_no_pymupdf_returns_empty(self):
        from tools.qr_scanner import scan_pdf_images
        result = scan_pdf_images(b"fake pdf bytes")
        assert result == []

    def test_invalid_pdf_bytes_graceful(self):
        from tools.qr_scanner import scan_pdf_images
        result = scan_pdf_images(b"not a pdf")
        assert result == []  # should not raise


class TestQrResultDataclass:
    def test_to_dict(self):
        from tools.qr_scanner import QRResult
        qr = QRResult(url="https://example.com", raw_data="https://example.com")
        d = qr.to_dict()
        assert d["url"] == "https://example.com"
        assert "rect" in d
        assert "overlay_detected" in d


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
