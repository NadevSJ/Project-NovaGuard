"""
tests/test_email_auth.py
Unit tests for the Email Authentication Engine.

Run with: pytest tests/test_email_auth.py -v
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from unittest.mock import patch, MagicMock
from tools.email_auth import (
    check_spf, check_dkim, check_dmarc, analyze_headers,
    check_display_name, run_full_auth, EmailAuthResult,
)


# ── SAMPLE EMAIL FIXTURES ──────────────────────────────────────────────────────
CLEAN_EMAIL = b"""\
From: sender@example.com
To: receiver@boc.lk
Subject: Hello
MIME-Version: 1.0
Return-Path: <sender@example.com>
Received: from mail.example.com ([93.184.216.34]) by mx.boc.lk; Mon, 1 Jan 2024 10:00:00 +0530
Message-ID: <abc123@example.com>

Hello, this is a normal email.
"""

BEC_EMAIL = b"""\
From: CFO Kanchana Senarath <cfo@b0c-lk.xyz>
To: accounts@boc.lk
Subject: URGENT - New Bank Account Details
MIME-Version: 1.0
Return-Path: <noreply@totally-different.com>
Reply-To: attacker@gmail.com
Received: from [192.168.1.1] (unknown) by mx.boc.lk; Mon, 1 Jan 2024 10:00:00 +0530

Dear Team,
Please note our bank account has changed. Please wire the payment to:
IBAN LK0200000010001234567890
SWIFT BCEYLKLX

This is URGENT. Please process today. CEO has approved.
Do not discuss this with anyone.
"""

SPOOFED_DISPLAY_EMAIL = b"""\
From: "Kanchana Ratwatte CEO" <random-sender@gmail.com>
To: accounts@boc.lk
Subject: Urgent Wire Transfer
MIME-Version: 1.0
Return-Path: <random-sender@gmail.com>

Please transfer LKR 5 million immediately.
"""


# ── SPF TESTS ─────────────────────────────────────────────────────────────────
class TestCheckSpf:
    def test_missing_email_from(self):
        result, detail = check_spf("", "1.2.3.4")
        assert result in ("none", "error")

    def test_invalid_ip(self):
        result, detail = check_spf("sender@example.com", "not_an_ip")
        assert result in ("error", "none")  # graceful handling

    @patch("tools.email_auth.DNS_OK", False)
    def test_no_dnspython(self):
        result, detail = check_spf("sender@example.com", "1.2.3.4")
        assert result == "error"
        assert "dnspython" in detail

    def test_no_spf_record_real_lookup(self):
        """When DNS is unavailable or domain has no SPF, result must be non-pass."""
        # Use a clearly fake domain that will never have an SPF record
        result, detail = check_spf("user@this-domain-absolutely-does-not-exist-xyzabc.invalid", "1.2.3.4")
        assert result in ("none", "error", "neutral", "fail", "softfail")


# ── DKIM TESTS ────────────────────────────────────────────────────────────────
class TestCheckDkim:
    @patch("tools.email_auth.DKIM_OK", False)
    def test_no_dkimpy(self):
        result, detail = check_dkim(b"raw email")
        assert result == "none"
        assert "dkimpy" in detail

    def test_empty_bytes(self):
        result, _ = check_dkim(b"")
        assert result == "none"

    @patch("tools.email_auth.dkim")
    def test_dkim_fail(self, mock_dkim):
        mock_dkim.verify.return_value = False
        result, detail = check_dkim(b"test email bytes")
        assert result == "fail"

    @patch("tools.email_auth.dkim")
    def test_dkim_pass(self, mock_dkim):
        mock_dkim.verify.return_value = True
        result, detail = check_dkim(b"test email bytes")
        assert result == "pass"


# ── DMARC TESTS ───────────────────────────────────────────────────────────────
class TestCheckDmarc:
    @patch("tools.email_auth.DNS_OK", False)
    def test_no_dnspython(self):
        result, policy, detail = check_dmarc("user@example.com")
        assert result == "error"

    def test_empty_from(self):
        result, policy, detail = check_dmarc("")
        assert result == "none"

    @patch("tools.email_auth.dns")
    def test_reject_policy(self, mock_dns):
        mock_rdata = MagicMock()
        mock_rdata.to_text.return_value = '"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"'
        mock_dns.resolver.resolve.return_value = [mock_rdata]
        result, policy, detail = check_dmarc("user@example.com")
        assert result == "pass"
        assert policy == "reject"


# ── HEADER ANALYSIS TESTS ─────────────────────────────────────────────────────
class TestAnalyzeHeaders:
    def test_clean_email(self):
        import email
        msg = email.message_from_bytes(CLEAN_EMAIL)
        score, signals = analyze_headers(msg)
        assert score >= 0
        assert isinstance(signals, list)

    def test_bec_email_return_path_mismatch(self):
        import email
        msg = email.message_from_bytes(BEC_EMAIL)
        score, signals = analyze_headers(msg)
        # Should detect Return-Path ≠ From AND Reply-To mismatch
        assert score > 0
        assert any("Return-Path" in s or "Reply-To" in s for s in signals)

    def test_private_ip_first_hop(self):
        import email
        msg = email.message_from_bytes(BEC_EMAIL)
        score, signals = analyze_headers(msg)
        # The BEC email has Received from [192.168.1.1]
        assert score > 0

    def test_missing_mime_version(self):
        import email
        raw = b"From: test@example.com\n\nBody"
        msg = email.message_from_bytes(raw)
        score, signals = analyze_headers(msg)
        assert any("MIME" in s for s in signals)


# ── DISPLAY-NAME SPOOF TESTS ──────────────────────────────────────────────────
class TestCheckDisplayName:
    EXECUTIVES = ["Kanchana Ratwatte", "Siddhika Senarath"]

    def test_no_executives_list(self):
        is_spoof, exec_name = check_display_name("Kanchana Ratwatte CEO", "user@gmail.com", "boc.lk", [])
        assert is_spoof is False

    def test_exact_match_wrong_domain(self):
        is_spoof, exec_name = check_display_name(
            "kanchana ratwatte", "attacker@gmail.com", "boc.lk", self.EXECUTIVES
        )
        assert is_spoof is True
        assert "Kanchana" in exec_name

    def test_correct_domain_not_spoofed(self):
        is_spoof, exec_name = check_display_name(
            "Kanchana Ratwatte", "kanchana@boc.lk", "boc.lk", self.EXECUTIVES
        )
        assert is_spoof is False

    def test_no_match(self):
        is_spoof, exec_name = check_display_name(
            "John Random Person", "john@gmail.com", "boc.lk", self.EXECUTIVES
        )
        assert is_spoof is False


# ── RUN_FULL_AUTH INTEGRATION TESTS ──────────────────────────────────────────
class TestRunFullAuth:
    @patch("tools.email_auth.DNS_OK", False)
    @patch("tools.email_auth.DKIM_OK", False)
    def test_clean_email_no_deps(self):
        result = run_full_auth(CLEAN_EMAIL, sender_ip="93.184.216.34", org_domain="boc.lk")
        assert isinstance(result, EmailAuthResult)
        assert result.overall_risk >= 0
        assert result.recommended_action in ("allow", "warn", "quarantine", "block")

    @patch("tools.email_auth.DNS_OK", False)
    @patch("tools.email_auth.DKIM_OK", False)
    def test_bec_email_return_path_risk(self):
        result = run_full_auth(BEC_EMAIL, org_domain="boc.lk")
        # Should detect Return-Path / Reply-To mismatch via header analysis
        assert result.overall_risk > 0
        assert len(result.signals) > 0

    @patch("tools.email_auth.DNS_OK", False)
    @patch("tools.email_auth.DKIM_OK", False)
    def test_display_name_spoofing(self):
        result = run_full_auth(
            SPOOFED_DISPLAY_EMAIL,
            org_domain="boc.lk",
            known_executives=["Kanchana Ratwatte"],
        )
        assert result.display_name_spoof is True
        assert result.spoofed_executive == "Kanchana Ratwatte"
        assert result.overall_risk >= 50

    def test_empty_email_bytes(self):
        result = run_full_auth(b"", org_domain="boc.lk")
        assert isinstance(result, EmailAuthResult)

    def test_to_dict(self):
        result = run_full_auth(CLEAN_EMAIL)
        d = result.to_dict()
        assert "overall_risk" in d
        assert "recommended_action" in d
        assert "signals" in d


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
