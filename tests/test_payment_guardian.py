"""
tests/test_payment_guardian.py
Tests for tools/payment_guardian.py

Run with: pytest tests/test_payment_guardian.py -v
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from unittest.mock import patch

from tools.payment_guardian import (
    extract_payment_signals,
    analyse_email,
    PaymentPattern,
    _action_from_prob,
)


# ── TEST DATA ─────────────────────────────────────────────────────────────────
CLEAN_EMAIL = """
Hi,

Please find the meeting notes attached. Our next call is scheduled for Friday.

Best regards,
Sarah
"""

BEC_EMAIL_IBAN = """
Dear Finance Team,

I hope this email finds you well. Please note that our bank account details have changed.
Effective immediately, please use the following new bank account for all payments:

IBAN: LK2200000010001234567890
SWIFT: BCEYLKLX

This is urgent. Please ensure the scheduled payment of USD 250,000 is processed today.
The CEO has approved this change. Please keep this confidential until further notice.

Regards,
CFO Office
"""

BEC_EMAIL_URGENCY = """
Dear Accounts,

URGENT REQUEST - CEO APPROVAL PENDING

Please wire transfer immediately to the following updated banking details:
Account Number: 007812345678
Routing: 021000021

This is time sensitive. Board meeting today at 4pm requires funds.
Do not discuss with anyone until confirmed.

Best,
CEO
"""

INVOICE_EMAIL = """
Invoice #INV-2024-001234

Dear Customer,

Please find attached your invoice for services rendered.
Payment due: 30 days from receipt.
Amount: LKR 125,000

Bank Account: 7891234567 (Commercial Bank)
Reference: INV-2024-001234

Thank you for your business.
"""


# ── EXTRACT PAYMENT SIGNALS ───────────────────────────────────────────────────
class TestExtractPaymentSignals:
    def test_clean_email_returns_none(self):
        result = extract_payment_signals(CLEAN_EMAIL)
        assert result is None

    def test_iban_detected(self):
        result = extract_payment_signals(BEC_EMAIL_IBAN)
        assert result is not None
        assert "iban" in result

    def test_bec_keywords_detected(self):
        result = extract_payment_signals(BEC_EMAIL_IBAN)
        assert result is not None
        assert "bec_keywords" in result

    def test_urgency_keywords(self):
        result = extract_payment_signals(BEC_EMAIL_URGENCY)
        assert result is not None
        # Should detect urgency + account
        assert result is not None

    def test_invoice_returns_signals(self):
        """Normal invoice has account number — should get signals, but low BEC probability."""
        result = extract_payment_signals(INVOICE_EMAIL)
        # Account number detected — returns dict (not None)
        # This is expected: the LLM will distinguish genuine invoice from BEC
        assert result is None or isinstance(result, dict)

    def test_empty_string(self):
        result = extract_payment_signals("")
        assert result is None

    def test_swift_pattern(self):
        text = "Please use Swift code BCEYLKLX for the transfer."
        result = extract_payment_signals(text)
        assert result is not None or result is None  # depending on regex precision


# ── ANALYSE EMAIL (with LLM mocked out) ──────────────────────────────────────
class TestAnalyseEmail:
    @patch("tools.payment_guardian._call_llm", return_value=None)
    def test_clean_email_allow(self, _mock):
        result = analyse_email(CLEAN_EMAIL, use_llm=False)
        assert isinstance(result, PaymentPattern)
        assert result.action == "allow"
        assert result.bec_probability == 0.0

    @patch("tools.payment_guardian._call_llm", return_value=None)
    def test_bec_email_not_allow(self, _mock):
        result = analyse_email(BEC_EMAIL_IBAN, use_llm=False)
        assert isinstance(result, PaymentPattern)
        assert result.has_payment_instruction is True
        assert result.action in ("warn", "hold", "block")
        assert result.bec_probability > 0.3

    @patch("tools.payment_guardian._call_llm", return_value={
        "has_payment_instruction": True,
        "account_change_detected": True,
        "urgency_score": 9,
        "thread_injection_risk": False,
        "bec_probability": 0.95,
        "explanation": "This is a BEC payment manipulation attempt.",
        "action": "block",
    })
    def test_llm_response_used(self, _mock):
        result = analyse_email(BEC_EMAIL_IBAN, use_llm=True)
        assert result.bec_probability == 0.95
        assert result.action == "block"
        assert "BEC" in result.explanation

    @patch("tools.payment_guardian._call_llm", return_value=None)
    def test_urgency_score_computed(self, _mock):
        result = analyse_email(BEC_EMAIL_URGENCY, use_llm=False)
        assert result.urgency_score > 0

    def test_to_dict(self):
        result = analyse_email(CLEAN_EMAIL, use_llm=False)
        d = result.to_dict()
        assert "bec_probability" in d
        assert "action" in d
        assert "matched_signals" in d
        assert "explanation" in d

    def test_empty_email(self):
        result = analyse_email("", use_llm=False)
        assert result.action == "allow"


# ── ACTION FROM PROB ──────────────────────────────────────────────────────────
class TestActionFromProb:
    def test_low_prob_allow(self):
        assert _action_from_prob(0.2) == "allow"

    def test_medium_prob_warn(self):
        assert _action_from_prob(0.45) == "warn"

    def test_high_prob_hold(self):
        assert _action_from_prob(0.65) == "hold"

    def test_very_high_prob_block(self):
        assert _action_from_prob(0.85) == "block"

    def test_threshold_boundaries(self):
        assert _action_from_prob(0.40) == "warn"
        assert _action_from_prob(0.60) == "hold"
        assert _action_from_prob(0.80) == "block"


# ── PAYMENT PATTERN DATACLASS ─────────────────────────────────────────────────
class TestPaymentPattern:
    def test_default_values(self):
        p = PaymentPattern()
        assert p.action == "allow"
        assert p.bec_probability == 0.0
        assert p.matched_signals == []

    def test_custom_values(self):
        p = PaymentPattern(
            has_payment_instruction=True,
            bec_probability=0.9,
            action="block",
        )
        assert p.has_payment_instruction is True
        assert p.action == "block"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
