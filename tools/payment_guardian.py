"""
tools/payment_guardian.py
NovaGuard Shield — Payment BEC Guardian

Detects Business Email Compromise (BEC) payment-manipulation attacks
by combining a fast regex pre-filter with LLM-based intent analysis.
"""
from __future__ import annotations

import json
import re
import logging
from dataclasses import dataclass, field
from typing import Literal, Optional

log = logging.getLogger(__name__)

# ─── PAYMENT SIGNAL PATTERNS ──────────────────────────────────────────────────
_IBAN_RE      = re.compile(r'\b[A-Z]{2}\d{2}[A-Z0-9]{4,}\b')
_SWIFT_RE     = re.compile(r'\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?\b')
_ACCOUNT_RE   = re.compile(r'\b(\d[\s\-]?){8,18}\d\b')
_BEC_KEYWORDS = [
    r'bank.{0,8}(account|detail|information)\s*(has\s*)?changed',
    r'(new|updated?)\s*(banking|payment|wire|transfer)\s*(detail|instruction|information)',
    r'(please|kindly)\s*(update|use|note)\s*(the\s*)?(new|following|below)\s*(bank|account|IBAN|Swift)',
    r'(urgent|immediate|critical|asap|time.?sensitive)',
    r'(wire|bank)\s*(transfer|payment)\s*(instruction|detail)',
    r'(revised?|amended?)\s*(invoice|payment)',
    r'do\s*not\s*(discuss|share|reply)',
    r'(ceo|cfo|director|management)\s*(request|instruction|approval)',
]
_BEC_COMPILED = [re.compile(p, re.IGNORECASE) for p in _BEC_KEYWORDS]


@dataclass
class PaymentPattern:
    """Structured result from payment BEC analysis."""
    has_payment_instruction:  bool = False
    account_change_detected:  bool = False
    urgency_score:            int  = 0   # 0-10
    thread_injection_risk:    bool = False
    bec_probability:          float = 0.0  # 0.0-1.0
    explanation:              str   = ""
    action: Literal["allow", "warn", "hold", "block"] = "allow"
    matched_signals:          list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "has_payment_instruction": self.has_payment_instruction,
            "account_change_detected": self.account_change_detected,
            "urgency_score": self.urgency_score,
            "thread_injection_risk": self.thread_injection_risk,
            "bec_probability": self.bec_probability,
            "explanation": self.explanation,
            "action": self.action,
            "matched_signals": self.matched_signals,
        }


# ─── LAYER 1: FAST REGEX PRE-FILTER ──────────────────────────────────────────
def extract_payment_signals(email_body: str) -> Optional[dict]:
    """
    Fast regex pass. Returns None immediately if no payment signals found
    (avoids LLM cost for non-payment emails).

    Returns a dict of detected signals or None.
    """
    if not email_body:
        return None

    signals = {}

    # IBAN detection
    ibans = _IBAN_RE.findall(email_body)
    if ibans:
        signals["iban"] = ibans

    # Swift/BIC detection
    swifts = _SWIFT_RE.findall(email_body[:2000])  # usually near top
    if swifts:
        signals["swift"] = [s[0] if isinstance(s, tuple) else s for s in swifts]

    # Account number patterns
    accts = _ACCOUNT_RE.findall(email_body)
    if accts:
        signals["account_numbers"] = accts[:5]

    # BEC keyword phrases
    matched_keywords = []
    for cre in _BEC_COMPILED:
        m = cre.search(email_body)
        if m:
            matched_keywords.append(m.group(0).strip())
    if matched_keywords:
        signals["bec_keywords"] = matched_keywords

    if not signals:
        return None  # No payment signals — skip LLM
    return signals


# ─── LAYER 2: LLM BEC ANALYSIS ───────────────────────────────────────────────
QUISHING_BEC_PROMPT = """You are a cybersecurity analyst specialising in Business Email Compromise (BEC).
Analyse the following email for BEC payment manipulation attacks.

Answer strictly in JSON with these exact fields:
{
  "has_payment_instruction": bool,
  "account_change_detected": bool,
  "urgency_score": int (0-10),
  "thread_injection_risk": bool,
  "bec_probability": float (0.0-1.0),
  "explanation": "one or two plain-English sentences explaining your verdict",
  "action": "allow" | "warn" | "hold" | "block"
}

Reasoning guidance:
- has_payment_instruction: true if the email contains any request to make or change a payment
- account_change_detected: true if bank account, IBAN, Swift, or payment routing details appear to have changed
- urgency_score: how urgently the email pressures the reader to act (0=none, 10=extreme)
- thread_injection_risk: true if the email appears to have been injected into an existing thread
- bec_probability: your overall confidence (0.0-1.0) that this is a BEC attack
- action: "allow" (safe), "warn" (suspicious), "hold" (likely BEC, hold payment), "block" (confirmed BEC)

Output ONLY the JSON object. No preamble or explanation outside the JSON.

EMAIL TO ANALYSE:
"""


def _call_llm(email_text: str) -> Optional[dict]:
    """Call the configured LLM with the BEC analysis prompt."""
    try:
        # Try to use the existing NovaGuard LLM configuration
        from langchain_core.messages import HumanMessage, SystemMessage
        from agent.llm_factory import build_llm

        llm = build_llm(temperature=0.1)
        messages = [
            SystemMessage(content="You are a BEC detection expert. Output only valid JSON."),
            HumanMessage(content=QUISHING_BEC_PROMPT + email_text[:3000]),
        ]
        response = llm.invoke(messages)
        content = response.content if hasattr(response, "content") else str(response)

        # Strip markdown fences if present
        content = re.sub(r'^```(?:json)?\s*|\s*```$', '', content.strip(), flags=re.MULTILINE)
        return json.loads(content)

    except ImportError:
        log.warning("LangChain/LLM not available — using heuristic BEC scoring only")
        return None
    except json.JSONDecodeError as exc:
        log.warning("BEC LLM returned invalid JSON: %s", exc)
        return None
    except Exception as exc:
        log.warning("BEC LLM call failed: %s", exc)
        return None


# ─── ORCHESTRATOR ─────────────────────────────────────────────────────────────
def analyse_email(
    raw_email_text: str,
    use_llm: bool = True,
) -> PaymentPattern:
    """
    Full BEC analysis pipeline.

    1. Fast regex pre-filter (extract_payment_signals).
    2. If signals found AND use_llm=True, run LLM analysis.
    3. Fall back to heuristic scoring if LLM unavailable.

    Returns a PaymentPattern with an action recommendation.
    """
    # Layer 1: regex
    signals = extract_payment_signals(raw_email_text)
    if signals is None:
        return PaymentPattern(action="allow", explanation="No payment signals detected.")

    matched = []
    if "iban" in signals:
        matched.append(f"IBAN patterns: {signals['iban'][:3]}")
    if "swift" in signals:
        matched.append(f"Swift/BIC codes: {signals['swift'][:3]}")
    if "bec_keywords" in signals:
        matched.extend([f"BEC phrase: '{kw}'" for kw in signals["bec_keywords"][:4]])

    # Heuristic urgency from keywords
    urgency = 0
    for kw in (signals.get("bec_keywords") or []):
        if any(x in kw.lower() for x in ["urgent", "asap", "immediate", "critical"]):
            urgency = min(urgency + 3, 10)

    has_account_change = bool(signals.get("iban") or signals.get("swift") or signals.get("account_numbers"))
    heuristic_prob = min(0.4 + len(matched) * 0.08 + urgency * 0.03, 0.9)

    # Layer 2: LLM
    if use_llm:
        llm_result = _call_llm(raw_email_text)
        if llm_result:
            try:
                prob = float(llm_result.get("bec_probability", heuristic_prob))
                return PaymentPattern(
                    has_payment_instruction=bool(llm_result.get("has_payment_instruction", True)),
                    account_change_detected=bool(llm_result.get("account_change_detected", has_account_change)),
                    urgency_score=int(llm_result.get("urgency_score", urgency)),
                    thread_injection_risk=bool(llm_result.get("thread_injection_risk", False)),
                    bec_probability=prob,
                    explanation=str(llm_result.get("explanation", "")),
                    action=llm_result.get("action", _action_from_prob(prob)),
                    matched_signals=matched,
                )
            except Exception as exc:
                log.debug("BEC LLM result parsing failed: %s", exc)

    # Fallback: heuristic only
    action = _action_from_prob(heuristic_prob)
    return PaymentPattern(
        has_payment_instruction=True,
        account_change_detected=has_account_change,
        urgency_score=urgency,
        thread_injection_risk=False,
        bec_probability=round(heuristic_prob, 2),
        explanation=(
            f"Heuristic detection: {len(matched)} payment signal(s) found. "
            f"IBAN/Swift: {bool(signals.get('iban') or signals.get('swift'))}. "
            f"Urgency score: {urgency}/10."
        ),
        action=action,
        matched_signals=matched,
    )


def _action_from_prob(prob: float) -> str:
    if prob >= 0.80:   return "block"
    elif prob >= 0.60: return "hold"
    elif prob >= 0.40: return "warn"
    return "allow"
