# ANALYSIS: ReAct agent over Gemini using Config.GEMINI_MODEL; system prompt has
#           red-flag block and a simple TOOL USAGE RULE; 4-label output;
#           no email path, no logger, no ZRM awareness.
# CHANGES:  Added EMAIL PHISHING INDICATORS, replaced TOOL USAGE RULE with the
#           HYBRID INVESTIGATION DECISION TREE, added "Sender Analysis" output
#           field; added a no-op _log_query gated by Config.ZERO_RETENTION_MODE.
"""NovaGuard ReAct agent.

Wraps Google Gemini (model selected by `Config.GEMINI_MODEL`) in a LangChain
ReAct agent with a single tool — `inspect_url` from `tools.selenium_tool` —
and a Sri-Lanka-aware system prompt. The agent emits a fixed-format markdown
report from which the verdict and risk score can be parsed reliably.
"""

from __future__ import annotations

import re
import threading
import time
from typing import Any

from langchain.agents import AgentExecutor, create_react_agent
from langchain_core.prompts import PromptTemplate

from agent.llm_factory import build_llm
from config import Config
from tools.selenium_tool import SeleniumInspector, inspect_url_tool

# Thread-local storage so concurrent investigations don't interfere
_tl = threading.local()


class _ReportCaptured(Exception):
    """Raised by the parse-error handler to stop the AgentExecutor loop immediately.

    When the LLM produces a valid NovaGuard report but omits the 'Final Answer:'
    prefix, continuing to retry wastes API calls and generates duplicate log lines.
    Raising this exception exits the executor on the *first* occurrence;
    `investigate()` catches it and uses _tl.captured_report directly.
    """


def _make_parse_error_handler() -> Any:
    """Return a callable for AgentExecutor.handle_parsing_errors.

    Llama/NVIDIA models often skip the 'Final Answer:' prefix and output the
    report directly.  Instead of retrying (which logs another error and costs
    another API call), we:

    1. Detect when the "invalid" output IS a complete NovaGuard report.
    2. Store it in _tl.captured_report.
    3. Raise _ReportCaptured to stop the executor loop immediately.
       investigate() catches this and uses the stored report.

    For truly malformed output (no verdict/score), return a short correction
    string so the executor can try to produce a properly formatted response.
    """

    def handler(exc: Exception) -> str:
        llm_output: str = getattr(exc, "llm_output", "") or str(exc)

        if "**Verdict:**" in llm_output and "**Risk Score:**" in llm_output:
            # Valid report — stop the executor loop right now
            _tl.captured_report = llm_output
            raise _ReportCaptured(llm_output)

        # Truly malformed: guide the LLM toward the correct format
        return (
            "Invalid format. When ready, output:\n"
            "Thought: I now have enough evidence.\n"
            "Final Answer: [your complete NovaGuard report]\n\n"
            "Do NOT write 'Action: None'. Go directly to Final Answer."
        )

    return handler

NOVAGUARD_SYSTEM_PROMPT = """You are NovaGuard, a senior cybersecurity investigator specializing
in financial fraud targeting Sri Lankan users. You have deep expertise
in local scam patterns including:

BANKING SCAMS: Fake BOC, Sampath, Commercial Bank, People's Bank,
NSB, HNB, Seylan Bank alerts and phishing pages.

TELCO SCAMS: Fake Dialog, Mobitel, Airtel, Hutch free data offers,
account suspension alerts, recharge bonus scams.

INVESTMENT SCAMS: Cryptocurrency doubling schemes, fake Forex trading
platforms, pyramid schemes marketed in Sinhala Facebook groups.

JOB SCAMS: Fake overseas job offers (Middle East), fake government
exam results, fake NGO job postings.

LOTTERY/PRIZE SCAMS: WhatsApp prize announcements, Dialog anniversary
free phone scams, supermarket lucky draw scams.

RED FLAGS YOU ALWAYS CHECK:
1. Domain mismatch - claimed brand vs actual domain
   (e.g., "boc-secure.xyz" ≠ boc.lk)
2. Presence of login, PIN, OTP, NIC, or CVV input forms
3. HTTP instead of HTTPS for financial pages
4. URL shorteners hiding destination (bit.ly, tinyurl, rb.gy)
5. Redirect chains that change domain
6. Urgency language: "suspended", "24 hours", "immediately",
   "act now", "your account will be closed"
7. Guaranteed returns: "double your money", "100% profit",
   "guaranteed income"
8. Poor grammar mixed with official-looking formatting
9. Requests for NIC number, passport, ATM PIN, OTP via link
10. Non-.lk domains impersonating Sri Lankan institutions

EMAIL PHISHING INDICATORS — apply when input_type is "email":
- Sender domain mismatch: display name says "BOC Bank" or "Dialog" but
  actual sending address is from gmail.com, outlook.com, or a random domain
- Generic salutation: "Dear Customer", "Dear User" instead of recipient's name
- Urgency in subject: "Account Suspended", "Immediate Action Required",
  "Your account will be closed in 24 hours"
- Mismatched hyperlinks: visible link text shows one URL, actual href
  points to a completely different domain
- Credential harvesting: asks user to click a link to "verify", "confirm",
  or "update" banking or personal details
- Suspicious attachments mentioned alongside requests for action
- Impersonation of Sri Lankan institutions: BOC, Sampath, ComBank,
  People's Bank, Dialog, Mobitel, IRD, Department of Immigration, Police

When analyzing email input:
1. Treat the sender address as a primary red flag if domain is non-official
2. Extract all URLs from the body and evaluate each one
3. Note if the email style matches known Sri Lankan institutional formatting

HYBRID INVESTIGATION DECISION TREE:

1. Input contains a URL starting with http:// or https://:
   → ALWAYS call inspect_url tool first (Selenium-based deep scan)
   → After getting Selenium results, if page is unreadable or tool fails,
     note this in your evidence as "Page blocked Selenium inspection"

2. Input is a text message with no URL:
   → Do NOT use any tool
   → Analyze linguistic patterns, urgency signals, and SL-specific formats

3. Input is an email (starts with "EMAIL INPUT" or contains "Sender:" + "Body:"):
   → Analyze sender domain immediately (no tool needed for this)
   → If URLs found in email body: call inspect_url on the FIRST URL found
   → Note any additional URLs found but not inspected

4. Tool returns an error or timeout:
   → Do NOT retry
   → Include the error in your evidence: "URL investigation failed: [error]"
   → Still produce a verdict based on the URL structure and any available info
   → Lower confidence: set score 10 points lower than you otherwise would

RESPONSE FORMAT - always use exactly this structure:

## \U0001F50D NovaGuard Investigation Report

**Verdict:** [SCAM / SUSPICIOUS / LIKELY_SAFE / SAFE]
**Risk Score:** [0-100]
**Input Type:** [URL / Text Message / Email]
**Sender Analysis:** [only for email inputs — official domain / suspicious domain / unknown]

**Evidence Found:**
- [specific red flag 1 with detail]
- [specific red flag 2 with detail]
- [add more as found, minimum 2, maximum 8]

**Why this conclusion:**
[2-3 sentences explaining the reasoning in plain English
 accessible to a non-technical Sri Lankan user]

**Recommended Action:**
[1-2 specific actionable steps the user should take]

---
*NovaGuard AI Investigation - Do not share sensitive information*
"""


_REACT_TEMPLATE = (
    NOVAGUARD_SYSTEM_PROMPT
    + """

You have access to the following tools:

{tools}

Use this EXACT ReAct format. Every step must start with one of the labels
"Thought:", "Action:", "Action Input:", "Observation:", or "Final Answer:".

Question: the user's input (a URL, SMS, or message)
Thought: think step by step about what to investigate next
Action: the action to take, must be one of [{tool_names}]
Action Input: the input to the action
Observation: the result of the action
... (Thought/Action/Action Input/Observation can repeat as needed)
Thought: I now have enough evidence to render a verdict
Final Answer: the complete NovaGuard Investigation Report in the exact markdown format described above.

STRICT RULES — violating these causes the investigation to fail:
1. The ONLY valid values after "Action:" are tool names: [{tool_names}].
   NEVER write "Action: None", "Action: N/A", or any explanation after "Action:".
2. When you have enough evidence and do NOT need a tool, skip straight to:
   "Thought: I now have enough evidence to render a verdict"
   "Final Answer: [your report]"
3. After writing "Final Answer:" and the report, STOP COMPLETELY.
   Do NOT write any Thought, Action, or other text after the report.

Begin!

Question: {input}
Thought: {agent_scratchpad}"""
)


_LABEL_PATTERN = re.compile(
    r"\*\*\s*Verdict\s*:\s*\*\*\s*\[?\s*([A-Z_ /]+?)\s*\]?\s*(?:\n|$)",
    re.IGNORECASE,
)
_SCORE_PATTERN = re.compile(
    r"\*\*\s*Risk Score\s*:\s*\*\*\s*\[?\s*(\d{1,3})\s*\]?",
    re.IGNORECASE,
)
_VALID_LABELS = {"SCAM", "SUSPICIOUS", "LIKELY_SAFE", "SAFE"}


class NovaGuardAgent:
    """ReAct agent wrapping the configured LLM and the Selenium inspection tool."""

    def __init__(self) -> None:
        Config.validate()
        self.llm = build_llm(temperature=0.2)
        self.inspector = SeleniumInspector()
        self.tools = [inspect_url_tool]
        prompt = PromptTemplate.from_template(_REACT_TEMPLATE)
        agent = create_react_agent(self.llm, self.tools, prompt)
        self.executor = AgentExecutor(
            agent=agent,
            tools=self.tools,
            verbose=True,
            max_iterations=Config.AGENT_MAX_ITERATIONS,
            handle_parsing_errors=_make_parse_error_handler(),
            early_stopping_method="generate",  # on iter-limit: LLM generates Final Answer
            return_intermediate_steps=False,
        )

    # ---------------------------------------------------------------- API
    def investigate(self, user_input: str) -> dict[str, Any]:
        """Run the agent against `user_input` and return a structured result."""
        cleaned = (user_input or "").strip()
        input_type = self._detect_input_type(cleaned)

        # Reset per-call thread-local capture slot
        _tl.captured_report = None

        start = time.perf_counter()
        try:
            raw = self.executor.invoke({"input": cleaned})
            response = raw.get("output", "") if isinstance(raw, dict) else str(raw)
        except _ReportCaptured:
            # Handler detected a valid report and raised immediately to skip retries.
            # Use the captured report; latency is measured to this point.
            response = _tl.captured_report or ""
        except Exception as exc:
            response = _build_error_report(cleaned, exc)
        latency = time.perf_counter() - start

        # Safety net: executor returned something without a verdict (edge case)
        if (not response or "**Verdict:**" not in response) and _tl.captured_report:
            response = _tl.captured_report

        label, score = self._parse_verdict(response)
        result = {
            "response": response,
            "latency_seconds": round(latency, 3),
            "input_type": input_type,
            "predicted_label": label,
            "predicted_score": score,
        }
        if not Config.ZERO_RETENTION_MODE:
            self._log_query(cleaned, result)
        return result

    # -------------------------------------------------------------- helpers
    @staticmethod
    def _detect_input_type(text: str) -> str:
        if text.lower().startswith(("http://", "https://")):
            return "url"
        head = text[:120].lower()
        if head.startswith("email input") or ("sender:" in head and "body:" in text.lower()):
            return "email"
        return "text"

    @staticmethod
    def _looks_like_url(text: str) -> bool:
        return text.lower().startswith(("http://", "https://"))

    def _log_query(self, user_input: str, result: dict[str, Any]) -> None:
        """Placeholder query logger. Bypassed entirely under ZERO_RETENTION_MODE.

        No content is written today; the hook exists so future logging code can
        be added in one place and immediately respect the zero-retention flag.
        """
        return None

    @staticmethod
    def _parse_verdict(response: str) -> tuple[str, int]:
        label, score = "SUSPICIOUS", 50
        if not response:
            return label, score

        label_match = _LABEL_PATTERN.search(response)
        if label_match:
            candidate = label_match.group(1).strip().upper().replace(" ", "_")
            candidate = candidate.split("/")[0].strip("_")
            if candidate in _VALID_LABELS:
                label = candidate

        score_match = _SCORE_PATTERN.search(response)
        if score_match:
            try:
                value = int(score_match.group(1))
                if 0 <= value <= 100:
                    score = value
            except ValueError:
                pass

        return label, score


# --------------------------------------------------------- module-level helpers
def _build_error_report(user_input: str, exc: BaseException) -> str:
    return (
        "## \U0001F50D NovaGuard Investigation Report\n\n"
        "**Verdict:** SUSPICIOUS\n"
        "**Risk Score:** 50\n"
        f"**Input Type:** {'URL' if user_input.lower().startswith('http') else 'Text Message'}\n\n"
        "**Evidence Found:**\n"
        f"- NovaGuard could not complete the investigation: {type(exc).__name__}.\n"
        f"- Internal detail: {str(exc)[:300]}\n\n"
        "**Why this conclusion:**\n"
        "An internal error prevented a full investigation, so NovaGuard cannot confirm safety. "
        "Treat the input as untrusted until it can be re-checked.\n\n"
        "**Recommended Action:**\n"
        "Do not click the link or share personal information. Try again later or verify "
        "directly with the official organisation's helpline.\n\n"
        "---\n"
        "*NovaGuard AI Investigation - Do not share sensitive information*\n"
    )


def run_investigation(user_input: str) -> str:
    """Module-level convenience wrapper that returns just the report string."""
    try:
        agent = NovaGuardAgent()
        result = agent.investigate(user_input)
        return result["response"]
    except Exception as exc:
        return _build_error_report(user_input, exc)
