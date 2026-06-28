# ANALYSIS: 4-state banner UI (st.error/warning/info/success), 2 input modes
#           (Text/Link, Screenshot), no email path, no feedback collection, no
#           ZRM toggle, tech-stack mentions gemini-1.5-flash.
# CHANGES:  3-state traffic-light UI, added 📧 Email mode, feedback widget,
#           zero-retention toggle in sidebar, session-state inits for the new
#           keys, updated tech-stack model reference.
"""NovaGuard Streamlit web app."""

from __future__ import annotations

import os
import re
from datetime import datetime

import streamlit as st

from agent.novaguard_agent import NovaGuardAgent, _build_error_report
from config import Config
from feedback.feedback_manager import get_feedback_stats, log_feedback
from tools.vision_tool import VisionInspector

# ---------------------------------------------------------------- page setup
st.set_page_config(
    page_title="NovaGuard 🛡️ - Sri Lanka Scam Investigator",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

CUSTOM_CSS = """
<style>
.main { font-family: 'Inter', 'Segoe UI', sans-serif; }
.nv-card {
    background: #11161d;
    color: #e6edf3;
    border-radius: 14px;
    padding: 1.5rem 1.75rem;
    border: 1px solid #1f2630;
    box-shadow: 0 4px 18px rgba(0,0,0,0.35);
    line-height: 1.55;
}
.nv-card h2, .nv-card h3 { color: #f0f6fc; margin-top: 0.4rem; }
.nv-card strong { color: #ffffff; }
.nv-verdict-scam   { background:#3a0d12; border-left:6px solid #ef4444;
                     padding:0.9rem 1.1rem; border-radius:8px; color:#fecaca;
                     font-weight:600; }
.nv-verdict-susp   { background:#3a2a07; border-left:6px solid #f59e0b;
                     padding:0.9rem 1.1rem; border-radius:8px; color:#fde68a;
                     font-weight:600; }
.nv-verdict-likely { background:#0c2540; border-left:6px solid #3b82f6;
                     padding:0.9rem 1.1rem; border-radius:8px; color:#bfdbfe;
                     font-weight:600; }
.nv-verdict-safe   { background:#0a2e1e; border-left:6px solid #10b981;
                     padding:0.9rem 1.1rem; border-radius:8px; color:#a7f3d0;
                     font-weight:600; }
.nv-subtitle { color:#94a3b8; margin-top:-0.5rem; margin-bottom:1rem; }
.nv-meta-row { display:flex; gap:1rem; flex-wrap:wrap; margin-top:0.6rem; }
div.stSpinner > div { border-top-color: #38bdf8 !important; }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


# ----------------------------------------------------------- shared state
if "agent" not in st.session_state:
    st.session_state["agent"] = None
if "vision" not in st.session_state:
    st.session_state["vision"] = None
if "prefill_text" not in st.session_state:
    st.session_state["prefill_text"] = ""
if "last_result" not in st.session_state:
    st.session_state["last_result"] = None
if "screenshot_outcome" not in st.session_state:
    st.session_state["screenshot_outcome"] = None
if "show_correction" not in st.session_state:
    st.session_state["show_correction"] = False
if "last_input" not in st.session_state:
    st.session_state["last_input"] = ""
if "last_input_type" not in st.session_state:
    st.session_state["last_input_type"] = "text"


def _get_agent() -> NovaGuardAgent | None:
    """Lazy-initialise the agent so a missing API key shows a clean error."""
    if st.session_state["agent"] is not None:
        return st.session_state["agent"]
    try:
        st.session_state["agent"] = NovaGuardAgent()
        return st.session_state["agent"]
    except Exception as exc:
        st.error(f"NovaGuard could not start: {exc}")
        return None


def _get_vision() -> VisionInspector | None:
    if st.session_state["vision"] is not None:
        return st.session_state["vision"]
    try:
        st.session_state["vision"] = VisionInspector()
        return st.session_state["vision"]
    except Exception as exc:
        st.error(f"Vision inspector could not start: {exc}")
        return None


# ----------------------------------------------------------- helpers
_LABEL_RE = re.compile(r"\*\*\s*Verdict\s*:\s*\*\*\s*\[?\s*([A-Za-z_ /]+)", re.IGNORECASE)
_SCORE_RE = re.compile(r"\*\*\s*Risk Score\s*:\s*\*\*\s*\[?\s*(\d{1,3})", re.IGNORECASE)


def parse_verdict(text: str) -> tuple[str, int]:
    label, score = "SUSPICIOUS", 50
    if not text:
        return label, score
    m = _LABEL_RE.search(text)
    if m:
        c = m.group(1).strip().upper().replace(" ", "_").split("/")[0].strip("_")
        if c in {"SCAM", "SUSPICIOUS", "LIKELY_SAFE", "SAFE"}:
            label = c
    s = _SCORE_RE.search(text)
    if s:
        try:
            v = int(s.group(1))
            if 0 <= v <= 100:
                score = v
        except ValueError:
            pass
    return label, score


TRAFFIC_LIGHT_MAP = {
    "SCAM":        {"color": "error",   "emoji": "🔴", "label": "DANGEROUS",
                    "action": "Do NOT click any links. Block the sender immediately."},
    "SUSPICIOUS":  {"color": "warning", "emoji": "🟡", "label": "SUSPICIOUS",
                    "action": "Proceed with extreme caution. Verify through official channels."},
    "LIKELY_SAFE": {"color": "success", "emoji": "🟢", "label": "LIKELY SAFE",
                    "action": "Appears safe, but always verify before sharing personal data."},
    "SAFE":        {"color": "success", "emoji": "🟢", "label": "SAFE",
                    "action": "No threats detected."},
}


def render_traffic_light(predicted_label: str, predicted_score: int, agent_response: str) -> None:
    tl = TRAFFIC_LIGHT_MAP.get(predicted_label, TRAFFIC_LIGHT_MAP["SUSPICIOUS"])

    st.markdown(
        f"""
<div style="text-align:center;padding:16px 0 8px">
  <span style="font-size:48px">{tl['emoji']}</span>
  <h2 style="margin:4px 0;letter-spacing:2px">{tl['label']}</h2>
  <p style="color:gray;font-size:14px">{tl['action']}</p>
</div>
""",
        unsafe_allow_html=True,
    )
    getattr(st, tl["color"])(f"Risk Score: {predicted_score}/100")
    st.markdown(agent_response)


# Screenshot OCR is delegated to tools.vision_tool.VisionInspector.


# ----------------------------------------------------------- sidebar
with st.sidebar:
    st.markdown("# 🛡️ NovaGuard")
    st.caption("Sri Lanka Scam Investigator")

    st.markdown("### How It Works")
    st.markdown(
        "**Step 1.** Paste a suspicious link or message.\n\n"
        "**Step 2.** The AI agent safely investigates in a sandboxed browser.\n\n"
        "**Step 3.** Receive a full investigation report."
    )

    with st.expander("Common Sri Lankan Scams"):
        st.markdown(
            "- Fake BOC / Sampath SMS alerts\n"
            "- Dialog free data phishing\n"
            "- Overseas job scams\n"
            "- Crypto investment schemes\n"
            "- Lottery / prize WhatsApp messages"
        )

    input_method = st.radio(
        "Input method",
        options=["Text/Link", "📧 Email", "Screenshot"],
        index=0,
    )

    st.markdown("---")
    zero_retention = st.toggle(
        "🔒 Zero-retention mode",
        value=Config.ZERO_RETENTION_MODE,
        help=(
            "When ON, your input is never written to disk. "
            "Turn OFF only for research/evaluation purposes."
        ),
    )
    os.environ["ZERO_RETENTION_MODE"] = "true" if zero_retention else "false"
    Config.ZERO_RETENTION_MODE = bool(zero_retention)

    st.markdown("---")
    st.markdown("### 📱 Mobile users")
    if Config.is_configured("telegram"):
        st.markdown(
            "Forward suspicious messages to NovaGuard on Telegram. Start the bot "
            "with `/start` after running `python bot/novaguard_bot.py`."
        )
    else:
        st.info(
            "Telegram bot: configure `TELEGRAM_BOT_TOKEN` in `.env` to enable the "
            "forward-from-mobile workflow."
        )

    st.markdown("---")
    st.caption(
        "⚠️ NovaGuard is an AI tool. Always verify with official sources before "
        "sharing personal information."
    )

    _feedback_stats = get_feedback_stats()
    if _feedback_stats["total"] > 0:
        st.divider()
        st.caption(f"📊 Community feedback: {_feedback_stats['total']} reports")
        if _feedback_stats["accuracy_from_feedback"] is not None:
            st.caption(
                f"User-confirmed accuracy: {_feedback_stats['accuracy_from_feedback']}%"
            )


# ----------------------------------------------------------- header
st.markdown("# NovaGuard 🛡️")
st.markdown(
    '<div class="nv-subtitle">An AI investigator for scam links and messages '
    "targeting Sri Lankan users.</div>",
    unsafe_allow_html=True,
)

investigate_tab, about_tab = st.tabs(["🔍 Investigate", "📊 About"])


# ----------------------------------------------------------- INVESTIGATE TAB
with investigate_tab:
    user_input: str = ""

    if input_method == "Text/Link":
        user_input = st.text_area(
            "Paste a suspicious SMS, WhatsApp message, email, or URL",
            value=st.session_state.get("prefill_text", ""),
            height=150,
            placeholder=(
                "Paste a suspicious SMS, WhatsApp message, email, or URL here..."
            ),
            key="main_input",
        )
    elif input_method == "📧 Email":
        email_sender = st.text_input(
            "Sender email address",
            placeholder="e.g. support@boc-alert.xyz or noreply@boc.lk",
            key="email_sender",
        )
        email_body = st.text_area(
            "Email body content",
            placeholder="Paste the full email text here...",
            height=180,
            key="email_body",
        )
        if email_body and email_body.strip():
            user_input = f"EMAIL INPUT\nSender: {email_sender}\nBody:\n{email_body}"
    else:
        uploaded = st.file_uploader(
            "Upload a screenshot of a suspicious message or page",
            type=["png", "jpg", "jpeg", "webp"],
        )
        if uploaded is not None:
            image_bytes = uploaded.read()
            st.image(image_bytes, caption="Uploaded screenshot", width=420)

            if st.button("Extract & Analyze 🔍", type="primary", key="screenshot_extract"):
                vision = _get_vision()
                if vision is None:
                    st.session_state["screenshot_outcome"] = None
                else:
                    with st.spinner("Step 1: Extracting text from screenshot..."):
                        extraction = vision.extract_text_from_image(image_bytes)
                    confidence = extraction.get("extraction_confidence", "low")
                    if not extraction.get("success") or confidence == "low":
                        st.session_state["screenshot_outcome"] = {
                            "status": "extraction_failed",
                            "extraction": extraction,
                            "investigation_report": None,
                        }
                    else:
                        st.success(
                            f"Extracted {len(extraction['message_text'])} characters "
                            f"(confidence: {confidence})."
                        )
                        st.info(extraction["message_text"])
                        with st.spinner("Step 2: Running investigation..."):
                            agent = _get_agent()
                            if agent is None:
                                report_text = _build_error_report(
                                    extraction["message_text"],
                                    RuntimeError("Agent not initialised"),
                                )
                                investigation = {
                                    "response": report_text,
                                    "latency_seconds": 0.0,
                                    "input_type": "text",
                                    "predicted_label": "SUSPICIOUS",
                                    "predicted_score": 50,
                                }
                            else:
                                investigation = agent.investigate(
                                    extraction["message_text"]
                                )
                        st.session_state["screenshot_outcome"] = {
                            "status": "ok",
                            "extraction": extraction,
                            "investigation": investigation,
                        }
                        st.session_state["last_result"] = investigation

            outcome = st.session_state.get("screenshot_outcome")
            if outcome:
                if outcome.get("status") == "extraction_failed":
                    st.warning(
                        "Could not read the screenshot clearly. Please re-upload "
                        "a sharper image, or switch to **Text/Link** and paste "
                        "the message text directly."
                    )
                    raw = outcome["extraction"].get("raw_response", "")
                    if raw:
                        with st.expander("Raw Gemini response (debug)"):
                            st.code(raw)
                elif outcome.get("status") == "ok":
                    extraction = outcome["extraction"]
                    with st.expander("Extracted fields", expanded=False):
                        st.write({
                            "sender": extraction.get("sender"),
                            "urls_found": extraction.get("urls_found"),
                            "confidence": extraction.get("extraction_confidence"),
                        })
                    user_input = extraction["message_text"]

    # ---------- example inputs
    with st.expander("Try an example input"):
        ex1 = (
            "URGENT: Your BOC account suspended. Verify PIN: "
            "http://boc-verify.xyz"
        )
        ex2 = (
            "Earn Rs.50,000/week from home! Guaranteed Forex profits. "
            "WhatsApp 0771234567. Limited slots!"
        )
        ex3 = (
            "Your Sampath Bank transaction of Rs.2,500 on 15/01/2025. "
            "Ref: TXN789456. Hotline: 0112-303030"
        )

        ex4 = (
            "Subject: URGENT - Your BOC Internet Banking Account Suspended\n"
            "From: boc-support@secure-banking-alert.com\n"
            "Body: Dear Customer, Your BOC account has been temporarily "
            "suspended due to suspicious activity. Click here to verify: "
            "http://boc-verify-now.xyz/login"
        )

        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.markdown("**Example 1 — SCAM SMS**")
            st.code(ex1, language=None)
            if st.button("Use this example", key="ex1"):
                st.session_state["prefill_text"] = ex1
                st.rerun()
        with c2:
            st.markdown("**Example 2 — Investment scam**")
            st.code(ex2, language=None)
            if st.button("Use this example", key="ex2"):
                st.session_state["prefill_text"] = ex2
                st.rerun()
        with c3:
            st.markdown("**Example 3 — Legitimate**")
            st.code(ex3, language=None)
            if st.button("Use this example", key="ex3"):
                st.session_state["prefill_text"] = ex3
                st.rerun()
        with c4:
            st.markdown("**Example 4 — Email phishing**")
            st.code(ex4, language=None)
            if st.button("Use this example", key="ex4"):
                st.session_state["prefill_text"] = ex4
                st.rerun()

    # ---------- investigate button
    if st.button("Investigate 🔍", type="primary"):
        if not user_input or not user_input.strip():
            st.warning("Please paste a message, link, or upload a screenshot first.")
        else:
            stripped = user_input.strip()
            if stripped.lower().startswith(("http://", "https://")):
                detected_input_type = "url"
            elif input_method == "📧 Email" or stripped.lower().startswith("email input"):
                detected_input_type = "email"
            else:
                detected_input_type = "text"

            st.session_state["last_input"] = user_input
            st.session_state["last_input_type"] = detected_input_type
            st.session_state["show_correction"] = False

            agent = _get_agent()
            with st.spinner("🔍 NovaGuard is investigating — opening link in sandbox browser, may take 1–3 min..."):
                if agent is None:
                    result = {
                        "response": _build_error_report(
                            user_input, RuntimeError("Agent not initialised")
                        ),
                        "latency_seconds": 0.0,
                        "input_type": detected_input_type,
                        "predicted_label": "SUSPICIOUS",
                        "predicted_score": 50,
                    }
                else:
                    result = agent.investigate(user_input)
                    if not result.get("input_type"):
                        result["input_type"] = detected_input_type
            st.session_state["last_result"] = result

    # ---------- result rendering
    result = st.session_state.get("last_result")
    if result:
        response_text = result["response"]
        predicted_label, predicted_score = parse_verdict(response_text)

        render_traffic_light(predicted_label, predicted_score, response_text)

        c1, c2, c3 = st.columns(3)
        c1.metric("Risk Score", f"{predicted_score} / 100")
        c2.metric("Latency", f"{result['latency_seconds']:.2f} s")
        c3.metric("Input Type", result["input_type"].upper())

        st.caption(
            f"Investigation complete · {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )

        # ---------- feedback widget ----------
        st.divider()
        st.caption("🙋 Help improve NovaGuard — was this verdict correct?")

        fb_col1, fb_col2, fb_col3 = st.columns([2, 2, 4])

        with fb_col1:
            if st.button("✅ Yes, correct", use_container_width=True, key="fb_correct"):
                log_feedback(
                    user_input=st.session_state.get("last_input", ""),
                    predicted_label=predicted_label,
                    feedback_type="correct",
                    input_type=st.session_state.get("last_input_type", "unknown"),
                )
                st.success("Thank you! Your feedback helps us improve.")

        with fb_col2:
            if st.button("❌ No, wrong verdict", use_container_width=True, key="fb_wrong"):
                st.session_state["show_correction"] = True

        if st.session_state.get("show_correction"):
            with fb_col3:
                correction = st.selectbox(
                    "What should the verdict be?",
                    ["SCAM", "SUSPICIOUS", "LIKELY_SAFE", "SAFE"],
                    key="correction_select",
                )
                if st.button("Submit correction", type="primary", key="fb_submit"):
                    log_feedback(
                        user_input=st.session_state.get("last_input", ""),
                        predicted_label=predicted_label,
                        feedback_type="incorrect",
                        correct_label=correction,
                        input_type=st.session_state.get("last_input_type", "unknown"),
                    )
                    st.success("Correction recorded. Thank you!")
                    st.session_state["show_correction"] = False


# ----------------------------------------------------------- ABOUT TAB
with about_tab:
    st.markdown("### About NovaGuard")
    st.markdown(
        "NovaGuard is an LLM-powered agent that investigates suspicious links and "
        "messages aimed at Sri Lankan users — covering banking phishing, telco "
        "lures, overseas-job scams, and investment fraud. It opens candidate URLs "
        "in a sandboxed headless browser, extracts evidence (forms, redirects, "
        "external links), and reasons over that evidence with Google Gemini to "
        "produce a calibrated, plain-English risk report."
    )

    st.markdown("### Tech stack")
    from agent.llm_factory import llm_summary as _llm_summary
    _summary = _llm_summary()
    st.markdown(
        f"- **Agent LLM:** {_summary['provider']} → `{_summary['model']}`\n"
        f"- **Vision LLM:** {_summary['vision_provider']} → `{_summary['vision_model']}` "
        "(screenshot OCR only)\n"
        "- **Agent framework:** LangChain ReAct agent\n"
        "- **Browser automation:** Selenium + webdriver-manager (headless Chrome)\n"
        "- **UI:** Streamlit web app and a Telegram bot front-end\n"
        "- **Evaluation:** scikit-learn / pandas / matplotlib pipeline under `evaluation/`"
    )

    st.markdown("### Research context")
    st.markdown(
        "NovaGuard is the system component of a final-year research project on "
        "agentic scam detection for the Sri Lankan threat landscape. Quantitative "
        "results, baselines, and annotation methodology live under `evaluation/` "
        "and the generated `reports/` directory."
    )

    st.markdown("### Telegram bot")
    if Config.is_configured("telegram"):
        st.success(
            "Telegram bot is configured. Run `python bot/novaguard_bot.py` to start it."
        )
    else:
        st.info(
            "Telegram bot token is not configured. Set `TELEGRAM_BOT_TOKEN` in `.env` "
            "to enable the bot front-end."
        )

    st.markdown("### Source")
    st.markdown("- GitHub: _link to be added on release_")
