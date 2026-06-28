"""NovaGuard Streamlit frontend — calls the FastAPI backend over HTTP.

Run:
    # Terminal 1
    python run_backend.py
    # Terminal 2
    streamlit run frontend/streamlit_app.py
"""

from __future__ import annotations

import sys
from pathlib import Path

# Streamlit puts this script's directory on sys.path, not the project root.
# Make the project root importable so `from config import ...` resolves.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from datetime import datetime

import streamlit as st

from config import Config
from frontend.api_client import NovaGuardAPIClient, NovaGuardAPIError

st.set_page_config(
    page_title="NovaGuard 🛡️ - Sri Lanka Scam Investigator",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------- styling
st.markdown(
    """
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
.nv-subtitle { color:#94a3b8; margin-top:-0.5rem; margin-bottom:1rem; }
</style>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------- state
for key, default in [
    ("client", None),
    ("last_result", None),
    ("last_input", ""),
    ("last_input_type", "text"),
    ("show_correction", False),
    ("prefill_text", ""),
    ("api_base_url", Config.API_URL),
    ("api_key", Config.API_KEY or ""),
]:
    if key not in st.session_state:
        st.session_state[key] = default


def _client() -> NovaGuardAPIClient:
    if st.session_state["client"] is None:
        st.session_state["client"] = NovaGuardAPIClient(
            base_url=st.session_state["api_base_url"],
            api_key=st.session_state["api_key"] or None,
        )
    return st.session_state["client"]


def _reset_client() -> None:
    st.session_state["client"] = None


# ---------------------------------------------------------------- sidebar
with st.sidebar:
    st.markdown("# 🛡️ NovaGuard")
    st.caption("Sri Lanka Scam Investigator — API frontend")

    with st.expander("🔌 Backend connection", expanded=False):
        new_url = st.text_input("API base URL", value=st.session_state["api_base_url"])
        new_key = st.text_input(
            "X-API-Key (optional)",
            value=st.session_state["api_key"],
            type="password",
            help="Only needed if NOVAGUARD_API_KEY is set on the backend.",
        )
        if new_url != st.session_state["api_base_url"] or new_key != st.session_state["api_key"]:
            st.session_state["api_base_url"] = new_url
            st.session_state["api_key"] = new_key
            _reset_client()

        if st.button("Test connection"):
            try:
                info = _client().health()
                st.success(f"OK — {info.get('status')}")
                st.json(info)
            except NovaGuardAPIError as exc:
                st.error(f"API error: {exc}")
            except Exception as exc:
                st.error(f"Could not reach backend: {exc}")

    st.markdown("### How It Works")
    st.markdown(
        "**1.** Pick an input mode.\n\n"
        "**2.** The frontend POSTs to the NovaGuard API.\n\n"
        "**3.** The API runs the agent and returns a verdict."
    )

    input_method = st.radio(
        "Input method",
        options=["Text/Link", "📧 Email", "Screenshot"],
        index=0,
    )

    st.markdown("---")
    try:
        stats = _client().feedback_stats()
        if stats.get("total", 0) > 0:
            st.caption(f"📊 Community feedback: {stats['total']} reports")
            if stats.get("accuracy_from_feedback") is not None:
                st.caption(f"User-confirmed accuracy: {stats['accuracy_from_feedback']}%")
    except Exception:
        pass

    st.caption(
        "⚠️ NovaGuard is an AI tool. Always verify with official sources before "
        "sharing personal information."
    )


# ---------------------------------------------------------------- header
st.markdown("# NovaGuard 🛡️")
st.markdown(
    '<div class="nv-subtitle">REST-API-backed investigator for scam links and messages '
    "targeting Sri Lankan users.</div>",
    unsafe_allow_html=True,
)


# ---------------------------------------------------------------- tabs
investigate_tab, about_tab = st.tabs(["🔍 Investigate", "📊 About"])


TRAFFIC_LIGHT_STYLE = {
    "red": st.error,
    "yellow": st.warning,
    "green": st.success,
}


def _render_result(result: dict, extra_caption: str | None = None) -> None:
    investigation = result if "report" in result else result.get("investigation") or {}
    label = investigation.get("predicted_label", "SUSPICIOUS")
    score = investigation.get("predicted_score", 50)
    tl_color = investigation.get("traffic_light", "yellow")
    tl_label = investigation.get("traffic_light_label", "SUSPICIOUS")
    action = investigation.get("recommended_action") or ""
    emoji = {"red": "🔴", "yellow": "🟡", "green": "🟢"}.get(tl_color, "🟡")

    st.markdown(
        f"""
<div style="text-align:center;padding:16px 0 8px">
  <span style="font-size:48px">{emoji}</span>
  <h2 style="margin:4px 0;letter-spacing:2px">{tl_label}</h2>
  <p style="color:gray;font-size:14px">{action}</p>
</div>
""",
        unsafe_allow_html=True,
    )
    banner = TRAFFIC_LIGHT_STYLE.get(tl_color, st.info)
    banner(f"Risk Score: {score}/100")
    st.markdown(investigation.get("report") or "")

    c1, c2, c3 = st.columns(3)
    c1.metric("Risk Score", f"{score} / 100")
    c2.metric("Latency", f"{investigation.get('latency_seconds', 0.0):.2f} s")
    c3.metric("Input Type", str(investigation.get("input_type", "")).upper())
    if extra_caption:
        st.caption(extra_caption)
    st.caption(f"Investigation complete · {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


# ---------------------------------------------------------------- investigate tab
with investigate_tab:
    user_input: str = ""
    email_payload: tuple[str, str, str] | None = None
    screenshot_payload: tuple[bytes, str, str] | None = None

    if input_method == "Text/Link":
        user_input = st.text_area(
            "Paste a suspicious SMS, WhatsApp message, email, or URL",
            value=st.session_state.get("prefill_text", ""),
            height=150,
            placeholder="Paste a suspicious SMS, WhatsApp message, email, or URL here...",
            key="main_input",
        )
    elif input_method == "📧 Email":
        email_sender = st.text_input(
            "Sender email address",
            placeholder="e.g. support@boc-alert.xyz or noreply@boc.lk",
            key="email_sender",
        )
        email_subject = st.text_input(
            "Subject (optional)",
            placeholder="e.g. URGENT - Your BOC account suspended",
            key="email_subject",
        )
        email_body = st.text_area(
            "Email body content",
            placeholder="Paste the full email text here...",
            height=180,
            key="email_body",
        )
        if email_body and email_body.strip():
            email_payload = (email_sender.strip(), email_subject.strip(), email_body.strip())
            user_input = email_body  # for feedback context
    else:
        uploaded = st.file_uploader(
            "Upload a screenshot of a suspicious message or page",
            type=["png", "jpg", "jpeg", "webp"],
        )
        if uploaded is not None:
            data = uploaded.read()
            st.image(data, caption="Uploaded screenshot", width=420)
            screenshot_payload = (data, uploaded.name, uploaded.type or "image/png")

    with st.expander("Try an example input"):
        examples = [
            ("Example 1 — SCAM SMS", "URGENT: Your BOC account suspended. Verify PIN: http://boc-verify.xyz"),
            ("Example 2 — Investment scam", "Earn Rs.50,000/week from home! Guaranteed Forex profits. WhatsApp 0771234567."),
            ("Example 3 — Legitimate", "Your Sampath Bank transaction of Rs.2,500 on 15/01/2025. Ref: TXN789456. Hotline: 0112-303030"),
            ("Example 4 — Email phishing",
             "Subject: URGENT - Your BOC Internet Banking Account Suspended\n"
             "From: boc-support@secure-banking-alert.com\n"
             "Body: Dear Customer, Your BOC account has been suspended. Click http://boc-verify-now.xyz/login"),
        ]
        cols = st.columns(len(examples))
        for col, (title, body) in zip(cols, examples):
            with col:
                st.markdown(f"**{title}**")
                st.code(body, language=None)
                if st.button("Use this example", key=f"ex_{title}"):
                    st.session_state["prefill_text"] = body
                    st.rerun()

    if st.button("Investigate 🔍", type="primary"):
        client = _client()
        try:
            if input_method == "📧 Email":
                if not email_payload:
                    st.warning("Please paste an email body first.")
                else:
                    sender, subject, body = email_payload
                    with st.spinner("🔍 Investigating email — this may take 1–3 minutes..."):
                        result = client.investigate_email(sender, subject, body)
                    st.session_state["last_input"] = body
                    st.session_state["last_input_type"] = "email"
                    st.session_state["last_result"] = result
                    st.session_state["show_correction"] = False
            elif input_method == "Screenshot":
                if not screenshot_payload:
                    st.warning("Please upload a screenshot first.")
                else:
                    data, name, ctype = screenshot_payload
                    with st.spinner("📷 OCR + investigation — this may take 1–3 minutes..."):
                        result = client.investigate_screenshot(data, filename=name, content_type=ctype)
                    if result.get("status") == "extraction_failed":
                        st.warning(result.get("user_message", "Could not read screenshot."))
                        st.session_state["last_result"] = None
                    else:
                        st.session_state["last_input"] = result["extraction"].get("message_text", "")
                        st.session_state["last_input_type"] = "text"
                        st.session_state["last_result"] = result
                        st.session_state["show_correction"] = False
            else:
                stripped = (user_input or "").strip()
                if not stripped:
                    st.warning("Please paste a message, link, or upload a screenshot first.")
                else:
                    detected = "url" if stripped.lower().startswith(("http://", "https://")) else "text"
                    with st.spinner("🔍 Investigating — opening link in sandboxed browser, this may take 1–3 minutes..."):
                        result = client.investigate(stripped, input_type_hint=detected)
                    st.session_state["last_input"] = stripped
                    st.session_state["last_input_type"] = detected
                    st.session_state["last_result"] = result
                    st.session_state["show_correction"] = False
        except NovaGuardAPIError as exc:
            st.error(f"API error: {exc}")
        except Exception as exc:
            st.error(f"Request failed: {exc}")

    result = st.session_state.get("last_result")
    if result:
        if "extraction" in result and result.get("status") == "ok":
            st.info(f"📝 Extracted: {result['extraction'].get('message_text', '')}")
            _render_result(result["investigation"])
        else:
            _render_result(result)

        # ----- feedback -----
        investigation = result if "report" in result else result.get("investigation") or {}
        predicted_label = investigation.get("predicted_label", "SUSPICIOUS")

        st.divider()
        st.caption("🙋 Help improve NovaGuard — was this verdict correct?")
        fb1, fb2, fb3 = st.columns([2, 2, 4])
        with fb1:
            if st.button("✅ Yes, correct", use_container_width=True, key="fb_correct"):
                try:
                    _client().feedback(
                        user_input=st.session_state["last_input"],
                        predicted_label=predicted_label,
                        feedback_type="correct",
                        input_type=st.session_state["last_input_type"],
                    )
                    st.success("Thank you! Your feedback helps us improve.")
                except Exception as exc:
                    st.error(f"Feedback failed: {exc}")
        with fb2:
            if st.button("❌ No, wrong verdict", use_container_width=True, key="fb_wrong"):
                st.session_state["show_correction"] = True
        if st.session_state["show_correction"]:
            with fb3:
                correction = st.selectbox(
                    "What should the verdict be?",
                    ["SCAM", "SUSPICIOUS", "LIKELY_SAFE", "SAFE"],
                    key="correction_select",
                )
                if st.button("Submit correction", type="primary", key="fb_submit"):
                    try:
                        _client().feedback(
                            user_input=st.session_state["last_input"],
                            predicted_label=predicted_label,
                            feedback_type="incorrect",
                            correct_label=correction,
                            input_type=st.session_state["last_input_type"],
                        )
                        st.success("Correction recorded. Thank you!")
                        st.session_state["show_correction"] = False
                    except Exception as exc:
                        st.error(f"Feedback failed: {exc}")


# ---------------------------------------------------------------- about tab
with about_tab:
    st.markdown("### About this frontend")
    st.markdown(
        "This Streamlit app talks to the NovaGuard FastAPI backend at "
        f"`{st.session_state['api_base_url']}`. All investigation, screenshot OCR, "
        "and feedback flows go through `/api/v1/...` endpoints — the agent itself "
        "runs in the backend process."
    )
    try:
        v = _client().version()
        st.json(v)
    except Exception as exc:
        st.error(f"Could not fetch /api/v1/version: {exc}")

    st.markdown("### Postman collection")
    st.markdown(
        "Import `postman/NovaGuard.postman_collection.json` to exercise every "
        "endpoint. Set the `base_url` and `api_key` collection variables to "
        "match this backend."
    )
