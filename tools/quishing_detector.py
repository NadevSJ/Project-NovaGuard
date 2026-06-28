"""
tools/quishing_detector.py
NovaGuard QR Scanner — 4-Layer Quishing Detection Engine

Analyses a decoded URL from a QR code for quishing (QR + phishing) attacks.
Layer 1: Fast structural checks (regex, no API, < 50ms)
Layer 2: Domain enrichment (WHOIS + VirusTotal + URLScan — < 2s)
Layer 3: Visual context (label mismatch, overlay — from qr_scanner)
Layer 4: LLM intent analysis (only fires when Layer1-3 score > 40)
"""
from __future__ import annotations

import json
import logging
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional, Literal

log = logging.getLogger(__name__)

# ─── SIGNAL LISTS ─────────────────────────────────────────────────────────────
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "rb.gy", "shorturl.at",
    "ow.ly", "cutt.ly", "is.gd", "v.gd", "tiny.cc", "buff.ly", "dlvr.it",
    "ift.tt", "snip.ly", "bl.ink",
}

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".pw", ".icu", ".click", ".life", ".online", ".site",
    ".work", ".tk", ".ml", ".ga", ".cf", ".gq", ".monster", ".uno",
}

PHISHING_PATH_PATTERNS = re.compile(
    r'/(login|secure|verify|update|confirm|account|auth|signin|bank|pay|'
    r'wallet|portal|reset|renew|validate|customer|service|support)',
    re.IGNORECASE,
)


# ─── DATA CLASS ───────────────────────────────────────────────────────────────
@dataclass
class QuishingResult:
    """Full quishing analysis result for one decoded URL."""
    decoded_url:         str
    risk_score:          int = 0          # 0-100 aggregated
    risk_level:          Literal["green", "yellow", "red"] = "green"
    quishing_probability:float = 0.0      # 0.0-1.0
    signals:             list[str] = field(default_factory=list)
    explanation:         str = ""
    redirect_chain:      list[str] = field(default_factory=list)
    page_title:          str = ""
    screenshot_url:      str = ""
    label_mismatch:      bool = False
    overlay_detected:    bool = False

    def to_dict(self) -> dict:
        return {
            "decoded_url": self.decoded_url,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "quishing_probability": self.quishing_probability,
            "signals": self.signals,
            "explanation": self.explanation,
            "redirect_chain": self.redirect_chain,
            "page_title": self.page_title,
            "screenshot_url": self.screenshot_url,
            "label_mismatch": self.label_mismatch,
            "overlay_detected": self.overlay_detected,
        }


# ─── LAYER 1: STRUCTURAL CHECKS ──────────────────────────────────────────────
def check_structural(url: str, label_text: str = "") -> tuple[int, list[str]]:
    """
    Fast structural risk checks. Zero API calls. Runs in < 50ms.
    Returns (risk_points, signals[]).
    """
    signals: list[str] = []
    risk = 0

    if not url:
        return 0, []

    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return 10, ["Malformed URL"]

    netloc   = parsed.netloc.lower()
    scheme   = parsed.scheme.lower()
    path     = parsed.path.lower()

    # 1. URL shortener
    domain_only = netloc.split(":")[0]
    if domain_only in SHORTENER_DOMAINS:
        risk += 30
        signals.append(f"URL shortener detected: {domain_only}")

    # 2. No HTTPS
    if scheme == "http":
        risk += 25
        signals.append("Non-HTTPS URL — uncommon in legitimate QR codes")

    # 3. IP address as host
    try:
        import ipaddress
        ipaddress.ip_address(netloc.split(":")[0])
        risk += 40
        signals.append(f"IP address used as host: {netloc} — bypasses domain reputation")
    except ValueError:
        pass

    # 4. Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if domain_only.endswith(tld):
            risk += 20
            signals.append(f"Suspicious TLD: {tld}")
            break

    # 5. Brand lookalike (reuse existing spoofing detector)
    try:
        from tools.spoofing_detector import SpoofingDetector
        det = SpoofingDetector()
        findings = det.check_typosquat(domain_only)
        for f in findings:
            risk += 50
            signals.append(f"Brand typosquat: {f.domain} resembles {f.brand}")
    except Exception as exc:
        log.debug("Typosquat check failed: %s", exc)

    # 6. Phishing-kit-like URL path
    if PHISHING_PATH_PATTERNS.search(path):
        risk += 15
        signals.append(f"Phishing-kit URL path detected: {path[:60]}")

    # 7. Label vs URL mismatch (OCR from qr_scanner)
    if label_text:
        label_words = set(re.findall(r'\w+', label_text.lower()))
        url_words   = set(re.findall(r'\w+', domain_only.lower()))
        overlap     = label_words & url_words
        if label_words and not overlap:
            risk += 35
            signals.append(
                f"Label text near QR ('{label_text[:40]}') does not match URL domain"
            )

    return min(risk, 100), signals


# ─── LAYER 2: ENRICHMENT ─────────────────────────────────────────────────────
def enrich_url(url: str) -> tuple[int, list[str], dict]:
    """
    Enrich a URL with external reputation data.
    Returns (extra_risk_pts, extra_signals, metadata_dict).
    metadata_dict may contain: page_title, screenshot_url, redirect_chain.
    """
    risk = 0
    signals: list[str] = []
    meta: dict = {"page_title": "", "screenshot_url": "", "redirect_chain": []}

    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.split(":")[0].lower()

    # Domain age check (reuse existing RDAP check)
    try:
        from tools.spoofing_detector import SpoofingDetector
        det = SpoofingDetector()
        age_result = det.check_domain_age(domain)
        if age_result and age_result.age_days is not None and age_result.age_days < 30:
            risk += 40
            signals.append(f"Domain age: {age_result.age_days} days — newly registered")
    except Exception as exc:
        log.debug("Domain age check failed: %s", exc)

    # VirusTotal
    try:
        import requests as req
        from config import Config
        vt_key = getattr(Config, "VIRUSTOTAL_API_KEY", None)
        if vt_key:
            import base64 as b64
            url_id = b64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
            r = req.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": vt_key},
                timeout=8,
            )
            if r.status_code == 200:
                stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                if malicious > 0:
                    risk += 60
                    signals.append(f"VirusTotal: {malicious} engines flagged URL as malicious")
                elif suspicious > 0:
                    risk += 25
                    signals.append(f"VirusTotal: {suspicious} engines flagged URL as suspicious")
    except Exception as exc:
        log.debug("VirusTotal check failed: %s", exc)

    # URLScan.io
    try:
        import requests as _req_sync
        from config import Config
        us_key = getattr(Config, "URLSCAN_API_KEY", None)
        if us_key:
            r = _req_sync.post(
                "https://urlscan.io/api/v1/scan/",
                headers={"API-Key": us_key, "Content-Type": "application/json"},
                json={"url": url, "visibility": "unlisted"},
                timeout=8,
            )
            if r.status_code == 200:
                scan_id = r.json().get("uuid", "")
                if scan_id:
                    # Poll for result — up to 5 attempts × 3 seconds = 15s max
                    # Using short sleeps in a loop keeps total block time bounded
                    import time as _time
                    result_data = None
                    for _ in range(5):
                        _time.sleep(3)
                        res = _req_sync.get(
                            f"https://urlscan.io/api/v1/result/{scan_id}/",
                            timeout=8,
                        )
                        if res.status_code == 200:
                            result_data = res.json()
                            break
                    if result_data:
                        verdict = result_data.get("verdicts", {}).get("overall", {})
                        score = verdict.get("score", 0)
                        if score >= 75:
                            risk += 60
                            signals.append(f"URLScan.io verdict score: {score}/100 (malicious)")
                        elif score >= 40:
                            risk += 30
                            signals.append(f"URLScan.io suspicious score: {score}/100")
                        meta["page_title"]     = result_data.get("page", {}).get("title", "")
                        meta["screenshot_url"] = f"https://urlscan.io/screenshots/{scan_id}.png"
                        final_url = result_data.get("page", {}).get("url", url)
                        if final_url != url:
                            meta["redirect_chain"] = [url, final_url]
    except Exception as exc:
        log.debug("URLScan.io check failed: %s", exc)

    return min(risk, 100), signals, meta


# ─── LAYER 4: LLM ANALYSIS ───────────────────────────────────────────────────
QUISHING_PROMPT = """You are a cybersecurity expert specialising in QR code phishing (quishing).
Analyse this URL and available context. Output ONLY a JSON object:
{
  "quishing_probability": float (0.0-1.0),
  "explanation": "one or two plain-English sentences",
  "risk_level": "green" | "yellow" | "red"
}

URL: {url}
Domain age: {domain_info}
Signals so far: {signals}

Reasoning checklist:
1. Does the URL or page title suggest credential harvesting?
2. Does it visually impersonate a Sri Lankan bank, government, or telco?
3. Are there urgency or scare tactics?
4. Is the URL path typical of a phishing kit?

Output ONLY the JSON.
"""


def _llm_quishing_analysis(url: str, domain_info: str, signals: list[str]) -> Optional[dict]:
    try:
        from langchain_core.messages import HumanMessage, SystemMessage
        from agent.llm_factory import build_llm

        llm = build_llm(temperature=0.1)
        prompt = QUISHING_PROMPT.format(
            url=url,
            domain_info=domain_info,
            signals="; ".join(signals[:8]),
        )
        response = llm.invoke([
            SystemMessage(content="You are a quishing detection expert. Output only JSON."),
            HumanMessage(content=prompt),
        ])
        content = response.content if hasattr(response, "content") else str(response)
        content = re.sub(r'^```(?:json)?\s*|\s*```$', '', content.strip(), flags=re.MULTILINE)
        return json.loads(content)
    except ImportError:
        return None
    except Exception as exc:
        log.debug("Quishing LLM analysis failed: %s", exc)
        return None


# ─── ORCHESTRATOR ─────────────────────────────────────────────────────────────
def analyse_quishing(
    url: str,
    label_text: str = "",
    overlay_detected: bool = False,
    use_llm: bool = True,
    use_enrichment: bool = True,
) -> QuishingResult:
    """
    Full 4-layer quishing analysis pipeline.

    Args:
        url:              The URL decoded from a QR code.
        label_text:       OCR text near the QR code (from qr_scanner).
        overlay_detected: Whether an image overlay was detected (from qr_scanner).
        use_llm:          Enable LLM analysis (Layer 4).
        use_enrichment:   Enable external API enrichment (Layer 2).

    Returns:
        QuishingResult with all fields populated.
    """
    result = QuishingResult(decoded_url=url)

    if not url:
        result.explanation = "Empty URL — nothing to analyse"
        return result

    # Layer 1: fast structural
    l1_risk, l1_signals = check_structural(url, label_text)
    result.signals.extend(l1_signals)

    # Layer 3: context signals from QR scanner
    if overlay_detected:
        l1_risk = min(l1_risk + 35, 100)
        result.signals.append("QR code appears overlaid on another image — possible swap attack")
    result.overlay_detected = overlay_detected
    result.label_mismatch = label_text != "" and any("mismatch" in s for s in l1_signals)

    # Layer 2: enrichment
    l2_risk, l2_signals, meta = 0, [], {}
    if use_enrichment and l1_risk >= 0:  # always enrich (cheap checks first)
        l2_risk, l2_signals, meta = enrich_url(url)
        result.signals.extend(l2_signals)
        result.page_title     = meta.get("page_title", "")
        result.screenshot_url = meta.get("screenshot_url", "")
        result.redirect_chain = meta.get("redirect_chain", [])

    combined_risk = min(l1_risk + l2_risk, 100)

    # Layer 4: LLM (only when combined score > 40)
    if use_llm and combined_risk > 40:
        domain = urllib.parse.urlparse(url).netloc
        llm_res = _llm_quishing_analysis(url, domain, result.signals)
        if llm_res:
            try:
                result.quishing_probability = float(llm_res.get("quishing_probability", combined_risk / 100))
                result.explanation          = str(llm_res.get("explanation", ""))
                level = str(llm_res.get("risk_level", "")).lower()
                if level in ("green", "yellow", "red"):
                    result.risk_level = level  # type: ignore
            except Exception:
                pass

    # Finalise risk score and level
    result.risk_score = combined_risk
    if not result.explanation:
        result.explanation = (
            f"Structural + enrichment analysis: {len(result.signals)} signal(s) detected. "
            f"Combined risk: {combined_risk}/100."
        ) if result.signals else "No risk signals detected — URL appears safe."

    if result.risk_level == "green":  # not yet set by LLM
        if combined_risk >= 65:
            result.risk_level = "red"
        elif combined_risk >= 36:
            result.risk_level = "yellow"
        else:
            result.risk_level = "green"

    if result.quishing_probability == 0.0:
        result.quishing_probability = round(combined_risk / 100, 2)

    return result
