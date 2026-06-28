"""
tools/email_auth.py
NovaGuard Shield — Email Authentication Engine

Checks SPF, DKIM, DMARC, header chain, and display-name spoofing
for every inbound email processed through the Shield pipeline.

Dependencies (add to requirements.txt):
    dnspython>=2.4.0
    dkimpy>=1.0.5
"""
from __future__ import annotations

import difflib
import email
import email.policy
import ipaddress
import re
import logging
from dataclasses import dataclass, field
from typing import Literal, Optional

log = logging.getLogger(__name__)

# ── optional dependency guards ──────────────────────────────────────────────
try:
    import dns.resolver
    import dns.exception
    DNS_OK = True
except ImportError:
    DNS_OK = False
    log.warning("dnspython not installed — SPF/DMARC checks will return 'error'. "
                "Run: pip install dnspython")

try:
    import dkim
    DKIM_OK = True
except ImportError:
    DKIM_OK = False
    log.warning("dkimpy not installed — DKIM checks will return 'none'. "
                "Run: pip install dkimpy")


# ─── DATA CLASSES ─────────────────────────────────────────────────────────────
@dataclass
class EmailAuthResult:
    """Aggregated result of all email authentication checks."""
    spf_result:         Literal["pass", "fail", "softfail", "neutral", "none", "error"]
    dkim_result:        Literal["pass", "fail", "none", "error"]
    dmarc_result:       Literal["pass", "fail", "none", "error"]
    dmarc_policy:       str  # "none" | "quarantine" | "reject"
    header_risk_score:  int  # 0-100
    display_name_spoof: bool
    spoofed_executive:  Optional[str]
    signals:            list[str] = field(default_factory=list)
    overall_risk:       int = 0  # 0-100, computed in __post_init__
    recommended_action: Literal["allow", "warn", "quarantine", "block"] = "allow"
    from_address:       str = ""
    subject:            str = ""
    qr_codes_found:     list[str] = field(default_factory=list)  # decoded URLs from QR in email

    def __post_init__(self):
        score = 0
        if self.spf_result == "fail":                score += 40
        elif self.spf_result == "softfail":          score += 20
        if self.dkim_result == "fail":               score += 30
        if self.dmarc_result == "fail":              score += 20
        if self.display_name_spoof:                  score += 50
        score += min(self.header_risk_score, 20)
        self.overall_risk = min(score, 100)

        if self.overall_risk >= 70:    self.recommended_action = "block"
        elif self.overall_risk >= 50:  self.recommended_action = "quarantine"
        elif self.overall_risk >= 25:  self.recommended_action = "warn"
        else:                          self.recommended_action = "allow"

    def to_dict(self) -> dict:
        return {
            "spf_result": self.spf_result,
            "dkim_result": self.dkim_result,
            "dmarc_result": self.dmarc_result,
            "dmarc_policy": self.dmarc_policy,
            "header_risk_score": self.header_risk_score,
            "display_name_spoof": self.display_name_spoof,
            "spoofed_executive": self.spoofed_executive,
            "signals": self.signals,
            "overall_risk": self.overall_risk,
            "recommended_action": self.recommended_action,
            "from_address": self.from_address,
            "subject": self.subject,
            "qr_codes_found": self.qr_codes_found,
        }


# ─── SPF ──────────────────────────────────────────────────────────────────────
def check_spf(email_from: str, sender_ip: str) -> tuple[str, str]:
    """
    Minimal SPF check — queries DNS TXT for the sender domain, checks if
    the sender IP appears in ip4/ip6 mechanisms, respects -all/~all.

    Returns:
        (result, detail) where result is one of:
        "pass" | "fail" | "softfail" | "neutral" | "none" | "error"
    """
    if not DNS_OK:
        return "error", "dnspython not installed"
    if not email_from or "@" not in email_from:
        return "none", "No valid From address to check"

    domain = email_from.split("@")[-1].strip().lower()
    try:
        try:
            ip_obj = ipaddress.ip_address(sender_ip)
        except ValueError:
            return "error", f"Invalid sender IP: {sender_ip}"

        try:
            answers = dns.resolver.resolve(domain, "TXT", lifetime=5)
        except dns.resolver.NXDOMAIN:
            return "none", f"No DNS record for {domain}"

        spf_record = None
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.startswith("v=spf1"):
                spf_record = txt
                break

        if not spf_record:
            return "none", f"No SPF TXT record at {domain}"

        # Walk mechanisms
        for part in spf_record.split():
            if part.startswith("ip4:"):
                try:
                    net = ipaddress.ip_network(part[4:], strict=False)
                    if ip_obj in net:
                        return "pass", f"{sender_ip} matched {part}"
                except ValueError:
                    pass
            elif part.startswith("ip6:"):
                try:
                    net = ipaddress.ip_network(part[4:], strict=False)
                    if ip_obj in net:
                        return "pass", f"{sender_ip} matched {part}"
                except ValueError:
                    pass

        if "-all" in spf_record:
            return "fail", f"{sender_ip} not in SPF; -all = hard fail"
        elif "~all" in spf_record:
            return "softfail", f"{sender_ip} not in SPF; ~all = soft fail"
        return "neutral", f"{sender_ip} not matched; neutral policy"

    except dns.exception.Timeout:
        return "error", "DNS timeout checking SPF"
    except Exception as exc:
        log.debug("SPF check error: %s", exc)
        return "error", str(exc)


# ─── DKIM ─────────────────────────────────────────────────────────────────────
def check_dkim(raw_email_bytes: bytes) -> tuple[str, str]:
    """
    Verify the DKIM signature in the raw email bytes.
    Returns ("pass"|"fail"|"none"|"error", detail).
    """
    if not DKIM_OK:
        return "none", "dkimpy not installed"
    if not raw_email_bytes:
        return "none", "Empty email bytes"
    try:
        result = dkim.verify(raw_email_bytes)
        if result:
            return "pass", "DKIM signature valid"
        return "fail", "DKIM signature verification failed — body or headers tampered"
    except Exception as exc:
        log.debug("DKIM check error: %s", exc)
        return "none", f"DKIM parse error: {exc}"


# ─── DMARC ────────────────────────────────────────────────────────────────────
def check_dmarc(email_from: str) -> tuple[str, str, str]:
    """
    Look up _dmarc.<domain> TXT record and extract policy.
    Returns (result, policy, detail).
    """
    if not DNS_OK:
        return "error", "none", "dnspython not installed"
    if not email_from or "@" not in email_from:
        return "none", "none", "No From address"

    domain = email_from.split("@")[-1].strip().lower()
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=5)
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if "v=DMARC1" in txt:
                policy = "none"
                m = re.search(r'\bp=(\w+)', txt)
                if m:
                    policy = m.group(1).lower()
                return "pass", policy, f"DMARC record found: p={policy}"
        return "none", "none", f"No DMARC record at _dmarc.{domain}"
    except dns.resolver.NXDOMAIN:
        return "none", "none", f"No DMARC record (NXDOMAIN) for _dmarc.{domain}"
    except dns.exception.Timeout:
        return "error", "none", "DNS timeout checking DMARC"
    except Exception as exc:
        log.debug("DMARC check error: %s", exc)
        return "error", "none", str(exc)


# ─── HEADER CHAIN ANALYSIS ────────────────────────────────────────────────────
def analyze_headers(msg: email.message.Message) -> tuple[int, list[str]]:
    """
    Analyze Received headers and other metadata for anomalies.
    Returns (risk_score 0-100, signals[]).
    """
    signals: list[str] = []
    risk = 0

    # 1. Return-Path vs From domain mismatch
    from_header = msg.get("From", "")
    return_path = msg.get("Return-Path", "").strip("<>")
    if from_header and return_path and "@" in from_header and "@" in return_path:
        from_domain = re.search(r'@([\w.-]+)', from_header)
        rp_domain   = re.search(r'@([\w.-]+)', return_path)
        if from_domain and rp_domain:
            fd = from_domain.group(1).lower()
            rpd = rp_domain.group(1).lower()
            if fd != rpd:
                risk += 25
                signals.append(f"Return-Path domain ({rpd}) ≠ From domain ({fd}) — spoofing indicator")

    # 2. First received-hop private IP (suggests relay manipulation)
    received_headers = msg.get_all("Received") or []
    for i, recv in enumerate(received_headers[:3]):
        ip_m = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', recv)
        if ip_m and i == 0:
            try:
                if ipaddress.ip_address(ip_m.group(1)).is_private:
                    risk += 10
                    signals.append(
                        f"First Received hop IP {ip_m.group(1)} is private — possible internal relay manipulation"
                    )
            except ValueError:
                pass

    # 3. Reply-To domain differs from From domain
    reply_to = msg.get("Reply-To", "")
    if reply_to and "@" in reply_to and "@" in from_header:
        from_d = re.search(r'@([\w.-]+)', from_header)
        rt_d   = re.search(r'@([\w.-]+)', reply_to)
        if from_d and rt_d and from_d.group(1).lower() != rt_d.group(1).lower():
            risk += 20
            signals.append(
                f"Reply-To domain ({rt_d.group(1)}) ≠ From domain ({from_d.group(1)}) — classic BEC redirect"
            )

    # 4. Missing MIME-Version (uncommon for legitimate MUAs)
    if not msg.get("MIME-Version"):
        risk += 5
        signals.append("Missing MIME-Version header — unusual for legitimate mail clients")

    return min(risk, 100), signals


# ─── DISPLAY-NAME SPOOF ───────────────────────────────────────────────────────
def check_display_name(
    display_name: str,
    from_addr: str,
    org_domain: str,
    known_executives: Optional[list[str]] = None,
) -> tuple[bool, Optional[str]]:
    """
    Check if display_name resembles a known executive but the email
    comes from a non-org domain (classic BEC technique).

    Returns (is_spoof, matched_name_or_None).
    """
    if not display_name or not known_executives:
        return False, None

    display_clean = display_name.strip().lower()
    from_domain = from_addr.split("@")[-1].strip().lower() if "@" in from_addr else ""
    org_clean = org_domain.strip().lower()

    for exec_name in known_executives:
        ratio = difflib.SequenceMatcher(None, display_clean, exec_name.lower()).ratio()
        if ratio >= 0.82 and from_domain and org_clean and from_domain != org_clean:
            return True, exec_name

    return False, None


# ─── ORCHESTRATOR ─────────────────────────────────────────────────────────────
def run_full_auth(
    raw_email_bytes: bytes,
    sender_ip: str = "0.0.0.0",
    org_domain: str = "",
    known_executives: Optional[list[str]] = None,
) -> EmailAuthResult:
    """
    Run all email authentication checks and return a consolidated EmailAuthResult.

    Args:
        raw_email_bytes:    Raw bytes of the email (as received by the MTA).
        sender_ip:          IP address of the sending mail server.
        org_domain:         The protected organisation's primary domain (e.g. "boc.lk").
        known_executives:   List of known executive names to check display-name spoofing.

    Returns:
        EmailAuthResult with all fields populated.
    """
    signals: list[str] = []

    try:
        msg = email.message_from_bytes(
            raw_email_bytes,
            policy=email.policy.compat32,
        )
    except Exception as exc:
        return EmailAuthResult(
            spf_result="error", dkim_result="error", dmarc_result="error",
            dmarc_policy="none", header_risk_score=0,
            display_name_spoof=False, spoofed_executive=None,
            signals=[f"Failed to parse email bytes: {exc}"],
        )

    from_header = msg.get("From", "")
    subject     = msg.get("Subject", "")
    email_m     = re.search(r'[\w.+-]+@[\w.-]+\.\w+', from_header)
    email_from  = email_m.group(0) if email_m else ""

    # Extract display name (text before the <email> part)
    display_name = ""
    if "<" in from_header:
        display_name = from_header.split("<")[0].strip().strip('"').strip("'")

    # ── Run checks ──────────────────────────────────────────────────────────
    spf_result, spf_detail = check_spf(email_from, sender_ip)
    if spf_result != "pass":
        signals.append(f"SPF {spf_result.upper()}: {spf_detail}")

    dkim_result, dkim_detail = check_dkim(raw_email_bytes)
    if dkim_result != "pass":
        signals.append(f"DKIM {dkim_result.upper()}: {dkim_detail}")

    dmarc_result, dmarc_policy, dmarc_detail = check_dmarc(email_from)
    if dmarc_result != "pass":
        signals.append(f"DMARC {dmarc_result.upper()}: {dmarc_detail}")

    header_risk, header_signals = analyze_headers(msg)
    signals.extend(header_signals)

    is_spoof, spoofed_exec = check_display_name(
        display_name, email_from, org_domain, known_executives
    )
    if is_spoof:
        signals.append(
            f"Display-name spoofing: '{display_name}' resembles executive "
            f"'{spoofed_exec}' but email originates from non-org domain"
        )

    # ── QR code check (optional — requires tools.qr_scanner) ────────────────
    qr_urls: list[str] = []
    try:
        from tools.qr_scanner import scan_email_attachments
        qr_results = scan_email_attachments(raw_email_bytes)
        for qr in qr_results:
            # qr is a QRResult dataclass — use attribute access, not .get()
            qr_urls.append(qr.url)
            signals.append(f"QR code detected in email attachment — decoded URL: {qr.url}")
    except ImportError:
        pass  # qr_scanner not yet installed — skip silently
    except Exception as exc:
        log.debug("QR scan on email failed: %s", exc)

    return EmailAuthResult(
        spf_result=spf_result,
        dkim_result=dkim_result,
        dmarc_result=dmarc_result,
        dmarc_policy=dmarc_policy,
        header_risk_score=header_risk,
        display_name_spoof=is_spoof,
        spoofed_executive=spoofed_exec,
        signals=signals,
        from_address=email_from,
        subject=subject,
        qr_codes_found=qr_urls,
    )
