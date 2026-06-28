"""
tools/domain_watcher.py
NovaGuard Shield — Domain Intelligence Watcher

Proactively monitors newly-registered domains and SSL certificate
transparency logs for brand lookalikes targeting registered Shield orgs.

Runs as a background asyncio scheduler inside the FastAPI process.
"""
from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime, timezone
from typing import Optional

import aiohttp
import requests

log = logging.getLogger(__name__)

# ── CRT.SH certificate transparency endpoint ──────────────────────────────────
CRT_SH_URL = "https://crt.sh/?q=%.{domain}&output=json"

# ── CZDS zone file download (requires free ICANN account) ─────────────────────
CZDS_AUTH_URL  = "https://account.icann.org/api/authenticate"
CZDS_LINKS_URL = "https://czds-api.icann.org/czds/downloads/links"


# ─── CERT TRANSPARENCY ────────────────────────────────────────────────────────
async def check_cert_transparency(brand_domain: str, hours: int = 6) -> list[dict]:
    """
    Query crt.sh for SSL certificates issued against a brand domain in the
    last `hours` hours. New certs for lookalike domains = strong attack signal.

    Returns list of {suspicious_domain, cert_id, first_seen, issuer}.
    """
    base_domain = brand_domain.split(".")[-2] + "." + brand_domain.split(".")[-1]
    url = CRT_SH_URL.format(domain=base_domain)
    alerts: list[dict] = []

    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as session:
            async with session.get(url, ssl=False) as resp:
                if resp.status != 200:
                    return []
                data = await resp.json(content_type=None)

        now = datetime.now(timezone.utc)
        for entry in (data or []):
            name_value   = entry.get("name_value", "")
            not_before   = entry.get("not_before", "")
            issuer_name  = entry.get("issuer_name", "")
            cert_id      = entry.get("id", "")

            # Check age
            try:
                issued_at = datetime.fromisoformat(not_before.replace("Z", "+00:00"))
                age_hours = (now - issued_at).total_seconds() / 3600
                if age_hours > hours:
                    continue
            except Exception:
                continue

            # Check if domain name differs from the monitored brand (lookalike)
            for domain_name in name_value.split("\n"):
                domain_name = domain_name.strip().lstrip("*.")
                if not domain_name or domain_name == brand_domain:
                    continue
                # Simple similarity: brand keyword appears in the lookalike domain
                brand_keyword = base_domain.split(".")[0]
                if brand_keyword.lower() in domain_name.lower() and domain_name != brand_domain:
                    alerts.append({
                        "suspicious_domain": domain_name,
                        "cert_id":           cert_id,
                        "first_seen":        not_before,
                        "issuer":            issuer_name,
                        "monitored_brand":   brand_domain,
                    })
                    break

    except Exception as exc:
        log.warning("crt.sh query failed for %s: %s", brand_domain, exc)

    return alerts


# ─── RUN A FULL DOMAIN SCAN ──────────────────────────────────────────────────
async def run_domain_scan(org_domains: list[str]) -> list[dict]:
    """
    Run typosquat checks against a given list of brand domains.
    Uses the existing SpoofingDetector.check_typosquat() for each domain.

    Returns list of detection dicts suitable for ShieldAlert creation.
    """
    alerts: list[dict] = []
    try:
        from tools.spoofing_detector import SpoofingDetector
        det = SpoofingDetector()
    except ImportError:
        log.error("SpoofingDetector not available — cannot run domain scan")
        return []

    tasks = [check_cert_transparency(d) for d in org_domains]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for domain, cert_alerts in zip(org_domains, results):
        if isinstance(cert_alerts, Exception):
            log.debug("CT check failed for %s: %s", domain, cert_alerts)
            continue
        for alert in (cert_alerts or []):
            # Also run local typosquat check on the newly-discovered domain
            suspicious = alert.get("suspicious_domain", "")
            try:
                findings = det.check_typosquat(suspicious)
                similarity = findings[0].similarity_score if findings else 0.5
            except Exception:
                similarity = 0.5
            alerts.append({
                "alert_type":         "domain_lookalike",
                "suspicious_domain":  suspicious,
                "monitored_brand":    domain,
                "similarity_score":   similarity,
                "evidence":           alert,
                "severity":           "high" if similarity > 0.85 else "medium",
                "detected_at":        datetime.now(timezone.utc).isoformat(),
            })

    return alerts


# ─── BACKGROUND SCHEDULER ─────────────────────────────────────────────────────
async def _schedule_loop(interval_hours: float = 6.0):
    """
    Background asyncio task. Runs domain_scan every `interval_hours` hours.
    Publishes results to shield_bus.
    """
    while True:
        try:
            log.info("[DomainWatcher] Starting scheduled domain scan")
            await _run_and_publish()
        except Exception as exc:
            log.error("[DomainWatcher] Scan error: %s", exc)
        await asyncio.sleep(interval_hours * 3600)


async def _run_and_publish():
    """Fetch current Shield org domains from DB and publish any alerts."""
    try:
        from backend.database import SessionLocal
        from backend.models.shield import ShieldOrg, ShieldAlert
        from backend.shield_bus import publish_shield_event

        db = SessionLocal()
        try:
            orgs = db.query(ShieldOrg).all()
            all_domains = []
            org_map: dict[str, str] = {}  # domain -> org_id
            for org in orgs:
                for d in (org.registered_domains or []):
                    all_domains.append(d)
                    org_map[d] = org.org_id

            if not all_domains:
                return

            alerts = await run_domain_scan(all_domains)
            for alert_data in alerts:
                # Find which org owns this domain
                org_id = org_map.get(alert_data.get("monitored_brand", ""), "unknown")
                db_alert = ShieldAlert(
                    org_id      = org_id,
                    alert_type  = alert_data["alert_type"],
                    severity    = alert_data["severity"],
                    detail      = alert_data,
                    action_taken= "alerted",
                )
                db.add(db_alert)
                db.commit()
                db.refresh(db_alert)
                await publish_shield_event({
                    "event":    "domain_alert",
                    "alert_id": str(db_alert.alert_id),
                    "org_id":   org_id,
                    **alert_data,
                })
        finally:
            db.close()
    except Exception as exc:
        log.error("[DomainWatcher] DB/publish failed: %s", exc)


def start_domain_watcher():
    """
    Entry point called from backend/main.py startup:
        asyncio.create_task(domain_watcher.start_domain_watcher())
    """
    return _schedule_loop(interval_hours=6.0)
