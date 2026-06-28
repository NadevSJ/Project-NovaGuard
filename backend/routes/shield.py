"""
backend/routes/shield.py
NovaGuard Shield — Business-Level Spoofing Prevention API

Endpoints:
  POST /shield/org/register        — Register an organisation for Shield monitoring
  POST /shield/scan-email          — Scan a raw email for auth failures + BEC patterns
  POST /shield/payment/hold        — Hold a flagged payment and fire webhook
  GET  /shield/payment/queue/{id}  — List pending payment holds for an org
  GET  /shield/alerts/{org_id}     — SSE stream of Shield alerts for an org
  GET  /shield/org/{org_id}        — Get org details
  GET  /shield/domain/alerts/{id}  — Domain lookalike alerts for an org
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
from datetime import datetime, timezone

import requests as req
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

try:
    from backend.database import get_db
except ImportError:
    from database import get_db

try:
    from backend.models.shield import ShieldOrg, ShieldAlert
except ImportError:
    from models.shield import ShieldOrg, ShieldAlert

try:
    from backend.shield_bus import publish_shield_event, subscribe_shield_org
except ImportError:
    from shield_bus import publish_shield_event, subscribe_shield_org

from tools.email_auth import run_full_auth
from tools.payment_guardian import analyse_email

router = APIRouter(prefix="/shield", tags=["Shield"])
log = logging.getLogger(__name__)


# ─── PYDANTIC SCHEMAS ─────────────────────────────────────────────────────────
class OrgRegisterRequest(BaseModel):
    org_name:           str
    sector_tag:         str = "general"
    registered_domains: list[str] = []
    known_executives:   list[str] = []
    org_domain:         str = ""
    webhook_url:        str = ""

class ScanEmailRequest(BaseModel):
    raw_email:    str          # base64-encoded raw email bytes
    sender_ip:    str = "0.0.0.0"
    org_id:       str = ""

class PaymentHoldRequest(BaseModel):
    org_id:      str
    email_id:    str           # UUID of the Investigation or raw identifier
    reason:      str
    evidence:    dict = {}

class PaymentDecisionRequest(BaseModel):
    decision:    str           # "approve" | "reject"
    reviewer:    str = ""


# ─── REGISTER ORG ─────────────────────────────────────────────────────────────
@router.post("/org/register")
async def register_org(body: OrgRegisterRequest, db: Session = Depends(get_db)):
    """Register an organisation for Shield monitoring."""
    org = ShieldOrg(
        org_name           = body.org_name,
        sector_tag         = body.sector_tag,
        registered_domains = body.registered_domains,
        known_executives   = body.known_executives,
        org_domain         = body.org_domain,
        webhook_url        = body.webhook_url,
    )
    db.add(org)
    db.commit()
    db.refresh(org)
    log.info("[Shield] Registered org: %s (%s)", org.org_name, org.org_id)
    return {
        "org_id":   org.org_id,
        "org_name": org.org_name,
        "api_key":  org.api_key,
        "message":  f"Organisation '{org.org_name}' registered. Store api_key securely.",
    }


@router.get("/org/{org_id}")
async def get_org(org_id: str, db: Session = Depends(get_db)):
    org = db.query(ShieldOrg).filter(ShieldOrg.org_id == org_id).first()
    if not org:
        raise HTTPException(404, "Organisation not found")
    return org.to_dict()


# ─── SCAN EMAIL ───────────────────────────────────────────────────────────────
@router.post("/scan-email")
async def scan_email(body: ScanEmailRequest, db: Session = Depends(get_db)):
    """
    Run full email authentication + BEC payment detection.
    Accepts base64-encoded raw email bytes.
    """
    import base64

    try:
        raw_bytes = base64.b64decode(body.raw_email)
    except Exception as exc:
        raise HTTPException(400, f"Invalid base64 email data: {exc}")

    # Fetch org config (optional — for display-name check)
    org = None
    if body.org_id:
        org = db.query(ShieldOrg).filter(ShieldOrg.org_id == body.org_id).first()

    org_domain = org.org_domain or "" if org else ""
    known_executives = org.known_executives or [] if org else []

    # ── Email Authentication ─────────────────────────────────────────────────
    auth_result = run_full_auth(
        raw_bytes,
        sender_ip       = body.sender_ip,
        org_domain      = org_domain,
        known_executives= known_executives,
    )

    # ── BEC Payment Analysis ────────────────────────────────────────────────
    try:
        import email
        msg = email.message_from_bytes(raw_bytes)
        email_body = ""
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                email_body += part.get_payload(decode=True).decode("utf-8", errors="replace")
        bec_result = analyse_email(email_body)
    except Exception as exc:
        log.warning("[Shield] BEC analysis failed: %s", exc)
        bec_result = None

    # Determine combined severity
    combined_risk = auth_result.overall_risk
    if bec_result and bec_result.bec_probability > 0.5:
        combined_risk = min(combined_risk + int(bec_result.bec_probability * 40), 100)

    severity = (
        "critical" if combined_risk >= 70
        else "high"   if combined_risk >= 50
        else "medium" if combined_risk >= 25
        else "low"
    )

    # ── Save ShieldAlert ────────────────────────────────────────────────────
    detail = {
        "email_auth": auth_result.to_dict(),
        "bec_analysis": bec_result.to_dict() if bec_result else None,
        "combined_risk": combined_risk,
    }

    alert = None
    if body.org_id and combined_risk >= 20:
        alert = ShieldAlert(
            org_id      = body.org_id,
            alert_type  = "email_auth_fail" if auth_result.overall_risk > 0 else "bec_payment",
            severity    = severity,
            detail      = detail,
            action_taken= auth_result.recommended_action,
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)

        # Publish SSE event
        await publish_shield_event({
            "event":       "shield_alert",
            "alert_id":    alert.alert_id,
            "org_id":      body.org_id,
            "alert_type":  alert.alert_type,
            "severity":    severity,
            "combined_risk": combined_risk,
            "signals":     auth_result.signals[:6],
        })

        # Fire webhook if configured
        if org and org.webhook_url:
            await _fire_webhook(org, alert, detail)

    return {
        "email_auth":      auth_result.to_dict(),
        "bec_analysis":    bec_result.to_dict() if bec_result else None,
        "combined_risk":   combined_risk,
        "severity":        severity,
        "recommended_action": auth_result.recommended_action,
        "alert_id":        alert.alert_id if alert else None,
        "qr_codes_found":  auth_result.qr_codes_found,
    }


# ─── PAYMENT HOLD ─────────────────────────────────────────────────────────────
@router.post("/payment/hold")
async def hold_payment(body: PaymentHoldRequest, db: Session = Depends(get_db)):
    """Flag a payment as held pending second-approval. Fires org webhook."""
    org = db.query(ShieldOrg).filter(ShieldOrg.org_id == body.org_id).first()
    if not org:
        raise HTTPException(404, "Organisation not found")

    alert = ShieldAlert(
        org_id      = body.org_id,
        alert_type  = "bec_payment",
        severity    = "critical",
        detail      = {
            "email_id": body.email_id,
            "reason":   body.reason,
            "evidence": body.evidence,
            "status":   "held",
            "held_at":  datetime.now(timezone.utc).isoformat(),
        },
        action_taken = "held",
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)

    await publish_shield_event({
        "event":    "payment_hold",
        "alert_id": alert.alert_id,
        "org_id":   body.org_id,
        "reason":   body.reason,
    })

    if org.webhook_url:
        await _fire_webhook(org, alert, {"payment_hold": True, **alert.detail})

    return {
        "alert_id": alert.alert_id,
        "status":   "held",
        "message":  "Payment flagged as held. Awaiting second-approval.",
    }


@router.get("/payment/queue/{org_id}")
async def get_payment_queue(org_id: str, db: Session = Depends(get_db)):
    """Return all pending payment holds for an org."""
    alerts = (
        db.query(ShieldAlert)
        .filter(
            ShieldAlert.org_id == org_id,
            ShieldAlert.alert_type == "bec_payment",
            ShieldAlert.resolved == False,
        )
        .order_by(ShieldAlert.created_at.desc())
        .limit(50)
        .all()
    )
    return {"holds": [a.to_dict() for a in alerts], "total": len(alerts)}


# ─── SSE ALERT STREAM ─────────────────────────────────────────────────────────
@router.get("/alerts/{org_id}")
async def shield_alert_stream(org_id: str):
    """
    SSE stream of live Shield alerts for a specific org.
    Connect with: EventSource('/shield/alerts/{org_id}')
    """
    return StreamingResponse(
        subscribe_shield_org(org_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/alerts/{org_id}/history")
async def get_alert_history(
    org_id: str,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
):
    """Return recent Shield alerts for an org (for history table)."""
    alerts = (
        db.query(ShieldAlert)
        .filter(ShieldAlert.org_id == org_id)
        .order_by(ShieldAlert.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    total = db.query(ShieldAlert).filter(ShieldAlert.org_id == org_id).count()
    return {"alerts": [a.to_dict() for a in alerts], "total": total}


# ─── DOMAIN ALERTS ────────────────────────────────────────────────────────────
@router.get("/domain/alerts/{org_id}")
async def get_domain_alerts(org_id: str, db: Session = Depends(get_db)):
    """Return recent domain-lookalike alerts for an org."""
    alerts = (
        db.query(ShieldAlert)
        .filter(
            ShieldAlert.org_id == org_id,
            ShieldAlert.alert_type == "domain_lookalike",
        )
        .order_by(ShieldAlert.created_at.desc())
        .limit(30)
        .all()
    )
    return {"alerts": [a.to_dict() for a in alerts]}


# ─── WEBHOOK HELPER ───────────────────────────────────────────────────────────
async def _fire_webhook(org: ShieldOrg, alert: ShieldAlert, payload: dict):
    """Fire the org's configured webhook URL with a signed payload."""
    if not org.webhook_url:
        return
    try:
        body_str = json.dumps({
            "alert_id":   alert.alert_id,
            "org_id":     org.org_id,
            "alert_type": alert.alert_type,
            "severity":   alert.severity,
            "payload":    payload,
        }, default=str)
        sig = hmac.new(
            org.api_key.encode(),
            body_str.encode(),
            hashlib.sha256,
        ).hexdigest()
        req.post(
            org.webhook_url,
            data=body_str,
            headers={
                "Content-Type": "application/json",
                "X-NovaGuard-Signature": sig,
                "X-NovaGuard-Alert-Type": alert.alert_type,
            },
            timeout=5,
        )
        log.info("[Shield] Webhook fired for org %s: %s", org.org_id, alert.alert_type)
    except Exception as exc:
        log.warning("[Shield] Webhook failed for %s: %s", org.org_id, exc)


# ─── DOMAIN REGISTER + TAKEDOWN ───────────────────────────────────────────────
class DomainRegisterRequest(BaseModel):
    org_id:             str
    domains:            list[str]
    brand_keywords:     list[str] = []
    contacts:           list[str] = []

class TakedownRequest(BaseModel):
    domain:     str
    org_id:     str
    evidence_type: str = "domain_lookalike"


@router.post("/domain/register")
async def register_domains(body: DomainRegisterRequest, db: Session = Depends(get_db)):
    """Add monitored domains to a Shield org."""
    org = db.query(ShieldOrg).filter(ShieldOrg.org_id == body.org_id).first()
    if not org:
        raise HTTPException(404, "Organisation not found")
    existing = org.registered_domains or []
    updated  = list(set(existing + body.domains))
    org.registered_domains = updated
    db.commit()
    return {"org_id": body.org_id, "monitored_domains": updated, "status": "monitoring"}


@router.post("/domain/takedown")
async def initiate_takedown(body: TakedownRequest, db: Session = Depends(get_db)):
    """
    Initiate an automated takedown request for a spoofed domain.
    Logs the request as a ShieldAlert and fires the org webhook.
    The actual abuse email / ICANN submission runs as a background task.
    """
    import asyncio

    org = None
    if body.org_id:
        org = db.query(ShieldOrg).filter(ShieldOrg.org_id == body.org_id).first()

    alert = ShieldAlert(
        org_id       = body.org_id or "global",
        alert_type   = "domain_lookalike",
        severity     = "high",
        detail       = {
            "domain":        body.domain,
            "evidence_type": body.evidence_type,
            "status":        "takedown_initiated",
            "initiated_at":  datetime.now(timezone.utc).isoformat(),
        },
        action_taken = "takedown_initiated",
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)

    # Fire SSE notification
    await publish_shield_event({
        "event":    "takedown_initiated",
        "alert_id": alert.alert_id,
        "org_id":   body.org_id,
        "domain":   body.domain,
    })

    # Webhook
    if org and org.webhook_url:
        await _fire_webhook(org, alert, {"takedown": True, "domain": body.domain})

    # Background task: generate abuse email (best-effort, does not block response)
    asyncio.create_task(_background_takedown(body.domain, alert.alert_id))

    return {
        "alert_id": alert.alert_id,
        "domain":   body.domain,
        "status":   "takedown_initiated",
        "message":  (
            f"Takedown request for {body.domain} logged. "
            "Abuse report will be submitted to registrar within 60 seconds."
        ),
    }


async def _background_takedown(domain: str, alert_id: str):
    """
    Best-effort background takedown pipeline:
    1. RDAP lookup for registrar abuse contact.
    2. Send abuse email via SMTP (uses SMTP settings from config if configured).
    3. Update the ShieldAlert action_taken field.
    """
    import asyncio
    try:
        # Step 1: RDAP abuse contact
        from tools.spoofing_detector import SpoofingDetector
        det  = SpoofingDetector()
        rdap = det.check_domain_age(domain)
        abuse_email = (rdap.registrar_abuse_contact if rdap else None) or "abuse@icann.org"

        # Step 2: Compose abuse report
        body_text = (
            f"To Whom It May Concern,\n\n"
            f"We are reporting the domain {domain} for abuse. "
            f"This domain is spoofing a legitimate Sri Lankan institution "
            f"and is being used in Business Email Compromise (BEC) phishing attacks.\n\n"
            f"Evidence Reference: NovaGuard Shield Alert {alert_id}\n"
            f"Reported by: NovaGuard Shield (novaguard.lk)\n\n"
            f"Please suspend this domain immediately.\n\nRegards,\nNovaGuard Shield"
        )

        try:
            from config import Config
            import smtplib
            from email.mime.text import MIMEText
            smtp_host = getattr(Config, "SMTP_HOST", None)
            smtp_from = getattr(Config, "SMTP_FROM", None)
            if smtp_host and smtp_from:
                msg = MIMEText(body_text)
                msg["Subject"] = f"Abuse Report — Spoofed Domain: {domain}"
                msg["From"]    = smtp_from
                msg["To"]      = abuse_email
                with smtplib.SMTP(smtp_host, 587, timeout=10) as srv:
                    srv.sendmail(smtp_from, [abuse_email], msg.as_string())
                log.info("[Shield] Abuse report sent to %s for %s", abuse_email, domain)
        except Exception as smtp_exc:
            log.warning("[Shield] SMTP abuse report failed: %s", smtp_exc)

        # Step 3: Update alert
        from backend.database import SessionLocal
        db2 = SessionLocal()
        try:
            al = db2.query(ShieldAlert).filter(ShieldAlert.alert_id == alert_id).first()
            if al:
                detail = dict(al.detail or {})
                detail["abuse_contact"] = abuse_email
                detail["abuse_report_sent"] = True
                al.detail = detail
                al.action_taken = "abuse_report_sent"
                db2.commit()
        finally:
            db2.close()

    except Exception as exc:
        log.error("[Shield] Background takedown failed for %s: %s", domain, exc)
