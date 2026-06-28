"""
backend/models/shield.py
NovaGuard Shield — SQLAlchemy Database Models

Add to backend/database.py:
    from backend.models.shield import ShieldOrg, ShieldAlert
    (create_all() will handle the new tables automatically)
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    Boolean, Column, DateTime, Float, Integer,
    JSON, String, Text, ForeignKey,
)
from sqlalchemy.orm import relationship

# Import Base from the existing database module
try:
    from backend.database import Base
except ImportError:
    # Fallback for standalone testing
    from sqlalchemy.orm import declarative_base
    Base = declarative_base()


def _now() -> datetime:
    return datetime.now(timezone.utc)

def _uuid() -> str:
    return str(uuid.uuid4())


class ShieldOrg(Base):
    """
    A business/government organisation registered for Shield monitoring.
    """
    __tablename__ = "shield_orgs"

    org_id             = Column(String(36), primary_key=True, default=_uuid)
    org_name           = Column(String(255), nullable=False)
    sector_tag         = Column(String(64),  nullable=False, default="general")
    # List of official domains e.g. ["boc.lk", "bankofceylon.lk"]
    registered_domains = Column(JSON, nullable=False, default=list)
    # List of known executive names for display-name spoof check
    known_executives   = Column(JSON, nullable=False, default=list)
    org_domain         = Column(String(255), nullable=True)   # primary email domain
    webhook_url        = Column(String(512), nullable=True)   # for push alerts
    api_key            = Column(String(64),  nullable=False, default=_uuid)
    is_active          = Column(Boolean,     nullable=False, default=True)
    created_at         = Column(DateTime(timezone=True), default=_now)

    alerts = relationship("ShieldAlert", back_populates="org", lazy="dynamic")

    def to_dict(self) -> dict:
        return {
            "org_id":             self.org_id,
            "org_name":           self.org_name,
            "sector_tag":         self.sector_tag,
            "registered_domains": self.registered_domains or [],
            "org_domain":         self.org_domain,
            "webhook_url":        self.webhook_url,
            "is_active":          self.is_active,
            "created_at":         self.created_at.isoformat() if self.created_at else None,
        }


class ShieldAlert(Base):
    """
    A detected threat event for a Shield-registered organisation.
    """
    __tablename__ = "shield_alerts"

    alert_id     = Column(String(36), primary_key=True, default=_uuid)
    org_id       = Column(String(36), ForeignKey("shield_orgs.org_id",
                            ondelete="CASCADE"), nullable=False, index=True)
    alert_type   = Column(String(64),  nullable=False)
    # Possible values: email_auth_fail | bec_payment | domain_lookalike | qr_quishing
    severity     = Column(String(16),  nullable=False, default="medium")
    # Possible values: low | medium | high | critical
    detail       = Column(JSON,        nullable=True)
    action_taken = Column(String(64),  nullable=True)
    # Possible values: alerted | held | blocked | reviewed
    resolved     = Column(Boolean,     nullable=False, default=False)
    created_at   = Column(DateTime(timezone=True), default=_now)

    org = relationship("ShieldOrg", back_populates="alerts")

    def to_dict(self) -> dict:
        return {
            "alert_id":    self.alert_id,
            "org_id":      self.org_id,
            "alert_type":  self.alert_type,
            "severity":    self.severity,
            "detail":      self.detail,
            "action_taken":self.action_taken,
            "resolved":    self.resolved,
            "created_at":  self.created_at.isoformat() if self.created_at else None,
        }
