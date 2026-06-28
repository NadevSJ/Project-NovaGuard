"""Pydantic request/response models for the NovaGuard API."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

# ----------------------------------------------------------- investigate
class InvestigateRequest(BaseModel):
    input: str = Field(..., min_length=1, max_length=8000, description="Raw text, URL, or pasted message.")
    input_type_hint: Literal["url", "text", "email", "auto"] | None = Field(
        "auto",
        description="Optional explicit input-type hint. 'auto' lets the backend detect.",
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {"input": "URGENT: Your BOC account suspended. Verify PIN: http://boc-verify.xyz"},
                {"input": "https://suspicious-site.example/login", "input_type_hint": "url"},
            ]
        }
    }


class EmailInvestigateRequest(BaseModel):
    sender: str = Field("", max_length=500, description="Sender address shown in the From: header.")
    subject: str = Field("", max_length=500, description="Email subject line (optional).")
    body: str = Field(..., min_length=1, max_length=8000, description="Full email body.")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "sender": "boc-support@secure-banking-alert.com",
                    "subject": "URGENT - Your BOC Internet Banking Account Suspended",
                    "body": "Dear Customer, Your BOC account has been suspended. Click http://boc-verify-now.xyz/login",
                }
            ]
        }
    }


class InvestigationResponse(BaseModel):
    predicted_label: str
    predicted_score: int
    input_type: str
    latency_seconds: float
    report: str = Field(..., description="Full NovaGuard markdown investigation report.")
    traffic_light: Literal["red", "yellow", "green"]
    traffic_light_label: str
    recommended_action: str


class ScreenshotInvestigationResponse(BaseModel):
    status: Literal["ok", "extraction_failed"]
    extraction: dict[str, Any]
    investigation: InvestigationResponse | None = None
    user_message: str


# ----------------------------------------------------------- feedback
class FeedbackRequest(BaseModel):
    input: str = Field(..., min_length=1, max_length=8000)
    predicted_label: str
    feedback_type: Literal["correct", "incorrect"]
    correct_label: Literal["SCAM", "SUSPICIOUS", "LIKELY_SAFE", "SAFE"] | None = None
    input_type: str = "unknown"


class FeedbackResponse(BaseModel):
    ok: bool
    message: str


class FeedbackStatsResponse(BaseModel):
    total: int
    correct: int
    incorrect: int
    false_negatives: int
    accuracy_from_feedback: float | None = None
    false_negative_rate: float | None = None


class FeedbackExportRequest(BaseModel):
    output_path: str | None = Field(
        None,
        description="Where to write the dataset JSON. Defaults to evaluation/dataset/feedback_dataset.json.",
    )


class FeedbackExportResponse(BaseModel):
    exported_count: int
    output_path: str


# ----------------------------------------------------------- health / version
class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"]
    components: dict[str, str]


class VersionResponse(BaseModel):
    version: str
    model: str
    zero_retention_mode: bool
    optional_services: dict[str, bool]


class WarmupResponse(BaseModel):
    ok: bool
    agent_ready: bool
    vision_ready: bool
    latency_seconds: float
