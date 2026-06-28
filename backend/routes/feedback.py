"""Feedback endpoints: log, stats, export."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from backend.dependencies import require_api_key
from backend.schemas import (
    FeedbackExportRequest,
    FeedbackExportResponse,
    FeedbackRequest,
    FeedbackResponse,
    FeedbackStatsResponse,
)
from feedback.feedback_manager import (
    export_as_dataset,
    get_feedback_stats,
    log_feedback,
)

router = APIRouter(prefix="/feedback", tags=["feedback"])

_VALID_LABELS = {"SCAM", "SUSPICIOUS", "LIKELY_SAFE", "SAFE"}


@router.post(
    "",
    response_model=FeedbackResponse,
    dependencies=[Depends(require_api_key)],
    summary="Log a single feedback record",
)
async def submit_feedback(request: FeedbackRequest) -> FeedbackResponse:
    if request.feedback_type == "incorrect" and not request.correct_label:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="`correct_label` is required when feedback_type='incorrect'.",
        )
    predicted = (request.predicted_label or "").upper()
    if predicted not in _VALID_LABELS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"predicted_label must be one of {sorted(_VALID_LABELS)}.",
        )
    log_feedback(
        user_input=request.input,
        predicted_label=predicted,
        feedback_type=request.feedback_type,
        correct_label=request.correct_label,
        input_type=request.input_type,
    )
    return FeedbackResponse(ok=True, message="Feedback recorded.")


@router.get(
    "/stats",
    response_model=FeedbackStatsResponse,
    dependencies=[Depends(require_api_key)],
    summary="Aggregate community feedback statistics",
)
async def feedback_stats() -> FeedbackStatsResponse:
    stats = get_feedback_stats()
    return FeedbackStatsResponse(
        total=int(stats.get("total", 0)),
        correct=int(stats.get("correct", 0)),
        incorrect=int(stats.get("incorrect", 0)),
        false_negatives=int(stats.get("false_negatives", 0)),
        accuracy_from_feedback=stats.get("accuracy_from_feedback"),
        false_negative_rate=stats.get("false_negative_rate"),
    )


@router.post(
    "/export",
    response_model=FeedbackExportResponse,
    dependencies=[Depends(require_api_key)],
    summary="Export confirmed incorrect predictions as a labeled dataset",
)
async def feedback_export(request: FeedbackExportRequest) -> FeedbackExportResponse:
    output = request.output_path or "evaluation/dataset/feedback_dataset.json"
    count = export_as_dataset(output_path=output)
    return FeedbackExportResponse(exported_count=count, output_path=output)
