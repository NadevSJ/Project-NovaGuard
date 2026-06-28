"""Investigation history endpoints — requires JWT authentication."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.database import Investigation, User, get_db
from backend.dependencies import _make_current_user_dep

router = APIRouter(prefix="/history", tags=["history"])

get_current_user = _make_current_user_dep(get_db)


# ---------------------------------------------------------------- schemas
class InvestigationSummary(BaseModel):
    id: int
    input_preview: str
    input_type: str
    predicted_label: str
    predicted_score: int
    traffic_light: str
    latency_seconds: float
    created_at: str


class InvestigationDetail(InvestigationSummary):
    report: str | None
    recommended_action: str | None


class HistoryListResponse(BaseModel):
    items: list[InvestigationSummary]
    total: int
    page: int
    limit: int
    pages: int


# ---------------------------------------------------------------- endpoints
@router.get("", response_model=HistoryListResponse)
async def list_history(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> HistoryListResponse:
    """Paginated investigation history for the authenticated user."""
    base_q = (
        db.query(Investigation)
        .filter(Investigation.user_id == current_user.id)
        .order_by(Investigation.created_at.desc())
    )
    total = base_q.count()
    offset = (page - 1) * limit
    rows = base_q.offset(offset).limit(limit).all()
    pages = max(1, -(-total // limit))  # ceiling division
    items = [
        InvestigationSummary(
            id=r.id,
            input_preview=r.input_preview,
            input_type=r.input_type,
            predicted_label=r.predicted_label,
            predicted_score=r.predicted_score,
            traffic_light=r.traffic_light,
            latency_seconds=r.latency_seconds,
            created_at=r.created_at.isoformat(),
        )
        for r in rows
    ]
    return HistoryListResponse(items=items, total=total, page=page, limit=limit, pages=pages)


@router.get("/{investigation_id}", response_model=InvestigationDetail)
async def get_investigation(
    investigation_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> InvestigationDetail:
    """Fetch a single investigation by ID (must belong to the current user)."""
    row = (
        db.query(Investigation)
        .filter(
            Investigation.id == investigation_id,
            Investigation.user_id == current_user.id,
        )
        .first()
    )
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found.",
        )
    return InvestigationDetail(
        id=row.id,
        input_preview=row.input_preview,
        input_type=row.input_type,
        predicted_label=row.predicted_label,
        predicted_score=row.predicted_score,
        traffic_light=row.traffic_light,
        latency_seconds=row.latency_seconds,
        created_at=row.created_at.isoformat(),
        report=row.report,
        recommended_action=row.recommended_action,
    )


@router.delete("/{investigation_id}")
async def delete_investigation(
    investigation_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Response:
    """Delete an investigation (must belong to the current user)."""
    row = (
        db.query(Investigation)
        .filter(
            Investigation.id == investigation_id,
            Investigation.user_id == current_user.id,
        )
        .first()
    )
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found.",
        )
    db.delete(row)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
