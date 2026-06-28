"""Health, version, and warmup endpoints."""

from __future__ import annotations

import time

from fastapi import APIRouter, Depends

from agent.llm_factory import active_model_id, llm_summary
from backend.dependencies import get_agent, get_vision, require_api_key
from backend.schemas import HealthResponse, VersionResponse, WarmupResponse
from config import Config

router = APIRouter(tags=["meta"])


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    components = {
        "llm_provider": Config.LLM_PROVIDER,
        "llm_model": active_model_id(),
        "sambanova_api_key": "configured" if Config.SAMBANOVA_API_KEY else "missing",
        "gemini_api_key": "configured" if Config.GOOGLE_API_KEY else "missing",
        "urlscan": "configured" if Config.is_configured("urlscan") else "not_configured",
        "virustotal": "configured" if Config.is_configured("virustotal") else "not_configured",
        "telegram": "configured" if Config.is_configured("telegram") else "not_configured",
    }
    if Config.LLM_PROVIDER == "sambanova":
        ok = bool(Config.SAMBANOVA_API_KEY)
    else:
        ok = bool(Config.GOOGLE_API_KEY)
    return HealthResponse(status="ok" if ok else "degraded", components=components)


@router.get("/version", response_model=VersionResponse)
async def version() -> VersionResponse:
    summary = llm_summary()
    return VersionResponse(
        version="1.0.0",
        model=f"{summary['provider']}:{summary['model']} (vision={summary['vision_model']})",
        zero_retention_mode=Config.ZERO_RETENTION_MODE,
        optional_services={
            "urlscan": Config.is_configured("urlscan"),
            "virustotal": Config.is_configured("virustotal"),
            "telegram": Config.is_configured("telegram"),
        },
    )


@router.post(
    "/warmup",
    response_model=WarmupResponse,
    dependencies=[Depends(require_api_key)],
)
async def warmup() -> WarmupResponse:
    """Eagerly initialise the agent + vision inspector so the first user request is fast."""
    start = time.perf_counter()
    agent_ready = vision_ready = False
    try:
        get_agent()
        agent_ready = True
    except Exception:
        agent_ready = False
    try:
        get_vision()
        vision_ready = True
    except Exception:
        vision_ready = False
    return WarmupResponse(
        ok=agent_ready and vision_ready,
        agent_ready=agent_ready,
        vision_ready=vision_ready,
        latency_seconds=round(time.perf_counter() - start, 3),
    )
