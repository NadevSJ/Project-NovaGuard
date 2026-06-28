"""NovaGuard FastAPI application.

Run:
    python run_backend.py
or:
    uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000

Browse the auto-generated docs at:
    http://localhost:8000/docs        (Swagger UI)
    http://localhost:8000/redoc       (ReDoc)
"""

from __future__ import annotations

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.database import create_tables
from backend.routes import auth as auth_routes
from backend.routes import browse_live as browse_live_routes
from backend.routes import feedback as feedback_routes
from backend.routes import health as health_routes
from backend.routes import history as history_routes
from backend.routes import investigate as investigate_routes
from backend.routes import qr_scan as qr_scan_routes
from backend.routes import shield as shield_routes
from config import Config

logging.basicConfig(
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger("novaguard.backend")

API_V1_PREFIX = "/api/v1"


def create_app() -> FastAPI:
    app = FastAPI(
        title="NovaGuard API",
        description=(
            "REST API for the NovaGuard scam-detection agent. Investigate text, "
            "URLs, emails, and screenshots; record community feedback. Powered by "
            f"`{Config.GEMINI_MODEL}` and LangChain ReAct."
        ),
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )

    # CORS — allow React dev server and any origin (tighten in production)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://localhost:3000", "*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/", include_in_schema=False)
    async def root() -> JSONResponse:
        return JSONResponse({
            "service": "novaguard-api",
            "version": "1.0.0",
            "docs": "/docs",
            "v1": API_V1_PREFIX,
        })

    app.include_router(auth_routes.router, prefix=API_V1_PREFIX)
    app.include_router(history_routes.router, prefix=API_V1_PREFIX)
    app.include_router(health_routes.router, prefix=API_V1_PREFIX)
    app.include_router(investigate_routes.router, prefix=API_V1_PREFIX)
    app.include_router(browse_live_routes.router, prefix=API_V1_PREFIX)
    app.include_router(feedback_routes.router, prefix=API_V1_PREFIX)
    app.include_router(qr_scan_routes.router, prefix=API_V1_PREFIX)
    app.include_router(shield_routes.router, prefix=API_V1_PREFIX)

    @app.on_event("startup")
    async def _on_startup() -> None:
        import asyncio
        create_tables()
        from backend.shield_bus import bind_shield_loop
        bind_shield_loop()
        from tools import domain_watcher
        asyncio.create_task(domain_watcher.start_domain_watcher())
        from agent.llm_factory import active_model_id
        logger.info(
            "NovaGuard API ready | provider=%s | model=%s | api_key_required=%s | zero_retention=%s",
            Config.LLM_PROVIDER,
            active_model_id(),
            bool(Config.API_KEY),
            Config.ZERO_RETENTION_MODE,
        )

    return app


app = create_app()
