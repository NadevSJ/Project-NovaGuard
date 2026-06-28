"""Project-root shim: `python run_backend.py` to start the API."""

from __future__ import annotations

import uvicorn

from config import Config


def main() -> None:
    print(
        f"Starting NovaGuard API on http://{Config.API_HOST}:{Config.API_PORT}\n"
        f"  Docs: http://{Config.API_HOST}:{Config.API_PORT}/docs\n"
        f"  Model: {Config.GEMINI_MODEL}\n"
        f"  X-API-Key required: {bool(Config.API_KEY)}\n"
    )
    uvicorn.run(
        "backend.main:app",
        host=Config.API_HOST,
        port=Config.API_PORT,
        reload=False,
        log_level="info",
    )


if __name__ == "__main__":
    main()
