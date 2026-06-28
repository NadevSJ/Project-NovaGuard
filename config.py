# ANALYSIS: single-source GEMINI_MODEL, 4-label system, ZRM-aware, feedback/
#           auto-created, agent + app + bot + vision all route through this.
# CHANGES:  Model bumped to gemini-2.5-pro (current flagship reasoning tier).
"""NovaGuard configuration.

Loads environment variables, exposes project-wide constants, validates
required credentials, and ensures runtime directories exist on import.
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


class Config:
    # API credentials (loaded from .env)
    GOOGLE_API_KEY: str | None = os.getenv("GOOGLE_API_KEY")
    TELEGRAM_BOT_TOKEN: str | None = os.getenv("TELEGRAM_BOT_TOKEN")
    URLSCAN_API_KEY: str | None = os.getenv("URLSCAN_API_KEY")
    VIRUSTOTAL_API_KEY: str | None = os.getenv("VIRUSTOTAL_API_KEY")
    SAMBANOVA_API_KEY: str | None = os.getenv("SAMBANOVA_API_KEY")
    GROQ_API_KEY: str | None = os.getenv("GROQ_API_KEY")
    NVIDIA_API_KEY: str | None = os.getenv("NVIDIA_API_KEY")

    # LLM provider selection
    # LLM_PROVIDER ∈ {"nvidia", "sambanova", "groq", "gemini"}; vision uses NVIDIA NIM.
    LLM_PROVIDER: str = os.getenv("LLM_PROVIDER", "nvidia").lower()
    # Default changes based on provider; always overrideable via .env LLM_MODEL.
    # sambanova default: Meta-Llama-3.3-70B-Instruct
    # gemini default   : gemini-2.0-flash
    LLM_MODEL: str = os.getenv("LLM_MODEL", "gemini-2.0-flash")
    SAMBANOVA_BASE_URL: str = os.getenv(
        "SAMBANOVA_BASE_URL", "https://api.sambanova.ai/v1"
    )

    # Model / agent settings
    GEMINI_MODEL: str = "gemini-2.5-pro"  # used by Gemini-direct baseline only
    # Screenshot OCR model on NVIDIA NIM free tier (avoids Google quota limits)
    NVIDIA_VISION_MODEL: str = os.getenv(
        "NVIDIA_VISION_MODEL", "meta/llama-3.2-11b-vision-instruct"
    )
    MAX_TOKENS: int = 2048
    AGENT_MAX_ITERATIONS: int = 5   # needs buffer for Llama parse-error recovery

    # Privacy: when True, no query content is written to disk.
    # Set to True for production, False for research/evaluation mode.
    ZERO_RETENTION_MODE: bool = (
        os.getenv("ZERO_RETENTION_MODE", "false").lower() == "true"
    )

    # Backend API (FastAPI service)
    API_URL: str = os.getenv("NOVAGUARD_API_URL", "http://localhost:8000")
    API_KEY: str | None = os.getenv("NOVAGUARD_API_KEY") or None
    API_HOST: str = os.getenv("NOVAGUARD_API_HOST", "0.0.0.0")
    API_PORT: int = int(os.getenv("NOVAGUARD_API_PORT", "8000"))

    # JWT authentication (for React frontend user accounts)
    JWT_SECRET: str = os.getenv(
        "NOVAGUARD_JWT_SECRET", "novaguard-jwt-secret-change-in-production"
    )
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = int(os.getenv("NOVAGUARD_JWT_EXPIRE_MINUTES", "10080"))  # 7 days

    # Scraping settings
    SELENIUM_TIMEOUT: int = 6       # pages taking >6s are suspicious; was 10
    MAX_SCRAPED_CHARS: int = 3000

    # Runtime directories
    LOG_DIR: str = "logs"
    RESULTS_DIR: str = "results"
    REPORTS_DIR: str = "reports"

    # Evaluation artifacts
    DATASET_PATH: str = "evaluation/dataset/ground_truth.json"
    ANNOTATION_GUIDELINES_PATH: str = "evaluation/annotation/guidelines.md"

    _OPTIONAL_SERVICES: dict[str, str | None] = {
        "urlscan": URLSCAN_API_KEY,
        "virustotal": VIRUSTOTAL_API_KEY,
        "telegram": TELEGRAM_BOT_TOKEN,
    }

    @classmethod
    def validate(cls) -> None:
        """Raise a clear error if required credentials are missing."""
        provider = cls.LLM_PROVIDER
        if provider == "nvidia":
            if not cls.NVIDIA_API_KEY or cls.NVIDIA_API_KEY.startswith("your_"):
                raise RuntimeError(
                    "NVIDIA_API_KEY is not set. Get a key from "
                    "https://build.nvidia.com/ and put it in .env."
                )
        elif provider == "sambanova":
            if not cls.SAMBANOVA_API_KEY or cls.SAMBANOVA_API_KEY.startswith("your_"):
                raise RuntimeError(
                    "SAMBANOVA_API_KEY is not set. Get a key from "
                    "https://cloud.sambanova.ai/ and put it in .env."
                )
        elif provider == "groq":
            if not cls.GROQ_API_KEY or cls.GROQ_API_KEY.startswith("your_"):
                raise RuntimeError(
                    "GROQ_API_KEY is not set. Get a free key from "
                    "https://console.groq.com/ and put it in .env."
                )
        else:  # gemini
            if not cls.GOOGLE_API_KEY or cls.GOOGLE_API_KEY == "your_gemini_api_key_here":
                raise RuntimeError(
                    "GOOGLE_API_KEY is not set. Copy .env.example to .env and "
                    "add your Gemini API key from https://aistudio.google.com/."
                )
        # Vision always needs Gemini (for screenshot OCR); not fatal if missing.
        # Only screenshot analysis will fail if GOOGLE_API_KEY is absent.

    @classmethod
    def is_configured(cls, service: str) -> bool:
        """Return True if the given optional service has a non-placeholder key."""
        key = cls._OPTIONAL_SERVICES.get(service.lower())
        if not key:
            return False
        return not key.startswith("your_")


def _ensure_runtime_dirs() -> None:
    base = Path(__file__).resolve().parent
    for relative in (
        Config.LOG_DIR,
        Config.RESULTS_DIR,
        f"{Config.REPORTS_DIR}/figures",
        "feedback",
    ):
        (base / relative).mkdir(parents=True, exist_ok=True)


_ensure_runtime_dirs()
