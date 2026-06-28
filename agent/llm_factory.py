"""Factory for the text-generation LLM used by the agent and baselines.

Supports four text-LLM providers selectable via LLM_PROVIDER in .env:
  • nvidia     — NVIDIA NIM (OpenAI-compatible). Needs NVIDIA_API_KEY.
  • sambanova  — SambaNova Cloud (OpenAI-compatible). Needs SAMBANOVA_API_KEY.
  • groq       — Groq Cloud (OpenAI-compatible, free tier). Needs GROQ_API_KEY.
  • gemini     — Google Gemini via langchain_google_genai. Needs GOOGLE_API_KEY.

Vision (tools.vision_tool) uses NVIDIA NIM's free vision model
(meta/llama-3.2-11b-vision-instruct) regardless of this setting,
configurable via NVIDIA_VISION_MODEL in .env.
"""

from __future__ import annotations

from typing import Any

from langchain_core.language_models import BaseChatModel

from config import Config

_GROQ_BASE_URL   = "https://api.groq.com/openai/v1"
_NVIDIA_BASE_URL = "https://integrate.api.nvidia.com/v1"


def build_llm(
    *,
    temperature: float = 0.2,
    max_tokens: int | None = None,
) -> BaseChatModel:
    """Return a chat model honouring Config.LLM_PROVIDER."""
    max_tok = max_tokens if max_tokens is not None else Config.MAX_TOKENS
    provider = Config.LLM_PROVIDER

    # ---------------------------------------------------------------- NVIDIA NIM
    if provider == "nvidia":
        if not Config.NVIDIA_API_KEY:
            raise RuntimeError(
                "LLM_PROVIDER=nvidia but NVIDIA_API_KEY is not set. "
                "Get a key at https://build.nvidia.com/"
            )
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(
            model=Config.LLM_MODEL,
            api_key=Config.NVIDIA_API_KEY,
            base_url=_NVIDIA_BASE_URL,
            temperature=temperature,
            max_tokens=max_tok,
            # Disable DeepSeek chain-of-thought thinking tokens via NVIDIA NIM flag.
            extra_body={"chat_template_kwargs": {"thinking": False}},
        )

    # ---------------------------------------------------------------- SambaNova
    if provider == "sambanova":
        if not Config.SAMBANOVA_API_KEY:
            raise RuntimeError(
                "LLM_PROVIDER=sambanova but SAMBANOVA_API_KEY is not set."
            )
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(
            model=Config.LLM_MODEL,
            api_key=Config.SAMBANOVA_API_KEY,
            base_url=Config.SAMBANOVA_BASE_URL,
            temperature=temperature,
            max_tokens=max_tok,
        )

    # ---------------------------------------------------------------- Groq
    if provider == "groq":
        if not Config.GROQ_API_KEY:
            raise RuntimeError(
                "LLM_PROVIDER=groq but GROQ_API_KEY is not set. "
                "Get a free key at https://console.groq.com/"
            )
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(
            model=Config.LLM_MODEL,
            api_key=Config.GROQ_API_KEY,
            base_url=_GROQ_BASE_URL,
            temperature=temperature,
            max_tokens=max_tok,
        )

    # ---------------------------------------------------------------- Gemini (default)
    if not Config.GOOGLE_API_KEY:
        raise RuntimeError(
            "LLM_PROVIDER=gemini but GOOGLE_API_KEY is not set."
        )
    # Use LLM_MODEL for the agent; GEMINI_MODEL is reserved for vision OCR only.
    gemini_agent_model = Config.LLM_MODEL or Config.GEMINI_MODEL
    from langchain_google_genai import ChatGoogleGenerativeAI
    return ChatGoogleGenerativeAI(
        model=gemini_agent_model,
        google_api_key=Config.GOOGLE_API_KEY,
        temperature=temperature,
        max_output_tokens=max_tok,
    )


def active_model_id() -> str:
    """Return the human-readable model identifier for the currently active provider."""
    return Config.LLM_MODEL or Config.GEMINI_MODEL


def llm_summary() -> dict[str, Any]:
    """Lightweight info dict for /version, About panels, and logs."""
    return {
        "provider": Config.LLM_PROVIDER,
        "model": active_model_id(),
        "vision_provider": "gemini",
        "vision_model": Config.GEMINI_MODEL,
    }
