"""Direct-LLM baseline.

Sends each sample straight to the active LLM (Gemini or SambaNova) with a
minimal classification prompt — no LangChain agent, no tools, no ReAct loop.
This is the "raw LLM" comparison point that isolates the value added by
NovaGuard's agentic scaffolding.

The class is still called `GeminiDirectBaseline` for backwards compatibility
with existing result files; the model is whatever `Config.LLM_PROVIDER`
selects, exposed as `self.model_id`.
"""

from __future__ import annotations

import re
import time
from typing import Any

from tqdm import tqdm

from agent.llm_factory import active_model_id, build_llm
from config import Config

_VALID_LABELS = {"SCAM", "SUSPICIOUS", "LIKELY_SAFE", "SAFE"}

DIRECT_PROMPT = """You are a scam detection system. Analyze the following message or URL.

Classify it as exactly one of: SCAM, SUSPICIOUS, LIKELY_SAFE, SAFE

Also provide a risk score from 0 (completely safe) to 100 (definite scam).

Respond in EXACTLY this format, nothing else:
VERDICT: [label]
SCORE: [0-100]
REASON: [one sentence]
"""

_VERDICT_RE = re.compile(r"VERDICT:\s*\[?\s*([A-Z_ ]+?)\s*\]?\s*$", re.IGNORECASE | re.MULTILINE)
_SCORE_RE = re.compile(r"SCORE:\s*\[?\s*(\d{1,3})", re.IGNORECASE)
_REASON_RE = re.compile(r"REASON:\s*(.+)", re.IGNORECASE)


class GeminiDirectBaseline:
    """Raw Gemini classifier with no agentic scaffolding."""

    SYSTEM_NAME = "GeminiDirectBaseline"

    def __init__(self) -> None:
        Config.validate()
        self.llm = build_llm(temperature=0.2)
        self.model_id = active_model_id()

    # ----------------------------------------------------------- single call
    def analyze(self, user_input: str) -> dict[str, Any]:
        prompt = f"{DIRECT_PROMPT}\n\nINPUT:\n{user_input}"
        start = time.perf_counter()
        try:
            response = self.llm.invoke(prompt)
            text = (getattr(response, "content", "") or "").strip()
        except Exception as exc:
            return {
                "predicted_label": "SUSPICIOUS",
                "predicted_score": 50,
                "reason": f"error: {exc}",
                "latency_seconds": round(time.perf_counter() - start, 3),
                "raw_response": "",
                "error": str(exc),
            }
        latency = time.perf_counter() - start

        label, score, reason = self._parse(text)
        return {
            "predicted_label": label,
            "predicted_score": score,
            "reason": reason,
            "latency_seconds": round(latency, 3),
            "raw_response": text,
        }

    # ----------------------------------------------------------- dataset run
    def run_on_dataset(self, samples: list[dict[str, Any]]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for sample in tqdm(samples, desc="GeminiDirect", unit="sample"):
            base = self._copy_ground_truth(sample)
            if sample.get("input_type") == "url":
                base.update({
                    "status": "skipped",
                    "skip_reason": "URL-only tool not available in direct baseline",
                    "predicted_label": None,
                    "predicted_score": None,
                    "latency_seconds": 0.0,
                })
                out.append(base)
                continue

            result = self.analyze(sample.get("input", ""))
            base.update({"status": "ok", **result})
            out.append(base)
        return out

    # ----------------------------------------------------------- helpers
    @staticmethod
    def _copy_ground_truth(sample: dict[str, Any]) -> dict[str, Any]:
        return {
            "sample_id": sample.get("id"),
            "input": sample.get("input"),
            "input_type": sample.get("input_type"),
            "category": sample.get("category"),
            "ground_truth_label": sample.get("ground_truth_label"),
            "ground_truth_score_range": sample.get("ground_truth_score_range"),
            "source": sample.get("source"),
        }

    @staticmethod
    def _parse(text: str) -> tuple[str, int, str]:
        label = "SUSPICIOUS"
        score = 50
        reason = ""

        m = _VERDICT_RE.search(text)
        if m:
            candidate = m.group(1).strip().upper().replace(" ", "_")
            candidate = candidate.split("/")[0].strip("_")
            if candidate in _VALID_LABELS:
                label = candidate

        s = _SCORE_RE.search(text)
        if s:
            try:
                v = int(s.group(1))
                if 0 <= v <= 100:
                    score = v
            except ValueError:
                pass

        r = _REASON_RE.search(text)
        if r:
            reason = r.group(1).strip()
        return label, score, reason
