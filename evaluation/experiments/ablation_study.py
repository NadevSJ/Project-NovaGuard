"""Ablation study.

Systematically removes one component at a time from the NovaGuard agent
to quantify each component's contribution to overall accuracy and scam
detection rate.
"""

from __future__ import annotations

import re
import time
from typing import Any, Callable

import pandas as pd
from langchain.agents import AgentExecutor, create_react_agent
from langchain_core.prompts import PromptTemplate

from agent.llm_factory import build_llm
from agent.novaguard_agent import NOVAGUARD_SYSTEM_PROMPT
from config import Config
from evaluation.experiments.simulation_runner import SimulationRunner
from evaluation.metrics.scorer import NovaGuardScorer
from tools.selenium_tool import inspect_url_tool

# Anchors used to surgically remove sections from the system prompt.
_SL_CONTEXT_START = "BANKING SCAMS:"
_SL_CONTEXT_END = "RED FLAGS YOU ALWAYS CHECK:"
_RED_FLAGS_START = "RED FLAGS YOU ALWAYS CHECK:"
_RED_FLAGS_END = "EMAIL PHISHING INDICATORS"
_STRUCTURED_OUTPUT_START = "RESPONSE FORMAT - always use exactly this structure:"

_REACT_SUFFIX = """

You have access to the following tools:

{tools}

Use this exact ReAct format. Every step must start with one of the labels
"Thought:", "Action:", "Action Input:", "Observation:", or "Final Answer:".

Question: the user's input (a URL, SMS, or message)
Thought: think step by step about what to investigate next
Action: the action to take, must be one of [{tool_names}]
Action Input: the input to the action
Observation: the result of the action
... (Thought/Action/Action Input/Observation can repeat as needed)
Thought: I now have enough evidence to render a verdict
Final Answer: the complete report in the format described above.

Begin!

Question: {input}
Thought: {agent_scratchpad}"""

_DIRECT_SUFFIX = """

Now analyse the following input and respond with the report described above:

Input:
{input}
"""

_GENERIC_PREAMBLE = (
    "You are a senior cybersecurity investigator who detects financial fraud, "
    "phishing, and scam messages. You explain your reasoning carefully and "
    "give the user a clear actionable verdict."
)

_VERDICT_RE = re.compile(
    r"\*\*\s*Verdict\s*:\s*\*\*\s*\[?\s*(SCAM|SUSPICIOUS|LIKELY[_ ]SAFE|SAFE)",
    re.IGNORECASE,
)
_SCORE_RE = re.compile(
    r"\*\*\s*Risk Score\s*:\s*\*\*\s*\[?\s*(\d{1,3})", re.IGNORECASE
)
_FREEFORM_LABEL_RE = re.compile(
    r"\b(SCAM|SUSPICIOUS|LIKELY[_ ]SAFE|SAFE)\b", re.IGNORECASE
)


class AblationStudy:
    """Run NovaGuard with selected components removed and compare results."""

    CONFIGS: dict[str, dict[str, Any]] = {
        "full_system": {
            "description": "Complete NovaGuard with all components",
            "use_tool": True,
            "use_sri_lanka_context": True,
            "use_red_flag_list": True,
            "use_structured_output": True,
        },
        "no_tool": {
            "description": "Remove Selenium tool - AI reasoning only",
            "use_tool": False,
            "use_sri_lanka_context": True,
            "use_red_flag_list": True,
            "use_structured_output": True,
        },
        "no_local_context": {
            "description": "Generic scam detector without SL context",
            "use_tool": True,
            "use_sri_lanka_context": False,
            "use_red_flag_list": True,
            "use_structured_output": True,
        },
        "no_red_flags": {
            "description": "No explicit red flag checklist in prompt",
            "use_tool": True,
            "use_sri_lanka_context": True,
            "use_red_flag_list": False,
            "use_structured_output": True,
        },
        "no_structured_output": {
            "description": "Free-form response without format constraint",
            "use_tool": True,
            "use_sri_lanka_context": True,
            "use_red_flag_list": True,
            "use_structured_output": False,
        },
    }

    def __init__(self) -> None:
        Config.validate()
        self.runner = SimulationRunner()
        self.scorer = NovaGuardScorer()
        self.llm = build_llm(temperature=0.2)

    # --------------------------------------------------- prompt construction
    @staticmethod
    def _build_prompt_body(config: dict[str, Any]) -> str:
        body = NOVAGUARD_SYSTEM_PROMPT

        if not config.get("use_sri_lanka_context", True):
            body = AblationStudy._splice_out(body, _SL_CONTEXT_START, _SL_CONTEXT_END)
            body = body.replace(
                "You are NovaGuard, a senior cybersecurity investigator "
                "specializing\nin financial fraud targeting Sri Lankan users. "
                "You have deep expertise\nin local scam patterns including:",
                _GENERIC_PREAMBLE,
            )

        if not config.get("use_red_flag_list", True):
            body = AblationStudy._splice_out(body, _RED_FLAGS_START, _RED_FLAGS_END)

        if not config.get("use_structured_output", True):
            idx = body.find(_STRUCTURED_OUTPUT_START)
            if idx >= 0:
                body = body[:idx].rstrip() + (
                    "\n\nRespond with a short paragraph that clearly states the "
                    "verdict (SCAM / SUSPICIOUS / LIKELY_SAFE / SAFE), a risk "
                    "score from 0 to 100, and the reasons. No fixed format is "
                    "required.\n"
                )

        return body

    @staticmethod
    def _splice_out(text: str, start_anchor: str, end_anchor: str) -> str:
        s_idx = text.find(start_anchor)
        e_idx = text.find(end_anchor)
        if s_idx == -1 or e_idx == -1 or e_idx <= s_idx:
            return text
        return text[:s_idx] + text[e_idx:]

    # --------------------------------------------------- analyzer factory
    def build_agent_for_config(
        self, config: dict[str, Any]
    ) -> Callable[[str], dict[str, Any]]:
        body = self._build_prompt_body(config)
        use_tool = config.get("use_tool", True)
        structured = config.get("use_structured_output", True)

        if use_tool:
            tools = [inspect_url_tool]
            template = PromptTemplate.from_template(body + _REACT_SUFFIX)
            react_agent = create_react_agent(self.llm, tools, template)
            executor = AgentExecutor(
                agent=react_agent,
                tools=tools,
                verbose=False,
                max_iterations=Config.AGENT_MAX_ITERATIONS,
                handle_parsing_errors=True,
            )

            def _run(user_input: str) -> dict[str, Any]:
                start = time.perf_counter()
                try:
                    raw = executor.invoke({"input": user_input})
                    response = raw.get("output", "") if isinstance(raw, dict) else str(raw)
                except Exception as exc:
                    response = f"ERROR: {exc}"
                latency = time.perf_counter() - start
                label, score = _parse_label_score(response, structured)
                return {
                    "predicted_label": label,
                    "predicted_score": score,
                    "latency_seconds": round(latency, 3),
                    "response": response,
                }

            return _run

        template = PromptTemplate.from_template(body + _DIRECT_SUFFIX)

        def _run_no_tool(user_input: str) -> dict[str, Any]:
            start = time.perf_counter()
            prompt_str = template.format(input=user_input)
            try:
                response_obj = self.llm.invoke(prompt_str)
                response = getattr(response_obj, "content", str(response_obj))
            except Exception as exc:
                response = f"ERROR: {exc}"
            latency = time.perf_counter() - start
            label, score = _parse_label_score(response, structured)
            return {
                "predicted_label": label,
                "predicted_score": score,
                "latency_seconds": round(latency, 3),
                "response": response,
            }

        return _run_no_tool

    # --------------------------------------------------- run all
    def run_all(
        self,
        text_only_samples: list[dict[str, Any]],
        dry_run: bool = False,
    ) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for name, config in self.CONFIGS.items():
            print(f"\n[ablation] Running config: {name} — {config['description']}")
            analyzer = self.build_agent_for_config(config)
            results = self.runner.run_agent(
                analyzer=analyzer,
                samples=text_only_samples,
                system_name=f"ablation_{name}",
                dry_run=dry_run,
                desc=name,
            )
            latencies = [
                r.get("latency_seconds", 0.0)
                for r in results
                if r.get("latency_seconds") is not None
            ]
            report = self.scorer.full_evaluation_report(
                results=results,
                latency_list=latencies,
                system_name=f"ablation_{name}",
            )
            saved = self.runner.save_results(
                results=results,
                system_name="ablation",
                suffix=name,
            )
            out[name] = {
                "config": config,
                "results": results,
                "metrics": report,
                "files": saved,
            }
        return out

    # --------------------------------------------------- impact analysis
    @staticmethod
    def compute_component_impact(
        ablation_results: dict[str, dict[str, Any]],
    ) -> pd.DataFrame:
        full = ablation_results.get("full_system")
        if not full:
            return pd.DataFrame()

        full_f1 = float(full["metrics"]["classification"].get("f1_macro", 0.0))
        full_sdr = float(full["metrics"]["classification"].get("scam_detection_rate", 0.0))

        rows: list[dict[str, Any]] = []
        for name, payload in ablation_results.items():
            cls = payload["metrics"]["classification"]
            f1 = float(cls.get("f1_macro", 0.0))
            sdr = float(cls.get("scam_detection_rate", 0.0))
            rows.append({
                "config_name": name,
                "description": payload["config"]["description"],
                "f1_macro": round(f1, 4),
                "f1_drop": round(full_f1 - f1, 4),
                "scam_detection_rate": round(sdr, 4),
                "scam_detection_drop": round(full_sdr - sdr, 4),
            })

        df = pd.DataFrame(rows)
        return df.sort_values("f1_drop", ascending=False).reset_index(drop=True)


# ----------------------------------------------------------------- parse helpers
def _parse_label_score(response: str, structured: bool) -> tuple[str, int]:
    response = response or ""
    label = "SUSPICIOUS"
    score = 50

    verdict_match = _VERDICT_RE.search(response) if structured else None
    if verdict_match:
        candidate = verdict_match.group(1).upper().replace(" ", "_")
        if candidate in {"SCAM", "SUSPICIOUS", "LIKELY_SAFE", "SAFE"}:
            label = candidate
    else:
        free_match = _FREEFORM_LABEL_RE.search(response)
        if free_match:
            candidate = free_match.group(1).upper().replace(" ", "_")
            if candidate in {"SCAM", "SUSPICIOUS", "LIKELY_SAFE", "SAFE"}:
                label = candidate

    score_match = _SCORE_RE.search(response)
    if score_match:
        try:
            v = int(score_match.group(1))
            if 0 <= v <= 100:
                score = v
        except ValueError:
            pass
    else:
        free_score = re.search(r"\b(\d{1,3})\s*(?:/\s*100|out of 100)", response)
        if free_score:
            try:
                v = int(free_score.group(1))
                if 0 <= v <= 100:
                    score = v
            except ValueError:
                pass

    return label, score
