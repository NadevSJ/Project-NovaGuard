"""End-to-end experiment runner.

Drives the full evaluation pipeline: load dataset, filter by mode, run
NovaGuard plus baselines, run ablation, score everything, and print a
summary table.
"""

from __future__ import annotations

import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from tabulate import tabulate

from config import Config
from evaluation.benchmarks.baseline_gemini_direct import GeminiDirectBaseline
from evaluation.benchmarks.baseline_urlscan import URLScanBaseline
from evaluation.benchmarks.baseline_virustotal import VirusTotalBaseline
from evaluation.experiments.ablation_study import AblationStudy
from evaluation.experiments.simulation_runner import SimulationRunner
from evaluation.metrics.scorer import NovaGuardScorer


class ExperimentRunner:
    """Orchestrates a complete NovaGuard evaluation run."""

    def __init__(self) -> None:
        self.runner = SimulationRunner()
        self.scorer = NovaGuardScorer()
        self.results_dir = Path(Config.RESULTS_DIR)
        self.results_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------ main entry
    def run_full_experiment(
        self,
        mode: str = "text-only",
        limit: int | None = None,
        dry_run: bool = False,
        skip_ablation: bool = False,
    ) -> dict[str, Any]:
        print(f"\n=== NovaGuard Experiment Runner ===")
        print(f"Mode={mode!r}  limit={limit}  dry_run={dry_run}  skip_ablation={skip_ablation}")

        samples = self.runner.load_dataset()
        samples = self.runner.filter_samples(samples, mode=mode, limit=limit)
        print(f"Loaded {len(samples)} samples after filtering.")
        if not samples:
            raise RuntimeError("No samples to evaluate — check dataset and mode.")

        per_system_reports: dict[str, dict[str, Any]] = {}

        # ----- NovaGuard agent -----
        nova_analyzer = self._build_nova_analyzer(dry_run)
        print("\n[1] Running NovaGuard agent...")
        nova_results = self.runner.run_agent(
            analyzer=nova_analyzer,
            samples=samples,
            system_name="NovaGuard",
            dry_run=dry_run,
            desc="NovaGuard",
        )
        per_system_reports["NovaGuard"] = self._score_and_save(
            nova_results, system_name="NovaGuard"
        )

        # ----- Gemini direct baseline (text samples only) -----
        text_samples = [s for s in samples if s.get("input_type") == "text"]
        if text_samples:
            print("\n[2] Running GeminiDirectBaseline...")
            direct_analyzer = self._build_direct_analyzer(dry_run)
            direct_results = self.runner.run_agent(
                analyzer=direct_analyzer,
                samples=text_samples,
                system_name="GeminiDirectBaseline",
                dry_run=dry_run,
                desc="GeminiDirect",
            )
            per_system_reports["GeminiDirectBaseline"] = self._score_and_save(
                direct_results, system_name="GeminiDirectBaseline"
            )

        # ----- URLScan / VirusTotal baselines (URL samples) -----
        url_samples = [s for s in samples if s.get("input_type") == "url"]
        if url_samples and not dry_run:
            if Config.is_configured("urlscan"):
                print("\n[3] Running URLScanBaseline...")
                urlscan_results = self._run_url_baseline(URLScanBaseline(), url_samples)
                per_system_reports["URLScanBaseline"] = self._score_and_save(
                    urlscan_results, system_name="URLScanBaseline"
                )
            else:
                print("\n[3] Skipping URLScanBaseline — URLSCAN_API_KEY not configured.")
            if Config.is_configured("virustotal"):
                print("\n[4] Running VirusTotalBaseline...")
                vt_results = self._run_url_baseline(VirusTotalBaseline(), url_samples)
                per_system_reports["VirusTotalBaseline"] = self._score_and_save(
                    vt_results, system_name="VirusTotalBaseline"
                )
            else:
                print("\n[4] Skipping VirusTotalBaseline — VIRUSTOTAL_API_KEY not configured.")

        # ----- Ablation study on text samples -----
        ablation_payload: dict[str, Any] = {}
        if not skip_ablation and text_samples:
            print("\n[5] Running AblationStudy...")
            ablation = AblationStudy()
            ablation_results = ablation.run_all(text_samples, dry_run=dry_run)
            impact_df = AblationStudy.compute_component_impact(ablation_results)
            ablation_payload = {
                "results_by_config": {
                    name: payload["metrics"]
                    for name, payload in ablation_results.items()
                },
                "impact_table": impact_df.to_dict(orient="records"),
            }
            impact_path = (
                self.results_dir
                / f"ablation_impact_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.csv"
            )
            impact_df.to_csv(impact_path, index=False)
            print(f"Ablation impact saved to {impact_path}")

        # ----- Aggregate & print summary -----
        summary = self._build_summary(per_system_reports)
        self._print_summary_table(summary)

        full_report = {
            "metadata": {
                "mode": mode,
                "limit": limit,
                "dry_run": dry_run,
                "skip_ablation": skip_ablation,
                "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "sample_count": len(samples),
            },
            "systems": per_system_reports,
            "ablation": ablation_payload,
            "summary_table": summary,
        }
        report_path = (
            self.results_dir
            / f"experiment_report_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
        )
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(full_report, f, ensure_ascii=False, indent=2)
        print(f"\nFull experiment report saved to {report_path}")

        return full_report

    # ------------------------------------------------------------ helpers
    def _build_nova_analyzer(self, dry_run: bool) -> Callable[[str], dict[str, Any]]:
        if dry_run:
            return lambda _: {
                "predicted_label": "SUSPICIOUS",
                "predicted_score": 50,
                "latency_seconds": 0.01,
                "response": "[DRY-RUN] mocked NovaGuard response",
            }
        from agent.novaguard_agent import NovaGuardAgent

        agent = NovaGuardAgent()

        def _run(user_input: str) -> dict[str, Any]:
            result = agent.investigate(user_input)
            return {
                "predicted_label": result.get("predicted_label"),
                "predicted_score": result.get("predicted_score"),
                "latency_seconds": result.get("latency_seconds"),
                "response": result.get("response"),
            }

        return _run

    def _build_direct_analyzer(
        self, dry_run: bool
    ) -> Callable[[str], dict[str, Any]]:
        if dry_run:
            return lambda _: {
                "predicted_label": "SUSPICIOUS",
                "predicted_score": 50,
                "latency_seconds": 0.01,
                "response": "[DRY-RUN] mocked direct-Gemini response",
            }
        baseline = GeminiDirectBaseline()
        return lambda user_input: baseline.analyze(user_input)

    def _run_url_baseline(
        self,
        baseline: URLScanBaseline | VirusTotalBaseline,
        samples: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        results = baseline.run_on_dataset(samples)
        normalised: list[dict[str, Any]] = []
        for r in results:
            if r.get("status") in {"skipped", "error", "timeout"}:
                continue
            scored = self.scorer.score_prediction(
                predicted_label=r.get("predicted_label") or "SUSPICIOUS",
                predicted_score=int(r.get("predicted_score") or 50),
                ground_truth_label=r.get("ground_truth_label", ""),
                ground_truth_score_range=r.get("ground_truth_score_range"),
            )
            normalised.append({**r, **scored, "system_name": baseline.SYSTEM_NAME})
        return normalised

    def _score_and_save(
        self,
        results: list[dict[str, Any]],
        system_name: str,
    ) -> dict[str, Any]:
        usable = [
            r
            for r in results
            if r.get("predicted_label") and r.get("ground_truth_label")
        ]
        latencies = [
            r.get("latency_seconds", 0.0)
            for r in usable
            if r.get("latency_seconds") is not None
        ]
        report = self.scorer.full_evaluation_report(
            results=usable,
            latency_list=latencies,
            system_name=system_name,
        )
        files = self.runner.save_results(results=results, system_name=system_name)
        return {"metrics": report, "files": files, "n_usable": len(usable)}

    @staticmethod
    def _build_summary(
        per_system_reports: dict[str, dict[str, Any]],
    ) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for name, payload in per_system_reports.items():
            cls = payload["metrics"]["classification"]
            lat = payload["metrics"]["latency"]
            rows.append({
                "system": name,
                "n": cls.get("n"),
                "accuracy": cls.get("accuracy"),
                "f1_macro": cls.get("f1_macro"),
                "scam_detect_rate": cls.get("scam_detection_rate"),
                "false_pos_rate": cls.get("false_positive_rate"),
                "latency_p50": lat.get("median"),
                "latency_p95": lat.get("p95"),
            })
        return rows

    @staticmethod
    def _print_summary_table(summary: list[dict[str, Any]]) -> None:
        if not summary:
            print("(no systems produced usable results)")
            return
        headers = list(summary[0].keys())
        rows = [[row[h] for h in headers] for row in summary]
        print("\n=== Experiment Summary ===")
        print(tabulate(rows, headers=headers, floatfmt=".4f", tablefmt="github"))


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="NovaGuard experiment runner")
    parser.add_argument(
        "--mode",
        choices=["text-only", "urls-only", "full"],
        default="text-only",
    )
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--skip-ablation", action="store_true")
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    runner = ExperimentRunner()
    runner.run_full_experiment(
        mode=args.mode,
        limit=args.limit,
        dry_run=args.dry_run,
        skip_ablation=args.skip_ablation,
    )
