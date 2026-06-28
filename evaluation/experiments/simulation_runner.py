"""Simulation runner.

Drives a callable analyzer (NovaGuard agent, baseline, ablation variant)
over a fixed dataset, captures per-sample results, supports a dry-run mode
that returns deterministic mock responses, and writes timestamped JSON / CSV
artifacts under `results/`.
"""

from __future__ import annotations

import csv
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import pandas as pd
from tqdm import tqdm

from config import Config
from evaluation.metrics.scorer import NovaGuardScorer


class SimulationRunner:
    """Runs a system on a ground-truth dataset and records per-sample results."""

    def __init__(
        self,
        dataset_path: str = Config.DATASET_PATH,
        results_dir: str = Config.RESULTS_DIR,
    ) -> None:
        self.dataset_path = dataset_path
        self.results_dir = Path(results_dir)
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.scorer = NovaGuardScorer()

    # ----------------------------------------------------------- dataset
    def load_dataset(self) -> list[dict[str, Any]]:
        path = Path(self.dataset_path)
        if not path.exists():
            raise FileNotFoundError(
                f"Ground-truth dataset not found at {path}. "
                "Run `python run_data_collection.py` first."
            )
        with open(path, "r", encoding="utf-8") as f:
            payload = json.load(f)
        samples = payload.get("samples") if isinstance(payload, dict) else payload
        if not isinstance(samples, list):
            raise ValueError(f"Dataset {path} does not contain a 'samples' list.")
        return samples

    def filter_samples(
        self,
        samples: list[dict[str, Any]],
        mode: str = "text-only",
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        if mode == "text-only":
            filtered = [s for s in samples if s.get("input_type") == "text"]
        elif mode == "urls-only":
            filtered = [s for s in samples if s.get("input_type") == "url"]
        elif mode == "full":
            filtered = list(samples)
        else:
            raise ValueError(f"Unknown mode: {mode}")
        if limit is not None:
            filtered = filtered[:limit]
        return filtered

    # ----------------------------------------------------------- run agent
    def run_agent(
        self,
        analyzer: Callable[[str], dict[str, Any]],
        samples: list[dict[str, Any]],
        system_name: str = "NovaGuardAgent",
        dry_run: bool = False,
        desc: str | None = None,
    ) -> list[dict[str, Any]]:
        """Run `analyzer(input_text) -> result_dict` over `samples`."""
        results: list[dict[str, Any]] = []
        bar_desc = desc or system_name
        for sample in tqdm(samples, desc=bar_desc, unit="sample"):
            ground_truth = self._copy_ground_truth(sample)

            if dry_run:
                outcome = self._mock_outcome(sample)
            else:
                try:
                    outcome = analyzer(sample.get("input", "")) or {}
                except Exception as exc:
                    outcome = {
                        "predicted_label": "SUSPICIOUS",
                        "predicted_score": 50,
                        "latency_seconds": 0.0,
                        "error": str(exc),
                    }

            scored = self.scorer.score_prediction(
                predicted_label=outcome.get("predicted_label") or "SUSPICIOUS",
                predicted_score=int(outcome.get("predicted_score") or 50),
                ground_truth_label=sample.get("ground_truth_label", ""),
                ground_truth_score_range=sample.get("ground_truth_score_range"),
            )

            record = {
                **ground_truth,
                "system_name": system_name,
                "predicted_label": outcome.get("predicted_label"),
                "predicted_score": outcome.get("predicted_score"),
                "latency_seconds": outcome.get("latency_seconds", 0.0),
                "response": outcome.get("response", outcome.get("raw_response", "")),
                "reason": outcome.get("reason"),
                **scored,
            }
            if "error" in outcome:
                record["error"] = outcome["error"]
            results.append(record)
        return results

    # ----------------------------------------------------------- comparison
    def run_comparison(
        self,
        systems: dict[str, Callable[[str], dict[str, Any]]],
        samples: list[dict[str, Any]],
        dry_run: bool = False,
    ) -> dict[str, list[dict[str, Any]]]:
        comparison: dict[str, list[dict[str, Any]]] = {}
        for name, analyzer in systems.items():
            print(f"\n[runner] System: {name}  ({len(samples)} samples)")
            comparison[name] = self.run_agent(
                analyzer=analyzer,
                samples=samples,
                system_name=name,
                dry_run=dry_run,
                desc=name,
            )
        return comparison

    @staticmethod
    def generate_comparison_dataframe(
        comparison_results: dict[str, list[dict[str, Any]]],
    ) -> pd.DataFrame:
        rows: dict[str, dict[str, Any]] = {}
        for system_name, results in comparison_results.items():
            for r in results:
                sid = r.get("sample_id")
                row = rows.setdefault(sid, {
                    "sample_id": sid,
                    "category": r.get("category"),
                    "ground_truth_label": r.get("ground_truth_label"),
                })
                row[f"{system_name}_predicted_label"] = r.get("predicted_label")
                row[f"{system_name}_correct"] = bool(r.get("label_correct"))
                row[f"{system_name}_latency"] = r.get("latency_seconds")
        df = pd.DataFrame(list(rows.values()))
        return df.sort_values("sample_id").reset_index(drop=True) if not df.empty else df

    # ----------------------------------------------------------- save
    def save_results(
        self,
        results: list[dict[str, Any]],
        system_name: str,
        suffix: str = "",
    ) -> dict[str, str]:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        slug = system_name.replace(" ", "_").lower()
        tag = f"_{suffix}" if suffix else ""
        json_path = self.results_dir / f"{slug}{tag}_{timestamp}.json"
        csv_path = self.results_dir / f"{slug}{tag}_{timestamp}.csv"

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "system_name": system_name,
                    "timestamp": timestamp,
                    "n_results": len(results),
                    "results": results,
                },
                f,
                ensure_ascii=False,
                indent=2,
            )

        if results:
            fieldnames = sorted({k for r in results for k in r.keys()})
            with open(csv_path, "w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for r in results:
                    writer.writerow({k: r.get(k, "") for k in fieldnames})

        return {"json": str(json_path), "csv": str(csv_path)}

    # ----------------------------------------------------------- internals
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
    def _mock_outcome(sample: dict[str, Any]) -> dict[str, Any]:
        """Deterministic mock that lets the pipeline run without LLM calls."""
        gt = (sample.get("ground_truth_label") or "SUSPICIOUS").upper()
        rng = sample.get("ground_truth_score_range") or [40, 60]
        score = int((rng[0] + rng[1]) / 2)
        time.sleep(0.01)
        return {
            "predicted_label": gt,
            "predicted_score": score,
            "latency_seconds": 0.01,
            "response": f"[DRY-RUN] mocked verdict {gt} score {score}",
        }
