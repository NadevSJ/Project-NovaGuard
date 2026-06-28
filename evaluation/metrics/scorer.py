"""NovaGuard scoring & metrics.

Parses NovaGuard markdown reports, computes classification / regression /
latency / cost metrics, and assembles a full evaluation report.
"""

from __future__ import annotations

import re
import statistics
from datetime import datetime, timezone
from typing import Any, Sequence

import numpy as np
from scipy.stats import pearsonr
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    cohen_kappa_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

LABELS_ORDER: list[str] = ["SAFE", "LIKELY_SAFE", "SUSPICIOUS", "SCAM"]
_LABEL_INDEX: dict[str, int] = {lbl: i for i, lbl in enumerate(LABELS_ORDER)}

# Gemini Flash pricing (USD / 1M tokens) and per-query token estimates.
_PRICE_PER_M_INPUT_USD = 0.075
_PRICE_PER_M_OUTPUT_USD = 0.30
_AVG_INPUT_TOKENS = 800
_AVG_OUTPUT_TOKENS = 300

_VERDICT_RE = re.compile(
    r"\*\*\s*Verdict\s*:\s*\*\*\s*\[?\s*(SCAM|SUSPICIOUS|LIKELY[_ ]SAFE|SAFE)",
    re.IGNORECASE,
)
_SCORE_RE = re.compile(
    r"\*\*\s*Risk Score\s*:\s*\*\*\s*\[?\s*(\d{1,3})", re.IGNORECASE
)
_INPUT_TYPE_RE = re.compile(
    r"\*\*\s*Input Type\s*:\s*\*\*\s*\[?\s*(URL|Text Message|TEXT)",
    re.IGNORECASE,
)
_EVIDENCE_BLOCK_RE = re.compile(
    r"\*\*\s*Evidence Found\s*:\s*\*\*\s*(.+?)(?=\n\s*\*\*|\Z)",
    re.IGNORECASE | re.DOTALL,
)
_RECOMMENDATION_BLOCK_RE = re.compile(
    r"\*\*\s*Recommended Action\s*:\s*\*\*\s*(.+?)(?=\n\s*\*\*|\n---|\Z)",
    re.IGNORECASE | re.DOTALL,
)


class NovaGuardScorer:
    """Parses NovaGuard reports and computes evaluation metrics."""

    # ------------------------------------------------------------- parsing
    @staticmethod
    def parse_agent_response(response: str) -> dict[str, Any]:
        response = response or ""

        verdict_match = _VERDICT_RE.search(response)
        predicted_label = "SUSPICIOUS"
        if verdict_match:
            raw = verdict_match.group(1).upper().replace(" ", "_")
            if raw in _LABEL_INDEX:
                predicted_label = raw

        score_match = _SCORE_RE.search(response)
        predicted_score = 50
        if score_match:
            try:
                value = int(score_match.group(1))
                predicted_score = max(0, min(100, value))
            except ValueError:
                pass

        evidence_items: list[str] = []
        block_match = _EVIDENCE_BLOCK_RE.search(response)
        if block_match:
            block = block_match.group(1)
            for line in block.splitlines():
                line = line.strip()
                if line.startswith(("-", "*", "•")):
                    item = line.lstrip("-*• ").strip()
                    if item:
                        evidence_items.append(item)

        rec_match = _RECOMMENDATION_BLOCK_RE.search(response)
        has_recommendation = bool(rec_match and rec_match.group(1).strip())

        input_type_detected = "unknown"
        itm = _INPUT_TYPE_RE.search(response)
        if itm:
            value = itm.group(1).lower()
            input_type_detected = "url" if value == "url" else "text"

        return {
            "predicted_label": predicted_label,
            "predicted_score": predicted_score,
            "evidence_items": evidence_items,
            "evidence_count": len(evidence_items),
            "has_recommendation": has_recommendation,
            "response_length": len(response),
            "input_type_detected": input_type_detected,
        }

    # --------------------------------------------------------- per-sample
    @staticmethod
    def score_prediction(
        predicted_label: str,
        predicted_score: int,
        ground_truth_label: str,
        ground_truth_score_range: Sequence[int] | None,
    ) -> dict[str, Any]:
        pred = (predicted_label or "SUSPICIOUS").upper()
        gt = (ground_truth_label or "").upper()
        label_correct = pred == gt

        score_in_range = False
        if ground_truth_score_range and len(ground_truth_score_range) == 2:
            low, high = ground_truth_score_range
            score_in_range = low <= predicted_score <= high

        is_missed_scam = gt == "SCAM" and pred in {"SAFE", "LIKELY_SAFE"}
        is_false_alarm = gt == "SAFE" and pred == "SCAM"

        gt_idx = _LABEL_INDEX.get(gt, _LABEL_INDEX["SUSPICIOUS"])
        pred_idx = _LABEL_INDEX.get(pred, _LABEL_INDEX["SUSPICIOUS"])
        severity_error = abs(pred_idx - gt_idx)

        return {
            "label_correct": label_correct,
            "score_in_range": score_in_range,
            "is_missed_scam": is_missed_scam,
            "is_false_alarm": is_false_alarm,
            "severity_error": severity_error,
        }

    # --------------------------------------------------- classification metrics
    @staticmethod
    def calculate_classification_metrics(
        results: list[dict[str, Any]],
    ) -> dict[str, Any]:
        if not results:
            return {"n": 0, "warning": "no results"}

        y_true = [str(r.get("ground_truth_label", "")).upper() for r in results]
        y_pred = [str(r.get("predicted_label", "")).upper() for r in results]

        per_class_precision = precision_score(
            y_true, y_pred, labels=LABELS_ORDER, average=None, zero_division=0
        )
        per_class_recall = recall_score(
            y_true, y_pred, labels=LABELS_ORDER, average=None, zero_division=0
        )
        per_class_f1 = f1_score(
            y_true, y_pred, labels=LABELS_ORDER, average=None, zero_division=0
        )

        cm = confusion_matrix(y_true, y_pred, labels=LABELS_ORDER).tolist()

        total_scams = sum(1 for y in y_true if y == "SCAM")
        missed_scams = sum(
            1
            for y, p in zip(y_true, y_pred)
            if y == "SCAM" and p in {"SAFE", "LIKELY_SAFE"}
        )
        total_safes = sum(1 for y in y_true if y == "SAFE")
        false_alarms = sum(
            1 for y, p in zip(y_true, y_pred) if y == "SAFE" and p == "SCAM"
        )
        false_negative_rate = (missed_scams / total_scams) if total_scams else 0.0
        false_positive_rate = (false_alarms / total_safes) if total_safes else 0.0
        scam_detection_rate = 1.0 - false_negative_rate

        return {
            "n": len(results),
            "labels": LABELS_ORDER,
            "accuracy": float(accuracy_score(y_true, y_pred)),
            "precision_macro": float(
                precision_score(y_true, y_pred, labels=LABELS_ORDER, average="macro", zero_division=0)
            ),
            "precision_weighted": float(
                precision_score(y_true, y_pred, labels=LABELS_ORDER, average="weighted", zero_division=0)
            ),
            "recall_macro": float(
                recall_score(y_true, y_pred, labels=LABELS_ORDER, average="macro", zero_division=0)
            ),
            "recall_weighted": float(
                recall_score(y_true, y_pred, labels=LABELS_ORDER, average="weighted", zero_division=0)
            ),
            "f1_macro": float(
                f1_score(y_true, y_pred, labels=LABELS_ORDER, average="macro", zero_division=0)
            ),
            "f1_weighted": float(
                f1_score(y_true, y_pred, labels=LABELS_ORDER, average="weighted", zero_division=0)
            ),
            "per_class": {
                lbl: {
                    "precision": float(per_class_precision[i]),
                    "recall": float(per_class_recall[i]),
                    "f1": float(per_class_f1[i]),
                }
                for i, lbl in enumerate(LABELS_ORDER)
            },
            "confusion_matrix": cm,
            "classification_report": classification_report(
                y_true, y_pred, labels=LABELS_ORDER, zero_division=0
            ),
            "total_scams": total_scams,
            "missed_scams": missed_scams,
            "total_safes": total_safes,
            "false_alarms": false_alarms,
            "false_negative_rate": round(false_negative_rate, 4),
            "false_positive_rate": round(false_positive_rate, 4),
            "scam_detection_rate": round(scam_detection_rate, 4),
        }

    # ----------------------------------------------------- score regression
    @staticmethod
    def calculate_score_metrics(results: list[dict[str, Any]]) -> dict[str, Any]:
        preds: list[float] = []
        midpoints: list[float] = []
        out_of_range = 0
        scored_with_range = 0

        for r in results:
            try:
                score = float(r.get("predicted_score"))
            except (TypeError, ValueError):
                continue
            rng = r.get("ground_truth_score_range")
            if isinstance(rng, (list, tuple)) and len(rng) == 2:
                low, high = float(rng[0]), float(rng[1])
                midpoint = (low + high) / 2.0
                preds.append(score)
                midpoints.append(midpoint)
                scored_with_range += 1
                if not (low <= score <= high):
                    out_of_range += 1

        if not preds:
            return {
                "n_scored": 0,
                "mean_absolute_error": None,
                "pearson_correlation": None,
                "score_calibration_error": None,
            }

        mae = float(np.mean(np.abs(np.array(preds) - np.array(midpoints))))
        try:
            corr, _ = pearsonr(preds, midpoints)
            corr = float(corr) if not np.isnan(corr) else None
        except Exception:
            corr = None

        calibration_error = (
            out_of_range / scored_with_range if scored_with_range else None
        )

        return {
            "n_scored": len(preds),
            "mean_absolute_error": round(mae, 4),
            "pearson_correlation": (round(corr, 4) if corr is not None else None),
            "score_calibration_error": (
                round(calibration_error, 4)
                if calibration_error is not None
                else None
            ),
        }

    # ----------------------------------------------------- latency
    @staticmethod
    def calculate_latency_metrics(latency_list: Sequence[float]) -> dict[str, Any]:
        values = [float(v) for v in latency_list if v is not None]
        if not values:
            return {"n": 0}

        arr = np.array(values, dtype=float)
        return {
            "n": len(values),
            "mean": round(float(np.mean(arr)), 3),
            "median": round(float(np.median(arr)), 3),
            "p90": round(float(np.percentile(arr, 90)), 3),
            "p95": round(float(np.percentile(arr, 95)), 3),
            "p99": round(float(np.percentile(arr, 99)), 3),
            "min": round(float(np.min(arr)), 3),
            "max": round(float(np.max(arr)), 3),
            "std_dev": round(
                float(statistics.pstdev(values)) if len(values) > 1 else 0.0, 3
            ),
        }

    # ----------------------------------------------------- cost estimate
    @staticmethod
    def calculate_cost_estimate(results: list[dict[str, Any]]) -> dict[str, Any]:
        n = len(results)
        per_query = (
            _AVG_INPUT_TOKENS * _PRICE_PER_M_INPUT_USD
            + _AVG_OUTPUT_TOKENS * _PRICE_PER_M_OUTPUT_USD
        ) / 1_000_000
        return {
            "assumed_avg_input_tokens": _AVG_INPUT_TOKENS,
            "assumed_avg_output_tokens": _AVG_OUTPUT_TOKENS,
            "cost_per_query_usd": round(per_query, 6),
            "estimated_total_cost_usd": round(per_query * n, 6),
            "projected_1000_queries_usd": round(per_query * 1_000, 4),
            "projected_10000_queries_usd": round(per_query * 10_000, 4),
        }

    # ----------------------------------------------------- kappa
    @staticmethod
    def cohen_kappa(results: list[dict[str, Any]]) -> float:
        y_true = [str(r.get("ground_truth_label", "")).upper() for r in results]
        y_pred = [str(r.get("predicted_label", "")).upper() for r in results]
        if len(y_true) < 2 or len(set(y_true) | set(y_pred)) < 2:
            return float("nan")
        return float(cohen_kappa_score(y_true, y_pred, labels=LABELS_ORDER))

    # ----------------------------------------------------- full report
    def full_evaluation_report(
        self,
        results: list[dict[str, Any]],
        latency_list: Sequence[float],
        system_name: str,
    ) -> dict[str, Any]:
        kappa = self.cohen_kappa(results)
        return {
            "system_name": system_name,
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "sample_count": len(results),
            "classification": self.calculate_classification_metrics(results),
            "score_metrics": self.calculate_score_metrics(results),
            "latency": self.calculate_latency_metrics(latency_list),
            "cost": self.calculate_cost_estimate(results),
            "cohen_kappa": (None if np.isnan(kappa) else round(kappa, 4)),
        }
