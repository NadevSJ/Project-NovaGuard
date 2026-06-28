"""Annotation tooling: create tasks, load completed annotations, and
compute inter-annotator agreement (Cohen's kappa)."""

from __future__ import annotations

import json
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sklearn.metrics import cohen_kappa_score

from config import Config

_VALID_LABELS = ["SCAM", "SUSPICIOUS", "LIKELY_SAFE", "SAFE"]


class AnnotationManager:
    """Manage human (and optional LLM tie-break) annotation workflow."""

    # --------------------------------------------------- create / load tasks
    def create_annotation_task(
        self,
        samples: list[dict[str, Any]],
        annotator_name: str,
        output_path: str,
    ) -> str:
        """Write an annotation task JSON, stripping ground-truth labels."""
        task_items: list[dict[str, Any]] = []
        for sample in samples:
            task_items.append({
                "id": sample.get("id"),
                "input_type": sample.get("input_type"),
                "input": sample.get("input"),
                "category_hint": sample.get("category"),
                "annotator_label": None,
                "annotator_score": None,
                "annotator_notes": "",
            })

        payload = {
            "metadata": {
                "annotator_name": annotator_name,
                "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "label_options": _VALID_LABELS,
                "score_bands": {
                    "SCAM": [75, 100],
                    "SUSPICIOUS": [40, 74],
                    "LIKELY_SAFE": [15, 39],
                    "SAFE": [0, 14],
                },
                "instructions": (
                    "Fill in annotator_label (one of label_options), "
                    "annotator_score (integer in the matching band), and "
                    "optional annotator_notes. See annotation/guidelines.md."
                ),
            },
            "items": task_items,
        }

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        return os.path.abspath(output_path)

    def load_annotations(self, path: str) -> list[dict[str, Any]]:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        items = data.get("items") if isinstance(data, dict) else data
        if not isinstance(items, list):
            raise ValueError(f"Annotation file '{path}' has no 'items' list.")
        return items

    # --------------------------------------------------- agreement
    def compute_agreement(
        self,
        annotation_file_1: str,
        annotation_file_2: str,
    ) -> dict[str, Any]:
        items1 = self.load_annotations(annotation_file_1)
        items2 = self.load_annotations(annotation_file_2)

        by_id_1 = {it["id"]: it for it in items1 if it.get("annotator_label")}
        by_id_2 = {it["id"]: it for it in items2 if it.get("annotator_label")}
        shared_ids = sorted(set(by_id_1) & set(by_id_2))

        labels_1: list[str] = []
        labels_2: list[str] = []
        disagreements: list[dict[str, Any]] = []
        confusion: Counter[tuple[str, str]] = Counter()

        for sid in shared_ids:
            l1 = str(by_id_1[sid]["annotator_label"]).upper()
            l2 = str(by_id_2[sid]["annotator_label"]).upper()
            labels_1.append(l1)
            labels_2.append(l2)
            if l1 != l2:
                disagreements.append({
                    "id": sid,
                    "ann1_label": l1,
                    "ann2_label": l2,
                    "input_preview": (by_id_1[sid].get("input") or "")[:120],
                })
            confusion[(l1, l2)] += 1

        agreements = sum(1 for a, b in zip(labels_1, labels_2) if a == b)
        n = len(shared_ids)
        percent_agreement = (agreements / n) if n else 0.0

        if n >= 2 and len(set(labels_1) | set(labels_2)) >= 2:
            kappa = float(cohen_kappa_score(labels_1, labels_2, labels=_VALID_LABELS))
        else:
            kappa = float("nan")

        return {
            "n_shared": n,
            "cohen_kappa": kappa,
            "percent_agreement": round(percent_agreement, 4),
            "confusion": {f"{a}->{b}": c for (a, b), c in confusion.items()},
            "disagreements": disagreements,
            "annotator_1_file": os.path.abspath(annotation_file_1),
            "annotator_2_file": os.path.abspath(annotation_file_2),
        }

    # --------------------------------------------------- adjudication
    def adjudicate(
        self,
        annotation_file_1: str,
        annotation_file_2: str,
        output_path: str,
        use_gemini_tiebreak: bool = True,
    ) -> dict[str, Any]:
        items1 = self.load_annotations(annotation_file_1)
        items2 = self.load_annotations(annotation_file_2)

        by_id_2 = {it["id"]: it for it in items2}

        agreed: list[dict[str, Any]] = []
        disputes: list[dict[str, Any]] = []
        for it1 in items1:
            sid = it1.get("id")
            if sid is None or sid not in by_id_2:
                continue
            it2 = by_id_2[sid]
            l1 = (it1.get("annotator_label") or "").upper()
            l2 = (it2.get("annotator_label") or "").upper()
            if not l1 or not l2:
                continue

            if l1 == l2:
                agreed.append({
                    "id": sid,
                    "input": it1.get("input"),
                    "final_label": l1,
                    "final_score": self._avg_score(it1, it2),
                    "resolution": "agreement",
                })
                continue

            tiebreak: dict[str, Any] | None = None
            if use_gemini_tiebreak and self._tiebreak_credentials_present():
                tiebreak = self._gemini_tiebreak(it1.get("input") or "", (l1, l2))

            disputes.append({
                "id": sid,
                "input": it1.get("input"),
                "ann1": {"label": l1, "score": it1.get("annotator_score")},
                "ann2": {"label": l2, "score": it2.get("annotator_score")},
                "gemini_tiebreak": tiebreak,
                "final_label": (tiebreak or {}).get("label"),
                "final_score": (tiebreak or {}).get("score"),
                "resolution": (
                    "gemini_tiebreak" if tiebreak else "needs_human_adjudication"
                ),
            })

        payload = {
            "metadata": {
                "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "n_agreed": len(agreed),
                "n_disputed": len(disputes),
                "gemini_tiebreak_enabled": bool(
                    use_gemini_tiebreak and self._tiebreak_credentials_present()
                ),
            },
            "agreed": agreed,
            "disputes": disputes,
        }
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        return payload

    # --------------------------------------------------- helpers
    @staticmethod
    def _tiebreak_credentials_present() -> bool:
        if Config.LLM_PROVIDER == "sambanova":
            return bool(Config.SAMBANOVA_API_KEY)
        return bool(Config.GOOGLE_API_KEY)

    @staticmethod
    def _avg_score(it1: dict[str, Any], it2: dict[str, Any]) -> int | None:
        s1, s2 = it1.get("annotator_score"), it2.get("annotator_score")
        if isinstance(s1, (int, float)) and isinstance(s2, (int, float)):
            return int(round((s1 + s2) / 2))
        if isinstance(s1, (int, float)):
            return int(s1)
        if isinstance(s2, (int, float)):
            return int(s2)
        return None

    @staticmethod
    def _gemini_tiebreak(
        input_text: str,
        candidate_labels: tuple[str, str],
    ) -> dict[str, Any] | None:
        """Use the active LLM (SambaNova or Gemini) as a third annotator.

        The method name is kept for backwards compatibility; the actual
        model is chosen by `Config.LLM_PROVIDER`.
        """
        try:
            from agent.llm_factory import build_llm
        except ImportError:
            return None
        try:
            llm = build_llm(temperature=0.0)
        except Exception:
            return None
        try:
            prompt = (
                "You are adjudicating an annotation disagreement for a Sri-Lankan "
                "scam-detection dataset.\n"
                f"Two annotators chose: {candidate_labels[0]} vs {candidate_labels[1]}.\n"
                "Choose the single correct label from: SCAM, SUSPICIOUS, LIKELY_SAFE, SAFE.\n"
                "Also give an integer risk score: SCAM 75-100, SUSPICIOUS 40-74, "
                "LIKELY_SAFE 15-39, SAFE 0-14.\n"
                "Respond as JSON only: {\"label\": ..., \"score\": ..., \"reason\": ...}.\n\n"
                f"Input:\n{input_text}"
            )
            response = llm.invoke(prompt)
            text = (getattr(response, "content", "") or "").strip()
            start = text.find("{")
            end = text.rfind("}")
            if start == -1 or end == -1 or end <= start:
                return None
            parsed = json.loads(text[start : end + 1])
            label = str(parsed.get("label", "")).upper().replace(" ", "_")
            if label not in _VALID_LABELS:
                return None
            score = parsed.get("score")
            if not isinstance(score, (int, float)):
                return None
            return {
                "label": label,
                "score": int(score),
                "reason": parsed.get("reason", "")[:300],
            }
        except Exception as exc:
            print(f"[annotator] Gemini tiebreak failed: {exc}")
            return None
