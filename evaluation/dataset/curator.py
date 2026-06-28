"""Dataset curation: combine, deduplicate, filter, balance, and save samples."""

from __future__ import annotations

import hashlib
import json
import os
import random
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from evaluation.dataset.collectors import (
    OpenPhishCollector,
    PhishTankCollector,
    UCISMSCollector,
    get_manual_samples,
)


class DatasetCurator:
    """Builds the NovaGuard ground-truth dataset from multiple sources."""

    def __init__(self) -> None:
        self.samples: list[dict[str, Any]] = []
        self.rejected: list[dict[str, Any]] = []
        self.source_counts: dict[str, int] = {}

    # -------------------------------------------------------- source loaders
    def add_from_phishtank(self, limit: int = 40) -> None:
        new = PhishTankCollector().fetch(limit=limit)
        self._extend("PhishTank", new)

    def add_from_openphish(self, limit: int = 25) -> None:
        new = OpenPhishCollector().fetch(limit=limit)
        self._extend("OpenPhish", new)

    def add_from_uci_sms(self, path: str, limit: int = 80) -> None:
        new = UCISMSCollector().load(path=path, limit=limit)
        self._extend("UCI-SMS-Spam-Collection", new)

    def add_manual_samples(self) -> None:
        new = get_manual_samples()
        self._extend("CERT.LK-manual", new)

    def _extend(self, source: str, new_samples: list[dict[str, Any]]) -> None:
        if not new_samples:
            print(f"[curator] No samples added from {source}.")
            self.source_counts.setdefault(source, 0)
            return
        self.samples.extend(new_samples)
        self.source_counts[source] = self.source_counts.get(source, 0) + len(new_samples)
        print(f"[curator] Added {len(new_samples)} samples from {source}.")

    # --------------------------------------------------------------- curation
    def deduplicate(self) -> None:
        before = len(self.samples)
        seen: set[str] = set()
        kept: list[dict[str, Any]] = []
        for sample in self.samples:
            text = (sample.get("input") or "").strip().lower()[:150]
            digest = hashlib.sha1(text.encode("utf-8")).hexdigest()
            if digest in seen:
                rejected = dict(sample)
                rejected["_rejection_reason"] = "duplicate"
                self.rejected.append(rejected)
                continue
            seen.add(digest)
            kept.append(sample)
        self.samples = kept
        print(f"[curator] Deduplicate: removed {before - len(kept)} duplicates.")

    def filter_quality(self) -> None:
        before = len(self.samples)
        kept: list[dict[str, Any]] = []
        for sample in self.samples:
            text = (sample.get("input") or "").strip()
            reason: str | None = None
            if len(text) < 15:
                reason = "too_short"
            elif len(text) > 3000:
                reason = "too_long"
            elif not any(ch.isalpha() for ch in text):
                reason = "no_semantic_content"
            if reason:
                rejected = dict(sample)
                rejected["_rejection_reason"] = reason
                self.rejected.append(rejected)
                continue
            kept.append(sample)
        self.samples = kept
        print(f"[curator] Quality filter: removed {before - len(kept)} samples.")

    def balance_classes(self, target_per_class: int = 25) -> None:
        before = Counter(s.get("ground_truth_label") for s in self.samples)
        rng = random.Random(42)

        per_label: dict[str, list[dict[str, Any]]] = {}
        for sample in self.samples:
            per_label.setdefault(sample.get("ground_truth_label", "UNKNOWN"), []).append(sample)

        balanced: list[dict[str, Any]] = []
        for label, group in per_label.items():
            if len(group) > target_per_class:
                rng.shuffle(group)
                kept = group[:target_per_class]
                dropped = group[target_per_class:]
                for d in dropped:
                    rd = dict(d)
                    rd["_rejection_reason"] = "balance_downsample"
                    self.rejected.append(rd)
                balanced.extend(kept)
            else:
                if len(group) < 10:
                    print(
                        f"[curator] WARNING: label '{label}' has only "
                        f"{len(group)} samples (below the 10-sample floor)."
                    )
                balanced.extend(group)

        self.samples = balanced
        after = Counter(s.get("ground_truth_label") for s in self.samples)
        print(f"[curator] Balance — before: {dict(before)} | after: {dict(after)}")

    def assign_final_ids(self) -> None:
        for index, sample in enumerate(self.samples, start=1):
            sample["source_id"] = sample.get("id")
            sample["id"] = f"REAL-{index:04d}"

    # ------------------------------------------------------------ statistics
    def get_statistics(self) -> dict[str, Any]:
        by_label = Counter(s.get("ground_truth_label") for s in self.samples)
        by_type = Counter(s.get("input_type") for s in self.samples)
        by_category = Counter(s.get("category") for s in self.samples)
        by_source = Counter(s.get("source") for s in self.samples)
        return {
            "total": len(self.samples),
            "by_label": dict(by_label),
            "by_type": dict(by_type),
            "by_category": dict(by_category),
            "by_source": dict(by_source),
            "url_samples_count": by_type.get("url", 0),
            "text_samples_count": by_type.get("text", 0),
            "requires_selenium_count": sum(
                1 for s in self.samples if s.get("requires_selenium")
            ),
            "rejected_count": len(self.rejected),
        }

    # ------------------------------------------------------------- save / build
    def save(self, path: str = "evaluation/dataset/ground_truth.json") -> str:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        by_label = Counter(s.get("ground_truth_label") for s in self.samples)
        by_type = Counter(s.get("input_type") for s in self.samples)
        sources = sorted({s.get("source") for s in self.samples if s.get("source")})

        payload = {
            "metadata": {
                "dataset_name": "NovaGuard Ground Truth",
                "version": "1.0",
                "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "description": (
                    "Combined ground-truth dataset for evaluating NovaGuard. "
                    "Aggregates verified phishing URLs (PhishTank, OpenPhish), "
                    "the UCI SMS Spam Collection, and manually curated Sri "
                    "Lankan samples derived from CERT.LK advisories."
                ),
                "total_samples": len(self.samples),
                "label_distribution": dict(by_label),
                "type_distribution": dict(by_type),
                "source_list": sources,
                "curation_notes": (
                    "Curation: sha1 dedup on first 150 chars; quality filter "
                    "(15 <= len(input) <= 3000, must contain alphabetic chars); "
                    "class balancing with seed=42; IDs reassigned as REAL-####."
                ),
            },
            "samples": self.samples,
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        print(f"[curator] Saved {len(self.samples)} samples to {path}")
        return os.path.abspath(path)

    def build_full_dataset(self, uci_path: str | None = None) -> dict[str, Any]:
        """Master pipeline: fetch (if not pre-populated), curate, save, report."""
        if not self.samples:
            self.add_from_phishtank(limit=40)
            self.add_from_openphish(limit=25)
            if uci_path and Path(uci_path).exists():
                self.add_from_uci_sms(uci_path, limit=80)
            self.add_manual_samples()

        self.deduplicate()
        self.filter_quality()
        self.balance_classes(target_per_class=25)
        self.assign_final_ids()
        self.save()
        return self.get_statistics()
