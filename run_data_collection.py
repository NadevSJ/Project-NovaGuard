"""NovaGuard dataset builder.

Run from the project root:

    python run_data_collection.py

Fetches verified phishing URLs from PhishTank and OpenPhish, loads the UCI
SMS Spam Collection (if present), and adds manually curated Sri Lankan
samples; then deduplicates, filters, balances, and writes
`evaluation/dataset/ground_truth.json`.
"""

from __future__ import annotations

import json
from pathlib import Path

from evaluation.dataset.curator import DatasetCurator


def main() -> None:
    banner = "=" * 60
    print(banner)
    print("NovaGuard Dataset Builder".center(60))
    print(banner)

    curator = DatasetCurator()

    print("\n[1/4] Fetching from PhishTank...")
    curator.add_from_phishtank(limit=40)

    print("\n[2/4] Fetching from OpenPhish...")
    curator.add_from_openphish(limit=25)

    uci_path = "evaluation/dataset/raw/spam.csv"
    print(f"\n[3/4] Loading UCI SMS dataset from {uci_path}...")
    if Path(uci_path).exists():
        curator.add_from_uci_sms(uci_path, limit=80)
    else:
        print(f"  UCI dataset not found at {uci_path}")
        print("  Download from: https://archive.ics.uci.edu/dataset/228")
        print("  Then re-run this script to include UCI SMS samples.")

    print("\n[4/4] Adding manual Sri Lankan samples...")
    curator.add_manual_samples()

    print("\nCurating (deduplicate, quality filter, balance, save)...")
    stats = curator.build_full_dataset(uci_path)

    print("\nDataset Statistics:")
    print(json.dumps(stats, indent=2))
    print("\nRun next: python -m evaluation.experiments.experiment_runner")


if __name__ == "__main__":
    main()
