"""UCI SMS Spam Collection loader.

Dataset source: https://archive.ics.uci.edu/dataset/228

Download the CSV (typically named `spam.csv`) and place it at
`evaluation/dataset/raw/spam.csv` before running this collector.
"""

from __future__ import annotations

import os
from typing import Any

import pandas as pd

_FINANCIAL_KEYWORDS = (
    "bank", "account", "pin", "otp", "verify", "credit card",
    "atm", "password", "suspended", "blocked", "urgent action",
)
_PRIZE_KEYWORDS = (
    "won", "winner", "prize", "claim", "selected", "lucky",
    "congratulations", "award", "gift",
)
_COMMERCIAL_KEYWORDS = (
    "free", "offer offer", "deal", "discount", "limited time",
)


class UCISMSCollector:
    """Loads the UCI SMS Spam Collection and maps rows to NovaGuard samples."""

    @staticmethod
    def check_file_exists(path: str) -> bool:
        if os.path.isfile(path):
            return True
        print(
            f"[UCISMSCollector] File not found at '{path}'.\n"
            "  Download the SMS Spam Collection from "
            "https://archive.ics.uci.edu/dataset/228 and place 'spam.csv' there.\n"
            "  The CSV is expected to have columns v1 (ham/spam) and v2 (message)."
        )
        return False

    def load(
        self,
        path: str = "evaluation/dataset/raw/spam.csv",
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        if not self.check_file_exists(path):
            return []

        try:
            df = pd.read_csv(path, encoding="latin-1")
        except UnicodeDecodeError:
            df = pd.read_csv(path)
        except Exception as exc:
            print(f"[UCISMSCollector] Failed to read CSV: {exc}")
            return []

        if "v1" not in df.columns or "v2" not in df.columns:
            possible_label = next(
                (c for c in df.columns if df[c].astype(str).str.lower().isin(["ham", "spam"]).any()),
                None,
            )
            possible_text = next(
                (c for c in df.columns if c != possible_label and df[c].dtype == object),
                None,
            )
            if possible_label and possible_text:
                df = df.rename(columns={possible_label: "v1", possible_text: "v2"})
            else:
                print("[UCISMSCollector] CSV does not contain expected v1/v2 columns.")
                return []

        df = df[["v1", "v2"]].dropna()
        df["v1"] = df["v1"].astype(str).str.strip().str.lower()
        df["v2"] = df["v2"].astype(str).str.strip()
        df = df[df["v2"].str.len() > 0]

        samples: list[dict[str, Any]] = []
        for index, row in df.iterrows():
            if len(samples) >= limit:
                break

            label_in, message = row["v1"], row["v2"]
            mapped = self._classify(label_in, message)
            if mapped is None:
                continue

            sample = {
                "id": f"UCI-{int(index):05d}",
                "input_type": "text",
                "input": message,
                "ground_truth_label": mapped["label"],
                "ground_truth_score_range": mapped["score_range"],
                "source": "UCI-SMS-Spam-Collection",
                "source_verified": True,
                "requires_selenium": False,
                "category": mapped["category"],
                "original_label": label_in,
            }
            samples.append(sample)

        return samples

    @staticmethod
    def _classify(label_in: str, message: str) -> dict[str, Any] | None:
        if label_in == "ham":
            return {
                "label": "SAFE",
                "score_range": [0, 20],
                "category": "legitimate_sms",
            }
        if label_in != "spam":
            return None

        msg_lower = message.lower()
        if any(kw in msg_lower for kw in _FINANCIAL_KEYWORDS):
            return {
                "label": "SCAM",
                "score_range": [80, 100],
                "category": "financial_scam_sms",
            }
        if any(kw in msg_lower for kw in _PRIZE_KEYWORDS):
            return {
                "label": "SCAM",
                "score_range": [75, 95],
                "category": "lottery_scam_sms",
            }
        if any(kw in msg_lower for kw in _COMMERCIAL_KEYWORDS):
            return {
                "label": "SUSPICIOUS",
                "score_range": [40, 65],
                "category": "commercial_spam",
            }
        return {
            "label": "SUSPICIOUS",
            "score_range": [35, 60],
            "category": "general_spam",
        }
