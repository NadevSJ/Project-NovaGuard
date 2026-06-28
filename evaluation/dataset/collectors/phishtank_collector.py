"""PhishTank verified-phishing collector.

Note:
    PhishTank distributes a free, frequently-updated feed of community-verified
    phishing URLs. Anonymous access to the JSON feed is rate-limited and may
    require registration in some cases. If `fetch()` returns an empty list with
    an HTTP error, fall back to downloading the database dump manually from
    https://phishtank.com/developer_info.php and pointing this collector at the
    local file (extend `fetch()` to accept a `local_path` if needed).
"""

from __future__ import annotations

import json
from typing import Any

import requests

_FEED_URL = "http://data.phishtank.com/data/online-valid.json"
_HEADERS = {"User-Agent": "NovaGuard-Research/1.0"}
_TIMEOUT = 30

_BANK_TOKENS = (
    "bank", "boc", "sampath", "commercial", "peoples", "nsb", "hnb",
    "seylan", "barclays", "hsbc", "chase", "wells fargo", "santander",
    "citibank", "lloyds",
)
_PAYMENT_TOKENS = ("paypal", "visa", "mastercard", "stripe", "venmo")


class PhishTankCollector:
    """Fetches verified phishing URLs from the PhishTank public feed."""

    def __init__(self, feed_url: str = _FEED_URL) -> None:
        self.feed_url = feed_url

    # --------------------------------------------------------------- fetch
    def fetch(
        self,
        limit: int = 50,
        target_filter: str | None = None,
    ) -> list[dict[str, Any]]:
        """Pull up to `limit` entries from PhishTank in NovaGuard sample format."""
        try:
            response = requests.get(self.feed_url, headers=_HEADERS, timeout=_TIMEOUT)
            response.raise_for_status()
            entries = response.json()
        except requests.exceptions.RequestException as exc:
            print(f"[PhishTankCollector] Network error fetching feed: {exc}")
            return []
        except json.JSONDecodeError as exc:
            print(f"[PhishTankCollector] Could not decode feed JSON: {exc}")
            return []
        except Exception as exc:  # pragma: no cover - defensive
            print(f"[PhishTankCollector] Unexpected error: {exc}")
            return []

        if not isinstance(entries, list):
            print("[PhishTankCollector] Unexpected feed shape (expected list).")
            return []

        samples: list[dict[str, Any]] = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            target = (entry.get("target") or "Unknown").strip() or "Unknown"
            if target_filter and target_filter.lower() not in target.lower():
                continue
            url = entry.get("url")
            if not isinstance(url, str) or not url.startswith(("http://", "https://")):
                continue

            phish_id = entry.get("phish_id")
            if phish_id is None:
                continue

            samples.append({
                "id": f"PT-{phish_id}",
                "input_type": "url",
                "input": url,
                "ground_truth_label": "SCAM",
                "ground_truth_score_range": [85, 100],
                "source": "PhishTank",
                "source_verified": entry.get("verified") == "yes",
                "target_brand": target,
                "requires_selenium": True,
                "category": self._categorize(target),
            })

            if len(samples) >= limit:
                break

        return samples

    # ----------------------------------------------------------- categorize
    @staticmethod
    def _categorize(target: str) -> str:
        t = (target or "").lower()
        if any(tok in t for tok in _BANK_TOKENS):
            return "fake_bank_url"
        if any(tok in t for tok in _PAYMENT_TOKENS):
            return "payment_phishing"
        return "generic_phishing"
