"""OpenPhish plain-text feed collector."""

from __future__ import annotations

from typing import Any

import requests

_FEED_URL = "https://openphish.com/feed.txt"
_HEADERS = {"User-Agent": "NovaGuard-Research/1.0"}
_TIMEOUT = 30


class OpenPhishCollector:
    """Fetches phishing URLs from the OpenPhish free feed (one URL per line)."""

    def __init__(self, feed_url: str = _FEED_URL) -> None:
        self.feed_url = feed_url

    def fetch(self, limit: int = 30) -> list[dict[str, Any]]:
        """Return up to `limit` phishing URLs in NovaGuard sample format."""
        try:
            response = requests.get(self.feed_url, headers=_HEADERS, timeout=_TIMEOUT)
            response.raise_for_status()
            body = response.text or ""
        except requests.exceptions.RequestException as exc:
            print(f"[OpenPhishCollector] Network error fetching feed: {exc}")
            return []
        except Exception as exc:  # pragma: no cover - defensive
            print(f"[OpenPhishCollector] Unexpected error: {exc}")
            return []

        samples: list[dict[str, Any]] = []
        index = 0
        for raw_line in body.splitlines():
            url = raw_line.strip()
            if not url:
                continue
            if not url.lower().startswith(("http://", "https://")):
                continue

            samples.append({
                "id": f"OP-{index:04d}",
                "input_type": "url",
                "input": url,
                "ground_truth_label": "SCAM",
                "ground_truth_score_range": [80, 100],
                "source": "OpenPhish",
                "source_verified": True,
                "requires_selenium": True,
                "category": "generic_phishing",
            })
            index += 1
            if len(samples) >= limit:
                break

        return samples
