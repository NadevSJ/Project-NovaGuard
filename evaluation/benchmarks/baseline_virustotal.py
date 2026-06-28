"""VirusTotal baseline.

Submits a URL to VirusTotal v3, retrieves the analysis stats, and maps
the engine-vote totals into NovaGuard's four-class taxonomy.
"""

from __future__ import annotations

import base64
import time
from typing import Any

import requests
from tqdm import tqdm

from config import Config

_SUBMIT_URL = "https://www.virustotal.com/api/v3/urls"
_GET_URL = "https://www.virustotal.com/api/v3/urls/{url_id}"
_REQUEST_TIMEOUT = 20
_POLL_INTERVAL = 5
_POLL_TIMEOUT = 30


class VirusTotalBaseline:
    """VirusTotal baseline classifier."""

    SYSTEM_NAME = "VirusTotalBaseline"

    def __init__(self) -> None:
        self.api_key = Config.VIRUSTOTAL_API_KEY
        self.configured = Config.is_configured("virustotal")

    # ----------------------------------------------------------- analyze
    def analyze_url(self, url: str) -> dict[str, Any]:
        if not self.configured:
            return {
                "status": "skipped",
                "reason": "VIRUSTOTAL_API_KEY not configured",
            }

        start = time.perf_counter()
        headers = {"x-apikey": self.api_key, "accept": "application/json"}

        try:
            submit_resp = requests.post(
                _SUBMIT_URL,
                headers={**headers, "content-type": "application/x-www-form-urlencoded"},
                data={"url": url},
                timeout=_REQUEST_TIMEOUT,
            )
        except requests.exceptions.RequestException as exc:
            return {
                "status": "error",
                "reason": f"submit failed: {exc}",
                "latency_seconds": round(time.perf_counter() - start, 3),
            }

        if submit_resp.status_code >= 400:
            return {
                "status": "error",
                "reason": f"submit HTTP {submit_resp.status_code}: {submit_resp.text[:200]}",
                "latency_seconds": round(time.perf_counter() - start, 3),
            }

        url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").rstrip("=")

        result_payload: dict[str, Any] | None = None
        deadline = time.perf_counter() + _POLL_TIMEOUT
        while time.perf_counter() < deadline:
            try:
                resp = requests.get(
                    _GET_URL.format(url_id=url_id),
                    headers=headers,
                    timeout=_REQUEST_TIMEOUT,
                )
            except requests.exceptions.RequestException as exc:
                return {
                    "status": "error",
                    "reason": f"get failed: {exc}",
                    "latency_seconds": round(time.perf_counter() - start, 3),
                }
            if resp.status_code == 200:
                try:
                    result_payload = resp.json()
                    stats = (
                        result_payload.get("data", {})
                        .get("attributes", {})
                        .get("last_analysis_stats")
                    )
                    if stats:
                        break
                except ValueError:
                    pass
            if resp.status_code == 404:
                pass
            time.sleep(_POLL_INTERVAL)

        latency = round(time.perf_counter() - start, 3)
        if result_payload is None:
            return {
                "status": "timeout",
                "reason": f"no result within {_POLL_TIMEOUT}s",
                "latency_seconds": latency,
            }

        attrs = result_payload.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats") or {}
        malicious_count = int(stats.get("malicious", 0))
        suspicious_count = int(stats.get("suspicious", 0))
        total_engines = int(sum(stats.values())) if stats else 0

        label, score = self._map_label(malicious_count, suspicious_count)
        return {
            "status": "ok",
            "predicted_label": label,
            "predicted_score": score,
            "vt_malicious_engines": malicious_count,
            "vt_suspicious_engines": suspicious_count,
            "vt_total_engines": total_engines,
            "latency_seconds": latency,
        }

    # ----------------------------------------------------------- dataset run
    def run_on_dataset(self, samples: list[dict[str, Any]]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        url_samples = [s for s in samples if s.get("input_type") == "url"]
        for sample in tqdm(url_samples, desc="VirusTotal", unit="url"):
            base = self._copy_ground_truth(sample)
            result = self.analyze_url(sample.get("input", ""))
            base.update(result)
            out.append(base)
            time.sleep(1)
        for sample in samples:
            if sample.get("input_type") != "url":
                base = self._copy_ground_truth(sample)
                base.update({"status": "skipped", "reason": "non-URL sample"})
                out.append(base)
        return out

    # ----------------------------------------------------------- helpers
    @staticmethod
    def _map_label(malicious_count: int, suspicious_count: int) -> tuple[str, int]:
        if malicious_count > 3:
            return "SCAM", min(99, malicious_count * 10)
        if malicious_count > 0 or suspicious_count > 2:
            return "SUSPICIOUS", 55
        return "SAFE", 10

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
