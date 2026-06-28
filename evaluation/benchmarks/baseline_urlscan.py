"""URLScan.io baseline.

Submits each URL to URLScan, polls for the result, and maps the verdict
into NovaGuard's four-class taxonomy.
"""

from __future__ import annotations

import time
from typing import Any

import requests
from tqdm import tqdm

from config import Config

_SUBMIT_URL = "https://urlscan.io/api/v1/scan/"
_RESULT_URL = "https://urlscan.io/api/v1/result/{uuid}/"
_POLL_INTERVAL = 5
_POLL_TIMEOUT = 30
_REQUEST_TIMEOUT = 20


class URLScanBaseline:
    """URLScan.io baseline classifier."""

    SYSTEM_NAME = "URLScanBaseline"

    def __init__(self) -> None:
        self.api_key = Config.URLSCAN_API_KEY
        self.configured = Config.is_configured("urlscan")

    # ----------------------------------------------------------- analyze
    def analyze_url(self, url: str) -> dict[str, Any]:
        if not self.configured:
            return {
                "status": "skipped",
                "reason": "URLSCAN_API_KEY not configured",
            }

        start = time.perf_counter()
        headers = {"API-Key": self.api_key, "Content-Type": "application/json"}

        try:
            submit_resp = requests.post(
                _SUBMIT_URL,
                json={"url": url, "visibility": "private"},
                headers=headers,
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

        try:
            submit_payload = submit_resp.json()
        except ValueError:
            return {
                "status": "error",
                "reason": "submit returned non-JSON",
                "latency_seconds": round(time.perf_counter() - start, 3),
            }

        scan_uuid = submit_payload.get("uuid")
        scan_url = submit_payload.get("result")
        if not scan_uuid:
            return {
                "status": "error",
                "reason": "submit response missing uuid",
                "latency_seconds": round(time.perf_counter() - start, 3),
            }

        result_payload: dict[str, Any] | None = None
        deadline = time.perf_counter() + _POLL_TIMEOUT
        while time.perf_counter() < deadline:
            time.sleep(_POLL_INTERVAL)
            try:
                resp = requests.get(
                    _RESULT_URL.format(uuid=scan_uuid),
                    headers={"API-Key": self.api_key},
                    timeout=_REQUEST_TIMEOUT,
                )
            except requests.exceptions.RequestException as exc:
                return {
                    "status": "error",
                    "reason": f"poll failed: {exc}",
                    "scan_url": scan_url,
                    "latency_seconds": round(time.perf_counter() - start, 3),
                }
            if resp.status_code == 200:
                try:
                    result_payload = resp.json()
                    break
                except ValueError:
                    continue
            if resp.status_code in (404, 202):
                continue
            return {
                "status": "error",
                "reason": f"poll HTTP {resp.status_code}",
                "scan_url": scan_url,
                "latency_seconds": round(time.perf_counter() - start, 3),
            }

        latency = round(time.perf_counter() - start, 3)
        if result_payload is None:
            return {
                "status": "timeout",
                "reason": f"no result within {_POLL_TIMEOUT}s",
                "scan_url": scan_url,
                "latency_seconds": latency,
            }

        verdicts = (result_payload.get("verdicts") or {}).get("overall") or {}
        score = verdicts.get("score", 0)
        if not isinstance(score, (int, float)):
            score = 0
        malicious = bool(verdicts.get("malicious"))

        label, mapped_score = self._map_label(score=int(score), malicious=malicious)
        return {
            "status": "ok",
            "predicted_label": label,
            "predicted_score": mapped_score,
            "scan_url": scan_url,
            "urlscan_score": score,
            "urlscan_malicious": malicious,
            "latency_seconds": latency,
        }

    # ----------------------------------------------------------- dataset run
    def run_on_dataset(self, samples: list[dict[str, Any]]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        url_samples = [s for s in samples if s.get("input_type") == "url"]
        for sample in tqdm(url_samples, desc="URLScan", unit="url"):
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
    def _map_label(score: int, malicious: bool) -> tuple[str, int]:
        if malicious or score > 70:
            return "SCAM", max(80, score)
        if score > 40:
            return "SUSPICIOUS", score
        if score > 15:
            return "LIKELY_SAFE", score
        return "SAFE", max(0, score)

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
