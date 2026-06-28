"""Thin HTTP client for the NovaGuard FastAPI backend."""

from __future__ import annotations

from typing import Any

import httpx

from config import Config

# Separate timeouts so health/version feel snappy while investigations
# can wait as long as the LLM + Selenium need (DeepSeek-V4 can take minutes).
_META_TIMEOUT = httpx.Timeout(connect=5.0, read=15.0, write=5.0, pool=5.0)
_INVESTIGATE_TIMEOUT = httpx.Timeout(connect=10.0, read=600.0, write=10.0, pool=10.0)


class NovaGuardAPIError(RuntimeError):
    def __init__(self, status_code: int, detail: str):
        super().__init__(f"HTTP {status_code}: {detail}")
        self.status_code = status_code
        self.detail = detail


class NovaGuardAPIClient:
    """Synchronous httpx wrapper. Streamlit reruns prefer sync calls."""

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        timeout: float | None = None,  # kept for back-compat; ignored internally
    ) -> None:
        self.base_url = (base_url or Config.API_URL).rstrip("/")
        self.api_key = api_key if api_key is not None else Config.API_KEY

    # ---------------------------------------------------------- private
    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        return headers

    def _url(self, path: str) -> str:
        if not path.startswith("/"):
            path = "/" + path
        return f"{self.base_url}{path}"

    def _check(self, response: httpx.Response) -> Any:
        if response.status_code >= 400:
            detail = response.text
            try:
                payload = response.json()
                detail = payload.get("detail") or detail
            except Exception:
                pass
            raise NovaGuardAPIError(response.status_code, detail)
        return response.json()

    # ---------------------------------------------------------- meta
    def health(self) -> dict[str, Any]:
        with httpx.Client(timeout=_META_TIMEOUT) as client:
            return self._check(client.get(self._url("/api/v1/health"), headers=self._headers()))

    def version(self) -> dict[str, Any]:
        with httpx.Client(timeout=_META_TIMEOUT) as client:
            return self._check(client.get(self._url("/api/v1/version"), headers=self._headers()))

    def warmup(self) -> dict[str, Any]:
        with httpx.Client(timeout=_INVESTIGATE_TIMEOUT) as client:
            return self._check(client.post(self._url("/api/v1/warmup"), headers=self._headers()))

    # ---------------------------------------------------------- investigate
    def investigate(self, user_input: str, input_type_hint: str | None = None) -> dict[str, Any]:
        body = {"input": user_input}
        if input_type_hint:
            body["input_type_hint"] = input_type_hint
        with httpx.Client(timeout=_INVESTIGATE_TIMEOUT) as client:
            return self._check(
                client.post(self._url("/api/v1/investigate"), headers=self._headers(), json=body)
            )

    def investigate_email(self, sender: str, subject: str, body: str) -> dict[str, Any]:
        payload = {"sender": sender, "subject": subject, "body": body}
        with httpx.Client(timeout=_INVESTIGATE_TIMEOUT) as client:
            return self._check(
                client.post(
                    self._url("/api/v1/investigate/email"),
                    headers=self._headers(),
                    json=payload,
                )
            )

    def investigate_screenshot(
        self, file_bytes: bytes, filename: str = "screenshot.png", content_type: str = "image/png"
    ) -> dict[str, Any]:
        files = {"file": (filename, file_bytes, content_type)}
        with httpx.Client(timeout=_INVESTIGATE_TIMEOUT) as client:
            return self._check(
                client.post(
                    self._url("/api/v1/investigate/screenshot"),
                    headers=self._headers(),
                    files=files,
                )
            )

    # ---------------------------------------------------------- feedback
    def feedback(
        self,
        user_input: str,
        predicted_label: str,
        feedback_type: str,
        correct_label: str | None = None,
        input_type: str = "unknown",
    ) -> dict[str, Any]:
        payload = {
            "input": user_input,
            "predicted_label": predicted_label,
            "feedback_type": feedback_type,
            "correct_label": correct_label,
            "input_type": input_type,
        }
        with httpx.Client(timeout=_META_TIMEOUT) as client:
            return self._check(
                client.post(self._url("/api/v1/feedback"), headers=self._headers(), json=payload)
            )

    def feedback_stats(self) -> dict[str, Any]:
        with httpx.Client(timeout=_META_TIMEOUT) as client:
            return self._check(
                client.get(self._url("/api/v1/feedback/stats"), headers=self._headers())
            )

    def feedback_export(self, output_path: str | None = None) -> dict[str, Any]:
        payload = {"output_path": output_path}
        with httpx.Client(timeout=_META_TIMEOUT) as client:
            return self._check(
                client.post(
                    self._url("/api/v1/feedback/export"),
                    headers=self._headers(),
                    json=payload,
                )
            )
