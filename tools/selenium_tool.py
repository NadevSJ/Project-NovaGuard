"""Selenium-based URL investigation tool for NovaGuard.

Exposes a `SeleniumInspector` that opens suspicious URLs in a sandboxed
headless Chrome browser, extracts evidence the agent uses to reason about
scam intent, and registers an `inspect_url` LangChain tool.
"""

from __future__ import annotations

import re
import time
from typing import Any
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from langchain.tools import Tool
from selenium import webdriver
from selenium.common.exceptions import (
    InvalidArgumentException,
    TimeoutException,
    WebDriverException,
)
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from webdriver_manager.chrome import ChromeDriverManager

from config import Config

_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
)


class SeleniumInspector:
    """Headless-browser inspector that gathers evidence from a candidate URL.

    The WebDriver instance is kept alive between calls (persistent driver)
    so Chrome does not cold-start on every investigation — saves ~2–3s per URL.
    Call `close()` to release the browser when the inspector is no longer needed.
    """

    def __init__(self) -> None:
        self.timeout = Config.SELENIUM_TIMEOUT
        self.max_chars = Config.MAX_SCRAPED_CHARS
        self._driver: webdriver.Chrome | None = None  # persisted across calls

    # ------------------------------------------------------------------ driver lifecycle
    def _get_driver(self) -> webdriver.Chrome:
        """Return the live driver, creating it on first use."""
        if self._driver is None:
            self._driver = self._build_driver()
        return self._driver

    def _reset_driver(self) -> None:
        """Clear cookies and navigate to blank between requests (no restart)."""
        if self._driver is None:
            return
        try:
            self._driver.delete_all_cookies()
            self._driver.get("about:blank")
        except Exception:
            # If the driver is broken, close it so next call spawns a fresh one.
            self._close_driver()

    def _close_driver(self) -> None:
        if self._driver is not None:
            try:
                self._driver.quit()
            except Exception:
                pass
            self._driver = None

    def close(self) -> None:
        """Shut down the browser. Call on application exit."""
        self._close_driver()

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _is_valid_http_url(url: str) -> bool:
        if not isinstance(url, str):
            return False
        url = url.strip()
        if not url:
            return False
        parsed = urlparse(url)
        return parsed.scheme in {"http", "https"} and bool(parsed.netloc)

    @staticmethod
    def _domain_of(url: str) -> str:
        try:
            netloc = urlparse(url).netloc.lower()
            return netloc[4:] if netloc.startswith("www.") else netloc
        except Exception:
            return ""

    def _build_driver(self) -> webdriver.Chrome:
        options = Options()
        options.add_argument("--headless=new")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        # --disable-gpu prevents GPU-process crashes on complex/scam redirect chains.
        # With --headless=new this does NOT cause blank screenshots (different pipeline
        # from legacy headless where it did).
        options.add_argument("--disable-gpu")
        options.add_argument("--no-zygote")          # extra renderer stability
        options.add_argument("--window-size=1920,1080")
        options.add_argument("--force-device-scale-factor=1")
        options.add_argument("--disable-blink-features=AutomationControlled")
        options.add_argument(f"user-agent={_USER_AGENT}")
        options.add_argument("--disable-popup-blocking")
        options.add_experimental_option("excludeSwitches", ["enable-automation"])
        options.add_experimental_option("useAutomationExtension", False)

        # page_load_strategy='none' — driver.get() returns the instant navigation
        # starts.  This prevents TimeoutException during long redirect chains and
        # stops the renderer from becoming unresponsive waiting for slow pages.
        # Our redirect-following loop handles waiting for real content manually.
        options.page_load_strategy = "none"

        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=options)
        driver.set_page_load_timeout(self.timeout)
        return driver

    # ----------------------------------------------------------------- API
    def inspect_url(self, url: str) -> str:
        """Open `url` in a sandboxed browser and return a structured evidence report."""
        url = (url or "").strip().strip("'\"")
        if not self._is_valid_http_url(url):
            return (
                f"ERROR: Invalid URL '{url}'. Input must start with http:// or "
                "https:// and include a domain."
            )

        driver = self._get_driver()
        try:
            try:
                # page_load_strategy='none' → returns immediately, never raises TimeoutException
                driver.get(url)
            except TimeoutException:
                pass  # should not happen with page_load_strategy='none', but kept for safety
            except InvalidArgumentException as exc:
                self._reset_driver()
                return f"ERROR (InvalidArgumentException): {exc}"
            except WebDriverException as exc:
                self._reset_driver()
                return self._classify_webdriver_error(url, exc)

            # Redirect-following wait loop — same strategy as browse_live.py
            _deadline    = time.time() + 18
            _prev_url    = None
            _stable_hits = 0
            while time.time() < _deadline:
                try:
                    _curr_url = driver.current_url
                    _body_len = len(
                        driver.execute_script(
                            "return document.body ? (document.body.innerText||'') : ''"
                        ) or ""
                    )
                    if _curr_url != _prev_url:
                        _prev_url    = _curr_url
                        _stable_hits = 0
                    elif _body_len >= 80:
                        _stable_hits += 1
                        if _stable_hits >= 3:
                            break
                    else:
                        _stable_hits = 0
                except Exception:
                    pass
                time.sleep(0.3)

            page_title = (driver.title or "").strip()
            final_url = driver.current_url
            url_changed = self._domain_of(url) != self._domain_of(final_url)

            body_text = ""
            try:
                body_text = driver.find_element(By.TAG_NAME, "body").text or ""
            except Exception:
                body_text = ""
            page_text = self._clean_text(body_text)[: self.max_chars]

            anchors = driver.find_elements(By.TAG_NAME, "a")
            all_links_raw: list[str] = []
            for a in anchors:
                try:
                    href = a.get_attribute("href")
                except Exception:
                    href = None
                if href and href.strip():
                    all_links_raw.append(href.strip())
            all_links = list(dict.fromkeys(all_links_raw))[:20]

            forms = driver.find_elements(By.TAG_NAME, "form")
            form_actions: list[str] = []
            for form in forms:
                try:
                    action = form.get_attribute("action")
                except Exception:
                    action = None
                if action:
                    form_actions.append(action.strip())

            inputs = driver.find_elements(By.TAG_NAME, "input")
            input_types: list[str] = []
            for inp in inputs:
                try:
                    t = (inp.get_attribute("type") or "").lower().strip()
                except Exception:
                    t = ""
                if t:
                    input_types.append(t)

            has_login_form = False
            for form in forms:
                try:
                    pwd_inputs = form.find_elements(By.CSS_SELECTOR, "input[type='password']")
                    if pwd_inputs:
                        has_login_form = True
                        break
                except Exception:
                    continue

            original_domain = self._domain_of(url)
            external_domains: list[str] = []
            for link in all_links_raw:
                d = self._domain_of(link)
                if d and d != original_domain and d not in external_domains:
                    external_domains.append(d)

            meta_description = ""
            try:
                meta_el = driver.find_element(
                    By.CSS_SELECTOR, "meta[name='description']"
                )
                meta_description = (meta_el.get_attribute("content") or "").strip()
            except Exception:
                meta_description = ""

            sensitive_input_keywords = {"password", "tel", "number"}
            sensitive_text_hits = [
                kw for kw in ("pin", "otp", "nic", "cvv", "passport", "atm")
                if re.search(rf"\b{kw}\b", page_text, re.IGNORECASE)
            ]

            return self._format_report(
                requested_url=url,
                final_url=final_url,
                url_changed=url_changed,
                page_title=page_title,
                meta_description=meta_description,
                page_text=page_text,
                all_links=all_links,
                form_actions=form_actions,
                input_types=input_types,
                has_login_form=has_login_form,
                external_domains=external_domains,
                sensitive_input_keywords=sorted(
                    set(input_types) & sensitive_input_keywords
                ),
                sensitive_text_hits=sensitive_text_hits,
            )

        except ConnectionRefusedError as exc:
            self._reset_driver()
            return (
                f"ERROR (ConnectionRefusedError): The server at {url} actively "
                f"refused the connection. ({exc})"
            )
        except Exception as exc:  # pragma: no cover - safety net
            self._reset_driver()
            return f"ERROR: Unexpected failure inspecting {url}: {exc}"
        else:
            # Success path — reset state for the next call without quitting.
            self._reset_driver()

    def get_url_metadata(self, url: str) -> dict[str, Any]:
        """Lightweight `requests`-based HEAD/GET metadata probe."""
        result: dict[str, Any] = {
            "url": url,
            "status_code": None,
            "content_type": None,
            "server": None,
            "final_url_after_redirects": None,
            "is_https": False,
            "redirect_chain": [],
            "ssl_valid": False,
            "error": None,
        }
        if not self._is_valid_http_url(url):
            result["error"] = "Invalid URL"
            return result

        try:
            response = requests.head(
                url,
                allow_redirects=True,
                timeout=5,
                headers={"User-Agent": _USER_AGENT},
            )
            if response.status_code in (403, 405) or not response.headers:
                response = requests.get(
                    url,
                    allow_redirects=True,
                    timeout=5,
                    headers={"User-Agent": _USER_AGENT},
                    stream=True,
                )

            result["status_code"] = response.status_code
            result["content_type"] = response.headers.get("Content-Type")
            result["server"] = response.headers.get("Server")
            result["final_url_after_redirects"] = response.url
            result["is_https"] = response.url.lower().startswith("https://")
            result["redirect_chain"] = [r.url for r in response.history] + [response.url]
            result["ssl_valid"] = result["is_https"]
            return result
        except requests.exceptions.SSLError as exc:
            result["error"] = f"SSLError: {exc}"
            result["ssl_valid"] = False
            return result
        except requests.exceptions.ConnectionError as exc:
            result["error"] = f"ConnectionError: {exc}"
            return result
        except requests.exceptions.Timeout as exc:
            result["error"] = f"Timeout: {exc}"
            return result
        except requests.exceptions.RequestException as exc:
            result["error"] = f"RequestException: {exc}"
            return result

    # --------------------------------------------------------------- internals
    @staticmethod
    def _clean_text(text: str) -> str:
        soup_text = BeautifulSoup(text, "html.parser").get_text(" ", strip=True)
        return re.sub(r"\s+", " ", soup_text).strip()

    @staticmethod
    def _classify_webdriver_error(url: str, exc: WebDriverException) -> str:
        message = str(exc).lower()
        if "ssl" in message or "err_cert" in message:
            return (
                f"ERROR (SSLError): The site {url} has an invalid or untrusted "
                f"SSL certificate. Detail: {exc.msg if hasattr(exc, 'msg') else exc}"
            )
        if "connection_refused" in message or "err_connection_refused" in message:
            return (
                f"ERROR (ConnectionRefusedError): {url} actively refused the "
                "connection. Detail: " + str(exc)
            )
        if "name_not_resolved" in message:
            return (
                f"ERROR (WebDriverException): DNS lookup failed for {url}. "
                "The domain may not exist — a strong scam indicator."
            )
        return f"ERROR (WebDriverException): {exc}"

    @staticmethod
    def _format_report(
        *,
        requested_url: str,
        final_url: str,
        url_changed: bool,
        page_title: str,
        meta_description: str,
        page_text: str,
        all_links: list[str],
        form_actions: list[str],
        input_types: list[str],
        has_login_form: bool,
        external_domains: list[str],
        sensitive_input_keywords: list[str],
        sensitive_text_hits: list[str],
    ) -> str:
        def fmt_list(items: list[str], empty: str = "(none)") -> str:
            return ", ".join(items) if items else empty

        return (
            "=== NovaGuard Selenium Inspection Report ===\n"
            f"Requested URL : {requested_url}\n"
            f"Final URL     : {final_url}\n"
            f"Redirect changed domain : {url_changed}\n"
            f"Page title    : {page_title or '(empty)'}\n"
            f"Meta description : {meta_description or '(none)'}\n"
            "----------\n"
            f"Has login form (password input) : {has_login_form}\n"
            f"Input types found : {fmt_list(input_types)}\n"
            f"Sensitive input types : {fmt_list(sensitive_input_keywords)}\n"
            f"Sensitive keywords in page text : {fmt_list(sensitive_text_hits)}\n"
            f"Form actions : {fmt_list(form_actions)}\n"
            f"External link domains : {fmt_list(external_domains)}\n"
            "----------\n"
            f"Page text (truncated to {len(page_text)} chars):\n{page_text or '(empty)'}\n"
            "----------\n"
            f"Sample links ({len(all_links)}):\n- "
            + ("\n- ".join(all_links) if all_links else "(none)")
            + "\n=== End of Report ===\n"
        )


# --------------------------------------------------------------- LangChain glue
_INSPECTOR_SINGLETON: SeleniumInspector | None = None


def _get_inspector() -> SeleniumInspector:
    global _INSPECTOR_SINGLETON
    if _INSPECTOR_SINGLETON is None:
        _INSPECTOR_SINGLETON = SeleniumInspector()
    return _INSPECTOR_SINGLETON


def _inspect_url_tool_fn(url: str) -> str:
    return _get_inspector().inspect_url(url)


inspect_url_tool = Tool(
    name="inspect_url",
    func=_inspect_url_tool_fn,
    description=(
        "Use this tool to safely investigate a suspicious URL or link. "
        "Input must be a complete URL starting with http:// or https://. "
        "The tool opens the URL in a sandboxed browser, extracts all text, "
        "forms, links, and detects redirects. Always use this tool when a "
        "user provides a URL before making any conclusions."
    ),
)
