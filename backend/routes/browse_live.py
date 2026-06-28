"""Live browser inspection endpoint — streams screenshots via Server-Sent Events.

GET /api/v1/investigate/browse?url=<url>&input=<full_text>&token=<optional-jwt>

  url   — the URL Chrome will navigate to (for the visual)
  input — the full message/text the agent investigates (defaults to url)
  token — optional JWT; if valid, saves result to investigation history

Event stream format:
    event: status      data: <plain text message>
    event: screenshot  data: <base64-png>
    event: result      data: <json investigation result>
    event: done        data: ""
    event: error       data: <plain text>   (non-fatal — stream continues)
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
from urllib.parse import urlparse

from fastapi import APIRouter, Query
from fastapi.responses import StreamingResponse

logger = logging.getLogger("novaguard.browse_live")

router = APIRouter(prefix="/investigate", tags=["investigate"])


# --------------------------------------------------------------- helpers
def _is_http_url(url: str) -> bool:
    try:
        p = urlparse(url.strip())
        return p.scheme in {"http", "https"} and bool(p.netloc)
    except Exception:
        return False


# --------------------------------------------------------------- SSE generator
async def _event_generator(url: str, input_text: str, token: str | None, visual_only: bool = False):
    loop = asyncio.get_event_loop()
    q: asyncio.Queue = asyncio.Queue()

    def put(event: str, data: str) -> None:
        """Thread-safe enqueue."""
        loop.call_soon_threadsafe(q.put_nowait, (event, data))

    def _selenium_thread() -> None:
        from selenium.webdriver.support.ui import WebDriverWait
        from tools.selenium_tool import SeleniumInspector
        from backend.dependencies import get_agent

        browser: SeleniumInspector | None = None
        try:
            put("status", "Launching browser…")
            browser = SeleniumInspector()
            driver = browser._get_driver()

            # --- Navigate ---
            # page_load_strategy='none' means driver.get() returns instantly
            # (no blocking wait, no TimeoutException from page loading).
            # Only genuine connection errors (ERR_NAME_NOT_RESOLVED etc.) raise here.
            put("status", f"Navigating to {url[:60]}…")
            nav_ok = True
            try:
                driver.get(url)
            except Exception as nav_err:
                nav_ok = False
                put("status", f"Site unreachable ({type(nav_err).__name__}) — capturing error page…")

            if nav_ok:
                # ── Redirect-following wait loop ──────────────────────────────────
                # URL shorteners chain: f1na.com → m0o1.com → fina.guru → …
                # We keep polling until the URL stops changing AND body has content.
                # Each iteration: 300 ms.  Total budget: 20 s.
                _deadline    = time.time() + 20
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
                            # URL changed (another redirect hop)
                            if _prev_url is not None:
                                put("status", f"Following redirect → {_curr_url[:55]}…")
                            _prev_url    = _curr_url
                            _stable_hits = 0

                        elif _body_len >= 100:
                            # URL stable + content present
                            _stable_hits += 1
                            if _stable_hits >= 3:   # stable for ~0.9 s
                                break
                        else:
                            # URL stable but body still empty (SPA / lazy render)
                            _stable_hits = 0
                            put("status", "Waiting for page content…")

                    except Exception:
                        pass

                    time.sleep(0.3)

                # ── Repaint trigger ──────────────────────────────────────────────
                # Forces the headless Chrome compositor to flush its render tree.
                # Without this, pages that finished loading can still screenshot blank.
                try:
                    driver.execute_script(
                        "document.body.getBoundingClientRect();"   # sync layout flush
                        "window.scrollTo(0, 1);"
                        "window.scrollTo(0, 0);"
                    )
                    time.sleep(0.4)
                except Exception:
                    pass

            else:
                # Unreachable site — give Chrome time to render its error page
                time.sleep(3.0)

            # Always capture at least one screenshot — even the error page is useful
            try:
                put("screenshot", driver.get_screenshot_as_base64())
            except Exception:
                pass

            if nav_ok:
                # Scroll and capture additional frames
                for scroll_y, label in [
                    (400, "Scanning page content…"),
                    (800, "Checking for forms and inputs…"),
                    (1200, "Inspecting links and redirects…"),
                ]:
                    try:
                        driver.execute_script(f"window.scrollTo(0, {scroll_y})")
                        time.sleep(0.5)
                        put("status", label)
                        put("screenshot", driver.get_screenshot_as_base64())
                    except Exception:
                        pass

                # Back to top for a clean final shot
                try:
                    driver.execute_script("window.scrollTo(0, 0)")
                    time.sleep(0.3)
                except Exception:
                    pass

            # --- AI investigation (skipped for visual-only tabs) ---
            if not visual_only:
                put("status", "Running AI investigation…")
                agent = get_agent()
                result = agent.investigate(input_text)

                # One final screenshot after investigation completes
                if nav_ok:
                    try:
                        put("screenshot", driver.get_screenshot_as_base64())
                    except Exception:
                        pass

                # --- Optionally save to DB ---
                if token:
                    try:
                        from jose import JWTError, jwt
                        from config import Config
                        from backend.database import SessionLocal, Investigation
                        from backend.dependencies import traffic_light_for

                        payload = jwt.decode(token, Config.JWT_SECRET, algorithms=[Config.JWT_ALGORITHM])
                        user_id = int(payload.get("sub", 0))
                        if user_id:
                            label = (result.get("predicted_label") or "SUSPICIOUS").upper()
                            tl = traffic_light_for(label)
                            db = SessionLocal()
                            try:
                                row = Investigation(
                                    user_id=user_id,
                                    input_preview=input_text[:200],
                                    input_type="url",
                                    predicted_label=label,
                                    predicted_score=int(result.get("predicted_score") or 50),
                                    report=result.get("response") or "",
                                    traffic_light=tl["color"],
                                    recommended_action=tl["action"],
                                    latency_seconds=float(result.get("latency_seconds") or 0.0),
                                )
                                db.add(row)
                                db.commit()
                            except Exception as db_err:
                                logger.warning("DB save failed: %s", db_err)
                                try:
                                    db.rollback()
                                except Exception:
                                    pass
                            finally:
                                db.close()
                    except Exception as jwt_err:
                        logger.debug("Token decode skipped: %s", jwt_err)

                put("result", json.dumps(result, ensure_ascii=False))
            else:
                put("status", "Visual scan complete")

        except Exception as exc:
            logger.exception("Live browser thread error: %s", exc)
            # Non-fatal — let the agent still try to run
            put("status", f"Browser error: {exc}")
        finally:
            try:
                if browser:
                    browser.close()
            except Exception:
                pass
            put("done", "")

    # Kick off Selenium in a daemon thread
    t = threading.Thread(target=_selenium_thread, daemon=True)
    t.start()

    # Stream events as they arrive in the queue
    while True:
        event, data = await q.get()
        yield f"event: {event}\ndata: {data}\n\n"
        if event == "done":
            break


# --------------------------------------------------------------- endpoint
@router.get("/browse")
async def browse_live(
    url: str = Query(..., description="URL Chrome will navigate to"),
    input: str | None = Query(None, description="Full message text for the agent (defaults to url)"),
    token: str | None = Query(None, description="Optional JWT for saving to history"),
    visual_only: bool = Query(False, description="Skip AI investigation — take screenshots only"),
) -> StreamingResponse:
    """Stream live Selenium screenshots + AI investigation result via SSE."""
    clean_url = url.strip()

    if not _is_http_url(clean_url):
        async def _err():
            yield 'event: status\ndata: Invalid URL — must start with http:// or https://\n\n'
            yield 'event: done\ndata: \n\n'
        return StreamingResponse(_err(), media_type="text/event-stream")

    # If the caller supplied a full message, investigate that; otherwise investigate the URL alone
    investigation_input = (input or "").strip() or clean_url

    return StreamingResponse(
        _event_generator(clean_url, investigation_input, token, visual_only),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )
