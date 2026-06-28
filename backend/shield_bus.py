"""
backend/shield_bus.py
NovaGuard Shield — Server-Sent Events pub/sub bus

Extends the same asyncio in-process pub/sub pattern used by
backend/spoofing_bus.py — just a separate topic namespace.

Usage from routes:
    from backend.shield_bus import publish_shield_event, subscribe_shield
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import AsyncGenerator

log = logging.getLogger(__name__)

_subscribers: list[asyncio.Queue] = []


async def publish_shield_event(event: dict) -> None:
    """Publish a Shield event dict to all active SSE subscribers."""
    dead: list[asyncio.Queue] = []
    for q in list(_subscribers):
        try:
            q.put_nowait(event)
        except asyncio.QueueFull:
            dead.append(q)
        except Exception:
            dead.append(q)
    for q in dead:
        try:
            _subscribers.remove(q)
        except ValueError:
            pass


async def subscribe_shield() -> AsyncGenerator[str, None]:
    """
    Async generator that yields SSE-formatted strings.
    Use as the response body of a FastAPI StreamingResponse.

    Example route:
        return StreamingResponse(subscribe_shield(), media_type="text/event-stream")
    """
    q: asyncio.Queue = asyncio.Queue(maxsize=200)
    _subscribers.append(q)
    try:
        while True:
            event = await asyncio.wait_for(q.get(), timeout=30)
            payload = json.dumps(event, default=str)
            yield f"data: {payload}\n\n"
    except asyncio.TimeoutError:
        yield ": keep-alive\n\n"
    except asyncio.CancelledError:
        pass
    finally:
        try:
            _subscribers.remove(q)
        except ValueError:
            pass


async def subscribe_shield_org(org_id: str) -> AsyncGenerator[str, None]:
    """
    Filtered SSE stream — only yields events for the specified org_id.
    """
    q: asyncio.Queue = asyncio.Queue(maxsize=200)
    _subscribers.append(q)
    try:
        while True:
            try:
                event = await asyncio.wait_for(q.get(), timeout=30)
                if event.get("org_id") == org_id or event.get("org_id") is None:
                    payload = json.dumps(event, default=str)
                    yield f"data: {payload}\n\n"
            except asyncio.TimeoutError:
                yield ": keep-alive\n\n"
    except asyncio.CancelledError:
        pass
    finally:
        try:
            _subscribers.remove(q)
        except ValueError:
            pass


def bind_shield_loop(loop: asyncio.AbstractEventLoop | None = None) -> None:
    """
    Called from backend/main.py startup (same pattern as spoofing_bus.bind_loop).
    Currently a no-op — the asyncio queues are lazily created.
    """
    log.info("[ShieldBus] Shield SSE bus ready (%d initial subscribers)", len(_subscribers))
