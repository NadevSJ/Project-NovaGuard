"""Shared FastAPI dependencies: lazy singletons, API-key auth, JWT auth, traffic-light mapping."""

from __future__ import annotations

import threading
from typing import Any

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from config import Config

# ---------------------------------------------------------------- JWT helpers
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)

# ---------------------------------------------------------------- traffic light
TRAFFIC_LIGHT_MAP: dict[str, dict[str, str]] = {
    "SCAM": {
        "color": "red",
        "label": "DANGEROUS",
        "action": "Do NOT click any links. Block the sender immediately.",
    },
    "SUSPICIOUS": {
        "color": "yellow",
        "label": "SUSPICIOUS",
        "action": "Proceed with extreme caution. Verify through official channels.",
    },
    "LIKELY_SAFE": {
        "color": "green",
        "label": "LIKELY SAFE",
        "action": "Appears safe, but always verify before sharing personal data.",
    },
    "SAFE": {
        "color": "green",
        "label": "SAFE",
        "action": "No threats detected.",
    },
}


def traffic_light_for(label: str) -> dict[str, str]:
    return TRAFFIC_LIGHT_MAP.get(label, TRAFFIC_LIGHT_MAP["SUSPICIOUS"])


# ---------------------------------------------------------------- lazy singletons
_lock = threading.Lock()
_agent: Any = None
_vision: Any = None


def get_agent() -> Any:
    """Lazily construct the NovaGuardAgent; reused across requests."""
    global _agent
    if _agent is not None:
        return _agent
    with _lock:
        if _agent is None:
            from agent.novaguard_agent import NovaGuardAgent
            _agent = NovaGuardAgent()
    return _agent


def get_vision() -> Any:
    """Lazily construct the VisionInspector."""
    global _vision
    if _vision is not None:
        return _vision
    with _lock:
        if _vision is None:
            from tools.vision_tool import VisionInspector
            _vision = VisionInspector()
    return _vision


def reset_singletons() -> None:
    """Test helper; not used in production paths."""
    global _agent, _vision
    with _lock:
        _agent = None
        _vision = None


# ---------------------------------------------------------------- JWT user deps
def get_current_user(
    token: str | None = Depends(oauth2_scheme),
    db: Session = Depends(lambda: None),  # overridden at call site via Depends(get_db)
) -> Any:
    """Return the authenticated User or raise 401. Import get_db at call site."""
    # NOTE: this stub is replaced by _get_current_user_impl which is the real function.
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not configured")


def _make_current_user_dep(get_db_fn: Any) -> Any:
    """Factory that returns a proper get_current_user dependency bound to get_db."""
    from backend.database import User  # avoid circular at module load

    async def _dep(
        token: str | None = Depends(oauth2_scheme),
        db: Session = Depends(get_db_fn),
    ) -> User:
        credentials_exc = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )
        if not token:
            raise credentials_exc
        try:
            payload = jwt.decode(token, Config.JWT_SECRET, algorithms=[Config.JWT_ALGORITHM])
            user_id_str: str | None = payload.get("sub")
            if user_id_str is None:
                raise credentials_exc
        except JWTError:
            raise credentials_exc
        user = db.query(User).filter(User.id == int(user_id_str)).first()
        if user is None:
            raise credentials_exc
        return user

    return _dep


def _make_optional_user_dep(get_db_fn: Any) -> Any:
    """Factory that returns an optional get_current_user dependency (returns None on failure)."""
    from backend.database import User  # avoid circular at module load

    async def _dep(
        token: str | None = Depends(oauth2_scheme),
        db: Session = Depends(get_db_fn),
    ) -> User | None:
        if not token:
            return None
        try:
            payload = jwt.decode(token, Config.JWT_SECRET, algorithms=[Config.JWT_ALGORITHM])
            user_id_str: str | None = payload.get("sub")
            if user_id_str is None:
                return None
            user = db.query(User).filter(User.id == int(user_id_str)).first()
            return user
        except (JWTError, ValueError):
            return None

    return _dep


# ---------------------------------------------------------------- api-key auth
async def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """FastAPI dependency that enforces the optional X-API-Key header.

    If `Config.API_KEY` is unset, all requests are allowed (dev mode).
    """
    expected = Config.API_KEY
    if not expected:
        return
    if x_api_key != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-API-Key header.",
        )
