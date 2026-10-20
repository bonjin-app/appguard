"""Optional Redis replay store; no connection is created implicitly."""

import base64
import hashlib
import json
import re

from .replay import ReplayStoreUnavailable


def redis_replay_key(scope: tuple[str, str, str]) -> str:
    if (type(scope) is not tuple or len(scope) != 3
            or any(type(part) is not str or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", part) for part in scope)):
        raise ReplayStoreUnavailable("invalid replay scope")
    nonce = scope[2]
    if (not re.fullmatch(r"[A-Za-z0-9_-]{22}", nonce)
            or base64.urlsafe_b64encode(base64.urlsafe_b64decode(nonce + "==")).decode().rstrip("=") != nonce):
        raise ReplayStoreUnavailable("invalid replay scope")
    encoded = json.dumps(list(scope), separators=(",", ":")).encode("ascii")
    return "appguard:v0:replay:" + hashlib.sha256(encoded).hexdigest()


class RedisReplayStore:
    def __init__(self, client):
        if not callable(getattr(client, "set", None)):
            raise ValueError("a configured Redis client is required")
        self._client = client

    def claim(self, scope: tuple[str, str, str], *, expires: int, now: int) -> bool:
        key = redis_replay_key(scope)
        if (type(now) is not int or type(expires) is not int
                or not 0 <= now < expires <= 999999999999999 or not 1 <= expires - now <= 150):
            raise ReplayStoreUnavailable("invalid replay deadline")
        try:
            result = self._client.set(key, b"1", nx=True, ex=expires - now)
        except Exception:
            raise ReplayStoreUnavailable("replay backend unavailable") from None
        if result is True:
            return True
        if result is None:
            return False
        raise ReplayStoreUnavailable("invalid replay backend response")
