"""Opt-in, explicit service-account OAuth for the Play Integrity transport.

No ADC, files, environment credentials, proxy discovery or network on import or
construction. The host supplies and stores the private key; do not accept these
parameters from a client. OAuth assertions are never exposed by the public API.
"""

import base64
from contextlib import contextmanager
import http.client
import json
import math
import re
import ssl
import threading
import time
from time import monotonic as _monotonic
from urllib.parse import urlencode

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from ..enrollment_types import _MAX_TIME
from .google import GoogleProviderError

_AUDIENCE = "https://oauth2.googleapis.com/token"
_SCOPE = "https://www.googleapis.com/auth/playintegrity"
_MAX_RESPONSE = 32768
_EMAIL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+\-]*@(?:[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?\.)+gserviceaccount\.com")
_PEM = re.compile(rb"-----BEGIN (PRIVATE KEY|RSA PRIVATE KEY)-----\r?\n[A-Za-z0-9+/=\r\n]+-----END \1-----")
_CONTENT_TYPE = re.compile(r'application/json(?:[ \t]*;[ \t]*charset[ \t]*=[ \t]*(?:utf-8|"utf-8"))?[ \t]*', re.I)


def _seconds(value):
    return type(value) in (int, float) and math.isfinite(value) and 0.1 <= value <= 30


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError
        value[key] = item
    return value


def _no_constant(_):
    raise ValueError


def _token_response(raw, skew):
    if type(raw) is not bytes or not 1 <= len(raw) <= _MAX_RESPONSE:
        raise ValueError
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_no_constant)
    stack, nodes = [(value, 0)], 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if depth > 8 or nodes > 256:
            raise ValueError
        if type(item) is dict:
            stack.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            stack.extend((child, depth + 1) for child in item)
        elif type(item) is float and not math.isfinite(item):
            raise ValueError
    if type(value) is not dict or "error" in value:
        raise ValueError
    token, lifetime = value.get("access_token"), value.get("expires_in")
    if (type(token) is not str or not 1 <= len(token) <= 8192
            or re.fullmatch(r"[A-Za-z0-9._~+/\-]+=*", token) is None
            or value.get("token_type") != "Bearer"
            or type(lifetime) is not int or not skew < lifetime <= 3600
            or ("scope" in value and value["scope"] != _SCOPE)):
        raise ValueError
    return token, lifetime


def _b64(raw):
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


class _Flight:
    def __init__(self):
        self.done = threading.Event()
        self.succeeded = False


class GoogleServiceAccountTokenProvider:
    """Callable explicit RSA service-account token source; compatible with decode.

    The host provides an unencrypted, complete RSA PEM (2048--4096 bits) and
    service-account email. Only the fixed Play Integrity scope is requested; no
    delegated user or alternate endpoint is supported. Cache state is per object,
    in memory, and should be created independently in each server process.

    timeout_seconds bounds socket operations, not total wall time or DNS. A
    concurrent caller waits at most wait_timeout_seconds for the current refresh
    and fails closed on timeout. Network work never holds the state lock. No
    retries or stale-token fallback occur. clock must quickly return integer UTC
    Unix seconds; a regressing/invalid clock discards the cached token.
    """

    def __init__(self, *, service_account_email, private_key_pem, timeout_seconds=5,
                 refresh_skew_seconds=60, wait_timeout_seconds=5, clock=None):
        valid, private_key = False, None
        try:
            valid = (type(service_account_email) is str and len(service_account_email) <= 254
                     and _EMAIL.fullmatch(service_account_email) is not None
                     and all(len(label) <= 63 for label in service_account_email.split("@")[1].split("."))
                     and type(private_key_pem) is bytes and 1 <= len(private_key_pem) <= 16384
                     and _PEM.fullmatch(private_key_pem.strip()) is not None
                     and _seconds(timeout_seconds) and _seconds(wait_timeout_seconds)
                     and type(refresh_skew_seconds) is int and 0 <= refresh_skew_seconds <= 300
                     and (clock is None or callable(clock)))
            if valid:
                private_key = serialization.load_pem_private_key(private_key_pem, password=None)
                valid = (isinstance(private_key, rsa.RSAPrivateKey)
                         and 2048 <= private_key.key_size <= 4096
                         and private_key.public_key().public_numbers().e == 65537)
        except Exception:
            valid = False
        if not valid:
            raise GoogleProviderError("GOOGLE_CONFIGURATION_INVALID")
        self._email, self._private_key = service_account_email, private_key
        self._timeout, self._skew, self._wait = timeout_seconds, refresh_skew_seconds, wait_timeout_seconds
        self._clock = clock if clock is not None else lambda: int(time.time())
        self._lock = threading.Lock()
        self._flight = None
        self._last_wall, self._last_mono = None, None
        self._clear_cache()

    def __repr__(self):
        return "GoogleServiceAccountTokenProvider(<redacted>)"

    def _clear_cache(self):
        self._token, self._expires_wall, self._expires_mono = None, 0, 0

    @contextmanager
    def _guard(self):
        if not self._lock.acquire(timeout=self._wait):
            raise ValueError
        try:
            yield
        finally:
            self._lock.release()

    def _now(self):
        # Called only under the state lock; track high water marks across both
        # cached calls and waiters so a clock rollback never extends validity.
        try:
            wall, mono = self._clock(), _monotonic()
            if (type(wall) is not int or not 0 <= wall <= _MAX_TIME - 3600
                    or type(mono) not in (int, float) or not math.isfinite(mono) or mono < 0
                    or (self._last_wall is not None and wall < self._last_wall)
                    or (self._last_mono is not None and mono < self._last_mono)):
                raise ValueError
        except Exception:
            self._clear_cache()
            raise
        self._last_wall, self._last_mono = wall, mono
        return wall, mono

    def _fresh(self, wall, mono):
        return (self._token is not None and wall < self._expires_wall - self._skew
                and mono < self._expires_mono - self._skew)

    def _exchange(self, issued):
        header = _b64(b'{"alg":"RS256","typ":"JWT"}')
        claims = _b64(json.dumps({"iss": self._email, "scope": _SCOPE, "aud": _AUDIENCE,
                                  "iat": issued, "exp": issued + 3600},
                                 separators=(",", ":")).encode("utf-8"))
        signed = (header + "." + claims).encode("ascii")
        signature = self._private_key.sign(signed, padding.PKCS1v15(), hashes.SHA256())
        assertion = signed.decode("ascii") + "." + _b64(signature)
        body = urlencode({"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                          "assertion": assertion}).encode("ascii")
        connection = http.client.HTTPSConnection("oauth2.googleapis.com", timeout=self._timeout,
                                                 context=ssl.create_default_context())
        try:
            connection.request("POST", "/token", body=body, headers={
                "Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json",
                "Accept-Encoding": "identity"})
            response = connection.getresponse()
            if (response.status != 200
                    or response.getheader("Content-Encoding", "identity") != "identity"):
                raise ValueError
            content_type = response.getheader("Content-Type")
            if type(content_type) is not str or _CONTENT_TYPE.fullmatch(content_type) is None:
                raise ValueError
            length, transfer = response.getheader("Content-Length"), response.getheader("Transfer-Encoding")
            if (transfer is not None and (transfer != "chunked" or length is not None)):
                raise ValueError
            if length is not None and (type(length) is not str
                    or re.fullmatch(r"[0-9]{1,5}", length) is None or int(length) > _MAX_RESPONSE):
                raise ValueError
            raw = response.read(_MAX_RESPONSE + 1)
            if length is not None and len(raw) != int(length):
                raise ValueError
            return _token_response(raw, self._skew)
        finally:
            connection.close()

    def _get_token(self):
        with self._guard():
            wall, mono = self._now()
            if self._fresh(wall, mono):
                return self._token
            if self._flight is not None and self._flight.done.is_set():
                self._flight = None
            leader = self._flight is None
            if leader:
                self._clear_cache()
                self._flight = _Flight()
            flight = self._flight
        if not leader:
            if not flight.done.wait(timeout=self._wait):
                raise ValueError
            with self._guard():
                wall, mono = self._now()
                if not flight.succeeded or not self._fresh(wall, mono):
                    raise ValueError
                return self._token
        try:
            token, lifetime = self._exchange(wall)
            with self._guard():
                after_wall, after_mono = self._now()
                # Anchor both expiries before network work, conservatively
                # charging the entire exchange/signing duration to token life.
                expires_wall, expires_mono = wall + lifetime, mono + lifetime
                if (after_wall >= expires_wall - self._skew
                        or after_mono >= expires_mono - self._skew):
                    raise ValueError
                self._token, self._expires_wall, self._expires_mono = token, expires_wall, expires_mono
                flight.succeeded = True
                return token
        finally:
            # Wake every waiter even when exchange/parsing/clock/lock validation
            # fails. Waiters share this outcome and never retry it themselves.
            flight.done.set()

    def __call__(self):
        result = None
        try:
            result = self._get_token()
        except Exception:
            pass
        # Deliberately outside the except block: neither cause nor context can
        # carry PEM, assertion, token, provider data or callback exceptions.
        if result is None:
            raise GoogleProviderError("GOOGLE_OAUTH_UNAVAILABLE")
        return result
