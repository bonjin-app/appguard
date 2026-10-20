"""Optional Play Integrity Standard backend, with explicit server trust boundaries.

Only the official authenticated transport (or a deliberately injected trusted
server test boundary) supplies decoded bytes. Client evidence is an opaque token.
No credentials, environment discovery, refresh, or network activity on import or
construction. Never pass a client-owned callable as either trusted boundary.
"""

import base64
import hashlib
import http.client
import json
import math
import re
import ssl
import time

from ..canonical import validate_identifier
from ..enrollment_types import AttestationVerdict, Challenge, _MAX_TIME, enrollment_message

_MAX_TOKEN = 65536
_MAX_RESPONSE = 131072
_PACKAGE = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+")
_DEVICE_LABELS = frozenset({"MEETS_BASIC_INTEGRITY", "MEETS_DEVICE_INTEGRITY", "MEETS_STRONG_INTEGRITY", "MEETS_VIRTUAL_INTEGRITY"})


class GoogleProviderError(Exception):
    """Fixed public code; raw provider/credential exceptions are discarded."""
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _package(value):
    return type(value) is str and len(value) <= 255 and _PACKAGE.fullmatch(value) is not None


def _digest(value):
    if type(value) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{43}", value):
        return False
    raw = base64.urlsafe_b64decode(value + "=")
    return len(raw) == 32 and base64.urlsafe_b64encode(raw).decode().rstrip("=") == value


def _opaque(value):
    return (type(value) is str and 1 <= len(value.encode("utf-8")) <= _MAX_TOKEN
            and all(ord(char) >= 32 and ord(char) != 127 for char in value))


def _int(value, minimum, maximum):
    return type(value) is int and minimum <= value <= maximum


class GooglePlayIntegrityTransport:
    """Authenticated official HTTPS decode with no redirects/proxy discovery.

    access_token_provider is an explicit trusted server credential callback,
    returning a fresh OAuth access token with the Play Integrity scope. Its
    refresh/storage/timeout policy is owned by the deployment. No ADC is used.
    timeout_seconds bounds HTTPS socket operations; response bytes are capped.
    """
    def __init__(self, *, access_token_provider, timeout_seconds=5):
        if (not callable(access_token_provider) or type(timeout_seconds) not in (int, float)
                or not math.isfinite(timeout_seconds) or not 0.1 <= timeout_seconds <= 30):
            raise GoogleProviderError("GOOGLE_CONFIGURATION_INVALID")
        self._access_token_provider = access_token_provider
        self._timeout_seconds = timeout_seconds

    def __call__(self, package_name, integrity_token):
        # Exit the except block before raising: even __context__ must not carry
        # a credential/provider exception to logging or tracing integrations.
        result, connection = None, None
        try:
            if not _package(package_name) or not _opaque(integrity_token):
                raise ValueError
            access_token = self._access_token_provider()
            if (type(access_token) is not str or not 1 <= len(access_token) <= 8192
                    or re.fullmatch(r"[A-Za-z0-9._~+/\-]+=*", access_token) is None):
                raise ValueError
            body = json.dumps({"integrityToken": integrity_token}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            connection = http.client.HTTPSConnection("playintegrity.googleapis.com", timeout=self._timeout_seconds,
                                                     context=ssl.create_default_context())
            connection.request("POST", f"/v1/{package_name}:decodeIntegrityToken", body=body,
                               headers={"Authorization": "Bearer " + access_token,
                                        "Content-Type": "application/json", "Accept": "application/json",
                                        "Accept-Encoding": "identity"})
            response = connection.getresponse()
            if response.status != 200 or response.getheader("Content-Encoding", "identity") != "identity":
                raise ValueError
            length = response.getheader("Content-Length")
            if length is not None and (not re.fullmatch(r"[0-9]{1,6}", length) or int(length) > _MAX_RESPONSE):
                raise ValueError
            raw = response.read(_MAX_RESPONSE + 1)
            if type(raw) is not bytes or not 1 <= len(raw) <= _MAX_RESPONSE:
                raise ValueError
            if length is not None and len(raw) != int(length):
                raise ValueError
            result = raw
        except Exception:
            pass
        finally:
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    result = None
        if result is None:
            raise GoogleProviderError("GOOGLE_PROVIDER_UNAVAILABLE")
        return result


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError
        value[key] = item
    return value


def _no_constant(value):
    raise ValueError


def _bounded_json(raw):
    if type(raw) is not bytes or not 1 <= len(raw) <= _MAX_RESPONSE:
        raise ValueError
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_no_constant)
    # Bound depth and object count independently of the JSON parser's own limit.
    stack, nodes = [(value, 0)], 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if depth > 16 or nodes > 10000:
            raise ValueError
        if type(item) is dict:
            stack.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            stack.extend((child, depth + 1) for child in item)
        elif type(item) is float and not math.isfinite(item):
            raise ValueError
    if type(value) is not dict or type(value.get("tokenPayloadExternal")) is not dict:
        raise ValueError
    return value["tokenPayloadExternal"]


class GooglePlayIntegrityVerifier:
    """EnrollmentService callback backed exclusively by a trusted decode transport.

    certificate_sha256_digests contains canonical unpadded base64url SHA256
    certificates allowed for the configured Play package. Every reported signer
    must be allowed. All required device labels must be present. Licensed Play
    acquisition is required by default; any relaxation is a deployment policy.
    """
    def __init__(self, *, app_id, package_name, certificate_sha256_digests, transport, clock=None,
                 max_age_seconds=120, future_skew_seconds=5, verdict_ttl_seconds=300,
                 required_device_labels=frozenset({"MEETS_DEVICE_INTEGRITY"}), require_licensed=True):
        valid = False
        try:
            validate_identifier(app_id)
            valid = (_package(package_name) and type(certificate_sha256_digests) in (set, frozenset, list, tuple)
                     and 1 <= len(certificate_sha256_digests) <= 32 and all(_digest(x) for x in certificate_sha256_digests)
                     and callable(transport) and (clock is None or callable(clock))
                     and _int(max_age_seconds, 1, 300) and _int(future_skew_seconds, 0, 60)
                     and _int(verdict_ttl_seconds, 1, 86400) and type(require_licensed) is bool
                     and type(required_device_labels) in (set, frozenset, list, tuple)
                     and 1 <= len(required_device_labels) <= len(_DEVICE_LABELS)
                     and all(type(x) is str and x in _DEVICE_LABELS for x in required_device_labels))
        except Exception:
            pass
        if not valid:
            raise GoogleProviderError("GOOGLE_CONFIGURATION_INVALID")
        self._app_id, self._package_name = app_id, package_name
        self._certificates = frozenset(certificate_sha256_digests)
        self._transport = transport
        self._clock = clock if clock is not None else lambda: int(time.time())
        self._max_age, self._future_skew, self._ttl = max_age_seconds, future_skew_seconds, verdict_ttl_seconds
        self._required_labels, self._require_licensed = frozenset(required_device_labels), require_licensed

    def _now(self):
        now = self._clock()
        if not _int(now, 0, _MAX_TIME):
            raise ValueError
        return now

    def __call__(self, challenge: Challenge, evidence: bytes) -> AttestationVerdict:
        result = None
        try:
            if type(evidence) is not bytes or not 1 <= len(evidence) <= _MAX_TOKEN:
                raise ValueError
            token = evidence.decode("utf-8")
            if not _opaque(token) or not isinstance(challenge, Challenge) or challenge.app_id != self._app_id:
                raise ValueError
            message_hash = hashlib.sha256(enrollment_message(challenge)).digest()
            request_hash = base64.urlsafe_b64encode(message_hash).decode().rstrip("=")
            if self._now() >= challenge.expires:
                raise ValueError
            payload = _bounded_json(self._transport(self._package_name, token))
            now = self._now()  # Provider work cannot extend challenge/token freshness.
            if "testingDetails" in payload:
                testing = payload["testingDetails"]
                if type(testing) is not dict or testing.get("isTestingResponse") is not False:
                    raise ValueError
            request = payload["requestDetails"]
            app, device = payload["appIntegrity"], payload["deviceIntegrity"]
            account = payload["accountDetails"]
            if any(type(section) is not dict for section in (request, app, device, account)):
                raise ValueError
            timestamp = request["timestampMillis"]
            if type(timestamp) is not str or re.fullmatch(r"(?:0|[1-9][0-9]{0,15})", timestamp) is None:
                raise ValueError
            token_ms = int(timestamp)
            if (now >= challenge.expires or request["requestPackageName"] != self._package_name
                    or request["requestHash"] != request_hash or token_ms > (now + self._future_skew) * 1000
                    or now * 1000 - token_ms >= self._max_age * 1000):
                raise ValueError
            certificates, labels = app["certificateSha256Digest"], device["deviceRecognitionVerdict"]
            if (app["appRecognitionVerdict"] != "PLAY_RECOGNIZED" or app["packageName"] != self._package_name
                    or type(certificates) is not list or not 1 <= len(certificates) <= 32
                    or not all(_digest(x) and x in self._certificates for x in certificates)
                    or type(labels) is not list or not 1 <= len(labels) <= 16
                    or not all(type(label) is str for label in labels)
                    or not self._required_labels.issubset(labels)
                    or (self._require_licensed and account["appLicensingVerdict"] != "LICENSED")):
                raise ValueError
            expires = min(challenge.expires, now + self._ttl, (token_ms + self._max_age * 1000) // 1000, _MAX_TIME)
            if expires <= now:
                raise ValueError
            result = AttestationVerdict("google", "verified", challenge.app_id, challenge.subject,
                                         challenge.public_key_sha256, message_hash.hex(), expires)
        except Exception:
            pass
        if result is None:
            raise GoogleProviderError("GOOGLE_ATTESTATION_REJECTED")
        return result
