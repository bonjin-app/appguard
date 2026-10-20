"""Restricted RFC 9421 profile; no raw HTTP/Structured Fields parsing."""

import base64
import binascii
import hashlib
import hmac
import re
from urllib.parse import unquote_to_bytes

from .types import RequestInput, SignatureParameters, VerificationError

ALGORITHM = "ecdsa-p256-sha256"
TAG = "appguard-request-v0"
COMPONENTS = ("@method", "@target-uri", "content-type", "content-digest", "authorization", "appguard-app-id")
_SINGLETONS = frozenset(COMPONENTS[2:]) | {"content-encoding"}
_IDENTIFIER = re.compile(r"[A-Za-z0-9._:-]{1,128}", re.ASCII)
_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", re.ASCII)


def validate_identifier(value: str) -> None:
    if type(value) is not str or not _IDENTIFIER.fullmatch(value):
        raise VerificationError("INVALID_REQUEST")


def _headers(request: RequestInput) -> dict[str, str]:
    if not isinstance(request, RequestInput) or type(request.body) is not bytes:
        raise VerificationError("INVALID_REQUEST")
    if len(request.body) > 1024 * 1024 or type(request.headers) is not tuple or len(request.headers) > 64:
        raise VerificationError("INVALID_REQUEST")
    if (type(request.method) is not str or not 1 <= len(request.method) <= 32
            or request.method != request.method.upper() or not _TOKEN.fullmatch(request.method)):
        raise VerificationError("INVALID_REQUEST")
    _validate_target(request.target)
    result: dict[str, str] = {}
    size = 0
    for pair in request.headers:
        if type(pair) is not tuple or len(pair) != 2:
            raise VerificationError("INVALID_REQUEST")
        name, value = pair
        if type(name) is not str or type(value) is not str:
            raise VerificationError("INVALID_REQUEST")
        size += len(name) + len(value)
        if size > 16384 or not _TOKEN.fullmatch(name):
            raise VerificationError("INVALID_REQUEST")
        if value != value.strip(" ") or any(not 0x20 <= ord(c) <= 0x7E for c in value):
            raise VerificationError("INVALID_REQUEST")
        name = name.lower()
        if name in _SINGLETONS and name in result:
            raise VerificationError("INVALID_REQUEST")
        result[name] = value
    if not all(name in result for name in COMPONENTS[2:]):
        raise VerificationError("INVALID_REQUEST")
    if not result["content-type"] or result.get("content-encoding", "identity") != "identity":
        raise VerificationError("INVALID_REQUEST")
    if not re.fullmatch(r"(?i:Bearer) [A-Za-z0-9._~+/-]+=*", result["authorization"]):
        raise VerificationError("INVALID_REQUEST")
    validate_identifier(result["appguard-app-id"])
    _digest_bytes(result["content-digest"])
    return result


def _validate_target(target: str) -> None:
    if (type(target) is not str or not 1 <= len(target) <= 8192 or target.startswith("//")
            or not re.fullmatch(r"/[A-Za-z0-9._~!$&'()*+,;=:@/?%\-]*", target)
            or re.search(r"%(?![0-9a-fA-F]{2})", target)):
        raise VerificationError("INVALID_REQUEST")
    decoded = unquote_to_bytes(target)
    if any(c < 0x20 or c == 0x7F for c in decoded) or b"\\" in decoded:
        raise VerificationError("INVALID_REQUEST")
    path = unquote_to_bytes(target.split("?", 1)[0])
    if any(segment in (b".", b"..") for segment in path.split(b"/")):
        raise VerificationError("INVALID_REQUEST")


def _validate_origin(origin: str) -> None:
    if type(origin) is not str or len(origin) > 512:
        raise VerificationError("INVALID_REQUEST")
    match = re.fullmatch(r"https://([a-z0-9.-]+)(?::([1-9][0-9]{0,4}))?", origin)
    if not match:
        raise VerificationError("INVALID_REQUEST")
    host, port = match.groups()
    if (len(host) > 253 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                               for label in host.split("."))
            or (port is not None and (int(port) > 65535 or int(port) == 443))):
        raise VerificationError("INVALID_REQUEST")


def _validate_parameters(parameters: SignatureParameters) -> None:
    if not isinstance(parameters, SignatureParameters):
        raise VerificationError("INVALID_REQUEST")
    if parameters.algorithm != ALGORITHM or parameters.tag != TAG:
        raise VerificationError("UNSUPPORTED_PROFILE")
    validate_identifier(parameters.key_id)
    nonce = parameters.nonce
    if type(nonce) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{22}", nonce):
        raise VerificationError("INVALID_REQUEST")
    raw = base64.urlsafe_b64decode(nonce + "==")
    if len(raw) != 16 or base64.urlsafe_b64encode(raw).decode().rstrip("=") != nonce:
        raise VerificationError("INVALID_REQUEST")
    for timestamp in (parameters.created, parameters.expires):
        if type(timestamp) is not int or not 0 <= timestamp <= 999999999999999:
            raise VerificationError("INVALID_TIME")


def _digest_bytes(value: str) -> bytes:
    match = re.fullmatch(r"sha-256=:([A-Za-z0-9+/]{43}=):", value)
    if not match:
        raise VerificationError("INVALID_REQUEST")
    try:
        raw = base64.b64decode(match[1], validate=True)
    except (binascii.Error, ValueError):
        raise VerificationError("INVALID_REQUEST") from None
    if len(raw) != 32 or base64.b64encode(raw).decode() != match[1]:
        raise VerificationError("INVALID_REQUEST")
    return raw


def build_signature_base(request: RequestInput, parameters: SignatureParameters, *, origin: str) -> bytes:
    headers = _headers(request)
    _validate_origin(origin)
    _validate_parameters(parameters)
    values = (request.method, origin + request.target, *(headers[name] for name in COMPONENTS[2:]))
    lines = [f'"{name}": {value}' for name, value in zip(COMPONENTS, values)]
    covered = " ".join(f'"{name}"' for name in COMPONENTS)
    params = (f'({covered});created={parameters.created};expires={parameters.expires}'
              f';nonce="{parameters.nonce}";keyid="{parameters.key_id}"'
              f';alg="{parameters.algorithm}";tag="{parameters.tag}"')
    lines.append(f'"@signature-params": {params}')
    return "\n".join(lines).encode("ascii")


def validate_content_digest(request: RequestInput) -> None:
    headers = _headers(request)
    expected = _digest_bytes(headers["content-digest"])
    if not hmac.compare_digest(expected, hashlib.sha256(request.body).digest()):
        raise VerificationError("DIGEST_MISMATCH")
