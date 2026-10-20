"""Strict v0 HTTP envelope parser."""

import base64
import binascii
import re
from dataclasses import dataclass, field

from .canonical import ALGORITHM, COMPONENTS, TAG
from .types import SignatureParameters, VerificationError

_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", re.ASCII)
_SINGLETONS = set(COMPONENTS[2:]) | {
    "signature-input", "signature", "content-encoding", "content-length", "transfer-encoding", "host",
}
_INT = r"(?:0|-?[1-9][0-9]{0,14})"
_COVERED = " ".join(f'"{name}"' for name in COMPONENTS)
_INPUT = re.compile(
    re.escape(f"appguard=({_COVERED})") + rf';created=({_INT});expires=({_INT})'
    + r';nonce="([A-Za-z0-9_-]{22})";keyid="([A-Za-z0-9._:-]{1,128})"'
    + r';alg="([A-Za-z0-9._:-]{1,64})";tag="([A-Za-z0-9._:-]{1,64})"', re.ASCII,
)


@dataclass(frozen=True)
class ParsedSignature:
    parameters: SignatureParameters
    signature: bytes = field(repr=False)


def validate_headers(headers: tuple[tuple[str, str], ...]) -> dict[str, str]:
    if type(headers) is not tuple or len(headers) > 64:
        raise VerificationError("INVALID_REQUEST")
    result: dict[str, str] = {}
    size = 0
    for pair in headers:
        if type(pair) is not tuple or len(pair) != 2 or any(type(v) is not str for v in pair):
            raise VerificationError("INVALID_REQUEST")
        name, value = pair
        size += len(name) + len(value)
        if size > 16384 or not _TOKEN.fullmatch(name):
            raise VerificationError("INVALID_REQUEST")
        if value != value.strip(" ") or any(not 0x20 <= ord(c) <= 0x7E for c in value):
            raise VerificationError("INVALID_REQUEST")
        name = name.lower()
        if name in _SINGLETONS and name in result:
            raise VerificationError("INVALID_REQUEST")
        result[name] = value
    if "content-length" in result:
        if not re.fullmatch(r"(?:0|[1-9][0-9]{0,14})", result["content-length"]):
            raise VerificationError("INVALID_REQUEST")
        if "transfer-encoding" in result:
            raise VerificationError("INVALID_REQUEST")
    if result.get("transfer-encoding", "chunked") != "chunked":
        raise VerificationError("INVALID_REQUEST")
    if result.get("content-encoding", "identity") != "identity":
        raise VerificationError("INVALID_REQUEST")
    return result


def parse_signatures(headers: tuple[tuple[str, str], ...]) -> ParsedSignature:
    values = validate_headers(headers)
    match = _INPUT.fullmatch(values.get("signature-input", ""))
    sigmatch = re.fullmatch(r"appguard=:([A-Za-z0-9+/]+={0,2}):", values.get("signature", ""))
    if not match or not sigmatch:
        raise VerificationError("INVALID_REQUEST")
    created, expires, nonce, key_id, algorithm, tag = match.groups()
    if algorithm != ALGORITHM or tag != TAG:
        raise VerificationError("UNSUPPORTED_PROFILE")
    try:
        signature = base64.b64decode(sigmatch[1], validate=True)
    except (binascii.Error, ValueError):
        raise VerificationError("INVALID_REQUEST") from None
    if len(signature) != 64 or base64.b64encode(signature).decode() != sigmatch[1]:
        raise VerificationError("INVALID_REQUEST")
    return ParsedSignature(SignatureParameters(int(created), int(expires), nonce, key_id, algorithm, tag), signature)
