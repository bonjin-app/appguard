"""Test-only portable corpus loader and scenario runner."""

import base64
import binascii
import json
from pathlib import Path

from appguard_reference.canonical import build_signature_base
from appguard_reference.replay import InMemoryReplayStore, ReplayStoreUnavailable
from appguard_reference.types import KeyRecord, RequestInput, SignatureParameters, VerificationError
from appguard_reference.verify import verify_request

CODES = {"VERIFIED", "INVALID_REQUEST", "UNSUPPORTED_PROFILE", "INVALID_TIME", "KEY_REJECTED",
         "DIGEST_MISMATCH", "INVALID_SIGNATURE", "REPLAY_DETECTED", "REPLAY_STORE_UNAVAILABLE"}
FIELDS = {"id", "request", "parameters", "signature_b64", "key", "context", "replay_store",
          "expected_signature_base", "expected_codes"}
REQUIRED = {"valid-json", "valid-empty-body", "valid-encoded-slash", "valid-lowercase-escape",
            "forwarded-origin-ignored", "query-reordered", "path-substitution", "body-substitution",
            "body-and-digest-substitution", "token-substitution", "method-substitution",
            "configured-app-mismatch", "authenticated-subject-mismatch", "key-id-mismatch",
            "revoked-key", "expired-at-boundary", "algorithm-downgrade", "duplicate-authorization",
            "wrong-signature-length", "replay", "store-unavailable", "store-capacity"}


class FixtureFormatError(ValueError):
    """Corrupt corpus transport/schema; not a protocol rejection."""


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise FixtureFormatError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(_):
    raise FixtureFormatError("invalid JSON constant")


def _shape(value, fields):
    if type(value) is not dict or set(value) != set(fields):
        raise FixtureFormatError("invalid fixture fields")


def _bytes(value):
    if type(value) is not str:
        raise FixtureFormatError("invalid base64 transport")
    try:
        result = base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, ValueError, UnicodeError):
        raise FixtureFormatError("invalid base64 transport") from None
    if base64.b64encode(result).decode() != value:
        raise FixtureFormatError("noncanonical base64 transport")
    return result


def load_vectors(path: Path) -> list[dict]:
    try:
        records = json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=_pairs,
                             parse_constant=_reject_constant)
    except (ValueError, OSError, UnicodeError):
        raise FixtureFormatError("invalid fixture JSON") from None
    if type(records) is not list or not records:
        raise FixtureFormatError("invalid corpus root")
    seen = set()
    for record in records:
        _shape(record, FIELDS)
        ident = record["id"]
        if type(ident) is not str or not ident or ident in seen:
            raise FixtureFormatError("invalid or duplicate fixture ID")
        seen.add(ident)
        _shape(record["request"], {"method", "target", "headers", "body_b64"})
        _shape(record["parameters"], {"created", "expires", "nonce", "key_id", "algorithm", "tag"})
        _shape(record["key"], {"app_id", "key_id", "subject", "public_key_pem", "algorithm", "revoked"})
        _shape(record["context"], {"origin", "app_id", "subject", "now"})
        headers = record["request"]["headers"]
        if (type(headers) is not list or any(type(pair) is not list or len(pair) != 2
                                            or any(type(v) is not str for v in pair) for pair in headers)):
            raise FixtureFormatError("invalid header transport")
        for field in ("method", "target"):
            if type(record["request"][field]) is not str:
                raise FixtureFormatError("invalid request transport")
        _bytes(record["request"]["body_b64"])
        _bytes(record["signature_b64"])
        pem = record["key"]["public_key_pem"]
        if type(pem) is not str or not pem.isascii():
            raise FixtureFormatError("invalid public key transport")
        expected = record["expected_signature_base"]
        if expected is not None and (type(expected) is not str or not expected.isascii()):
            raise FixtureFormatError("invalid expected byte transport")
        mode = record["replay_store"]
        if type(mode) is not str or mode not in {"memory", "unavailable", "full"}:
            raise FixtureFormatError("invalid store mode")
        codes = record["expected_codes"]
        if type(codes) is not list or not codes or any(type(c) is not str or c not in CODES for c in codes):
            raise FixtureFormatError("invalid expected codes")
    return records


def validate_coverage(records):
    if not REQUIRED.issubset({record["id"] for record in records}):
        raise FixtureFormatError("missing required attack scenario")


def run_vector(record):
    raw = record["request"]
    req = RequestInput(raw["method"], raw["target"], tuple(tuple(p) for p in raw["headers"]), _bytes(raw["body_b64"]))
    params = SignatureParameters(**record["parameters"])
    key_data = {**record["key"], "public_key_pem": record["key"]["public_key_pem"].encode("ascii")}
    key = KeyRecord(**key_data)
    context = record["context"]
    try:
        base = build_signature_base(req, params, origin=context["origin"])
    except VerificationError:
        assert record["expected_signature_base"] is None, f'{record["id"]}: unexpected canonical rejection'
    else:
        assert record["expected_signature_base"] is not None, f'{record["id"]}: expected canonical rejection'
        assert base == record["expected_signature_base"].encode("ascii"), f'{record["id"]}: signature base mismatch'

    class UnavailableStore:
        def claim(self, *args, **kwargs):
            raise ReplayStoreUnavailable("injected failure")

    store = InMemoryReplayStore(capacity=1 if record["replay_store"] == "full" else 10000)
    if record["replay_store"] == "unavailable":
        store = UnavailableStore()
    elif record["replay_store"] == "full":
        # Fault injection must not validate scenario input before the verifier.
        store.claim(("occupied", "occupied", "occupied"), expires=999999999999999, now=0)
    codes = []
    for _ in record["expected_codes"]:
        try:
            result = verify_request(req, params, _bytes(record["signature_b64"]), key=key, replay=store, **context)
            codes.append(result.code)
        except VerificationError as exc:
            codes.append(exc.code)
    assert codes == record["expected_codes"], f'{record["id"]}: reason mismatch {codes}'
    return codes
