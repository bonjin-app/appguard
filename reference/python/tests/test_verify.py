"""Catch cross-context signatures, time boundaries, nonce abuse and store failure."""

import traceback
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Barrier

import pytest

from appguard_reference.canonical import build_signature_base
from appguard_reference.replay import InMemoryReplayStore
from appguard_reference.types import VerificationError
from appguard_reference.verify import verify_request
from conftest import NOW, ORIGIN


def call(req, params, signature, key, **kwargs):
    options = dict(origin=ORIGIN, app_id="test-app", subject="test-user", key=key,
                   now=NOW, replay=InMemoryReplayStore())
    options.update(kwargs)
    return verify_request(req, params, signature, **options)


def test_verified_is_not_authorization(request_input, parameters, signature, key_record):
    result = call(request_input, parameters, signature, key_record)
    assert (result.code, result.app_id, result.key_id, result.expires) == (
        "VERIFIED", "test-app", "test-key", NOW + 120)
    assert not hasattr(result, "authorized")


@pytest.mark.parametrize("created_delta,life,now_delta,code", [
    (0, 120, 0, "VERIFIED"), (0, 121, 0, "INVALID_TIME"),
    (30, 120, 0, "VERIFIED"), (31, 120, 0, "INVALID_TIME"),
    (0, 120, 119, "VERIFIED"), (0, 120, 120, "INVALID_TIME"),
    (0, 0, 0, "INVALID_TIME"), (0, -1, 0, "INVALID_TIME"),
])
def test_time_boundaries(request_input, parameters, sign_case, created_delta, life, now_delta, code):
    params = replace(parameters, created=NOW + created_delta, expires=NOW + created_delta + life)
    key, sig = sign_case(request_input, params)
    if code == "VERIFIED":
        assert call(request_input, params, sig, key, now=NOW + now_delta).code == code
    else:
        with pytest.raises(VerificationError, match=f"^{code}$"):
            call(request_input, params, sig, key, now=NOW + now_delta)


@pytest.mark.parametrize("field,value", [("created", True), ("expires", False), ("created", 1.5),
                                       ("expires", "1"), ("created", -1), ("created", 10**15)])
def test_invalid_timestamp_types(request_input, parameters, signature, key_record, field, value):
    with pytest.raises(VerificationError, match="^INVALID_TIME$"):
        call(request_input, replace(parameters, **{field: value}), signature, key_record)


@pytest.mark.parametrize("now", [True, 1.5, "1", -1, 10**15])
def test_invalid_clock(request_input, parameters, signature, key_record, now):
    with pytest.raises(VerificationError, match="^INVALID_TIME$"):
        call(request_input, parameters, signature, key_record, now=now)


@pytest.mark.parametrize("nonce", ["", "a" * 21, "a" * 23, "AAECAwQFBgcICQoLDA0ODw==",
                                   "AAECAwQFBgcICQoLDA0ODx", "!" * 22, None])
def test_invalid_nonce(request_input, parameters, signature, key_record, nonce):
    with pytest.raises(VerificationError, match="^INVALID_REQUEST$"):
        call(request_input, replace(parameters, nonce=nonce), signature, key_record)


@pytest.mark.parametrize("field,value", [("app_id", "other-app"), ("subject", "other-user"),
                                       ("key_id", "other-key"), ("revoked", True),
                                       ("revoked", 0), ("algorithm", "hmac-sha256"),
                                       ("public_key_pem", b"TEST_ONLY_TOKEN")])
def test_untrusted_key_binding(request_input, parameters, signature, key_record, field, value):
    with pytest.raises(VerificationError, match="^KEY_REJECTED$"):
        call(request_input, parameters, signature, replace(key_record, **{field: value}))


@pytest.mark.parametrize("context", [dict(app_id="other-app"), dict(subject="other-user")])
def test_authenticated_context_binding(request_input, parameters, signature, key_record, context):
    with pytest.raises(VerificationError, match="^KEY_REJECTED$"):
        call(request_input, parameters, signature, key_record, **context)


def test_invalid_signature_cannot_reserve_nonce(request_input, parameters, signature, key_record):
    store = InMemoryReplayStore()
    with pytest.raises(VerificationError, match="^INVALID_SIGNATURE$"):
        call(request_input, parameters, b"x" * 64, key_record, replay=store)
    assert call(request_input, parameters, signature, key_record, replay=store).code == "VERIFIED"
    with pytest.raises(VerificationError, match="^REPLAY_DETECTED$"):
        call(request_input, parameters, signature, key_record, replay=store)


def test_parallel_verified_requests_accept_once(request_input, parameters, signature, key_record):
    store = InMemoryReplayStore()
    barrier = Barrier(32)

    def attempt(_):
        barrier.wait(timeout=10)
        try:
            return call(request_input, parameters, signature, key_record, replay=store).code
        except VerificationError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=32) as pool:
        codes = list(pool.map(attempt, range(32)))
    assert codes.count("VERIFIED") == 1
    assert codes.count("REPLAY_DETECTED") == 31


def test_store_error_does_not_leak_request(request_input, parameters, signature, key_record):
    class BrokenStore:
        def claim(self, *args, **kwargs):
            raise RuntimeError("TEST_ONLY_TOKEN BODY_SECRET")

    with pytest.raises(VerificationError, match="^REPLAY_STORE_UNAVAILABLE$") as caught:
        call(request_input, parameters, signature, key_record, replay=BrokenStore())
    error = "".join(traceback.format_exception(caught.value))
    assert "TEST_ONLY_TOKEN" not in error and "BODY_SECRET" not in error
    assert "TEST_ONLY_TOKEN" not in repr(request_input)
    assert "{}" not in repr(request_input)


@pytest.mark.parametrize("answer", [None, 1, "yes"])
def test_bad_store_contract_fails_closed(request_input, parameters, signature, key_record, answer):
    class BadStore:
        def claim(self, *args, **kwargs):
            return answer

    with pytest.raises(VerificationError, match="^REPLAY_STORE_UNAVAILABLE$"):
        call(request_input, parameters, signature, key_record, replay=BadStore())


def test_full_store_fails_closed(request_input, parameters, signature, key_record):
    store = InMemoryReplayStore(capacity=1)
    store.claim(("other", "key", "nonce"), expires=NOW + 120, now=NOW)
    with pytest.raises(VerificationError, match="^REPLAY_STORE_UNAVAILABLE$"):
        call(request_input, parameters, signature, key_record, replay=store)


def test_failure_precedence(request_input, parameters, signature, key_record):
    bad_body = replace(request_input, body=b"changed")
    with pytest.raises(VerificationError, match="^INVALID_TIME$"):
        call(bad_body, parameters, b"bad", replace(key_record, revoked=True), now=NOW + 120)
    with pytest.raises(VerificationError, match="^KEY_REJECTED$"):
        call(bad_body, parameters, b"bad", replace(key_record, revoked=True))
    with pytest.raises(VerificationError, match="^DIGEST_MISMATCH$"):
        call(bad_body, parameters, b"bad", key_record)


@pytest.mark.parametrize("limit_kind", ["body", "target", "header_count", "header_bytes", "app_id", "key_id"])
def test_input_limit_boundaries(request_input, parameters, limit_kind):
    def bounded(extra):
        req, params = request_input, parameters
        if limit_kind == "body":
            req = replace(req, body=b"x" * (1024 * 1024 + extra))
        elif limit_kind == "target":
            req = replace(req, target="/" + "x" * (8191 + extra))
        elif limit_kind == "header_count":
            req = replace(req, headers=req.headers + (("X", "v"),) * (60 + extra))
        elif limit_kind == "header_bytes":
            size = sum(len(k) + len(v) for k, v in req.headers)
            req = replace(req, headers=req.headers + (("X-Pad", "x" * (16384 - size - 5 + extra)),))
        elif limit_kind == "app_id":
            req = replace(req, headers=tuple((k, "a" * (128 + extra) if k == "AppGuard-App-Id" else v)
                                            for k, v in req.headers))
        else:
            params = replace(params, key_id="a" * (128 + extra))
        return req, params

    req, params = bounded(0)
    assert isinstance(build_signature_base(req, params, origin=ORIGIN), bytes)
    req, params = bounded(1)
    with pytest.raises(VerificationError, match="^INVALID_REQUEST$"):
        build_signature_base(req, params, origin=ORIGIN)


@pytest.mark.parametrize("subject", ["a" * 129, "bad\nsubject", "", None])
def test_subject_limit_and_syntax(request_input, parameters, signature, key_record, subject):
    with pytest.raises(VerificationError, match="^INVALID_REQUEST$"):
        call(request_input, parameters, signature, key_record, subject=subject)


def test_exact_subject_limit_can_verify(request_input, parameters, signature, key_record):
    subject = "a" * 128
    assert call(request_input, parameters, signature, replace(key_record, subject=subject), subject=subject).code == "VERIFIED"
