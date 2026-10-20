"""Offline trusted-transport fixtures, never genuine Google attestation proof."""
import base64
from dataclasses import replace
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from appguard.enrollment import EnrollmentError, EnrollmentService, SqliteEnrollmentStore, enrollment_message
from appguard.providers.google import GooglePlayIntegrityTransport, GooglePlayIntegrityVerifier, GoogleProviderError

CERT = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")
TOKEN = b"OFFLINE_TEST_ONLY_OPAQUE_TOKEN"
NOW = 1700000000


@pytest.fixture
def context(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    clock = [NOW]
    store = SqliteEnrollmentStore(tmp_path / "google.sqlite")
    service = EnrollmentService(store, profile="basic", clock=lambda: clock[0])
    challenge = service.issue(app_id="test-app", subject="test-user", key_id="test-key", origin="https://api.test", public_key_pem=pem)
    digest = hashlib.sha256(enrollment_message(challenge)).digest()
    payload = {"tokenPayloadExternal": {
        "requestDetails": {"requestPackageName": "io.appguard.test", "requestHash": base64.urlsafe_b64encode(digest).decode().rstrip("="), "timestampMillis": str(NOW * 1000)},
        "appIntegrity": {"appRecognitionVerdict": "PLAY_RECOGNIZED", "packageName": "io.appguard.test", "certificateSha256Digest": [CERT]},
        "deviceIntegrity": {"deviceRecognitionVerdict": ["MEETS_DEVICE_INTEGRITY"]},
        "accountDetails": {"appLicensingVerdict": "LICENSED"}}}
    def sign():
        r, s = utils.decode_dss_signature(key.sign(enrollment_message(challenge), ec.ECDSA(hashes.SHA256())))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return challenge, clock, payload, store, sign


def verifier(context, **kwargs):
    _, clock, payload, _, _ = context
    config = dict(app_id="test-app", package_name="io.appguard.test", certificate_sha256_digests={CERT},
                  transport=lambda package, token: json.dumps(payload).encode(), clock=lambda: clock[0])
    config.update(kwargs)
    return GooglePlayIntegrityVerifier(**config)


def assert_redacted(error, code):
    assert str(error.value) == code
    assert error.value.code == code
    assert error.value.__cause__ is None and error.value.__context__ is None
    assert TOKEN.decode() not in repr(error.value)


def test_verified_verdict_binds_every_enrollment_field(context):
    challenge, _, _, _, _ = context
    result = verifier(context)(challenge, TOKEN)
    assert result.provider == "google" and result.status == "verified"
    assert (result.app_id, result.subject, result.public_key_sha256) == ("test-app", "test-user", challenge.public_key_sha256)
    assert result.challenge_sha256 == hashlib.sha256(enrollment_message(challenge)).hexdigest()
    assert NOW < result.expires <= NOW + 120


@pytest.mark.parametrize("section,field,value", [
    ("requestDetails", "requestPackageName", "io.other.app"),
    ("requestDetails", "requestHash", "A" * 43),
    ("requestDetails", "requestHash", "A" * 43 + "="),
    ("requestDetails", "timestampMillis", str((NOW - 121) * 1000)),
    ("requestDetails", "timestampMillis", str((NOW + 6) * 1000)),
    ("requestDetails", "timestampMillis", NOW * 1000),
    ("requestDetails", "timestampMillis", "01700000000000"),
    ("appIntegrity", "appRecognitionVerdict", "UNRECOGNIZED_VERSION"),
    ("appIntegrity", "appRecognitionVerdict", "UNEVALUATED"),
    ("appIntegrity", "packageName", "io.other.app"),
    ("appIntegrity", "certificateSha256Digest", ["A" * 43]),
    ("appIntegrity", "certificateSha256Digest", [CERT, "A" * 43]),
    ("appIntegrity", "certificateSha256Digest", []),
    ("appIntegrity", "certificateSha256Digest", [CERT + "="]),
    ("deviceIntegrity", "deviceRecognitionVerdict", []),
    ("deviceIntegrity", "deviceRecognitionVerdict", ["MEETS_BASIC_INTEGRITY"]),
    ("deviceIntegrity", "deviceRecognitionVerdict", "MEETS_DEVICE_INTEGRITY"),
    ("accountDetails", "appLicensingVerdict", "UNLICENSED"),
    ("accountDetails", "appLicensingVerdict", "UNEVALUATED"),
])
def test_provider_checks_fail_closed(context, section, field, value):
    challenge, _, payload, _, _ = context
    payload["tokenPayloadExternal"][section][field] = value
    with pytest.raises(GoogleProviderError) as error:
        verifier(context)(challenge, TOKEN)
    assert_redacted(error, "GOOGLE_ATTESTATION_REJECTED")


@pytest.mark.parametrize("section", ["requestDetails", "appIntegrity", "deviceIntegrity", "accountDetails"])
def test_missing_sections_reject(context, section):
    challenge, _, payload, _, _ = context
    del payload["tokenPayloadExternal"][section]
    with pytest.raises(GoogleProviderError, match="^GOOGLE_ATTESTATION_REJECTED$"):
        verifier(context)(challenge, TOKEN)


@pytest.mark.parametrize("field,value", [("app_id", "other-app"), ("subject", "other-user"), ("public_key_sha256", "0" * 64), ("key_id", "other-key"), ("origin", "https://other.test"), ("expires", NOW + 121)])
def test_other_challenge_context_cannot_reuse_provider_token(context, field, value):
    challenge = replace(context[0], **{field: value})
    with pytest.raises(GoogleProviderError, match="^GOOGLE_ATTESTATION_REJECTED$"):
        verifier(context)(challenge, TOKEN)


@pytest.mark.parametrize("token", [b"", b"x" * 65537, b"\xff", b"token\nsecret", {"status": "verified"}])
def test_invalid_opaque_evidence_never_calls_transport(context, token):
    seen = []
    verify = verifier(context, transport=lambda *args: seen.append(args))
    with pytest.raises(GoogleProviderError, match="^GOOGLE_ATTESTATION_REJECTED$"):
        verify(context[0], token)
    assert seen == []


@pytest.mark.parametrize("body", [b'{}', b'{"tokenPayloadExternal":null}', b'{"tokenPayloadExternal":{},"tokenPayloadExternal":{}}', b'{} trailing', b'\xff', b'[' * 40 + b']' * 40, b'x' * 131073, {"tokenPayloadExternal": {}}])
def test_only_bounded_strict_raw_json_from_trusted_transport_is_used(context, body):
    with pytest.raises(GoogleProviderError, match="^GOOGLE_ATTESTATION_REJECTED$"):
        verifier(context, transport=lambda *args: body)(context[0], TOKEN)


def test_transport_and_clock_failures_are_redacted(context):
    def fail(*args):
        raise RuntimeError(TOKEN.decode())
    with pytest.raises(GoogleProviderError) as error:
        verifier(context, transport=fail)(context[0], TOKEN)
    assert_redacted(error, "GOOGLE_ATTESTATION_REJECTED")
    with pytest.raises(GoogleProviderError) as error:
        verifier(context, clock=fail)(context[0], TOKEN)
    assert_redacted(error, "GOOGLE_ATTESTATION_REJECTED")


@pytest.mark.parametrize("kwargs", [
    {"app_id": "bad app"}, {"package_name": "../evil"}, {"certificate_sha256_digests": set()},
    {"certificate_sha256_digests": {CERT + "="}}, {"transport": None}, {"clock": 4},
    {"required_device_labels": set()}, {"required_device_labels": {"TRUSTED"}},
    {"require_licensed": "false"}, {"max_age_seconds": True}, {"max_age_seconds": 0},
    {"future_skew_seconds": 61}, {"verdict_ttl_seconds": 0}])
def test_invalid_configuration_is_redacted(context, kwargs):
    with pytest.raises(GoogleProviderError) as error:
        verifier(context, **kwargs)
    assert_redacted(error, "GOOGLE_CONFIGURATION_INVALID")


def test_explicit_policy_overrides_are_enforced(context):
    challenge, _, payload, _, _ = context
    payload["tokenPayloadExternal"]["accountDetails"]["appLicensingVerdict"] = "UNLICENSED"
    payload["tokenPayloadExternal"]["deviceIntegrity"]["deviceRecognitionVerdict"].append("MEETS_STRONG_INTEGRITY")
    assert verifier(context, require_licensed=False, required_device_labels={"MEETS_DEVICE_INTEGRITY", "MEETS_STRONG_INTEGRITY"})(challenge, TOKEN).status == "verified"
    payload["tokenPayloadExternal"]["deviceIntegrity"]["deviceRecognitionVerdict"].remove("MEETS_STRONG_INTEGRITY")
    with pytest.raises(GoogleProviderError):
        verifier(context, require_licensed=False, required_device_labels={"MEETS_STRONG_INTEGRITY"})(challenge, TOKEN)


def test_expiry_and_freshness_are_rechecked_after_provider_work(context):
    challenge, clock, payload, _, _ = context
    def slow(*args):
        clock[0] += 121
        return json.dumps(payload).encode()
    with pytest.raises(GoogleProviderError):
        verifier(context, transport=slow)(challenge, TOKEN)


def test_real_enrollment_service_completes_and_consumes_once(context):
    challenge, clock, _, store, sign = context
    service = EnrollmentService(store, profile="strict", clock=lambda: clock[0], attestation_verifier=verifier(context))
    proof = sign()
    def attempt(_):
        try:
            return service.complete(challenge.nonce, app_id=challenge.app_id, subject=challenge.subject, proof=proof, evidence=TOKEN).provider
        except EnrollmentError as error:
            return error.code
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(attempt, range(4)))
    assert results.count("google") == 1
    assert set(results) <= {"google", "CHALLENGE_REJECTED"}
    assert store.lookup("test-app", "test-user", "test-key").attestation == "verified"


def test_stale_fixture_rejects_without_consuming_real_enrollment(context):
    challenge, clock, payload, store, sign = context
    payload["tokenPayloadExternal"]["requestDetails"]["timestampMillis"] = str((NOW - 121) * 1000)
    service = EnrollmentService(store, profile="balanced", clock=lambda: clock[0], attestation_verifier=verifier(context))
    with pytest.raises(EnrollmentError, match="^ATTESTATION_UNAVAILABLE$"):
        service.complete(challenge.nonce, app_id=challenge.app_id, subject=challenge.subject, proof=sign(), evidence=TOKEN)
    assert store.pending(challenge.nonce) == challenge
    assert store.lookup("test-app", "test-user", "test-key") is None


class Response:
    def __init__(self, body=b'{}', status=200, headers=None):
        self.body, self.status, self.headers = body, status, headers or {}
        self.offset, self.read_sizes = 0, []
    def getheader(self, name, default=None):
        return self.headers.get(name, default)
    def read(self, amount):
        self.read_sizes.append(amount)
        result = self.body[self.offset:self.offset + amount]
        self.offset += len(result)
        return result


@pytest.fixture
def wire(monkeypatch):
    connections = []
    response = Response()
    class Connection:
        def __init__(self, host, **kwargs):
            self.host, self.options, self.requests, self.closed = host, kwargs, [], False
            connections.append(self)
        def request(self, method, path, body=None, headers=None):
            self.requests.append((method, path, body, headers))
        def getresponse(self):
            return response
        def close(self):
            self.closed = True
    monkeypatch.setattr("appguard.providers.google.http.client.HTTPSConnection", Connection)
    return connections, response


def test_official_transport_is_explicit_authenticated_bounded_and_lazy(wire):
    connections, response = wire
    calls = []
    transport = GooglePlayIntegrityTransport(access_token_provider=lambda: calls.append(1) or "TEST_ONLY_BEARER", timeout_seconds=3)
    assert not connections and not calls
    assert transport("io.appguard.test", TOKEN.decode()) == b'{}'
    conn = connections[0]
    assert conn.host == "playintegrity.googleapis.com" and conn.options["timeout"] == 3
    assert conn.options["context"].verify_mode.name == "CERT_REQUIRED"
    method, path, body, headers = conn.requests[0]
    assert (method, path) == ("POST", "/v1/io.appguard.test:decodeIntegrityToken")
    assert json.loads(body) == {"integrityToken": TOKEN.decode()}
    assert headers["Authorization"] == "Bearer TEST_ONLY_BEARER"
    assert headers["Content-Type"] == "application/json" and conn.closed
    assert max(response.read_sizes) <= 131073


@pytest.mark.parametrize("status", [301, 302, 307, 400, 401, 403, 429, 500])
def test_official_transport_never_follows_redirect_or_accepts_error(wire, status):
    connections, response = wire
    response.status = status
    response.body = TOKEN
    response.headers = {"Location": "https://evil.test"}
    with pytest.raises(GoogleProviderError) as error:
        GooglePlayIntegrityTransport(access_token_provider=lambda: "TEST_ONLY_BEARER")("io.appguard.test", TOKEN.decode())
    assert_redacted(error, "GOOGLE_PROVIDER_UNAVAILABLE")
    assert len(connections) == 1 and connections[0].closed and response.offset == 0


@pytest.mark.parametrize("body,headers", [(b'x' * 131073, {}), (b'{}', {"Content-Length": "131073"}), (b'{}', {"Content-Encoding": "gzip"}), (b'{}', {"Content-Length": "invalid"})])
def test_official_transport_rejects_oversize_and_encoded_responses(wire, body, headers):
    _, response = wire
    response.body, response.headers = body, headers
    with pytest.raises(GoogleProviderError, match="^GOOGLE_PROVIDER_UNAVAILABLE$"):
        GooglePlayIntegrityTransport(access_token_provider=lambda: "TEST_ONLY_BEARER")("io.appguard.test", TOKEN.decode())


@pytest.mark.parametrize("token", ["", "secret\nInjected: header", None, "x" * 8193])
def test_bad_auth_never_opens_connection(wire, token):
    connections, _ = wire
    with pytest.raises(GoogleProviderError) as error:
        GooglePlayIntegrityTransport(access_token_provider=lambda: token)("io.appguard.test", TOKEN.decode())
    assert_redacted(error, "GOOGLE_PROVIDER_UNAVAILABLE")
    assert not connections


def test_credential_callback_error_loses_raw_exception(wire):
    def fail():
        raise RuntimeError(TOKEN.decode())
    with pytest.raises(GoogleProviderError) as error:
        GooglePlayIntegrityTransport(access_token_provider=fail)("io.appguard.test", TOKEN.decode())
    assert_redacted(error, "GOOGLE_PROVIDER_UNAVAILABLE")
    assert wire[0] == []


@pytest.mark.parametrize("kwargs", [{"access_token_provider": None}, {"access_token_provider": lambda: "token", "timeout_seconds": 0}, {"access_token_provider": lambda: "token", "timeout_seconds": float('nan')}, {"access_token_provider": lambda: "token", "timeout_seconds": 31}])
def test_official_transport_configuration_has_fixed_errors(kwargs):
    with pytest.raises(GoogleProviderError) as error:
        GooglePlayIntegrityTransport(**kwargs)
    assert_redacted(error, "GOOGLE_CONFIGURATION_INVALID")

@pytest.mark.parametrize("package", ["../evil", "io.appguard/test", "io.appguard.test?x", "io.appguard.test\r\nX:secret", None])
def test_transport_rejects_invalid_package_before_credentials_or_network(wire, package):
    calls = []
    with pytest.raises(GoogleProviderError) as error:
        GooglePlayIntegrityTransport(access_token_provider=lambda: calls.append(1) or "token")(package, TOKEN.decode())
    assert_redacted(error, "GOOGLE_PROVIDER_UNAVAILABLE")
    assert calls == [] and wire[0] == []


def test_network_timeout_is_redacted_and_connection_closed(wire, monkeypatch):
    connections, _ = wire
    def timeout(self):
        raise TimeoutError(TOKEN.decode())
    monkeypatch.setattr("appguard.providers.google.http.client.HTTPSConnection.getresponse", timeout)
    with pytest.raises(GoogleProviderError) as error:
        GooglePlayIntegrityTransport(access_token_provider=lambda: "token")("io.appguard.test", TOKEN.decode())
    assert_redacted(error, "GOOGLE_PROVIDER_UNAVAILABLE")
    assert connections[0].closed


@pytest.mark.parametrize("extra", [',"extra":NaN', ',"extra":Infinity', ',"extra":1e999', ',"extra":{"x":1,"x":2}'])
def test_nested_duplicates_and_nonfinite_json_cannot_reach_a_verdict(context, extra):
    payload = json.dumps(context[2]).encode()
    body = payload[:-1] + extra.encode() + b'}'
    with pytest.raises(GoogleProviderError):
        verifier(context, transport=lambda *args: body)(context[0], TOKEN)


@pytest.mark.parametrize("testing", [{"isTestingResponse": True}, {"isTestingResponse": "false"}, {}, None])
def test_google_testing_overrides_cannot_become_verified_attestation(context, testing):
    context[2]["tokenPayloadExternal"]["testingDetails"] = testing
    with pytest.raises(GoogleProviderError, match="^GOOGLE_ATTESTATION_REJECTED$"):
        verifier(context)(context[0], TOKEN)
