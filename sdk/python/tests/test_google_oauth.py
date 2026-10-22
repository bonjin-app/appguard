"""Synthetic OAuth only: no Google credentials, network, or attestation proof."""

import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib
import json
import threading
import time
from urllib.parse import parse_qs

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from appguard.providers.google import GooglePlayIntegrityTransport, GoogleProviderError

EMAIL = "offline-test@example-project.iam.gserviceaccount.com"
TOKEN = "OFFLINE_ONLY_ACCESS_TOKEN"
NOW = 1700000000
SCOPE = "https://www.googleapis.com/auth/playintegrity"


@pytest.fixture(scope="module")
def key():
    value = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = value.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption())
    return value, pem


@pytest.fixture
def oauth():
    # Import inside the fixture so the missing feature produces one direct failure.
    return importlib.import_module("appguard.providers.google_oauth")


class Response:
    def __init__(self, *, body=None, status=200, headers=None):
        self.body = body if body is not None else json.dumps({
            "access_token": TOKEN, "token_type": "Bearer", "expires_in": 3600,
            "scope": SCOPE}).encode()
        self.status = status
        self.headers = {"Content-Type": "application/json; charset=UTF-8"}
        self.headers.update(headers or {})
        self.read_sizes = []

    def getheader(self, name, default=None):
        return self.headers.get(name, default)

    def read(self, size):
        self.read_sizes.append(size)
        return self.body[:size]


@pytest.fixture
def wire(oauth, monkeypatch):
    calls, connections = [], []
    response = [Response()]

    class Connection:
        def __init__(self, host, **options):
            self.host, self.options, self.closed = host, options, False
            connections.append(self)

        def request(self, method, path, body, headers):
            calls.append((self.host, method, path, body, headers, self.options))

        def getresponse(self):
            return response[0]

        def close(self):
            self.closed = True

    monkeypatch.setattr(oauth.http.client, "HTTPSConnection", Connection)
    return calls, connections, response


def provider(oauth, key, **options):
    config = dict(service_account_email=EMAIL, private_key_pem=key[1], clock=lambda: NOW)
    config.update(options)
    return oauth.GoogleServiceAccountTokenProvider(**config)


def assert_error(error, code="GOOGLE_OAUTH_UNAVAILABLE"):
    assert type(error.value) is GoogleProviderError
    assert str(error.value) == error.value.code == code
    assert error.value.__cause__ is None and error.value.__context__ is None
    assert TOKEN not in repr(error.value) and EMAIL not in repr(error.value)


def test_service_account_oauth_api_exists():
    spec = importlib.util.find_spec("appguard.providers.google_oauth")
    assert spec is not None, "explicit service-account token lifecycle is missing"


def test_lazy_fixed_endpoint_jwt_and_independent_rsa_verification(oauth, key, wire, monkeypatch):
    calls, connections, response = wire
    monkeypatch.setenv("HTTPS_PROXY", "http://untrusted.invalid:8")
    source = provider(oauth, key, timeout_seconds=3)
    assert calls == connections == []
    assert source() == TOKEN
    host, method, path, body, headers, options = calls[0]
    assert (host, method, path) == ("oauth2.googleapis.com", "POST", "/token")
    assert options["timeout"] == 3
    assert options["context"].verify_mode.name == "CERT_REQUIRED"
    assert headers == {"Content-Type": "application/x-www-form-urlencoded",
                       "Accept": "application/json", "Accept-Encoding": "identity"}
    fields = parse_qs(body.decode("ascii"), strict_parsing=True)
    assert set(fields) == {"grant_type", "assertion"}
    assert fields["grant_type"] == ["urn:ietf:params:oauth:grant-type:jwt-bearer"]
    parts = fields["assertion"][0].split(".")
    assert len(parts) == 3 and all("=" not in part for part in parts)
    decode = lambda value: base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    assert json.loads(decode(parts[0])) == {"alg": "RS256", "typ": "JWT"}
    assert json.loads(decode(parts[1])) == {"iss": EMAIL, "scope": SCOPE,
        "aud": "https://oauth2.googleapis.com/token", "iat": NOW, "exp": NOW + 3600}
    # Independently recover and inspect EMSA-PKCS1-v1_5 using integer RSA,
    # rather than sharing the implementation's signing/encoding helpers.
    public = key[0].public_key().public_numbers()
    signature = decode(parts[2])
    encoded = pow(int.from_bytes(signature, "big"), public.e, public.n).to_bytes(256, "big")
    digest_info = bytes.fromhex("3031300d060960864801650304020105000420")
    digest_info += hashlib.sha256((parts[0] + "." + parts[1]).encode("ascii")).digest()
    assert encoded == b"\x00\x01" + b"\xff" * 202 + b"\x00" + digest_info
    assert connections[0].closed and response[0].read_sizes == [32769]
    assert EMAIL not in repr(source) and TOKEN not in repr(source)
    assert "PRIVATE KEY" not in repr(source)


def test_import_and_construction_do_not_open_network(oauth, key, monkeypatch):
    def deny(*args, **kwargs):
        pytest.fail("import/construction attempted a network operation")
    monkeypatch.setattr(oauth.http.client, "HTTPSConnection", deny)
    monkeypatch.setattr("socket.create_connection", deny)
    importlib.reload(oauth)
    provider(oauth, key)


def test_explicit_provider_integrates_with_existing_decode_transport(oauth, key, wire):
    calls, _, response = wire
    source = provider(oauth, key)
    transport = GooglePlayIntegrityTransport(access_token_provider=source)
    source()
    response[0] = Response(body=b'{"tokenPayloadExternal":{}}')
    assert transport("io.appguard.test", "OFFLINE_INTEGRITY_TOKEN") == response[0].body
    assert len(calls) == 2
    assert calls[1][0] == "playintegrity.googleapis.com"
    assert calls[1][4]["Authorization"] == "Bearer " + TOKEN


def test_cache_refreshes_at_skew_boundary_and_discards_old_token(oauth, key, wire):
    wall = [NOW]
    source = provider(oauth, key, clock=lambda: wall[0])
    assert source() == TOKEN
    wall[0] += 3539
    assert source() == TOKEN and len(wire[0]) == 1
    wall[0] += 1
    wire[2][0] = Response(body=b'{"error":"private provider detail"}', status=400)
    with pytest.raises(GoogleProviderError) as error:
        source()
    assert_error(error)
    assert len(wire[0]) == 2
    wall[0] += 60
    with pytest.raises(GoogleProviderError):
        source()
    assert len(wire[0]) == 3  # Never fall back to the old, now-expired token.
    wire[2][0] = Response()
    assert source() == TOKEN


def test_monotonic_expiry_prevents_stopped_wall_clock_extending_cache(oauth, key, wire, monkeypatch):
    mono = [100.0]
    monkeypatch.setattr(oauth, "_monotonic", lambda: mono[0])
    source = provider(oauth, key)
    assert source() == TOKEN
    mono[0] += 3540
    assert source() == TOKEN and len(wire[0]) == 2


@pytest.mark.parametrize("bad", [True, -1, float("nan"), float("inf"), 1.5, "1700000000", 10**16])
def test_bad_clock_rejects_before_network(oauth, key, wire, bad):
    source = provider(oauth, key, clock=lambda: bad)
    with pytest.raises(GoogleProviderError) as error:
        source()
    assert_error(error)
    assert wire[0] == []


def test_clock_regression_invalidates_cache(oauth, key, wire, monkeypatch):
    wall, mono = [NOW], [100.0]
    monkeypatch.setattr(oauth, "_monotonic", lambda: mono[0])
    source = provider(oauth, key, clock=lambda: wall[0])
    source()
    wall[0] -= 1
    with pytest.raises(GoogleProviderError):
        source()
    wall[0] = NOW
    source()
    assert len(wire[0]) == 2
    mono[0] -= 1
    with pytest.raises(GoogleProviderError):
        source()


def test_expiry_counts_network_time_and_rechecks_clock_after_exchange(oauth, key, wire, monkeypatch):
    wall = [NOW]
    source = provider(oauth, key, clock=lambda: wall[0])
    original = oauth.http.client.HTTPSConnection.getresponse
    def slow(self):
        wall[0] += 3540
        return original(self)
    monkeypatch.setattr(oauth.http.client.HTTPSConnection, "getresponse", slow)
    with pytest.raises(GoogleProviderError) as error:
        source()
    assert_error(error)


@pytest.mark.parametrize("options", [
    {"service_account_email": "person@example.com"}, {"service_account_email": EMAIL + "\n"},
    {"service_account_email": None}, {"private_key_pem": "no key"},
    {"private_key_pem": b"private secret"}, {"timeout_seconds": True},
    {"timeout_seconds": 0}, {"timeout_seconds": float("nan")}, {"timeout_seconds": 31},
    {"wait_timeout_seconds": 0}, {"wait_timeout_seconds": float("inf")},
    {"refresh_skew_seconds": True}, {"refresh_skew_seconds": -1},
    {"refresh_skew_seconds": 301}, {"clock": 1}])
def test_invalid_configuration_is_redacted(oauth, key, options):
    with pytest.raises(GoogleProviderError) as error:
        provider(oauth, key, **options)
    assert_error(error, "GOOGLE_CONFIGURATION_INVALID")


def test_only_one_complete_strong_rsa_pem_is_accepted(oauth, key):
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    ec_key = ec.generate_private_key(ec.SECP256R1())
    for value in (weak, ec_key):
        pem = value.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption())
        with pytest.raises(GoogleProviderError) as error:
            provider(oauth, key, private_key_pem=pem)
        assert_error(error, "GOOGLE_CONFIGURATION_INVALID")
    for pem in (key[1] + key[1], key[1] + b"secret trailing bytes", b"x" * 16385):
        with pytest.raises(GoogleProviderError):
            provider(oauth, key, private_key_pem=pem)


@pytest.mark.parametrize("body", [
    b'{}', b'[]', b'null', b'\xff', b'{} trailing', b'[' * 10 + b']' * 10,
    b'{"access_token":"x","access_token":"y"}',
    b'{"outer":{"nested":1,"nested":2}}', b'{"value":NaN}', b'{"value":1e999}',
    b'x' * 32769,
    *[json.dumps({"access_token": TOKEN, "token_type": "Bearer", "expires_in": value}).encode()
      for value in (True, 0, -1, 60, 3601, "3600", 1.5)],
    json.dumps({"access_token": "bad\ntoken", "token_type": "Bearer", "expires_in": 3600}).encode(),
    json.dumps({"access_token": TOKEN, "token_type": "mac", "expires_in": 3600}).encode(),
    json.dumps({"access_token": TOKEN, "token_type": "Bearer", "expires_in": 3600, "scope": "other"}).encode(),
    json.dumps({"access_token": TOKEN, "token_type": "Bearer", "expires_in": 3600, "error": "secret"}).encode(),
])
def test_malformed_token_response_is_rejected_without_secret_errors(oauth, key, wire, body):
    wire[2][0] = Response(body=body)
    with pytest.raises(GoogleProviderError) as error:
        provider(oauth, key)()
    assert_error(error)
    assert wire[1][0].closed


@pytest.mark.parametrize("headers", [
    {"Content-Type": "text/html"}, {"Content-Type": "application/json, application/json"},
    {"Content-Type": "application/json; charset=latin1"}, {"Content-Type": None},
    {"Content-Encoding": "gzip"}, {"Content-Length": "32769"},
    {"Content-Length": "no"}, {"Content-Length": "2"},
    {"Content-Length": "100, 100"}, {"Transfer-Encoding": "gzip"},
    {"Transfer-Encoding": "chunked", "Content-Length": "2"}])
def test_response_framing_and_content_type_are_enforced(oauth, key, wire, headers):
    wire[2][0] = Response(headers=headers)
    with pytest.raises(GoogleProviderError) as error:
        provider(oauth, key)()
    assert_error(error)


@pytest.mark.parametrize("status", [301, 302, 307, 400, 401, 403, 429, 500])
def test_redirects_and_provider_errors_never_retry_or_follow(oauth, key, wire, status):
    wire[2][0] = Response(body=TOKEN.encode(), status=status,
                        headers={"Location": "https://untrusted.invalid"})
    with pytest.raises(GoogleProviderError) as error:
        provider(oauth, key)()
    assert_error(error)
    assert len(wire[0]) == 1 and wire[1][0].closed
    assert wire[2][0].read_sizes == []


def test_transport_and_clock_exceptions_are_not_retained(oauth, key, wire, monkeypatch):
    def fail(*args):
        raise RuntimeError(TOKEN + " private JWT/provider message")
    with pytest.raises(GoogleProviderError) as error:
        provider(oauth, key, clock=fail)()
    assert_error(error)
    monkeypatch.setattr(oauth.http.client.HTTPSConnection, "getresponse", fail)
    with pytest.raises(GoogleProviderError) as error:
        provider(oauth, key)()
    assert_error(error)
    assert wire[1][0].closed


def test_concurrent_callers_share_one_exchange(oauth, key, wire, monkeypatch):
    entered, release, barrier = threading.Event(), threading.Event(), threading.Barrier(8)
    original = oauth.http.client.HTTPSConnection.getresponse
    def blocked(self):
        entered.set()
        assert release.wait(2)
        return original(self)
    monkeypatch.setattr(oauth.http.client.HTTPSConnection, "getresponse", blocked)
    source = provider(oauth, key)
    def call():
        barrier.wait(2)
        return source()
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(call) for _ in range(8)]
        assert entered.wait(2)
        release.set()
        assert [future.result(2) for future in futures] == [TOKEN] * 8
    assert len(wire[0]) == 1


def test_waiters_have_finite_deadline_during_stalled_exchange(oauth, key, wire, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    original = oauth.http.client.HTTPSConnection.getresponse
    def blocked(self):
        entered.set()
        assert release.wait(2)
        return original(self)
    monkeypatch.setattr(oauth.http.client.HTTPSConnection, "getresponse", blocked)
    source = provider(oauth, key, wait_timeout_seconds=0.1)
    with ThreadPoolExecutor(max_workers=1) as pool:
        first = pool.submit(source)
        assert entered.wait(2)
        started = time.perf_counter()
        try:
            with pytest.raises(GoogleProviderError) as error:
                source()
            assert_error(error)
            assert time.perf_counter() - started < 1
            assert len(wire[0]) == 1
        finally:
            release.set()
        assert first.result(2) == TOKEN


def test_failed_exchange_is_shared_by_already_waiting_callers(oauth, key, wire, monkeypatch):
    entered, release, waiting = threading.Event(), threading.Event(), threading.Event()
    count_lock, count = threading.Lock(), [0]

    class ObservedEvent(threading.Event):
        def wait(self, timeout=None):
            with count_lock:
                count[0] += 1
                if count[0] == 4:
                    waiting.set()
            return super().wait(timeout)

    class ObservedFlight:
        def __init__(self):
            self.done, self.succeeded = ObservedEvent(), False

    monkeypatch.setattr(oauth, "_Flight", ObservedFlight)
    def fail(self):
        entered.set()
        assert release.wait(2)
        raise TimeoutError(TOKEN)
    monkeypatch.setattr(oauth.http.client.HTTPSConnection, "getresponse", fail)
    source = provider(oauth, key)
    def attempt():
        with pytest.raises(GoogleProviderError) as error:
            source()
        assert_error(error)
    with ThreadPoolExecutor(max_workers=5) as pool:
        leader = pool.submit(attempt)
        assert entered.wait(2)
        followers = [pool.submit(attempt) for _ in range(4)]
        try:
            assert waiting.wait(2)
        finally:
            release.set()
        leader.result(2)
        for follower in followers:
            follower.result(2)
    assert len(wire[0]) == 1
    attempt()  # A later independent call may try again, with no automatic retry.
    assert len(wire[0]) == 2


def test_state_lock_wait_is_bounded_for_a_stalled_host_clock(oauth, key, wire):
    entered, release = threading.Event(), threading.Event()
    def clock():
        entered.set()
        assert release.wait(2)
        return NOW
    source = provider(oauth, key, clock=clock, wait_timeout_seconds=0.1)
    with ThreadPoolExecutor(max_workers=1) as pool:
        owner = pool.submit(source)
        assert entered.wait(2)
        started = time.perf_counter()
        try:
            with pytest.raises(GoogleProviderError) as error:
                source()
            assert_error(error)
            assert time.perf_counter() - started < 1
            assert wire[0] == []
        finally:
            release.set()
        assert owner.result(2) == TOKEN


def test_close_failure_cannot_cache_or_return_token(oauth, key, wire, monkeypatch):
    def fail(self):
        raise RuntimeError(TOKEN)
    monkeypatch.setattr(oauth.http.client.HTTPSConnection, "close", fail)
    source = provider(oauth, key)
    for _ in range(2):
        with pytest.raises(GoogleProviderError) as error:
            source()
        assert_error(error)
    assert len(wire[0]) == 2


@pytest.mark.parametrize("mono", [True, -1, float("nan"), float("inf"), "bad"])
def test_invalid_monotonic_clock_is_rejected(oauth, key, wire, monkeypatch, mono):
    monkeypatch.setattr(oauth, "_monotonic", lambda: mono)
    with pytest.raises(GoogleProviderError) as error:
        provider(oauth, key)()
    assert_error(error)
    assert wire[0] == []


def test_zero_skew_accepts_short_tokens_but_not_their_exact_expiry(oauth, key, wire):
    wall = [NOW]
    wire[2][0] = Response(body=json.dumps({"access_token": TOKEN, "token_type": "Bearer",
                                         "expires_in": 1}).encode())
    source = provider(oauth, key, clock=lambda: wall[0], refresh_skew_seconds=0)
    assert source() == TOKEN
    wall[0] += 1
    wire[2][0].status = 500
    with pytest.raises(GoogleProviderError) as error:
        source()
    assert_error(error)
    assert len(wire[0]) == 2


def test_valid_content_length_and_chunked_framing(oauth, key, wire):
    wire[2][0].headers["Content-Length"] = str(len(wire[2][0].body))
    assert provider(oauth, key)() == TOKEN
    del wire[2][0].headers["Content-Length"]
    wire[2][0].headers["Transfer-Encoding"] = "chunked"
    assert provider(oauth, key)() == TOKEN


@pytest.mark.parametrize("extra", [{"items": [0] * 256}, {"items": [[[[[[[[[0]]]]]]]]]}])
def test_token_response_complexity_is_bounded(oauth, key, wire, extra):
    payload = {"access_token": TOKEN, "token_type": "Bearer", "expires_in": 3600}
    payload.update(extra)
    wire[2][0] = Response(body=json.dumps(payload).encode())
    with pytest.raises(GoogleProviderError) as error:
        provider(oauth, key)()
    assert_error(error)
