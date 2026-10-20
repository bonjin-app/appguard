"""Catch target normalization, omitted binding, and body/digest confusion."""

from dataclasses import replace

import pytest

from appguard_reference.canonical import build_signature_base, validate_content_digest
from appguard_reference.types import VerificationError
from conftest import EXPECTED_BASE, ORIGIN


def test_handwritten_signature_base(request_input, parameters):
    assert build_signature_base(request_input, parameters, origin=ORIGIN) == EXPECTED_BASE


@pytest.mark.parametrize("target", ["/a%2Fb?x=2&x=1", "/a%2fb?x=1&x=2", "/empty?"])
def test_original_target_bytes_preserved(request_input, parameters, target):
    result = build_signature_base(replace(request_input, target=target), parameters, origin=ORIGIN)
    assert result.split(b"\n")[1] == f'"@target-uri": {ORIGIN}{target}'.encode()


@pytest.mark.parametrize("target", ["/한글", "//other.test/path", "/x#fragment", "/x\\y", "/x y",
                                   "/x\r\nY: z", "/x\x00", "/%", "/%GG", "/%0", "/a/../b",
                                   "/a/%2e%2E/b", "https://other.test/x", ""])
def test_invalid_target_rejected(request_input, parameters, target):
    with pytest.raises(VerificationError, match="^INVALID_REQUEST$"):
        build_signature_base(replace(request_input, target=target), parameters, origin=ORIGIN)


@pytest.mark.parametrize("origin", ["http://api.example.test", "https://a.test/path", "https://u@a.test",
                                   "https://a.test?x=1", "https://a.test#x", "https://A.test",
                                   "https://a.test:443", "https://a.test:0", "https://a.test:65536",
                                   "https://a.test\r\n", "https://a.test/", "https://a.test:abc"])
def test_invalid_origin_rejected(request_input, parameters, origin):
    with pytest.raises(VerificationError, match="^INVALID_REQUEST$"):
        build_signature_base(request_input, parameters, origin=origin)


def test_forwarded_origin_is_not_used(request_input, parameters):
    req = replace(request_input, headers=request_input.headers + (("Forwarded", "host=evil.test"),))
    assert build_signature_base(req, parameters, origin=ORIGIN) == EXPECTED_BASE


@pytest.mark.parametrize("pair", [("AUTHORIZATION", "Bearer other"), ("Content-Type", "text/plain"),
                                  ("content-digest", "wrong"), ("AppGuard-App-ID", "other"),
                                  ("Content-Encoding", "identity")])
def test_duplicate_singleton_rejected(request_input, parameters, pair):
    headers = request_input.headers
    if pair[0] == "Content-Encoding":
        headers += (pair,)
    with pytest.raises(VerificationError, match="^INVALID_REQUEST$"):
        build_signature_base(replace(request_input, headers=headers + (pair,)), parameters, origin=ORIGIN)


@pytest.mark.parametrize("pair", [("Bad Name", "x"), ("X-Test", "a\nb"), ("X-Test", "a\tb"),
                                  ("X-Test", " leading"), ("X-Test", "trailing "),
                                  ("X-Test", "한글"), ("Content-Encoding", "gzip")])
def test_ambiguous_header_rejected(request_input, parameters, pair):
    with pytest.raises(VerificationError, match="^INVALID_REQUEST$"):
        build_signature_base(replace(request_input, headers=request_input.headers + (pair,)), parameters, origin=ORIGIN)


@pytest.mark.parametrize("name,value", [("Authorization", "Basic xyz"), ("Authorization", "Bearer "),
                                       ("Content-Type", ""), ("AppGuard-App-Id", 'bad"id')])
def test_required_field_semantics(request_input, parameters, name, value):
    headers = tuple((k, value if k == name else v) for k, v in request_input.headers)
    with pytest.raises(VerificationError, match="^INVALID_REQUEST$"):
        build_signature_base(replace(request_input, headers=headers), parameters, origin=ORIGIN)


def test_missing_required_header_rejected(request_input, parameters):
    with pytest.raises(VerificationError, match="^INVALID_REQUEST$"):
        build_signature_base(replace(request_input, headers=request_input.headers[1:]), parameters, origin=ORIGIN)


@pytest.mark.parametrize("body,digest", [
    (b"", "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:"),
    (b"abc", "sha-256=:ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=:"),
    (b"\x00", "sha-256=:bjQLnP+zepicpUTmu3gKLHiQHT+zNzh2hRGjBhevoB0=:"),
])
def test_exact_content_digest(request_input, body, digest):
    req = replace(request_input, body=body, headers=tuple(
        (k, digest if k == "Content-Digest" else v) for k, v in request_input.headers))
    assert validate_content_digest(req) is None


def test_changed_body_digest_rejected(request_input):
    with pytest.raises(VerificationError, match="^DIGEST_MISMATCH$"):
        validate_content_digest(replace(request_input, body=b'{ "changed": true }'))


@pytest.mark.parametrize("digest", ["sha-512=:abcd:", "sha-256=:a!:", "sha-256=:YWJj:",
                                   "sha-256=:RBNvo1WzZ4oRRq0W9+hknpT7T8If536DEMBg9hyq/4o=:,x=1"])
def test_nonprofile_digest_rejected(request_input, digest):
    req = replace(request_input, headers=tuple((k, digest if k == "Content-Digest" else v)
                                             for k, v in request_input.headers))
    with pytest.raises(VerificationError, match="^INVALID_REQUEST$"):
        validate_content_digest(req)


@pytest.mark.parametrize("field,value", [("algorithm", "hmac-sha256"), ("tag", "appguard-request-v1")])
def test_profile_downgrade_rejected(request_input, parameters, field, value):
    with pytest.raises(VerificationError, match="^UNSUPPORTED_PROFILE$"):
        build_signature_base(request_input, replace(parameters, **{field: value}), origin=ORIGIN)
