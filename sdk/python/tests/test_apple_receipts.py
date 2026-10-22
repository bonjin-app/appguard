"""Independent synthetic PKI and CMS tests; these are not device/provider proof."""
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import importlib
import io
import socket
import ssl

import pytest
from asn1crypto import cms
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID, ObjectIdentifier

NOW = datetime(2026, 10, 22, 3, 0, tzinfo=timezone.utc)
APP_ID = "ABCDEFGHIJ.example.receipts"
CLIENT_HASH = b"x" * 32
LEAF_MARKER = ObjectIdentifier("1.2.840.113635.100.12.15")
CA_MARKER = ObjectIdentifier("1.2.840.113635.100.6.2.3")
POLICY = ObjectIdentifier("1.2.840.113635.100.5.1")


def tlv(tag, body):
    n = len(body)
    size = bytes([n]) if n < 128 else bytes([128 + (n.bit_length() + 7) // 8]) + n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag]) + size + body


def integer(value):
    body = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if body[0] & 128:
        body = b"\0" + body
    return tlv(2, body)


def stamp(value):
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z").encode()


def payload(key_der, *, kind="ATTEST", changes=None, extras=()):
    fields = {2: APP_ID.encode(), 3: key_der, 4: CLIENT_HASH, 5: base64.b64encode(b"token" * 8),
              6: kind.encode(), 7: b"production", 12: stamp(NOW - timedelta(seconds=1)),
              21: stamp(NOW + timedelta(days=30))}
    if kind == "RECEIPT":
        fields.update({17: b"5", 19: stamp(NOW + timedelta(days=1))})
    fields.update(changes or {})
    attrs = [tlv(48, integer(k) + integer(1) + tlv(4, v)) for k, v in fields.items() if v is not None]
    attrs.extend(tlv(48, integer(k) + integer(1) + tlv(4, v)) for k, v in extras)
    return tlv(49, b"".join(sorted(attrs)))


def certificate(key, name, issuer_key, issuer, serial, *, ca=False, marker=None, policy=False,
                unknown_critical=False, expired=False):
    builder = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .issuer_name(issuer).public_key(key.public_key()).serial_number(serial)
        .not_valid_before(NOW - timedelta(days=90))
        .not_valid_after(NOW - timedelta(days=1) if expired else NOW + timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=not ca, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=ca, crl_sign=ca,
            encipher_only=None, decipher_only=None), critical=True))
    if marker:
        builder = builder.add_extension(x509.UnrecognizedExtension(marker, b"\x05\x00"), critical=False)
    if policy:
        builder = builder.add_extension(x509.CertificatePolicies([x509.PolicyInformation(POLICY, None)]), critical=False)
    if unknown_critical:
        builder = builder.add_extension(x509.UnrecognizedExtension(ObjectIdentifier("1.2.3.4"), b"\x05\x00"), critical=True)
    return builder.sign(issuer_key, hashes.SHA384() if isinstance(issuer_key.curve, ec.SECP384R1) else hashes.SHA256())


@pytest.fixture
def setup(monkeypatch):
    try:
        module = importlib.import_module("appguard.providers.apple_receipts")
    except ModuleNotFoundError as error:
        if error.name == "appguard.providers.apple_receipts":
            pytest.fail("Independent Apple receipt verification has not been implemented")
        raise
    root_key, ca_key, leaf_key = ec.generate_private_key(ec.SECP384R1()), ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic receipt root")])
    root = certificate(root_key, "Synthetic receipt root", root_key, root_name, 1, ca=True)
    ca = certificate(ca_key, "Synthetic receipt CA", root_key, root.subject, 2, ca=True, marker=CA_MARKER)
    leaf = certificate(leaf_key, "Application Attestation Fraud Receipt Signing", ca_key, ca.subject, 3, marker=LEAF_MARKER, policy=True)
    key = ec.generate_private_key(ec.SECP256R1())
    key_der = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    monkeypatch.setattr(module, "_receipt_root", lambda: root)
    verifier = module.AppleReceiptVerifier(apple_app_id=APP_ID, public_key_der=key_der, environment="production", clock=lambda: NOW.timestamp())

    def sign(data=None, *, attrs=False, signer=leaf, signing_key=leaf_key, extra_certs=()):
        builder = pkcs7.PKCS7SignatureBuilder().set_data(payload(key_der) if data is None else data).add_signer(signer, signing_key, hashes.SHA256())
        for cert in (ca, root, *extra_certs):
            builder = builder.add_certificate(cert)
        options = [pkcs7.PKCS7Options.Binary, pkcs7.PKCS7Options.NoCapabilities if attrs else pkcs7.PKCS7Options.NoAttributes]
        return builder.sign(serialization.Encoding.DER, options)

    return module, verifier, sign, key_der, root, ca, leaf, ca_key, leaf_key


def test_verifies_direct_signature_receipt_and_hides_evidence(setup):
    module, verifier, sign, key_der, *_ = setup
    raw = sign()
    result = verifier.verify(raw, expected_client_hash=CLIENT_HASH, expected_type="ATTEST")
    assert result.receipt_type == "ATTEST" and result.risk_metric is None
    assert result.apple_app_id == APP_ID and result.environment == "production"
    assert result.public_key_der == key_der and result.receipt == raw
    assert result.created_at == (NOW - timedelta(seconds=1)).timestamp()
    assert result.expires_at == (NOW + timedelta(days=30)).timestamp()
    assert result.receipt_sha256 == hashlib.sha256(raw).hexdigest()
    assert APP_ID not in repr(result) and "token" not in repr(result) and "xxxx" not in repr(result)


def test_verifies_signed_attributes_and_risk_times(setup):
    _, verifier, sign, key_der, *_ = setup
    result = verifier.verify(sign(payload(key_der, kind="RECEIPT"), attrs=True), expected_client_hash=CLIENT_HASH, expected_type="RECEIPT")
    assert result.risk_metric == 5
    assert result.not_before == (NOW + timedelta(days=1)).timestamp()


@pytest.mark.parametrize("change", [{2: b"ABCDEFGHIJ.wrong"}, {4: b"wrong"}, {7: b"development"}, {7: None}, {6: b"OTHER"},
    {12: stamp(NOW - timedelta(seconds=301))}, {12: stamp(NOW + timedelta(seconds=1))},
    {21: stamp(NOW)}, {12: b"2026-10-22T03:00:00+00:00"}, {17: b"5"}, {5: b"not base64!"}])
def test_rejects_wrong_signed_bindings_and_lifetime(setup, change):
    module, verifier, sign, key_der, *_ = setup
    with pytest.raises(module.AppleReceiptError, match="^APPLE_RECEIPT_REJECTED$"):
        verifier.verify(sign(payload(key_der, changes=change)), expected_client_hash=CLIENT_HASH)


@pytest.mark.parametrize("change", [{17: None}, {19: None}, {17: b"-1"}, {17: b"05"}, {17: b"999999999999999999999999"},
    {19: stamp(NOW - timedelta(days=1))}, {19: stamp(NOW + timedelta(days=31))}])
def test_rejects_invalid_risk_receipt(setup, change):
    module, verifier, sign, key_der, *_ = setup
    with pytest.raises(module.AppleReceiptError):
        verifier.verify(sign(payload(key_der, kind="RECEIPT", changes=change)), expected_client_hash=CLIENT_HASH)


def test_accepts_cert_wrapped_attested_key_without_trusting_its_issuer(setup):
    _, verifier, sign, key_der, root, ca, leaf, ca_key, _ = setup
    # Field 3 in Apple's own public sample is a full attested certificate.
    key = ec.generate_private_key(ec.SECP256R1())
    cert = certificate(key, "attested key", ca_key, ca.subject, 99)
    verifier = type(verifier)(apple_app_id=APP_ID, public_key_der=key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo), environment="production", clock=lambda: NOW.timestamp())
    assert verifier.verify(sign(payload(cert.public_bytes(serialization.Encoding.DER))), expected_client_hash=CLIENT_HASH).receipt_type == "ATTEST"


def test_rejects_other_attested_key_and_wrong_type(setup):
    module, verifier, sign, key_der, *_ = setup
    other = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    for raw, kind in [(sign(payload(other)), "ATTEST"), (sign(), "RECEIPT")]:
        with pytest.raises(module.AppleReceiptError):
            verifier.verify(raw, expected_client_hash=CLIENT_HASH, expected_type=kind)


@pytest.mark.parametrize("extras", [[(2, APP_ID.encode())], [(99, b"unknown")]])
def test_rejects_duplicate_or_unknown_receipt_fields(setup, extras):
    module, verifier, sign, key_der, *_ = setup
    with pytest.raises(module.AppleReceiptError):
        verifier.verify(sign(payload(key_der, extras=extras)), expected_client_hash=CLIENT_HASH)


def test_rejects_payload_and_signature_tampering(setup):
    module, verifier, sign, *_ = setup
    raw = sign()
    obj = cms.ContentInfo.load(raw)
    obj["content"]["signer_infos"][0]["signature"] = b"bad signature"
    for damaged in [raw.replace(CLIENT_HASH, b"y" * 32), obj.dump()]:
        with pytest.raises(module.AppleReceiptError):
            verifier.verify(damaged, expected_client_hash=CLIENT_HASH)


@pytest.mark.parametrize("mutation", ["duplicate_digest", "wrong_digest", "wrong_content_type", "unsigned", "duplicate_signer", "crl"])
def test_rejects_ambiguous_cms_attributes_and_structure(setup, mutation):
    module, verifier, sign, *_ = setup
    obj = cms.ContentInfo.load(sign(attrs=True))
    data = obj["content"]
    signer = data["signer_infos"][0]
    if mutation in ("duplicate_digest", "wrong_digest", "wrong_content_type"):
        for attr in signer["signed_attrs"]:
            if attr["type"].native == "message_digest":
                digest = attr.copy()
                if mutation == "wrong_digest":
                    attr["values"][0] = b"x" * 32
            if attr["type"].native == "content_type" and mutation == "wrong_content_type":
                attr["values"][0] = "signed_data"
        if mutation == "duplicate_digest":
            signer["signed_attrs"].append(digest)
    elif mutation == "unsigned":
        signer["unsigned_attrs"] = [{"type": "signing_time", "values": [cms.Time({"utc_time": NOW})]}]
    elif mutation == "duplicate_signer":
        data["signer_infos"].append(signer.copy())
    else:
        data["crls"] = []
    with pytest.raises(module.AppleReceiptError):
        verifier.verify(obj.dump(), expected_client_hash=CLIENT_HASH)


@pytest.mark.parametrize("purpose", ["wrong_marker", "wrong_cn", "missing_policy", "critical", "expired"])
def test_rejects_unrelated_or_invalid_signer_certificates(setup, purpose):
    module, verifier, sign, _, root, ca, _, ca_key, leaf_key = setup
    cert = certificate(leaf_key, "Other Apple Signing" if purpose == "wrong_cn" else "Application Attestation Fraud Receipt Signing", ca_key, ca.subject, 55,
        marker=ObjectIdentifier("1.2.840.113635.100.12.99") if purpose == "wrong_marker" else LEAF_MARKER,
        policy=purpose != "missing_policy", unknown_critical=purpose == "critical", expired=purpose == "expired")
    with pytest.raises(module.AppleReceiptError):
        verifier.verify(sign(signer=cert), expected_client_hash=CLIENT_HASH)


def test_rejects_extra_certificates_even_with_valid_chain(setup):
    module, verifier, sign, _, root, ca, leaf, ca_key, leaf_key = setup
    unrelated = certificate(leaf_key, "unrelated", ca_key, ca.subject, 456)
    with pytest.raises(module.AppleReceiptError):
        verifier.verify(sign(extra_certs=(unrelated,)), expected_client_hash=CLIENT_HASH)


def test_allows_bounded_outer_ber_indefinite_but_rejects_malformed_frames(setup):
    module, verifier, sign, *_ = setup
    raw = sign()
    length_count = raw[1] & 127
    body = raw[2 + length_count:]
    ber = b"\x30\x80" + body + b"\0\0"
    assert verifier.verify(ber, expected_client_hash=CLIENT_HASH).receipt_type == "ATTEST"
    for bad in [raw + b"\0", raw[:-1], b"\x30\x80" * 40 + b"\0\0" * 40,
                b"\x30\x84\x7f\xff\xff\xff", b"x" * 262145, b"\x04\x80\0\0"]:
        with pytest.raises(module.AppleReceiptError):
            verifier.verify(bad, expected_client_hash=CLIENT_HASH)


def test_old_receipt_can_only_be_validated_for_refresh_without_freshness(setup):
    module, verifier, sign, key_der, *_ = setup
    old = sign(payload(key_der, changes={12: stamp(NOW - timedelta(days=1))}))
    assert verifier.verify(old, expected_client_hash=CLIENT_HASH, require_fresh=False).receipt_type == "ATTEST"
    with pytest.raises(module.AppleReceiptError):
        verifier.verify(old, expected_client_hash=CLIENT_HASH)


class Response:
    def __init__(self, body, status=200):
        self.status = status
        self.body = io.BytesIO(body)
    def read(self, maximum):
        return self.body.read(maximum)
    def close(self):
        self.body.close()


def connection_factory(monkeypatch, module, response, calls):
    class Connection:
        def __init__(self, host, *, timeout, context):
            calls.append((host, timeout, context))
            self.sock = None
        def connect(self):
            pass
        def request(self, method, path, *, body, headers):
            calls.append((method, path, body, headers))
        def getresponse(self):
            return response
        def close(self):
            calls.append("closed")
    monkeypatch.setattr(module.http.client, "HTTPSConnection", Connection)


def test_refresh_fixed_host_explicit_token_and_verifies_response_before_return(setup, monkeypatch):
    module, verifier, sign, key_der, *_ = setup
    old = sign(payload(key_der, changes={12: stamp(NOW - timedelta(days=1))}))
    new = sign(payload(key_der, kind="RECEIPT"))
    calls = []
    connection_factory(monkeypatch, module, Response(base64.b64encode(new)), calls)
    client = module.AppleReceiptRefreshClient(verifier=verifier, token_provider=lambda: "abc.def.ghi")
    result = client.refresh(old, expected_client_hash=CLIENT_HASH)
    assert result.receipt == new and result.risk_metric == 5
    assert calls[0][0] == "data.appattest.apple.com" and isinstance(calls[0][2], ssl.SSLContext)
    assert calls[1] == ("POST", "/v1/attestationData", base64.b64encode(old), {"Authorization": "abc.def.ghi", "Content-Type": "application/octet-stream"})
    assert calls[-1] == "closed"


@pytest.mark.parametrize("status,body", [(302, b"https://evil.invalid"), (304, b""), (401, b"secret token details"),
    (200, b"not!base64"), (200, b"A" * 349529)])
def test_refresh_rejects_redirect_errors_bad_and_oversize_response(setup, monkeypatch, status, body):
    module, verifier, sign, *_ = setup
    calls = []
    connection_factory(monkeypatch, module, Response(body, status), calls)
    client = module.AppleReceiptRefreshClient(verifier=verifier, token_provider=lambda: "abc.def.ghi")
    with pytest.raises(module.AppleReceiptError) as error:
        client.refresh(sign(), expected_client_hash=CLIENT_HASH)
    assert "secret" not in str(error.value) and calls[-1] == "closed"


def test_refresh_rejects_valid_signed_but_wrong_binding_response(setup, monkeypatch):
    module, verifier, sign, key_der, *_ = setup
    calls = []
    connection_factory(monkeypatch, module, Response(base64.b64encode(sign(payload(key_der, kind="RECEIPT", changes={4: b"wrong"})))), calls)
    with pytest.raises(module.AppleReceiptError):
        module.AppleReceiptRefreshClient(verifier=verifier, token_provider=lambda: "abc.def.ghi").refresh(sign(), expected_client_hash=CLIENT_HASH)


def test_refresh_blocks_before_not_before_and_after_expiry_without_token_or_network(setup, monkeypatch):
    module, verifier, sign, key_der, *_ = setup
    def unexpected():
        pytest.fail("token must not be requested before receipt checks")
    client = module.AppleReceiptRefreshClient(verifier=verifier, token_provider=unexpected)
    for raw in [sign(payload(key_der, kind="RECEIPT")), sign(payload(key_der, changes={21: stamp(NOW)}))]:
        with pytest.raises(module.AppleReceiptError):
            client.refresh(raw, expected_client_hash=CLIENT_HASH)


def test_refresh_does_not_disclose_callback_errors_or_invalid_tokens(setup):
    module, verifier, sign, *_ = setup
    def secret_failure():
        raise RuntimeError("private key secret")
    for provider in [secret_failure, lambda: "abc.def.ghi\r\nInjected: bad", lambda: "Bearer abc.def.ghi"]:
        with pytest.raises(module.AppleReceiptError) as error:
            module.AppleReceiptRefreshClient(verifier=verifier, token_provider=provider).refresh(sign(), expected_client_hash=CLIENT_HASH)
        assert str(error.value) == "APPLE_RECEIPT_REFRESH_REJECTED" and error.value.__cause__ is None


# Public Apple DocC example downloaded 2026-10-22, CMS SHA-256
# 26a7ef09ab4cff17140e02780c57bec69672f4933d1a175ee84229b0107b6de0.
_OFFICIAL_SAMPLE = base64.b64decode(
    "MIAGCSqGSIb3DQEHAqCAMIACAQExDzANBglghkgBZQMEAgEFADCABgkqhkiG9w0BBwGggCSABIID6DGCBUEwJAIBAgIBAQQcMTIz"
    "NDU2Nzg5MC5jb20uZXhhbXBsZS5teWFwcDCCBCsCAQMCAQEEggQhMIIEHTCCA6OgAwIBAgIGAZ2xPwtOMAoGCCqGSM49BAMCME8x"
    "IzAhBgNVBAMMGkFwcGxlIEFwcCBBdHRlc3RhdGlvbiBDQSAxMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y"
    "bmlhMB4XDTI2MDQyMDE4MTMxMloXDTI2MDQyMzE4MTMxMlowgZExSTBHBgNVBAMMQGNlMDQ5OGY1ODQ4M2ZiYjRkYTBkN2IyYzYz"
    "YTVhNTM4ZjU1MmQ0YWRjYjlhNGZhOTE2MTk1YzQ5NjEzZTY1NWQxGjAYBgNVBAsMEUFBQSBDZXJ0aWZpY2F0aW9uMRMwEQYDVQQK"
    "DApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQzJUSs8yPbd0RDyq8zn1"
    "bn6VxyT6wsFCWfNl4kRWULK1+yhbz1Sby2BZRBLnaCokJ+6tqftS3+0LGrF+0J+pvaOCAiYwggIiMAwGA1UdEwEB/wQCMAAwDgYD"
    "VR0PAQH/BAQDAgTwMBQGA1UdJQQNMAsGCSqGSIb3Y2QEGDB6BgkqhkiG92NkCAUEbTBrpAMCAQq/iTADAgEAv4kxAwIBAL+JMgMC"
    "AQC/iTMDAgEAv4k0HgQcMTIzNDU2Nzg5MC5jb20uZXhhbXBsZS5teWFwcL+JNgMCAQS/iTcDAgEAv4k5AwIBAL+JOgMCAQC/iTsD"
    "AgEAqgMCAQAwgeAGCSqGSIb3Y2QIBwSB0jCBz7+KeAYEBDI3LjC/iFADAgECv4p5CQQHMS4wLjIxNr+KewkEBzI0QTMyNWK/inwG"
    "BAQyNy4wv4p9BgQEMjcuML+KfgMCAQC/in8DAgEAv4sAAwIBAL+LAQMCAQC/iwIDAgEAv4sDAwIBAL+LBAMCAQG/iwUDAgEAv4sK"
    "EAQOMjQuMS4zMjUuMC4yLDC/iwsQBA4yNC4xLjMyNS4wLjIsML+LDBAEDjI0LjEuMzI1LjAuMiwwv4gCCgQIaXBob25lb3O/iAUK"
    "BAhJbnRlcm5hbDAzBgkqhkiG92NkCAIEJjAkoSIEIIe30G2TpClORvAR5mtsxADwurIHKZdsYZWAtCrmC/9uMFgGCSqGSIb3Y2QI"
    "BgRLMEmjRwRFMEMMAjExMD0wCgwDb2tkoQMBAf8wCQwCb2GhAwEB/zALDARvc2duoQMBAf8wCwwEb2RlbKEDAQH/MAoMA29ja6ED"
    "AQH/MAoGCCoEggFdhkjOPQQDAgNoADBlAjAhvMdo9tEpybaxrgm8NbJNfjTLP1TZvLEXFOGj4cgzQd5jAXccvIDc2uq/dYPL9R0C"
    "MQCk6jEvvN5BXTKG9qw97fX5zVli4QPERTqsOuF4VxUxFl6m9XXT6EXGAhZUxKlC7T0wIAIBBAIBAQQYZXhhbXBsZV9zZXJ2ZXJf"
    "Y2hhbGxlbmdlMGACAQUCAQEEWHJia3RNcTg5bXZEcFJDSy84bGNQaGRMNGRXUXo5T1hJd0hHZGU1eFFmU3VJS3NOM09qT1dGOHUr"
    "djBVQTRxOHZqQ1JnRUVKVGxjOUJ3aUl6TlNOT0hRPT0wDgIBBgIBAQQGQVRURVNUMBICAQcCAQEECnByb2R1Y3Rpb24wIAIBDAIB"
    "AQQYMjAyNi0wNC0yMVQxODoxMzoxMi4xNTNaMCACARUCAQEEGDIwMjYtMDctMjBUMTg6MTM6MTIuMTUzWgAAAAAAAKCAMIIDrjCC"
    "A1SgAwIBAgIQZgI4gAAUJvddiw4VLF9uQzAKBggqhkjOPQQDAjB8MTAwLgYDVQQDDCdBcHBsZSBBcHBsaWNhdGlvbiBJbnRlZ3Jh"
    "dGlvbiBDQSA1IC0gRzExJjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRMwEQYDVQQKDApBcHBsZSBJbmMu"
    "MQswCQYDVQQGEwJVUzAeFw0yNjAxMjAyMDIxMDlaFw0yNzAyMTgxODU4MzlaMFoxNjA0BgNVBAMMLUFwcGxpY2F0aW9uIEF0dGVz"
    "dGF0aW9uIEZyYXVkIFJlY2VpcHQgU2lnbmluZzETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwWTATBgcqhkjOPQIB"
    "BggqhkjOPQMBBwNCAAQ7GK7OxRmtilNRtEBEtKMDmVe0zb1bhR/gGm/t4o3vsPqww2oCpB9EbgBtWA5WimeAiQfzSICRQ4sgzqpM"
    "ndxWo4IB2DCCAdQwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBTZF/5LZ5A4S5L0287VV4AUC489yTBDBggrBgEFBQcBAQQ3MDUw"
    "MwYIKwYBBQUHMAGGJ2h0dHA6Ly9vY3NwLmFwcGxlLmNvbS9vY3NwMDMtYWFpY2E1ZzEwMTCCARwGA1UdIASCARMwggEPMIIBCwYJ"
    "KoZIhvdjZAUBMIH9MIHDBggrBgEFBQcCAjCBtgyBs1JlbGlhbmNlIG9uIHRoaXMgY2VydGlmaWNhdGUgYnkgYW55IHBhcnR5IGFz"
    "c3VtZXMgYWNjZXB0YW5jZSBvZiB0aGUgdGhlbiBhcHBsaWNhYmxlIHN0YW5kYXJkIHRlcm1zIGFuZCBjb25kaXRpb25zIG9mIHVz"
    "ZSwgY2VydGlmaWNhdGUgcG9saWN5IGFuZCBjZXJ0aWZpY2F0aW9uIHByYWN0aWNlIHN0YXRlbWVudHMuMDUGCCsGAQUFBwIBFilo"
    "dHRwOi8vd3d3LmFwcGxlLmNvbS9jZXJ0aWZpY2F0ZWF1dGhvcml0eTAdBgNVHQ4EFgQUNFWJcHRgDiLSumfPpVtpwiPxyigwDgYD"
    "VR0PAQH/BAQDAgeAMA8GCSqGSIb3Y2QMDwQCBQAwCgYIKoZIzj0EAwIDSAAwRQIgHGeXuYJF0dbccgS3mwI8r/h78u/4k33XIMRe"
    "iuRlwusCIQD8yFmEzsmhLMKGqdSSdv3w0vYl3HX8fPiHRWl75h6qtDCCAvkwggJ/oAMCAQICEFb7g9Qr/43DN5kjtVqubr0wCgYI"
    "KoZIzj0EAwMwZzEbMBkGA1UEAwwSQXBwbGUgUm9vdCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhv"
    "cml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwHhcNMTkwMzIyMTc1MzMzWhcNMzQwMzIyMDAwMDAwWjB8MTAw"
    "LgYDVQQDDCdBcHBsZSBBcHBsaWNhdGlvbiBJbnRlZ3JhdGlvbiBDQSA1IC0gRzExJjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRp"
    "b24gQXV0aG9yaXR5MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJLO"
    "Y719hrGrKAo7HOGv+wSUgJGs9jHfpssoNW9ES+Eh5VfdEo2NuoJ8lb5J+r4zyq7NBBnxL0Ml+vS+s8uDfrqjgfcwgfQwDwYDVR0T"
    "AQH/BAUwAwEB/zAfBgNVHSMEGDAWgBS7sN6hWDOImqSKmd6+veuv2sskqzBGBggrBgEFBQcBAQQ6MDgwNgYIKwYBBQUHMAGGKmh0"
    "dHA6Ly9vY3NwLmFwcGxlLmNvbS9vY3NwMDMtYXBwbGVyb290Y2FnMzA3BgNVHR8EMDAuMCygKqAohiZodHRwOi8vY3JsLmFwcGxl"
    "LmNvbS9hcHBsZXJvb3RjYWczLmNybDAdBgNVHQ4EFgQU2Rf+S2eQOEuS9NvO1VeAFAuPPckwDgYDVR0PAQH/BAQDAgEGMBAGCiqG"
    "SIb3Y2QGAgMEAgUAMAoGCCqGSM49BAMDA2gAMGUCMQCNb6afoeDk7FtOc4qSfz14U5iP9NofWB7DdUr+OKhMKoMaGqoNpmRt4bmT"
    "6NFVTO0CMGc7LLTh6DcHd8vV7HaoGjpVOz81asjF5pKw4WG+gElp5F8rqWzhEQKqzGHZOLdzSjCCAkMwggHJoAMCAQICCC3F/IjS"
    "xUuVMAoGCCqGSM49BAMDMGcxGzAZBgNVBAMMEkFwcGxlIFJvb3QgQ0EgLSBHMzEmMCQGA1UECwwdQXBwbGUgQ2VydGlmaWNhdGlv"
    "biBBdXRob3JpdHkxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYTAlVTMB4XDTE0MDQzMDE4MTkwNloXDTM5MDQzMDE4MTkw"
    "NlowZzEbMBkGA1UEAwwSQXBwbGUgUm9vdCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTET"
    "MBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAASY6S89QHKk7ZMicoETHN0QlfHF"
    "o05x3BQW2Q7lpgUqd2R7X04407scRLV/9R+2MmJdyemEW08wTxFaAP1YWAyl9Q8sTQdHE3Xal5eXbzFc7SudeyA72LlU2V6ZpDpR"
    "CjGjQjBAMB0GA1UdDgQWBBS7sN6hWDOImqSKmd6+veuv2sskqzAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAKBggq"
    "hkjOPQQDAwNoADBlAjEAg+nBxBZeGl00GNnt7/RsDgBGS7jfskYRxQ/95nqMoaZrzsID1Jz1k8Z0uGrfqiMVAjBtZooQytQN1E/N"
    "jUM+tIpjpTNu423aF7dkH8hTJvmIYnQ5Cxdby1GoDOgYA+eisigAADGB/TCB+gIBATCBkDB8MTAwLgYDVQQDDCdBcHBsZSBBcHBs"
    "aWNhdGlvbiBJbnRlZ3JhdGlvbiBDQSA1IC0gRzExJjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRMwEQYD"
    "VQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUwIQZgI4gAAUJvddiw4VLF9uQzANBglghkgBZQMEAgEFADAKBggqhkjOPQQDAgRH"
    "MEUCIFp+GIuJm5vqJhLtDX40gGP90KJtLoPyzcLEuKHYMr9zAiEAgPafgwU16p2N6GvCC3Gj4BAb66R38+IP+Arn3QYbD9QAAAAA"
    "AAA="
)


def test_current_official_apple_sample_cryptography_and_signed_fields():
    module = importlib.import_module("appguard.providers.apple_receipts")
    historical = datetime(2026, 4, 21, 18, 13, 13, tzinfo=timezone.utc).timestamp()
    # Published example is expired today: freeze only the verifier clock, never
    # the trust root, certificate signatures, or CMS/field parser.
    raw_payload = module._verify_cms(_OFFICIAL_SAMPLE, historical)
    from asn1crypto import core
    attrs = core.SetOf.load(raw_payload)
    attested_cert = next(a[2].native for a in attrs if a[0].native == 3)
    key = x509.load_der_x509_certificate(attested_cert).public_key()
    public_key = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    verifier = module.AppleReceiptVerifier(apple_app_id="1234567890.com.example.myapp", public_key_der=public_key, environment="production", clock=lambda: historical)
    result = verifier.verify(_OFFICIAL_SAMPLE, expected_client_hash=b"example_server_challenge", expected_type="ATTEST")
    assert result.created_at == datetime(2026, 4, 21, 18, 13, 12, 153000, tzinfo=timezone.utc).timestamp()
    assert result.expires_at == datetime(2026, 7, 20, 18, 13, 12, 153000, tzinfo=timezone.utc).timestamp()
    assert result.risk_metric is None and result.environment == "production"


def test_signed_attributes_reject_non_der_order_even_when_signature_matches(setup):
    module, verifier, sign, *_ = setup
    raw = sign(attrs=True)
    attrs = cms.ContentInfo.load(raw)["content"]["signer_infos"][0]["signed_attrs"]
    original = attrs.dump()
    reversed_attributes = tlv(160, b"".join(reversed([a.dump() for a in attrs])))
    assert original != reversed_attributes
    with pytest.raises(module.AppleReceiptError):
        verifier.verify(raw.replace(original, reversed_attributes), expected_client_hash=CLIENT_HASH)


@pytest.mark.parametrize("mutation", ["sha1", "sha1_signer", "rsa_signature", "wrong_sid", "bad_intermediate_signature", "no_ca_marker", "unknown_signed_attr", "wrong_ca_key_usage"])
def test_rejects_unsupported_algorithms_untrusted_paths_and_signed_attributes(setup, mutation):
    module, verifier, sign, key_der, root, ca, leaf, ca_key, leaf_key = setup
    raw = sign(attrs=True)
    obj = cms.ContentInfo.load(raw)
    data = obj["content"]
    signer = data["signer_infos"][0]
    if mutation == "sha1":
        data["digest_algorithms"][0]["algorithm"] = "sha1"
    elif mutation == "sha1_signer":
        signer["digest_algorithm"]["algorithm"] = "sha1"
    elif mutation == "rsa_signature":
        signer["signature_algorithm"]["algorithm"] = "sha256_rsa"
    elif mutation == "wrong_sid":
        signer["sid"] = {"issuer_and_serial_number": {
            "issuer": signer["sid"].chosen["issuer"], "serial_number": 654321}}
    elif mutation == "unknown_signed_attr":
        signer["signed_attrs"].append(cms.CMSAttribute({"type": "smime_capabilities", "values": [[]]}))
    else:
        if mutation == "bad_intermediate_signature":
            from asn1crypto import x509 as asn1_x509
            replacement = asn1_x509.Certificate.load(ca.public_bytes(serialization.Encoding.DER))
            replacement["signature_value"] = b"bad"
        else:
            fake_key = ec.generate_private_key(ec.SECP384R1())
            replacement = certificate(ca_key, "Synthetic receipt CA", fake_key, root.subject, 2,
                ca=mutation != "wrong_ca_key_usage", marker=None if mutation == "no_ca_marker" else CA_MARKER)
            from asn1crypto import x509 as asn1_x509
            replacement = asn1_x509.Certificate.load(replacement.public_bytes(serialization.Encoding.DER))
        for index, choice in enumerate(data["certificates"]):
            if choice.chosen.serial_number == 2:
                data["certificates"][index] = cms.CertificateChoices({"certificate": replacement})
                break
    with pytest.raises(module.AppleReceiptError):
        verifier.verify(obj.dump(), expected_client_hash=CLIENT_HASH)


def test_rejects_nonminimal_payload_integer_even_with_valid_cms_signature(setup):
    module, verifier, sign, key_der, *_ = setup
    from asn1crypto import core
    others = b"".join(a.dump() for a in core.SetOf.load(payload(key_der)) if a[0].native != 2)
    malformed = tlv(49, tlv(48, b"\x02\x02\0\x02" + integer(1) + tlv(4, APP_ID.encode()))
                    + others)
    with pytest.raises(module.AppleReceiptError):
        verifier.verify(sign(malformed), expected_client_hash=CLIENT_HASH)


def test_default_trust_rejects_self_issued_synthetic_root_and_wrong_pem_pin(setup, monkeypatch):
    module, verifier, sign, *_ = setup
    # Restore production trust after fixtures deliberately injected synthetic PKI.
    monkeypatch.undo()
    with pytest.raises(module.AppleReceiptError):
        verifier.verify(sign(), expected_client_hash=CLIENT_HASH)
    monkeypatch.setattr(module, "APPLE_RECEIPT_ROOT_DER_SHA256", "0" * 64)
    with pytest.raises(ValueError):
        module._receipt_root()


@pytest.mark.parametrize("config", [{"environment": "unknown"}, {"apple_app_id": "wrong"}, {"public_key_der": b"bad"}, {"clock": 12}])
def test_rejects_invalid_verifier_configuration(setup, config):
    module, _, _, key_der, *_ = setup
    kwargs = dict(apple_app_id=APP_ID, public_key_der=key_der, environment="production", clock=lambda: NOW.timestamp())
    kwargs.update(config)
    with pytest.raises(module.AppleReceiptError, match="^APPLE_RECEIPT_CONFIGURATION$"):
        module.AppleReceiptVerifier(**kwargs)


@pytest.mark.parametrize("clock", [lambda: True, lambda: float("nan"), lambda: float("inf"), lambda: -1, lambda: "secret"])
def test_rejects_invalid_clock_without_exposing_context(setup, clock):
    module, _, sign, key_der, *_ = setup
    verifier = module.AppleReceiptVerifier(apple_app_id=APP_ID, public_key_der=key_der, environment="production", clock=clock)
    with pytest.raises(module.AppleReceiptError, match="^APPLE_RECEIPT_REJECTED$"):
        verifier.verify(sign(), expected_client_hash=CLIENT_HASH)


def test_refresh_development_host_and_newer_risk_receipt_after_not_before(setup, monkeypatch):
    module, _, sign, key_der, *_ = setup
    verifier = module.AppleReceiptVerifier(apple_app_id=APP_ID, public_key_der=key_der, environment="development", clock=lambda: NOW.timestamp())
    old = sign(payload(key_der, kind="RECEIPT", changes={7: b"development", 12: stamp(NOW - timedelta(days=2)), 19: stamp(NOW - timedelta(days=1))}))
    new = sign(payload(key_der, kind="RECEIPT", changes={7: b"development", 17: b"7"}))
    calls = []
    connection_factory(monkeypatch, module, Response(base64.b64encode(new)), calls)
    result = module.AppleReceiptRefreshClient(verifier=verifier, token_provider=lambda: "abc.def.ghi").refresh(old, expected_client_hash=CLIENT_HASH)
    assert calls[0][0] == "data-development.appattest.apple.com" and result.risk_metric == 7


def test_refresh_rejects_replayed_or_rollback_response(setup, monkeypatch):
    module, verifier, sign, key_der, *_ = setup
    old = sign(payload(key_der, kind="RECEIPT", changes={12: stamp(NOW - timedelta(seconds=100)), 19: stamp(NOW - timedelta(seconds=90))}))
    rollback = sign(payload(key_der, kind="RECEIPT", changes={12: stamp(NOW - timedelta(seconds=101))}))
    for response in [old, rollback]:
        calls = []
        connection_factory(monkeypatch, module, Response(base64.b64encode(response)), calls)
        with pytest.raises(module.AppleReceiptError):
            module.AppleReceiptRefreshClient(verifier=verifier, token_provider=lambda: "abc.def.ghi").refresh(old, expected_client_hash=CLIENT_HASH)


@pytest.mark.parametrize("mode", ["success", "slow_headers", "slow_body", "untrusted_tls"])
def test_refresh_actual_tls_socket_with_fixed_apple_hostname(setup, monkeypatch, tmp_path, mode):
    import threading
    import time
    module, verifier, sign, key_der, root, ca, leaf, ca_key, leaf_key = setup
    # Route only the already-fixed Apple host to this owned TLS listener. The
    # connection uses real HTTPSConnection, validates a hostname and checks TLS.
    server_key = ec.generate_private_key(ec.SECP256R1())
    server_cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "data.appattest.apple.com")]))
        .issuer_name(ca.subject).public_key(server_key.public_key()).serial_number(123)
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("data.appattest.apple.com")]), critical=False)
        .sign(ca_key, hashes.SHA256()))
    cert_path, key_path = tmp_path / "tls.pem", tmp_path / "tls-key.pem"
    cert_path.write_bytes(server_cert.public_bytes(serialization.Encoding.PEM) + ca.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(server_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert_path, key_path)
    client_context = ssl.create_default_context(cadata=root.public_bytes(serialization.Encoding.PEM).decode() if mode != "untrusted_tls" else None)
    monkeypatch.setattr(module.ssl, "create_default_context", lambda: client_context)
    old = sign(payload(key_der, changes={12: stamp(NOW - timedelta(days=1))}))
    new = sign(payload(key_der, kind="RECEIPT"))
    body = base64.b64encode(new)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(3)
    address = listener.getsockname()
    observed, failures = [], []

    def serve():
        try:
            connection, _ = listener.accept()
            with server_context.wrap_socket(connection, server_side=True) as stream:
                stream.settimeout(3)
                request = bytearray()
                while b"\r\n\r\n" not in request:
                    request.extend(stream.recv(4096))
                head, received_body = bytes(request).split(b"\r\n\r\n", 1)
                size = int(next(line.split(b":", 1)[1].strip() for line in head.split(b"\r\n") if line.lower().startswith(b"content-length:")))
                while len(received_body) < size:
                    received_body += stream.recv(4096)
                observed.append((head, received_body))
                header = b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n"
                if mode == "slow_headers":
                    for octet in header[:20]:
                        stream.sendall(bytes([octet]))
                        time.sleep(0.025)
                    stream.sendall(header[20:] + body)
                elif mode == "slow_body":
                    stream.sendall(header)
                    for octet in body[:20]:
                        stream.sendall(bytes([octet]))
                        time.sleep(0.025)
                    stream.sendall(body[20:])
                else:
                    stream.sendall(header + body)
        except Exception as error:
            failures.append(type(error).__name__)
        finally:
            listener.close()

    real_connect = socket.create_connection
    def route(address_to_connect, *args, **kwargs):
        assert address_to_connect == ("data.appattest.apple.com", 443)
        return real_connect(address, *args, **kwargs)
    monkeypatch.setattr(socket, "create_connection", route)
    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        client = module.AppleReceiptRefreshClient(verifier=verifier, token_provider=lambda: "abc.def.ghi", timeout=0.15 if mode.startswith("slow") else 2)
        started = time.monotonic()
        if mode == "success":
            result = client.refresh(old, expected_client_hash=CLIENT_HASH)
            assert result.receipt == new and result.risk_metric == 5
        else:
            with pytest.raises(module.AppleReceiptError) as error:
                client.refresh(old, expected_client_hash=CLIENT_HASH)
            assert error.value.__context__ is None
            if mode.startswith("slow"):
                assert time.monotonic() - started < 0.45
    finally:
        thread.join(4)
    assert not thread.is_alive()
    if mode == "untrusted_tls":
        assert not observed
        return
    if mode == "success":
        assert not failures
    assert observed[0][0].startswith(b"POST /v1/attestationData HTTP/1.1\r\n")
    assert b"Host: data.appattest.apple.com" in observed[0][0]
    assert b"Authorization: abc.def.ghi" in observed[0][0]
    assert observed[0][1] == base64.b64encode(old)


def test_rejected_receipts_and_callback_errors_leave_no_private_exception_context(setup):
    module, verifier, sign, *_ = setup
    def callback():
        raise RuntimeError("private token and provider context")
    operations = [lambda: verifier.verify(b"private receipt not ASN.1", expected_client_hash=CLIENT_HASH),
        lambda: module.AppleReceiptRefreshClient(verifier=verifier, token_provider=callback).refresh(sign(), expected_client_hash=CLIENT_HASH)]
    for operation in operations:
        with pytest.raises(module.AppleReceiptError) as error:
            operation()
        assert error.value.__cause__ is None
        assert error.value.__context__ is None


@pytest.mark.parametrize("after_callback", [NOW.timestamp() + 2, NOW.timestamp() - 1, True, float('nan')])
def test_refresh_rechecks_expiry_clock_and_rollback_after_token_callback_before_network(setup, monkeypatch, after_callback):
    module, _, sign, key_der, *_ = setup
    wall = [NOW.timestamp()]
    verifier = module.AppleReceiptVerifier(apple_app_id=APP_ID, public_key_der=key_der, environment="production", clock=lambda: wall[0])
    old = sign(payload(key_der, changes={12: stamp(NOW - timedelta(seconds=10)), 21: stamp(NOW + timedelta(seconds=1))}))
    replacement = sign(payload(key_der, kind="RECEIPT", changes={12: stamp(NOW - timedelta(seconds=5))}))
    calls = []
    connection_factory(monkeypatch, module, Response(base64.b64encode(replacement)), calls)
    def callback():
        wall[0] = after_callback
        return "abc.def.ghi"
    with pytest.raises(module.AppleReceiptError) as error:
        module.AppleReceiptRefreshClient(verifier=verifier, token_provider=callback).refresh(old, expected_client_hash=CLIENT_HASH)
    assert calls == [], "expired or regressed clock must fail before network construction"
    assert error.value.__context__ is None and error.value.__cause__ is None


def append_sequence_field(raw, path):
    """Byte-level DER mutation, preserving unknown fields schema dump may drop."""
    def span(data, offset):
        count = data[offset + 1] & 127 if data[offset + 1] & 128 else 0
        header = 2 + count
        size = int.from_bytes(data[offset + 2:offset + header], "big") if count else data[offset + 1]
        return header, header + size
    header, total = span(raw, 0)
    assert total == len(raw)
    body = raw[header:]
    if not path:
        assert raw[0] == 48
        return tlv(raw[0], body + integer(7))
    children, position = [], 0
    while position < len(body):
        _, size = span(body, position)
        children.append(body[position:position + size])
        position += size
    assert position == len(body)
    children[path[0]] = append_sequence_field(children[path[0]], path[1:])
    return tlv(raw[0], b"".join(children))


@pytest.mark.parametrize("where", ["content_info", "signed_data", "encap_content", "signer_info", "sid", "digest", "signature_algorithm", "signed_attribute", "payload_attribute"])
def test_rejects_unknown_trailing_asn1_sequence_fields_even_with_valid_payload_signature(setup, where):
    from asn1crypto import core
    module, verifier, sign, key_der, *_ = setup
    if where == "payload_attribute":
        attrs = core.SetOf.load(payload(key_der))
        malformed = tlv(49, b"".join(tlv(48, a.contents + integer(7)) if a[0].native == 2 else a.dump() for a in attrs))
        raw = sign(malformed)
    else:
        paths = {"content_info": [], "signed_data": [1, 0], "encap_content": [1, 0, 2],
                 "signer_info": [1, 0, 4, 0], "sid": [1, 0, 4, 0, 1], "digest": [1, 0, 1, 0],
                 "signature_algorithm": [1, 0, 4, 0, 3], "signed_attribute": [1, 0, 4, 0, 3, 0]}
        raw = append_sequence_field(sign(attrs=where == "signed_attribute"), paths[where])
    with pytest.raises(module.AppleReceiptError):
        verifier.verify(raw, expected_client_hash=CLIENT_HASH)


def test_refresh_rejects_clock_rollback_while_awaiting_provider_response(setup, monkeypatch):
    module, _, sign, key_der, *_ = setup
    wall = [NOW.timestamp()]
    verifier = module.AppleReceiptVerifier(apple_app_id=APP_ID, public_key_der=key_der, environment="production", clock=lambda: wall[0])
    old = sign(payload(key_der, changes={12: stamp(NOW - timedelta(seconds=10))}))
    replacement = sign(payload(key_der, kind="RECEIPT", changes={12: stamp(NOW - timedelta(seconds=5))}))
    class RegressingResponse(Response):
        def read(self, maximum):
            wall[0] -= 1
            return super().read(maximum)
    calls = []
    connection_factory(monkeypatch, module, RegressingResponse(base64.b64encode(replacement)), calls)
    with pytest.raises(module.AppleReceiptError) as error:
        module.AppleReceiptRefreshClient(verifier=verifier, token_provider=lambda: "abc.def.ghi").refresh(old, expected_client_hash=CLIENT_HASH)
    assert calls[-1] == "closed"
    assert error.value.__context__ is None
