"""Offline generated PKI tests. No fixture is genuine Apple/device attestation."""

import base64
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
import random

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.x509.oid import NameOID, ObjectIdentifier

from appguard.enrollment import EnrollmentError, EnrollmentService, SqliteEnrollmentStore
from appguard.enrollment_types import Challenge, enrollment_message

import appguard.providers.apple as apple

NOW = 1792472400
APP_ID = "ABCDEFGHIJ.co.example.mobile"
NONCE_OID = ObjectIdentifier("1.2.840.113635.100.8.2")
ACL_OID = ObjectIdentifier("1.2.840.113635.100.8.6")
# Exact extension from Apple's public 2026 iPhone example; no ACL semantics assumed.
IOS_ACL_DER = base64.b64decode("MEmjRwRFMEMMAjExMD0wCgwDb2tkoQMBAf8wCQwCb2GhAwEB/zALDARvc2duoQMBAf8wCwwEb2RlbKEDAQH/MAoMA29ja6EDAQH/")


def b64(value):
    return base64.b64encode(value).decode("ascii")


def cbor(value):
    # Independent minimal definite-length CBOR fixture encoder, not production code.
    def head(major, size):
        if size < 24:
            return bytes([major * 32 + size])
        if size < 256:
            return bytes([major * 32 + 24, size])
        if size < 65536:
            return bytes([major * 32 + 25]) + size.to_bytes(2, "big")
        return bytes([major * 32 + 26]) + size.to_bytes(4, "big")
    if type(value) is int:
        return head(0, value) if value >= 0 else head(1, -value - 1)
    if type(value) is bytes:
        return head(2, len(value)) + value
    if type(value) is str:
        raw = value.encode()
        return head(3, len(raw)) + raw
    if type(value) is list:
        return head(4, len(value)) + b"".join(cbor(x) for x in value)
    if type(value) is dict:
        return head(5, len(value)) + b"".join(cbor(k) + cbor(v) for k, v in value.items())
    raise AssertionError("unsupported fixture type")


def public_bytes(key):
    return key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def certificate(subject, key, issuer_name, signer, *, ca, path_length=None, digital_signature=True,
                key_cert_sign=None, valid=True, unknown_critical=False, extra_extensions=(), nonce=None,
                not_valid_before=None, not_valid_after=None):
    now = datetime.fromtimestamp(NOW, timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
            .issuer_name(issuer_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(not_valid_before or now - timedelta(days=1))
            .not_valid_after(not_valid_after or (now + timedelta(days=1) if valid else now - timedelta(seconds=1)))
            .add_extension(x509.BasicConstraints(ca, path_length), critical=True)
            .add_extension(x509.KeyUsage(digital_signature, False, False, False, False,
                                        ca if key_cert_sign is None else key_cert_sign, ca, False, False), critical=True))
    if nonce is not None:
        cert = cert.add_extension(x509.UnrecognizedExtension(NONCE_OID, nonce), critical=False)
    if unknown_critical:
        cert = cert.add_extension(x509.UnrecognizedExtension(ObjectIdentifier("1.2.3.4.5"), b"\x05\x00"), critical=True)
    for extension, critical in extra_extensions:
        cert = cert.add_extension(extension, critical)
    return cert.sign(signer, hashes.SHA256())


class SyntheticPKI:
    def __init__(self):
        self.root_key = ec.generate_private_key(ec.SECP384R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TEST ONLY root")])
        self.root = certificate("TEST ONLY root", self.root_key, name, self.root_key, ca=True, path_length=1)
        self.inter_key = ec.generate_private_key(ec.SECP384R1())
        self.inter = certificate("TEST ONLY intermediate", self.inter_key, self.root.subject, self.root_key, ca=True, path_length=0)
        self.key = ec.generate_private_key(ec.SECP256R1())

    def evidence(self, challenge, *, auth_change=None, nonce_change=None, leaf_changes=None,
                 key=None, cose_change=None, top_change=None, extensions=None, raw_cose=None, include_acl=True):
        key = key or self.key
        point = public_bytes(key)
        key_hash = hashlib.sha256(point).digest()
        numbers = key.public_key().public_numbers()
        cose_key = {1: 2, 3: -7, -1: 1, -2: numbers.x.to_bytes(32, "big"), -3: numbers.y.to_bytes(32, "big")}
        if cose_change:
            cose_change(cose_key)
        auth = (hashlib.sha256(APP_ID.encode()).digest() + bytes([0xC0 if extensions is not None else 0x40])
                + b"\0" * 4 + b"appattestdevelop" + b"\0\x20" + key_hash
                + (cbor(cose_key) if raw_cose is None else raw_cose)
                + (cbor(extensions) if extensions is not None else b""))
        if auth_change:
            auth = auth_change(auth)
        digest = hashlib.sha256(auth + hashlib.sha256(enrollment_message(challenge)).digest()).digest()
        nonce = b"\x30\x24\xa1\x22\x04\x20" + digest
        if nonce_change:
            nonce = nonce_change(nonce)
        leaf_options = dict(ca=False, nonce=nonce)
        leaf_options.update(leaf_changes or {})
        extras = list(leaf_options.get("extra_extensions", ()))
        if include_acl and not any(extension.oid == ACL_OID for extension, _ in extras):
            extras.insert(0, (x509.UnrecognizedExtension(ACL_OID, IOS_ACL_DER), False))
        leaf_options["extra_extensions"] = extras
        leaf = certificate("TEST ONLY leaf", key, self.inter.subject, self.inter_key, **leaf_options)
        obj = {"fmt": "apple-appattest", "attStmt": {
            "x5c": [leaf.public_bytes(serialization.Encoding.DER), self.inter.public_bytes(serialization.Encoding.DER)],
            "receipt": b"TEST ONLY opaque unverified receipt"}, "authData": auth}
        if top_change:
            top_change(obj)
        return json.dumps({"keyId": b64(key_hash), "attestationObject": b64(cbor(obj))}, separators=(",", ":")).encode()


@pytest.fixture
def context():
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    spki = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    challenge = Challenge("test-app", "test-user", "test-key", "https://api.example.test", hashlib.sha256(spki).hexdigest(),
                          "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", NOW + 120, pem)
    return SyntheticPKI(), challenge, key


def verifier(pki, monkeypatch, **kwargs):
    # The only trust substitution is a private trust-loader patched in tests.
    # The deployable constructor has no configurable trust root.
    monkeypatch.setattr(apple, "_trusted_root", lambda: pki.root)
    return apple.AppleAppAttestVerifier(app_id="test-app", apple_app_id=APP_ID, platform="ios", environment="development",
                                       clock=lambda: NOW, **kwargs)


def rejected(backend, challenge, evidence):
    with pytest.raises(apple.AppleAttestationError, match="^APPLE_ATTESTATION_REJECTED$") as failure:
        backend(challenge, evidence)
    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None
    assert failure.value.__suppress_context__ is True


def test_real_generated_chain_and_p256_key_produce_bound_finite_verdict(context, monkeypatch):
    pki, challenge, _ = context
    backend = verifier(pki, monkeypatch)
    result = backend(challenge, pki.evidence(challenge))
    assert (result.provider, result.status, result.app_id, result.subject) == ("apple", "verified", "test-app", "test-user")
    assert result.public_key_sha256 == challenge.public_key_sha256
    assert result.challenge_sha256 == hashlib.sha256(enrollment_message(challenge)).hexdigest()
    assert result.expires == NOW + 120


def test_official_root_rejects_generated_synthetic_chain(context):
    pki, challenge, _ = context
    backend = apple.AppleAppAttestVerifier(app_id="test-app", apple_app_id=APP_ID, platform="ios", environment="development", clock=lambda: NOW)
    rejected(backend, challenge, pki.evidence(challenge))


@pytest.mark.parametrize("target,changes", [
    ("inter", {"ca": False, "path_length": None}), ("inter", {"key_cert_sign": False}),
    ("inter", {"valid": False}), ("inter", {"unknown_critical": True}),
    ("root", {"path_length": 0}), ("root", {"valid": False}),
    ("root", {"key_cert_sign": False}), ("root", {"unknown_critical": True})])
def test_intermediate_and_anchor_constraints_cannot_be_skipped(context, monkeypatch, target, changes):
    pki, challenge, _ = context
    options = dict(ca=True, path_length=0 if target == "inter" else 1)
    options.update(changes)
    if target == "inter":
        pki.inter = certificate("TEST ONLY intermediate", pki.inter_key, pki.root.subject, pki.root_key, **options)
    else:
        pki.root = certificate("TEST ONLY root", pki.root_key, pki.root.subject, pki.root_key, **options)
    rejected(verifier(pki, monkeypatch), challenge, pki.evidence(challenge))


def test_issuer_name_and_issuer_signature_both_must_verify(context, monkeypatch):
    pki, challenge, _ = context
    pki.inter = certificate("TEST ONLY intermediate", pki.inter_key,
                           x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "wrong issuer")]), pki.root_key,
                           ca=True, path_length=0)
    rejected(verifier(pki, monkeypatch), challenge, pki.evidence(challenge))
    wrong_signer = ec.generate_private_key(ec.SECP384R1())
    pki.inter = certificate("TEST ONLY intermediate", pki.inter_key, pki.root.subject, wrong_signer, ca=True, path_length=0)
    rejected(verifier(pki, monkeypatch), challenge, pki.evidence(challenge))


def test_root_or_duplicate_certificate_inside_evidence_never_becomes_trusted(context, monkeypatch):
    pki, challenge, _ = context
    backend = verifier(pki, monkeypatch)
    for extra in [pki.root.public_bytes(serialization.Encoding.DER), pki.inter.public_bytes(serialization.Encoding.DER)]:
        rejected(backend, challenge, pki.evidence(challenge, top_change=lambda obj: obj["attStmt"]["x5c"].append(extra)))


def test_production_and_development_aaguids_are_separate(context, monkeypatch):
    pki, challenge, _ = context
    verifier(pki, monkeypatch)
    production = apple.AppleAppAttestVerifier(app_id="test-app", apple_app_id=APP_ID, platform="ios", environment="production", clock=lambda: NOW)
    rejected(production, challenge, pki.evidence(challenge))
    evidence = pki.evidence(challenge, auth_change=lambda a: a[:37] + b"appattest" + b"\0" * 7 + a[53:])
    assert production(challenge, evidence).status == "verified"


def test_pin_rejects_replaced_root_resource(context, monkeypatch):
    pki, _, _ = context
    class Resource:
        def joinpath(self, _):
            return self
        def read_bytes(self):
            return pki.root.public_bytes(serialization.Encoding.PEM)
    monkeypatch.setattr(apple, "files", lambda _: Resource())
    with pytest.raises(apple.AppleAttestationError, match="^APPLE_ATTESTATION_CONFIGURATION$"):
        apple.AppleAppAttestVerifier(app_id="test-app", apple_app_id=APP_ID, platform="ios", environment="development")


@pytest.mark.parametrize("field,value", [("app_id", "wrong-app"), ("subject", "wrong-user"),
    ("public_key_sha256", "0" * 64), ("origin", "https://other.test"), ("key_id", "other-key"),
    ("nonce", "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"), ("expires", NOW + 121)])
def test_attestation_nonce_binds_entire_enrollment_message(context, monkeypatch, field, value):
    pki, challenge, _ = context
    rejected(verifier(pki, monkeypatch), replace(challenge, **{field: value}), pki.evidence(challenge))


@pytest.mark.parametrize("change", [
    lambda a: b"\0" * 32 + a[32:],
    lambda a: a[:32] + b"\x00" + a[33:],
    lambda a: a[:32] + b"\x41" + a[33:],
    lambda a: a[:32] + b"\x44" + a[33:],
    lambda a: a[:33] + b"\0\0\0\1" + a[37:],
    lambda a: a[:37] + b"appattest" + b"\0" * 7 + a[53:],
    lambda a: a[:53] + b"\0\x1f" + a[55:],
    lambda a: a[:55] + b"\0" * 32 + a[87:],
    lambda a: a + b"\0", lambda a: a[:54]])
def test_authenticated_bad_authenticator_data_rejects(context, monkeypatch, change):
    pki, challenge, _ = context
    rejected(verifier(pki, monkeypatch), challenge, pki.evidence(challenge, auth_change=change))


@pytest.mark.parametrize("mutation", [lambda n: n[:-1] + bytes([n[-1] ^ 1]), lambda n: n + b"\0",
    lambda n: b"\x30\x81\x24" + n[2:], lambda n: n[2:], lambda n: b"\x30\x22\x04\x20" + n[-32:]])
def test_nonce_requires_exact_der_wrapped_digest(context, monkeypatch, mutation):
    pki, challenge, _ = context
    rejected(verifier(pki, monkeypatch), challenge, pki.evidence(challenge, nonce_change=mutation))


@pytest.mark.parametrize("changes", [{"ca": True}, {"valid": False}, {"digital_signature": False},
    {"key_cert_sign": True}, {"unknown_critical": True}, {"nonce": None},
    {"extra_extensions": [(x509.NameConstraints([x509.DNSName("example.test")], None), False)]}])
def test_unacceptable_leaf_certificate_rejects(context, monkeypatch, changes):
    pki, challenge, _ = context
    rejected(verifier(pki, monkeypatch), challenge, pki.evidence(challenge, leaf_changes=changes))


@pytest.mark.parametrize("mutation", [lambda k: k.update({1: 3}), lambda k: k.update({3: -35}),
    lambda k: k.update({-1: 2}), lambda k: k.update({-2: b"\0" * 32}),
    lambda k: k.update({-3: b"\0" * 31}), lambda k: k.update({4: b"extra"})])
def test_cose_curve_algorithm_coordinates_and_leaf_key_are_bound(context, monkeypatch, mutation):
    pki, challenge, _ = context
    rejected(verifier(pki, monkeypatch), challenge, pki.evidence(challenge, cose_change=mutation))


@pytest.mark.parametrize("mutation", [
    lambda o: o.update({"fmt": "apple"}), lambda o: o.update({"unknown": b"field"}),
    lambda o: o["attStmt"].update({"unknown": b"field"}),
    lambda o: o["attStmt"].update({"receipt": b""}),
    lambda o: o["attStmt"].update({"x5c": o["attStmt"]["x5c"][::-1]}),
    lambda o: o["attStmt"].update({"x5c": o["attStmt"]["x5c"][:1]}),
    lambda o: o["attStmt"]["x5c"].__setitem__(0, o["attStmt"]["x5c"][0] + b"trailing"),
    lambda o: o["attStmt"]["x5c"].__setitem__(0, o["attStmt"]["x5c"][0][:-1] + bytes([o["attStmt"]["x5c"][0][-1] ^ 1]))])
def test_statement_shape_chain_order_der_and_signatures_fail_closed(context, monkeypatch, mutation):
    pki, challenge, _ = context
    rejected(verifier(pki, monkeypatch), challenge, pki.evidence(challenge, top_change=mutation))


def test_nonminimal_certificate_der_length_is_rejected(context, monkeypatch):
    pki, challenge, _ = context
    def mutate(obj):
        raw = obj["attStmt"]["x5c"][0]
        assert raw[:2] == b"\x30\x82"
        obj["attStmt"]["x5c"][0] = b"\x30\x83\0" + raw[2:]
    rejected(verifier(pki, monkeypatch), challenge, pki.evidence(challenge, top_change=mutate))


def test_certificate_time_boundary_and_not_yet_valid_reject(context, monkeypatch):
    pki, challenge, _ = context
    backend = verifier(pki, monkeypatch)
    now = datetime.fromtimestamp(NOW, timezone.utc)
    for changes in [{"not_valid_before": now + timedelta(seconds=1)}, {"not_valid_after": now}]:
        rejected(backend, challenge, pki.evidence(challenge, leaf_changes=changes))


def test_unexpected_verifier_exception_has_only_public_fixed_error(context, monkeypatch):
    pki, challenge, _ = context
    backend = verifier(pki, monkeypatch)
    def unavailable():
        raise RuntimeError("TEST ONLY PRIVATE TOKEN MATERIAL")
    backend._clock = unavailable
    with pytest.raises(apple.AppleAttestationError) as result:
        backend(challenge, pki.evidence(challenge))
    assert result.value.code == "APPLE_ATTESTATION_REJECTED"
    assert str(result.value) == "APPLE_ATTESTATION_REJECTED"
    assert result.value.__cause__ is None and result.value.__suppress_context__ is True
    assert result.value.__context__ is None


@pytest.mark.parametrize("field,value", [("keyId", b64(b"\0" * 32)), ("keyId", "invalid"),
    ("keyId", b64(b"\0" * 31)), ("keyId", True), ("attestationObject", "aA"),
    ("attestationObject", "AA==\n"), ("attestationObject", "AB=="), ("attestationObject", [])])
def test_envelope_types_and_canonical_base64_are_enforced(context, monkeypatch, field, value):
    pki, challenge, _ = context
    obj = json.loads(pki.evidence(challenge)); obj[field] = value
    rejected(verifier(pki, monkeypatch), challenge, json.dumps(obj).encode())


@pytest.mark.parametrize("raw", [b"", b"x" * 65537, b"\xff", b"[]", b"{}", b'{"keyId":"x","keyId":"y","attestationObject":"AA=="}',
    b'{"keyId":"x","attestationObject":"AA==","status":"verified"}', b'{"keyId":NaN,"attestationObject":"AA=="}', b"{} {}"])
def test_duplicate_unknown_oversized_malformed_json_rejects(context, monkeypatch, raw):
    pki, challenge, _ = context
    rejected(verifier(pki, monkeypatch), challenge, raw)


@pytest.mark.parametrize("raw", [b"\xa0\0", b"\xbf\xff", b"\xd8\x18\xa0", b"\xf5", b"\xf6", b"\xfb" + b"\0" * 8,
    b"\xb8\0", b"\xa2\x61a\0\x61a\1", b"\xa1\x41a\0", b"\x9b" + b"\xff" * 8,
    b"\x81" * 32 + b"\0", b"\xa1\x61\xff\0", b"\xa1\x18\x01\0"])
def test_strict_cbor_rejects_duplicate_depth_trailing_tags_indefinite_nonminimal_and_types(context, monkeypatch, raw):
    pki, challenge, _ = context
    rejected(verifier(pki, monkeypatch), challenge, json.dumps({"keyId": b64(b"\0" * 32), "attestationObject": b64(raw)}).encode())


def test_cose_duplicate_keys_reject_in_signed_authenticator(context, monkeypatch):
    pki, challenge, _ = context
    point = public_bytes(pki.key)
    raw = b"\xa6" + cbor(1) + cbor(2) + cbor(1) + cbor(2) + cbor(3) + cbor(-7) + cbor(-1) + cbor(1) + cbor(-2) + cbor(point[1:33]) + cbor(-3) + cbor(point[33:])
    rejected(verifier(pki, monkeypatch), challenge, pki.evidence(challenge, raw_cose=raw))


@pytest.mark.parametrize("mutation", [
    lambda raw: b"\xb8\x03" + raw[1:],
    lambda raw: b"\xbf" + raw[1:] + b"\xff",
    lambda raw: b"\xa4" + raw[1:] + cbor("fmt") + cbor("apple-appattest"),
    lambda raw: raw + b"\0", lambda raw: b"\xd8\x18" + raw])
def test_noncanonical_cbor_wrapping_of_otherwise_valid_attestation_rejects(context, monkeypatch, mutation):
    pki, challenge, _ = context
    evidence = json.loads(pki.evidence(challenge))
    evidence["attestationObject"] = b64(mutation(base64.b64decode(evidence["attestationObject"])))
    rejected(verifier(pki, monkeypatch), challenge, json.dumps(evidence).encode())


def test_nonminimal_cose_integer_with_otherwise_valid_key_rejects(context, monkeypatch):
    pki, challenge, _ = context
    point = public_bytes(pki.key)
    raw = b"\xa5\x18\x01\x02" + cbor(3) + cbor(-7) + cbor(-1) + cbor(1) + cbor(-2) + cbor(point[1:33]) + cbor(-3) + cbor(point[33:])
    rejected(verifier(pki, monkeypatch), challenge, pki.evidence(challenge, raw_cose=raw))


def test_new_mobile_extensions_need_explicit_category_and_bundle_policy(context, monkeypatch):
    pki, challenge, _ = context
    extensions = {"apple_validation_category_01": b"\x03\0\0\0", "apple_bundle_version_01": "42"}
    evidence = pki.evidence(challenge, extensions=extensions)
    rejected(verifier(pki, monkeypatch), challenge, evidence)
    backend = verifier(pki, monkeypatch, allowed_validation_categories={3}, allowed_bundle_versions={"42"})
    assert backend(challenge, evidence).status == "verified"
    for changed in [{**extensions, "apple_validation_category_01": b"\x04\0\0\0"},
                    {**extensions, "apple_validation_category_01": 3},
                    {**extensions, "apple_bundle_version_01": "43"}, {**extensions, "unknown": "value"}]:
        rejected(backend, challenge, pki.evidence(challenge, extensions=changed))


def test_configured_extension_policy_requires_extensions_and_rejects_unknown_acl(context, monkeypatch):
    pki, challenge, _ = context
    rejected(verifier(pki, monkeypatch, allowed_validation_categories={4}, allowed_bundle_versions={"42"}), challenge, pki.evidence(challenge))
    mac_nonce = [(x509.UnrecognizedExtension(ObjectIdentifier("1.2.840.113635.100.8.6"), b"TEST ONLY mac ACL"), False)]
    rejected(verifier(pki, monkeypatch), challenge, pki.evidence(challenge, leaf_changes={"extra_extensions": mac_nonce}))


def test_known_current_ios_acl_profile_is_accepted_and_absent_acl_needs_explicit_legacy_option(context, monkeypatch):
    pki, challenge, _ = context
    backend = verifier(pki, monkeypatch)
    assert backend(challenge, pki.evidence(challenge)).status == "verified"
    absent = pki.evidence(challenge, include_acl=False)
    rejected(backend, challenge, absent)
    legacy = verifier(pki, monkeypatch, allow_legacy_without_acl=True)
    assert legacy(challenge, absent).status == "verified"


@pytest.mark.parametrize("blob", [IOS_ACL_DER + b"\0", b"\x30\x81\x49" + IOS_ACL_DER[2:],
    b"\x30\x49\xa1" + IOS_ACL_DER[3:], IOS_ACL_DER[:-1] + b"\0",
    b"\x30\x02\x05\0", b""])
def test_malformed_unknown_ios_acl_never_downgrades_through_legacy_option(context, monkeypatch, blob):
    pki, challenge, _ = context
    extras = [(x509.UnrecognizedExtension(ACL_OID, blob), False)]
    for legacy in (False, True):
        backend = verifier(pki, monkeypatch, allow_legacy_without_acl=legacy)
        rejected(backend, challenge, pki.evidence(challenge, leaf_changes={"extra_extensions": extras}))


def test_clock_expiry_and_ttl_bounds_are_enforced(context, monkeypatch):
    pki, challenge, _ = context
    backend = verifier(pki, monkeypatch, verdict_ttl=30)
    assert backend(challenge, pki.evidence(challenge)).expires == NOW + 30
    rejected(backend, replace(challenge, expires=NOW), pki.evidence(challenge))
    for bad_clock in [lambda: True, lambda: "secret", lambda: -1]:
        backend = verifier(pki, monkeypatch); backend._clock = bad_clock
        rejected(backend, challenge, pki.evidence(challenge))


@pytest.mark.parametrize("settings", [{"apple_app_id": "co.example.mobile"}, {"environment": "auto"},
    {"app_id": ""}, {"clock": 3}, {"verdict_ttl": True}, {"verdict_ttl": 0}, {"verdict_ttl": 301},
    {"allowed_validation_categories": {3}}, {"allowed_validation_categories": {6}, "allowed_bundle_versions": {"42"}},
    {"platform": "macos"}, {"platform": "auto"}, {"allow_legacy_without_acl": 1}])
def test_configuration_is_explicit_and_rejects_unsupported_policy(context, settings):
    options = dict(app_id="test-app", apple_app_id=APP_ID, platform="ios", environment="development", clock=lambda: NOW)
    options.update(settings)
    with pytest.raises(apple.AppleAttestationError, match="^APPLE_ATTESTATION_CONFIGURATION$"):
        apple.AppleAppAttestVerifier(**options)


@pytest.mark.parametrize("profile", ["basic", "balanced"])
def test_actual_enrollment_with_synthetic_trust_one_use_and_distinct_request_key(context, monkeypatch, tmp_path, profile):
    pki, _, key = context
    backend = verifier(pki, monkeypatch)
    store = SqliteEnrollmentStore(tmp_path / "enrollment.sqlite")
    service = EnrollmentService(store, profile=profile, clock=lambda: NOW, attestation_verifier=backend)
    challenge = service.issue(app_id="test-app", subject="test-user", key_id="request-key", origin="https://api.example.test",
                              public_key_pem=key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    r, s = utils.decode_dss_signature(key.sign(enrollment_message(challenge), ec.ECDSA(hashes.SHA256())))
    proof = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    evidence = pki.evidence(challenge)
    def attempt(_):
        try:
            return service.complete(challenge.nonce, app_id="test-app", subject="test-user", proof=proof, evidence=evidence).attestation
        except EnrollmentError as error:
            return error.code
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(attempt, range(8)))
    assert results.count("verified") == 1
    assert set(results) == {"verified", "CHALLENGE_REJECTED"}
    credential = store.lookup("test-app", "test-user", "request-key")
    assert credential.provider == "apple" and credential.key.public_key_pem == challenge.public_key_pem


def test_bounded_random_cbor_evidence_never_escapes_redacted_failure(context, monkeypatch):
    pki, challenge, _ = context
    backend = verifier(pki, monkeypatch)
    rng = random.Random(3701)
    for _ in range(250):
        raw = rng.randbytes(rng.randrange(1, 256))
        rejected(backend, challenge, json.dumps({"keyId": b64(b"\0" * 32), "attestationObject": b64(raw)}).encode())


def test_actual_enrollment_rejects_cross_subject_spki_evidence_and_preserves_challenge(context, monkeypatch, tmp_path):
    pki, _, key = context
    store = SqliteEnrollmentStore(tmp_path / "enrollment.sqlite")
    service = EnrollmentService(store, profile="balanced", clock=lambda: NOW, attestation_verifier=verifier(pki, monkeypatch))
    pem = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    challenge = service.issue(app_id="test-app", subject="test-user", key_id="request-key", origin="https://api.example.test", public_key_pem=pem)
    r, s = utils.decode_dss_signature(key.sign(enrollment_message(challenge), ec.ECDSA(hashes.SHA256())))
    proof = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    for changes in [{"subject": "other-user"}, {"public_key_sha256": "0" * 64}]:
        with pytest.raises(EnrollmentError, match="^ATTESTATION_UNAVAILABLE$"):
            service.complete(challenge.nonce, app_id="test-app", subject="test-user", proof=proof,
                             evidence=pki.evidence(replace(challenge, **changes)))
        assert store.pending(challenge.nonce) == challenge
        assert store.lookup("test-app", "test-user", "request-key") is None


def test_actual_enrollment_rechecks_expiry_after_real_backend(context, monkeypatch, tmp_path):
    pki, _, key = context
    clock = [NOW]
    backend = verifier(pki, monkeypatch)
    store = SqliteEnrollmentStore(tmp_path / "enrollment.sqlite")
    def slow_verification(challenge, evidence):
        result = backend(challenge, evidence)
        clock[0] = challenge.expires
        return result
    service = EnrollmentService(store, profile="balanced", clock=lambda: clock[0], attestation_verifier=slow_verification)
    challenge = service.issue(app_id="test-app", subject="test-user", key_id="request-key", origin="https://api.example.test",
                              public_key_pem=key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    r, s = utils.decode_dss_signature(key.sign(enrollment_message(challenge), ec.ECDSA(hashes.SHA256())))
    with pytest.raises(EnrollmentError, match="^CHALLENGE_REJECTED$"):
        service.complete(challenge.nonce, app_id="test-app", subject="test-user", proof=r.to_bytes(32, "big") + s.to_bytes(32, "big"),
                         evidence=pki.evidence(challenge))
    assert store.lookup("test-app", "test-user", "request-key") is None


def test_malformed_json_error_does_not_retain_evidence(context, monkeypatch):
    pki, challenge, _ = context
    backend = verifier(pki, monkeypatch)
    with pytest.raises(apple.AppleAttestationError) as result:
        backend(challenge, b'PRIVATE_SYNTHETIC_EVIDENCE')
    assert str(result.value) == "APPLE_ATTESTATION_REJECTED"
    assert result.value.__cause__ is None
    assert result.value.__context__ is None


def test_configuration_error_does_not_retain_trust_loader_exception(monkeypatch):
    def unavailable():
        raise RuntimeError("PRIVATE_SYNTHETIC_CONFIGURATION")
    monkeypatch.setattr(apple, "_trusted_root", unavailable)
    with pytest.raises(apple.AppleAttestationError) as result:
        apple.AppleAppAttestVerifier(app_id="my-app", apple_app_id="ABCDE12345.com.example.app",
                                    platform="ios", environment="development")
    assert str(result.value) == "APPLE_ATTESTATION_CONFIGURATION"
    assert result.value.__cause__ is None
    assert result.value.__context__ is None
