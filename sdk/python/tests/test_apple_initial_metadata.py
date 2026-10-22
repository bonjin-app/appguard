"""Synthetic initial metadata behavior; no genuine device/provider assertion."""
import base64
import hashlib

from cryptography.hazmat.primitives import serialization

from test_apple_provider import APP_ID, NOW, context, public_bytes, verifier


def test_verified_initial_metadata_preserves_key_and_unverified_receipt(context, monkeypatch):
    pki, challenge, _ = context
    backend = verifier(pki, monkeypatch)
    evidence = pki.evidence(challenge)
    initial = backend.verify_initial(challenge, evidence)
    assert initial.verdict == backend(challenge, evidence)
    assert initial.key_id == base64.b64encode(hashlib.sha256(public_bytes(pki.key)).digest()).decode()
    assert initial.public_key_der == pki.key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert initial.apple_app_id == APP_ID
    assert initial.environment == "development"
    assert initial.verified_at == NOW
    assert initial.opaque_receipt == b"TEST ONLY opaque unverified receipt"
    assert initial.validation_category is None and initial.bundle_version is None
    assert "receipt" not in repr(initial) and challenge.subject not in repr(initial)


def test_verified_initial_metadata_retains_only_verified_signed_properties(context, monkeypatch):
    pki, challenge, _ = context
    backend = verifier(pki, monkeypatch, allowed_validation_categories={3}, allowed_bundle_versions={"42"})
    initial = backend.verify_initial(challenge, pki.evidence(challenge, extensions={
        "apple_validation_category_01": b"\x03\0\0\0", "apple_bundle_version_01": "42"}))
    assert (initial.validation_category, initial.bundle_version) == (3, "42")
