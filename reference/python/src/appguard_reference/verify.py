"""Typed-input reference verification orchestration."""

from .canonical import ALGORITHM, build_signature_base, validate_content_digest, validate_identifier
from .crypto import load_p256_key, verify_p256
from .replay import ReplayStore
from .types import KeyRecord, RequestInput, SignatureParameters, VerificationError, VerificationResult


def verify_request(
    request: RequestInput, parameters: SignatureParameters, signature: bytes, *, origin: str,
    app_id: str, subject: str, key: KeyRecord, now: int, replay: ReplayStore,
) -> VerificationResult:
    # The typed boundary is not a substitute for runtime validation.
    validate_identifier(app_id)
    validate_identifier(subject)
    base = build_signature_base(request, parameters, origin=origin)
    if (type(now) is not int or not 0 <= now <= 999999999999999
            or not parameters.created < parameters.expires
            or parameters.expires - parameters.created > 120
            or parameters.created > now + 30 or now >= parameters.expires):
        raise VerificationError("INVALID_TIME")

    signed_app = next(value for name, value in request.headers if name.lower() == "appguard-app-id")
    if (not isinstance(key, KeyRecord) or key.revoked is not False
            or key.app_id != app_id or signed_app != app_id
            or key.subject != subject or key.key_id != parameters.key_id or key.algorithm != ALGORITHM):
        raise VerificationError("KEY_REJECTED")
    load_p256_key(key.public_key_pem)
    validate_content_digest(request)
    verify_p256(key.public_key_pem, base, signature)

    try:
        claimed = replay.claim((app_id, key.key_id, parameters.nonce), expires=parameters.expires, now=now)
    except Exception:
        raise VerificationError("REPLAY_STORE_UNAVAILABLE") from None
    if claimed is False:
        raise VerificationError("REPLAY_DETECTED")
    if claimed is not True:
        raise VerificationError("REPLAY_STORE_UNAVAILABLE")
    return VerificationResult(app_id, key.key_id, parameters.expires)
