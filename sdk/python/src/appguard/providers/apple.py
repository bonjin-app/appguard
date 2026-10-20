"""Bounded initial App Attest verification; no assertions, network or hardware claim."""

import base64
import hashlib
import hmac
from importlib.resources import files
import json
import re
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtensionOID, ObjectIdentifier, SignatureAlgorithmOID

from ..enrollment_types import AttestationVerdict, _identifier, _time, enrollment_message


APPLE_APP_ATTESTATION_ROOT_SOURCE = "https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem"
APPLE_APP_ATTESTATION_ROOT_DER_SHA256 = "1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932"
# Opaque compatibility pin from Apple's current public iPhone example, fetched
# 2026-10-20. This is not an interpretation of undocumented ACL operations.
APPLE_IOS_ACL_SOURCE = "https://developer.apple.com/documentation/devicecheck/attestation-object-validation-guide"
APPLE_IOS_ACL_EXTENSION_DER_SHA256 = "7db346a6a4c741cc72b464c716914c52f28290c382a7cc27b9064be22b0e8c48"
APPLE_IOS_ACL_BLOB_SHA256 = "a71a166db83ac886fdf586337bb5588b9f23c145c04966672d080c5225236f2a"
_IOS_ACL_BLOB = base64.b64decode("MEMMAjExMD0wCgwDb2tkoQMBAf8wCQwCb2GhAwEB/zALDARvc2duoQMBAf8wCwwEb2RlbKEDAQH/MAoMA29ja6EDAQH/")
_NONCE_OID = ObjectIdentifier("1.2.840.113635.100.8.2")
_ACL_OID = ObjectIdentifier("1.2.840.113635.100.8.6")
_MAX_EVIDENCE = 65536


class AppleAttestationError(Exception):
    """Only fixed, redacted public error codes cross the provider boundary."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


class _CBOR:
    """Small definite-length App Attest profile, bounded before allocation/recursion.

    Only bytes, UTF-8 text, integers, arrays and maps with integer/text keys exist
    in this profile. RFC 8949 shortest scalar/length encodings are mandatory;
    map ordering is deliberately unrestricted because Apple does not promise it.
    """

    def __init__(self, raw):
        if type(raw) is not bytes or not 1 <= len(raw) <= _MAX_EVIDENCE:
            raise ValueError
        self.raw, self.position, self.items = raw, 0, 0

    def take(self, length):
        if length > len(self.raw) - self.position:
            raise ValueError
        start = self.position
        self.position += length
        return self.raw[start:self.position]

    def read(self, depth=0):
        self.items += 1
        if depth > 8 or self.items > 256:
            raise ValueError
        first = self.take(1)[0]
        major, additional = first >> 5, first & 31
        if major > 5 or additional > 27:
            raise ValueError
        if additional < 24:
            length = additional
        else:
            size = 1 << (additional - 24)
            length = int.from_bytes(self.take(size), "big")
            if length < {1: 24, 2: 256, 4: 65536, 8: 4294967296}[size]:
                raise ValueError
        if major == 0:
            return length
        if major == 1:
            return -1 - length
        if major in (2, 3):
            raw = self.take(length)
            return raw if major == 2 else raw.decode("utf-8", errors="strict")
        if length > 64:
            raise ValueError
        if major == 4:
            return [self.read(depth + 1) for _ in range(length)]
        result = {}
        for _ in range(length):
            key = self.read(depth + 1)
            if type(key) not in (int, str) or key in result:
                raise ValueError
            result[key] = self.read(depth + 1)
        return result

    def complete(self):
        result = self.read()
        if self.position != len(self.raw):
            raise ValueError
        return result


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _decode_base64(value):
    if type(value) is not str or not 1 <= len(value) <= _MAX_EVIDENCE:
        raise ValueError
    raw = base64.b64decode(value, validate=True)
    if base64.b64encode(raw).decode("ascii") != value:
        raise ValueError
    return raw


def _trusted_root():
    pem = files(__package__).joinpath("apple_app_attestation_root.pem").read_bytes()
    root = x509.load_pem_x509_certificate(pem)
    if root.fingerprint(hashes.SHA256()).hex() != APPLE_APP_ATTESTATION_ROOT_DER_SHA256:
        raise ValueError
    return root


def _single_der(raw, tag):
    # This pinned profile has only short definite lengths. Requiring the exact
    # whole TLV rejects nonminimal lengths, extra children and trailing data.
    if type(raw) is not bytes or len(raw) < 2 or raw[0] != tag or raw[1] >= 128 or raw[1] != len(raw) - 2:
        raise ValueError
    return raw[2:]


def _ios_acl(leaf, allow_legacy):
    try:
        extension = leaf.extensions.get_extension_for_oid(_ACL_OID)
    except x509.ExtensionNotFound:
        if not allow_legacy:
            raise ValueError
        return
    if not isinstance(extension.value, x509.UnrecognizedExtension):
        raise ValueError
    blob = _single_der(_single_der(_single_der(extension.value.value, 0x30), 0xA3), 0x04)
    if not hmac.compare_digest(blob, _IOS_ACL_BLOB):
        raise ValueError


def _valid_certificate(cert, now, *, ca, subordinate_cas):
    if not cert.not_valid_before_utc.timestamp() <= now < cert.not_valid_after_utc.timestamp():
        raise ValueError
    constraints = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
    usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
    if not constraints.critical or not usage.critical or constraints.value.ca is not ca:
        raise ValueError
    if ca:
        if not usage.value.key_cert_sign or (constraints.value.path_length is not None
                                             and subordinate_cas > constraints.value.path_length):
            raise ValueError
    elif not usage.value.digital_signature or usage.value.key_cert_sign or usage.value.crl_sign:
        raise ValueError
    # Unsupported constraints cannot silently weaken the hand-validated profile.
    unsupported = {ExtensionOID.NAME_CONSTRAINTS, ExtensionOID.POLICY_CONSTRAINTS,
                   ExtensionOID.INHIBIT_ANY_POLICY, ExtensionOID.POLICY_MAPPINGS}
    for extension in cert.extensions:
        if extension.oid in unsupported or (extension.critical and extension.oid not in {
                ExtensionOID.BASIC_CONSTRAINTS, ExtensionOID.KEY_USAGE}):
            raise ValueError
    public = cert.public_key()
    if (not isinstance(public, ec.EllipticCurvePublicKey)
            or not isinstance(public.curve, (ec.SECP256R1, ec.SECP384R1))
            or cert.signature_algorithm_oid not in {SignatureAlgorithmOID.ECDSA_WITH_SHA256,
                                                    SignatureAlgorithmOID.ECDSA_WITH_SHA384}):
        raise ValueError


def _chain(encoded, root, now):
    if type(encoded) is not list or not 2 <= len(encoded) <= 4:
        raise ValueError
    chain, seen = [], set()
    for raw in encoded:
        if type(raw) is not bytes or not 1 <= len(raw) <= 8192:
            raise ValueError
        cert = x509.load_der_x509_certificate(raw)
        # cryptography's strict DER parser + whole-input check reject ambiguities.
        if cert.public_bytes(serialization.Encoding.DER) != raw:
            raise ValueError
        digest = cert.fingerprint(hashes.SHA256())
        if digest in seen or digest == root.fingerprint(hashes.SHA256()):
            raise ValueError
        seen.add(digest)
        chain.append(cert)
    chain.append(root)
    for index, cert in enumerate(chain):
        _valid_certificate(cert, now, ca=index > 0, subordinate_cas=max(index - 1, 0))
        issuer = chain[min(index + 1, len(chain) - 1)]
        cert.verify_directly_issued_by(issuer)
    public = chain[0].public_key()
    if not isinstance(public.curve, ec.SECP256R1):
        raise ValueError
    return chain[0], public


class AppleAppAttestVerifier:
    """Callable EnrollmentService backend with a fixed official trust anchor.

    app_id is the server's AppGuard route ID; apple_app_id is the provisioned
    Apple App ID prefix + '.' + bundle ID, which need not share that route ID.
    Legacy mobile objects omit authenticator extensions. To require signed new
    mobile category/version extensions configure both allowlists.
    The iOS ACL profile pins Apple's public sample exactly; a changed or unknown
    profile fails closed. macOS is unsupported. Optional legacy absence of the
    ACL extension is a separate explicit server policy.
    """

    def __init__(self, *, app_id, apple_app_id, platform, environment, clock=None, verdict_ttl=120,
                 allowed_validation_categories=None, allowed_bundle_versions=None, allow_legacy_without_acl=False):
        configured = False
        try:
            _identifier(app_id)
            if (type(apple_app_id) is not str or len(apple_app_id) > 266
                    or re.fullmatch(r"[A-Z0-9]{10}\.[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*", apple_app_id) is None
                    or type(platform) is not str or platform != "ios"
                    or type(environment) is not str or environment not in {"development", "production"}
                    or type(allow_legacy_without_acl) is not bool
                    or (clock is not None and not callable(clock))
                    or type(verdict_ttl) is not int or not 1 <= verdict_ttl <= 300):
                raise ValueError
            if (allowed_validation_categories is None) != (allowed_bundle_versions is None):
                raise ValueError
            categories, versions = None, None
            if allowed_validation_categories is not None:
                if (type(allowed_validation_categories) not in (set, frozenset)
                        or not 1 <= len(allowed_validation_categories) <= 4
                        or any(type(x) is not int or x not in {2, 3, 4, 5} for x in allowed_validation_categories)
                        or type(allowed_bundle_versions) not in (set, frozenset)
                        or not 1 <= len(allowed_bundle_versions) <= 64
                        or any(type(x) is not str or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", x) is None
                               for x in allowed_bundle_versions)):
                    raise ValueError
                categories, versions = frozenset(allowed_validation_categories), frozenset(allowed_bundle_versions)
            self._root = _trusted_root()
            configured = True
        except Exception:
            pass
        if not configured:
            raise AppleAttestationError("APPLE_ATTESTATION_CONFIGURATION") from None
        self._app_id, self._rp_id = app_id, hashlib.sha256(apple_app_id.encode("ascii")).digest()
        self._aaguid = b"appattestdevelop" if environment == "development" else b"appattest" + b"\0" * 7
        self._clock = clock if clock is not None else lambda: int(time.time())
        self._ttl, self._categories, self._versions = verdict_ttl, categories, versions
        self._allow_legacy_acl = allow_legacy_without_acl

    def __call__(self, challenge, evidence):
        try:
            return self._verify(challenge, evidence)
        except Exception:
            pass
        raise AppleAttestationError("APPLE_ATTESTATION_REJECTED") from None

    def _verify(self, challenge, evidence):
        now = _time(self._clock())
        message = enrollment_message(challenge)
        if challenge.app_id != self._app_id or now >= challenge.expires:
            raise ValueError
        if type(evidence) is not bytes or not 1 <= len(evidence) <= _MAX_EVIDENCE:
            raise ValueError
        envelope = json.loads(evidence.decode("utf-8"), object_pairs_hook=_pairs,
                              parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if type(envelope) is not dict or set(envelope) != {"keyId", "attestationObject"}:
            raise ValueError
        key_id = _decode_base64(envelope["keyId"])
        if len(key_id) != 32:
            raise ValueError
        obj = _CBOR(_decode_base64(envelope["attestationObject"])).complete()
        if (type(obj) is not dict or set(obj) != {"fmt", "attStmt", "authData"}
                or obj["fmt"] != "apple-appattest" or type(obj["attStmt"]) is not dict
                or set(obj["attStmt"]) != {"x5c", "receipt"}
                or type(obj["attStmt"]["receipt"]) is not bytes
                or not 1 <= len(obj["attStmt"]["receipt"]) <= 32768):
            raise ValueError
        leaf, public = _chain(obj["attStmt"]["x5c"], self._root, now)
        _ios_acl(leaf, self._allow_legacy_acl)
        point = public.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        if not hmac.compare_digest(hashlib.sha256(point).digest(), key_id):
            raise ValueError
        auth = obj["authData"]
        if (type(auth) is not bytes or not 88 <= len(auth) <= 4096
                or auth[32] not in (0x40, 0xC0) or auth[33:37] != b"\0" * 4
                or not hmac.compare_digest(auth[:32], self._rp_id)
                or auth[37:53] != self._aaguid or auth[53:55] != b"\0\x20"
                or not hmac.compare_digest(auth[55:87], key_id)):
            raise ValueError
        cose_reader = _CBOR(auth[87:])
        cose = cose_reader.read()
        if (type(cose) is not dict or set(cose) != {1, 3, -1, -2, -3}
                or cose[1] != 2 or cose[3] != -7 or cose[-1] != 1
                or type(cose[-2]) is not bytes or len(cose[-2]) != 32
                or type(cose[-3]) is not bytes or len(cose[-3]) != 32
                or not hmac.compare_digest(b"\x04" + cose[-2] + cose[-3], point)):
            raise ValueError
        if auth[32] == 0xC0:
            extensions = cose_reader.read()
            if (type(extensions) is not dict or set(extensions) != {
                    "apple_validation_category_01", "apple_bundle_version_01"}
                    or self._categories is None):
                raise ValueError
            category, version = extensions["apple_validation_category_01"], extensions["apple_bundle_version_01"]
            if (type(category) is not bytes or len(category) != 4
                    or int.from_bytes(category, "little") not in self._categories
                    or type(version) is not str or version not in self._versions):
                raise ValueError
        elif self._categories is not None:
            raise ValueError
        if cose_reader.position != len(cose_reader.raw):
            raise ValueError
        digest = hashlib.sha256(message).digest()
        nonce = hashlib.sha256(auth + digest).digest()
        extension = leaf.extensions.get_extension_for_oid(_NONCE_OID)
        if (not isinstance(extension.value, x509.UnrecognizedExtension)
                or not hmac.compare_digest(extension.value.value, b"\x30\x24\xa1\x22\x04\x20" + nonce)):
            raise ValueError
        expires = min(challenge.expires, now + self._ttl)
        return AttestationVerdict("apple", "verified", challenge.app_id, challenge.subject,
                                  challenge.public_key_sha256, digest.hex(), expires)
