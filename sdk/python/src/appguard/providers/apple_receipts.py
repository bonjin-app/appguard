"""Opt-in, bounded Apple App Attest receipt verification and refresh.

This is a conservative profile of Apple's current published CMS sample. It is
independent of initial App Attest verification and does not authorize a request.
No network, credentials, certificate discovery, or persistence occurs on import.
"""
import base64
from dataclasses import dataclass, field
from datetime import datetime
from functools import wraps
import hashlib
import hmac
import http.client
from importlib.resources import files
import math
import re
import socket
import ssl
import threading
import time

from asn1crypto import cms
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtensionOID, NameOID, ObjectIdentifier

APPLE_RECEIPT_ROOT_SOURCE = "https://www.apple.com/certificateauthority/AppleRootCA-G3.cer"
APPLE_RECEIPT_ROOT_DER_SHA256 = "63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179"
_MAX_RECEIPT = 262144
_MAX_ENCODED = 4 * ((_MAX_RECEIPT + 2) // 3)
_LEAF_MARKER = ObjectIdentifier("1.2.840.113635.100.12.15")
_CA_MARKER = ObjectIdentifier("1.2.840.113635.100.6.2.3")
_POLICY = ObjectIdentifier("1.2.840.113635.100.5.1")
_HOSTS = {"production": "data.appattest.apple.com", "development": "data-development.appattest.apple.com"}


class AppleReceiptError(Exception):
    """Fixed public codes; provider bodies, tokens and parser errors stay private."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _boundary(code):
    def decorate(function):
        @wraps(function)
        def run(*args, **kwargs):
            try:
                return function(*args, **kwargs)
            except Exception:
                pass
            # Outside the handler: even __context__ must not retain raw parser,
            # credential callback, transport or provider-response exceptions.
            raise AppleReceiptError(code) from None
        return run
    return decorate


@dataclass(frozen=True)
class VerifiedAppleReceipt:
    """In-process result, with all identity/evidence fields excluded from repr.

    Fresh validation proves the configured app/key/environment and the exact
    caller-provided field-4 binding. An old result validated for refresh is not
    fresh attestation evidence. The receipt remains a bearer-like private value.
    """

    apple_app_id: str = field(repr=False)
    environment: str
    public_key_der: bytes = field(repr=False)
    client_hash: bytes = field(repr=False)
    receipt_type: str
    created_at: float
    expires_at: float
    not_before: float | None
    risk_metric: int | None
    verified_at: float
    fresh: bool
    receipt: bytes = field(repr=False)
    receipt_sha256: str = field(repr=False)


def _ber_bounds(raw):
    """Bound the entire ASN.1 tree before schema decoding, including BER EOCs.

    Apple's CMS uses indefinite constructed lengths. Primitive indefinite
    lengths, excessive tag/length encodings, trailing bytes and depth bombs are
    rejected here before asn1crypto can allocate or descend into the message.
    OCTET STRING contents are scanned separately when used as receipt payload.
    """
    if type(raw) is not bytes or not 1 <= len(raw) <= _MAX_RECEIPT:
        raise ValueError
    items = 0

    def node(position, limit, depth):
        nonlocal items
        items += 1
        if items > 2048 or depth > 24 or position + 2 > limit:
            raise ValueError
        first = raw[position]
        position += 1
        if first == 0:
            raise ValueError
        if first & 31 == 31:
            tag = 0
            for index in range(4):
                if position >= limit:
                    raise ValueError
                octet = raw[position]
                position += 1
                if index == 0 and octet & 127 == 0:
                    raise ValueError
                tag = (tag << 7) | (octet & 127)
                if not octet & 128:
                    break
            else:
                raise ValueError
            if tag < 31:
                raise ValueError
        if position >= limit:
            raise ValueError
        length = raw[position]
        position += 1
        if length == 128:
            if not first & 32:
                raise ValueError
            while True:
                if position + 2 > limit:
                    raise ValueError
                if raw[position:position + 2] == b"\0\0":
                    return position + 2
                position = node(position, limit, depth + 1)
        if length & 128:
            count = length & 127
            if not 1 <= count <= 4 or position + count > limit or raw[position] == 0:
                raise ValueError
            length = int.from_bytes(raw[position:position + count], "big")
            position += count
            if length < 128:
                raise ValueError
        end = position + length
        if end > limit:
            raise ValueError
        if first & 32:
            while position < end:
                position = node(position, end, depth + 1)
            if position != end:
                raise ValueError
        return end

    if node(0, len(raw), 0) != len(raw):
        raise ValueError


def _receipt_root():
    root = x509.load_pem_x509_certificate(files(__package__).joinpath("apple_receipt_root_g3.pem").read_bytes())
    if root.fingerprint(hashes.SHA256()).hex() != APPLE_RECEIPT_ROOT_DER_SHA256:
        raise ValueError
    return root


def _extension(cert, oid):
    return cert.extensions.get_extension_for_oid(oid)


def _certificate_profile(cert, now, *, ca, marker=None):
    # Deliberately narrow: no unknown critical extension or unsupported policy
    # semantics may be treated as understood by this private chain evaluator.
    for extension in cert.extensions:
        if extension.critical and extension.oid not in {ExtensionOID.BASIC_CONSTRAINTS, ExtensionOID.KEY_USAGE}:
            raise ValueError
    basic = _extension(cert, ExtensionOID.BASIC_CONSTRAINTS)
    usage = _extension(cert, ExtensionOID.KEY_USAGE)
    if not basic.critical or basic.value.ca != ca or not usage.critical:
        raise ValueError
    if not cert.not_valid_before_utc.timestamp() <= now < cert.not_valid_after_utc.timestamp():
        raise ValueError
    key = cert.public_key()
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, (ec.SECP256R1, ec.SECP384R1)):
        raise ValueError
    if ca:
        if not usage.value.key_cert_sign or (basic.value.path_length is not None and basic.value.path_length < 0):
            raise ValueError
    elif (not usage.value.digital_signature or usage.value.key_cert_sign or usage.value.crl_sign
          or not isinstance(key.curve, ec.SECP256R1)):
        raise ValueError
    if marker is not None:
        purpose = _extension(cert, marker)
        if purpose.critical or not isinstance(purpose.value, x509.UnrecognizedExtension) or purpose.value.value != b"\x05\x00":
            raise ValueError
    # Current sample has no EKU/name constraints/policy constraints. Any such
    # restriction requires a reviewed evaluator rather than an ignored hint.
    for oid in (ExtensionOID.EXTENDED_KEY_USAGE, ExtensionOID.NAME_CONSTRAINTS,
                ExtensionOID.POLICY_CONSTRAINTS, ExtensionOID.INHIBIT_ANY_POLICY):
        try:
            _extension(cert, oid)
        except x509.ExtensionNotFound:
            continue
        raise ValueError


def _verify_chain(certificates, leaf, root, now):
    encoded_root = root.public_bytes(serialization.Encoding.DER)
    others = [cert for cert in certificates if cert != leaf and cert.public_bytes(serialization.Encoding.DER) != encoded_root]
    if len(others) != 1:
        raise ValueError
    intermediate = others[0]
    _certificate_profile(root, now, ca=True)
    _certificate_profile(intermediate, now, ca=True, marker=_CA_MARKER)
    _certificate_profile(leaf, now, ca=False, marker=_LEAF_MARKER)
    if len(leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)) != 1 or leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value != "Application Attestation Fraud Receipt Signing":
        raise ValueError
    policies = _extension(leaf, ExtensionOID.CERTIFICATE_POLICIES).value
    if len(policies) != 1 or policies[0].policy_identifier != _POLICY:
        raise ValueError
    for cert, issuer in ((leaf, intermediate), (intermediate, root), (root, root)):
        if cert.issuer != issuer.subject or not isinstance(cert.signature_hash_algorithm, (hashes.SHA256, hashes.SHA384)):
            raise ValueError
        cert.verify_directly_issued_by(issuer)
    # Root path length counts the single non-self-issued intermediate.
    limit = _extension(root, ExtensionOID.BASIC_CONSTRAINTS).value.path_length
    if limit is not None and limit < 1:
        raise ValueError


def _sha256_algorithm(algorithm):
    if (len(algorithm) != 2 or algorithm["algorithm"].native != "sha256"
            or algorithm["parameters"].dump() not in (b"", b"\x05\x00")):
        raise ValueError


def _verify_cms(raw, now):
    _ber_bounds(raw)
    container = cms.ContentInfo.load(raw, strict=True)
    # Force lazy schema parsing while the bounded preflight still applies.
    container.native
    if len(container) != 2 or container["content_type"].native != "signed_data":
        raise ValueError
    data = container["content"]
    if (len(data) != 6 or data["version"].native != "v1" or len(data["digest_algorithms"]) != 1
            or len(data["encap_content_info"]) != 2
            or data["encap_content_info"]["content_type"].native != "data"
            or data["crls"].native is not None or len(data["signer_infos"]) != 1
            or not 2 <= len(data["certificates"]) <= 3):
        raise ValueError
    _sha256_algorithm(data["digest_algorithms"][0])
    payload = data["encap_content_info"]["content"].native
    if type(payload) is not bytes or not payload:
        raise ValueError
    signer = data["signer_infos"][0]
    if (len(signer) != 7 or signer["version"].native != "v1" or signer["sid"].name != "issuer_and_serial_number"
            or len(signer["sid"].chosen) != 2
            or signer["unsigned_attrs"].native is not None):
        raise ValueError
    _sha256_algorithm(signer["digest_algorithm"])
    algorithm = signer["signature_algorithm"]
    if (len(algorithm) != 2 or algorithm["algorithm"].native != "sha256_ecdsa"
            or algorithm["parameters"].dump() != b""):
        raise ValueError
    root = _receipt_root()
    certificates, candidates, seen = [], [], set()
    for choice in data["certificates"]:
        if choice.name != "certificate":
            raise ValueError
        value = choice.chosen
        der = value.dump()
        cert = x509.load_der_x509_certificate(der)
        if der in seen or cert.public_bytes(serialization.Encoding.DER) != der:
            raise ValueError
        seen.add(der)
        certificates.append(cert)
        sid = signer["sid"].chosen
        if sid["issuer"].dump() == value.issuer.dump() and sid["serial_number"].native == cert.serial_number:
            candidates.append(cert)
    if len(candidates) != 1:
        raise ValueError
    leaf = candidates[0]
    _verify_chain(certificates, leaf, root, now)
    signed = payload
    attrs = signer["signed_attrs"]
    if attrs.native is not None:
        found = {}
        for attr in attrs:
            name = attr["type"].native
            if (len(attr) != 2 or name in found or name not in {"content_type", "message_digest", "signing_time"}
                    or len(attr["values"]) != 1):
                raise ValueError
            found[name] = attr["values"][0].native
        if (found.get("content_type") != "data" or type(found.get("message_digest")) is not bytes
                or not hmac.compare_digest(found["message_digest"], hashlib.sha256(payload).digest())):
            raise ValueError
        # RFC 5652: signature covers the DER SET OF tag, not implicit [0].
        original_attrs = attrs.dump()
        signed = attrs.untag().dump(force=True)
        # SignedAttrs itself must be DER, even if outer CMS uses BER.
        if original_attrs != b"\xa0" + signed[1:]:
            raise ValueError
    signature = signer["signature"].native
    if type(signature) is not bytes or not 8 <= len(signature) <= 80:
        raise ValueError
    leaf.public_key().verify(signature, signed, ec.ECDSA(hashes.SHA256()))
    return payload


def _payload_fields(raw):
    _ber_bounds(raw)
    # Payload is a SET OF SEQUENCE { type INTEGER, version INTEGER,
    # value OCTET STRING }. Values are raw bytes in Apple's current sample.
    from asn1crypto import core

    class Attribute(core.Sequence):
        _fields = [("type", core.Integer), ("version", core.Integer), ("value", core.OctetString)]

    class Attributes(core.SetOf):
        _child_spec = Attribute

    attrs = Attributes.load(raw, strict=True)
    attrs.native
    # Apple's own sample does not sort this SET by DER encoding. Do not impose
    # DER SET order on its signed payload; uniqueness and scalar encodings are
    # checked independently. SignedAttrs, unlike this payload, must be DER.
    if len(attrs) > 16:
        raise ValueError
    result = {}
    for attribute in attrs:
        key, version, value = attribute["type"].native, attribute["version"].native, attribute["value"].native
        if (len(attribute) != 3 or key in result or key not in {2, 3, 4, 5, 6, 7, 12, 17, 19, 21}
                or version != 1 or attribute["type"].contents != bytes([key])
                or attribute["version"].contents != b"\x01"
                or type(value) is not bytes or not 1 <= len(value) <= 16384):
            raise ValueError
        result[key] = value
    if not {2, 3, 4, 5, 6, 7, 12, 21} <= result.keys():
        raise ValueError
    return result


def _public_key(raw):
    if type(raw) is not bytes or not 1 <= len(raw) <= 16384:
        raise ValueError
    _ber_bounds(raw)
    try:
        key = serialization.load_der_public_key(raw)
        if key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) != raw:
            raise ValueError
    except ValueError:
        # Apple's public CMS sample carries the attested certificate in field 3.
        # Only extract its key: its chain does not replace CMS or attestation trust.
        cert = x509.load_der_x509_certificate(raw)
        if cert.public_bytes(serialization.Encoding.DER) != raw:
            raise ValueError
        key = cert.public_key()
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _timestamp(raw):
    value = raw.decode("ascii", errors="strict")
    if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z", value):
        raise ValueError
    return datetime.fromisoformat(value[:-1] + "+00:00").timestamp()


class AppleReceiptVerifier:
    @_boundary("APPLE_RECEIPT_CONFIGURATION")
    def __init__(self, *, apple_app_id, public_key_der, environment, clock=None):
        if (type(apple_app_id) is not str or not re.fullmatch(r"[A-Z0-9]{10}\.[A-Za-z0-9][A-Za-z0-9.\-]{0,244}", apple_app_id)
                or environment not in _HOSTS or (clock is not None and not callable(clock))):
            raise ValueError
        self._apple_app_id, self._environment = apple_app_id, environment
        self._public_key_der = _public_key(public_key_der)
        self._clock = clock if clock is not None else time.time

    def _now(self):
        value = self._clock()
        if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 253402300799:
            raise ValueError
        return value

    @_boundary("APPLE_RECEIPT_REJECTED")
    def verify(self, receipt, *, expected_client_hash, expected_type=None, require_fresh=True):
        """Verify CMS, lifetime, app/key/environment and exact signed field 4.

        expected_client_hash comes from the server's verified initial attestation
        context, never receipt parsing. require_fresh=False is for refreshing an
        already retained receipt, not accepting an old initial enrollment.
        """
        if (type(expected_client_hash) is not bytes or not 1 <= len(expected_client_hash) <= 1024
                or expected_type not in (None, "ATTEST", "RECEIPT") or type(require_fresh) is not bool):
            raise ValueError
        now = self._now()
        fields = _payload_fields(_verify_cms(receipt, now))
        kind = fields[6].decode("ascii", errors="strict")
        if (kind not in {"ATTEST", "RECEIPT"} or (expected_type is not None and kind != expected_type)
                or fields[2] != self._apple_app_id.encode("ascii") or fields[7] != self._environment.encode("ascii")
                or not hmac.compare_digest(_public_key(fields[3]), self._public_key_der)
                or not hmac.compare_digest(fields[4], expected_client_hash)):
            raise ValueError
        token = base64.b64decode(fields[5], validate=True)
        if not 16 <= len(token) <= 1024 or base64.b64encode(token) != fields[5]:
            raise ValueError
        created, expires = _timestamp(fields[12]), _timestamp(fields[21])
        if not created <= now < expires or (require_fresh and now - created > 300):
            raise ValueError
        risk, not_before = None, None
        if kind == "RECEIPT":
            if 17 not in fields or 19 not in fields or not re.fullmatch(rb"0|[1-9][0-9]{0,9}", fields[17]):
                raise ValueError
            risk, not_before = int(fields[17]), _timestamp(fields[19])
            if not created <= not_before < expires:
                raise ValueError
        elif 17 in fields or 19 in fields:
            raise ValueError
        return VerifiedAppleReceipt(self._apple_app_id, self._environment, self._public_key_der,
            fields[4], kind, created, expires, not_before, risk, now, bool(now - created <= 300),
            receipt, hashlib.sha256(receipt).hexdigest())


class AppleReceiptRefreshClient:
    @_boundary("APPLE_RECEIPT_REFRESH_CONFIGURATION")
    def __init__(self, *, verifier, token_provider, timeout=5):
        if (type(verifier) is not AppleReceiptVerifier or not callable(token_provider)
                or type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0.1 <= timeout <= 30):
            raise ValueError
        self._verifier, self._token_provider, self._timeout = verifier, token_provider, timeout

    @_boundary("APPLE_RECEIPT_REFRESH_REJECTED")
    def refresh(self, receipt, *, expected_client_hash):
        """Return a verified replacement; the caller persists it atomically.

        Uses only explicit production/development Apple HTTPS hosts, the standard
        system TLS trust store and an explicit JWT callback. No redirects, proxy
        environment, URL overrides, discovery, retries, logging or response-body
        errors. A fresh RECEIPT result must still pass the host's authorization
        and risk policy; count is not a guarantee of an uncompromised device.
        """
        old = self._verifier.verify(receipt, expected_client_hash=expected_client_hash, require_fresh=False)
        if old.not_before is not None and old.verified_at < old.not_before:
            raise ValueError
        token = self._token_provider()
        if (type(token) is not str or len(token) > 16384
                or not re.fullmatch(r"[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", token)):
            raise ValueError
        # The host callback can take time or observe a changed clock. Recheck
        # the complete old receipt and certificate lifetime before any network
        # construction, and never allow a clock rollback to extend validity.
        rechecked = self._verifier.verify(receipt, expected_client_hash=expected_client_hash, require_fresh=False)
        if (rechecked.verified_at < old.verified_at
                or (rechecked.not_before is not None and rechecked.verified_at < rechecked.not_before)):
            raise ValueError
        old = rechecked
        connection = http.client.HTTPSConnection(_HOSTS[self._verifier._environment], timeout=self._timeout,
            context=ssl.create_default_context())
        transport, response = None, None
        expired = threading.Event()
        deadline = time.monotonic() + self._timeout

        def interrupt_transport():
            expired.set()
            # close() alone need not wake an existing blocking read. Keep the
            # socket even if HTTPConnection detaches it for Connection: close.
            if transport is not None:
                try:
                    transport.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            try:
                connection.close()
            except Exception:
                pass

        watchdog = threading.Timer(self._timeout, interrupt_transport)
        watchdog.daemon = True
        watchdog.start()
        try:
            connection.connect()
            transport = connection.sock
            if expired.is_set() or time.monotonic() >= deadline:
                raise ValueError
            connection.request("POST", "/v1/attestationData", body=base64.b64encode(receipt),
                headers={"Authorization": token, "Content-Type": "application/octet-stream"})
            response = connection.getresponse()
            if response.status != 200:
                raise ValueError
            encoded = response.read(_MAX_ENCODED + 1)
            if type(encoded) is not bytes or not 1 <= len(encoded) <= _MAX_ENCODED:
                raise ValueError
            replacement = base64.b64decode(encoded, validate=True)
            if base64.b64encode(replacement) != encoded:
                raise ValueError
            result = self._verifier.verify(replacement, expected_client_hash=expected_client_hash,
                expected_type="RECEIPT", require_fresh=True)
            if (expired.is_set() or time.monotonic() >= deadline or result.verified_at < old.verified_at
                    or result.created_at <= old.created_at
                    or hmac.compare_digest(result.receipt_sha256, old.receipt_sha256)):
                raise ValueError
            return result
        finally:
            watchdog.cancel()
            if response is not None:
                response.close()
            connection.close()
