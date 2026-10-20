"""Typed inputs preserve duplicate fields; annotations are not validation."""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class RequestInput:
    method: str
    target: str
    headers: tuple[tuple[str, str], ...] = field(repr=False)
    body: bytes = field(repr=False)


@dataclass(frozen=True)
class SignatureParameters:
    created: int
    expires: int
    nonce: str = field(repr=False)
    key_id: str
    algorithm: str
    tag: str


@dataclass(frozen=True)
class KeyRecord:
    app_id: str
    key_id: str
    subject: str = field(repr=False)
    public_key_pem: bytes = field(repr=False)
    algorithm: str
    revoked: bool


@dataclass(frozen=True)
class VerificationResult:
    app_id: str
    key_id: str
    expires: int
    code: str = field(default="VERIFIED", init=False)


class VerificationError(Exception):
    """Public failures carry a fixed reason code, never request data."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)
