"""Deterministic v0 policy; callers supply trusted authentication/verification states.

Local risk signals are untrusted hints. This module neither verifies platform
attestation nor replaces request verification, authentication, or authorization.
``observe`` permits processing with an audit observation; ``step_up`` does not
permit processing until a separate trusted verification flow succeeds.
"""
from dataclasses import dataclass, field
import re

_PROFILES = ("basic", "balanced", "strict")
_AUTHENTICATION = ("authenticated", "missing", "invalid")
_VERIFICATION = ("verified", "missing", "rejected", "unavailable")
_ATTESTATION = ("verified", "missing", "unsupported", "rejected", "unavailable")
_MAX_TIME = 999999999999999
_DENIAL_CODES = (
    "AUTHENTICATION_REQUIRED", "AUTHENTICATION_INVALID", "REQUEST_REJECTED",
    "VERIFICATION_UNAVAILABLE", "SIGNATURE_REQUIRED", "ATTESTATION_REJECTED", "RATE_LIMITED",
)
_OBSERVATION_CODES = (
    "ATTESTATION_MISSING", "ATTESTATION_UNSUPPORTED", "ATTESTATION_UNAVAILABLE",
    "ATTESTATION_EXPIRED", "RISK_DETECTED",
)


class PolicyError(ValueError):
    """Policy failures carry fixed codes without caller input."""

    def __init__(self, code: str):
        self.code = code if code in ("INVALID_POLICY", "INVALID_POLICY_CONTEXT", "INVALID_POLICY_DECISION") else "INVALID_POLICY"
        super().__init__(self.code)


def _enum(value, choices):
    return type(value) is str and value in choices


def _time(value):
    return type(value) is int and 0 <= value <= _MAX_TIME


def _signals(value):
    return (type(value) is tuple and len(value) <= 32
            and all(type(code) is str and re.fullmatch(r"[a-z][a-z0-9_]{0,63}", code) for code in value)
            and len(set(value)) == len(value))


@dataclass(frozen=True)
class Policy:
    """Version-v0 preset; only Basic may explicitly disable signature requirements."""

    profile: str = "basic"
    require_signature: bool = True
    suspicious_signals: tuple[str, ...] = field(default=("debugger", "root", "hook", "tamper"), repr=False)

    def __post_init__(self):
        if (not _enum(self.profile, _PROFILES) or type(self.require_signature) is not bool
                or (not self.require_signature and self.profile != "basic")
                or not _signals(self.suspicious_signals)):
            raise PolicyError("INVALID_POLICY")


@dataclass(frozen=True)
class PolicyContext:
    """Trusted server verdicts plus bounded, untrusted client-reported risk codes.

    A verified attestation without a fresh expiry cannot satisfy attestation
    policy. Never construct verified states directly from a client payload.
    """

    authentication: str = "missing"
    verification: str = "missing"
    attestation: str = "missing"
    attestation_expires: int | None = None
    risk_signals: tuple[str, ...] = field(default=(), repr=False)
    rate_limited: bool = False

    def __post_init__(self):
        if (not _enum(self.authentication, _AUTHENTICATION)
                or not _enum(self.verification, _VERIFICATION)
                or not _enum(self.attestation, _ATTESTATION)
                or (self.attestation_expires is not None and not _time(self.attestation_expires))
                or not _signals(self.risk_signals) or type(self.rate_limited) is not bool):
            raise PolicyError("INVALID_POLICY_CONTEXT")


@dataclass(frozen=True)
class PolicyDecision:
    action: str
    code: str
    profile: str

    def __post_init__(self):
        if not _valid_decision(self):
            raise PolicyError("INVALID_POLICY_DECISION")


def _valid_decision(decision):
    if (type(decision) is not PolicyDecision or not _enum(decision.profile, _PROFILES)
            or type(decision.code) is not str or type(decision.action) is not str):
        return False
    if decision.code in _DENIAL_CODES:
        return decision.action == "deny"
    if decision.code in _OBSERVATION_CODES:
        return decision.action == {"basic": "observe", "balanced": "step_up", "strict": "deny"}[decision.profile]
    return decision.code == "ALLOWED" and decision.action == "allow"


def evaluate_policy(profile: str | Policy, context: PolicyContext, *, now: int) -> PolicyDecision:
    """Return the first fixed decision; no I/O, AI, or provider calls occur.

    Precedence: authentication, request rejection/unavailability, attestation
    rejection, required signature, rate limit, attestation freshness, risk hints.
    """
    policy = Policy(profile) if type(profile) is str else profile
    if type(policy) is not Policy:
        raise PolicyError("INVALID_POLICY")
    policy.__post_init__()
    if type(context) is not PolicyContext or not _time(now):
        raise PolicyError("INVALID_POLICY_CONTEXT")
    context.__post_init__()

    def deny(code):
        return PolicyDecision("deny", code, policy.profile)

    def observation(code):
        return PolicyDecision({"basic": "observe", "balanced": "step_up", "strict": "deny"}[policy.profile], code, policy.profile)

    if context.authentication == "missing":
        return deny("AUTHENTICATION_REQUIRED")
    if context.authentication == "invalid":
        return deny("AUTHENTICATION_INVALID")
    if context.verification == "rejected":
        return deny("REQUEST_REJECTED")
    if context.verification == "unavailable":
        return deny("VERIFICATION_UNAVAILABLE")
    if context.attestation == "rejected":
        return deny("ATTESTATION_REJECTED")
    if context.verification == "missing" and policy.require_signature:
        return deny("SIGNATURE_REQUIRED")
    if context.rate_limited:
        return deny("RATE_LIMITED")
    if context.attestation != "verified":
        return observation({"missing": "ATTESTATION_MISSING", "unsupported": "ATTESTATION_UNSUPPORTED",
                            "unavailable": "ATTESTATION_UNAVAILABLE"}[context.attestation])
    if context.attestation_expires is None or now >= context.attestation_expires:
        return observation("ATTESTATION_EXPIRED")
    if any(code in policy.suspicious_signals for code in context.risk_signals):
        return observation("RISK_DETECTED")
    return PolicyDecision("allow", "ALLOWED", policy.profile)
