"""Literal shared decisions catch fail-open behavior and precedence regressions."""
import json
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from appguard.policy import Policy, PolicyContext, PolicyDecision, PolicyError, evaluate_policy

VECTORS = json.loads((Path(__file__).resolve().parents[3] / "conformance/v0/policy.json").read_text())


@pytest.mark.parametrize("case", VECTORS, ids=lambda c: c["id"])
def test_portable_policy_vectors(case):
    context = dict(case["context"])
    context["risk_signals"] = tuple(context.get("risk_signals", []))
    decision = evaluate_policy(Policy(**case["policy"]), PolicyContext(**context), now=case["now"])
    assert {"action": decision.action, "code": decision.code, "profile": decision.profile} == case["expected"]


@pytest.mark.parametrize("profile", ["basic", "balanced", "strict"])
@pytest.mark.parametrize("signals", [(), ("debugger",), ("verified",)])
def test_untrusted_signals_cannot_override_rejected_security(profile, signals):
    context = PolicyContext(authentication="authenticated", verification="rejected", attestation="rejected", risk_signals=signals)
    assert evaluate_policy(profile, context, now=100).code == "REQUEST_REJECTED"


@pytest.mark.parametrize("profile", ["basic", "balanced", "strict"])
def test_rejected_attestation_precedes_missing_signature(profile):
    context = PolicyContext(authentication="authenticated", verification="missing", attestation="rejected")
    assert evaluate_policy(profile, context, now=100).action == "deny"
    assert evaluate_policy(profile, context, now=100).code == "ATTESTATION_REJECTED"


@pytest.mark.parametrize("kwargs", [
    {"profile": "SECRET"}, {"profile": []}, {"require_signature": 0},
    {"profile": "balanced", "require_signature": False},
    {"profile": "strict", "require_signature": False},
    {"suspicious_signals": ["root"]}, {"suspicious_signals": ("SECRET token",)},
    {"suspicious_signals": ("root", "root")},
])
def test_invalid_configuration_is_fixed_error(kwargs):
    with pytest.raises(PolicyError, match="^INVALID_POLICY$") as failure:
        Policy(**kwargs)
    assert "SECRET" not in repr(failure.value)


@pytest.mark.parametrize("kwargs", [
    {"authentication": "SECRET"}, {"authentication": []}, {"verification": "SECRET"},
    {"attestation": "SECRET"}, {"attestation_expires": True}, {"attestation_expires": -1},
    {"attestation_expires": 1000000000000000}, {"risk_signals": ["root"]},
    {"risk_signals": ("SECRET token",)}, {"risk_signals": ("x" * 65,)},
    {"risk_signals": ("root",) * 33}, {"risk_signals": ("root", "root")},
    {"rate_limited": 1},
])
def test_malformed_context_is_fixed_error(kwargs):
    with pytest.raises(PolicyError, match="^INVALID_POLICY_CONTEXT$") as failure:
        PolicyContext(**kwargs)
    assert "SECRET" not in repr(failure.value)


@pytest.mark.parametrize("now", [True, -1, 1000000000000000, "SECRET", None])
def test_invalid_clock_is_rejected(now):
    with pytest.raises(PolicyError, match="^INVALID_POLICY_CONTEXT$"):
        evaluate_policy("basic", PolicyContext(), now=now)


@pytest.mark.parametrize("profile,context", [(None, PolicyContext()), ("basic", {}), ({}, PolicyContext())])
def test_untyped_inputs_are_rejected(profile, context):
    with pytest.raises(PolicyError):
        evaluate_policy(profile, context, now=100)


def test_frozen_configuration_and_context_do_not_expose_risk_payloads():
    policy = Policy(suspicious_signals=("private_signal",))
    context = PolicyContext(risk_signals=("private_signal",))
    assert "private_signal" not in repr(context)
    with pytest.raises(FrozenInstanceError):
        policy.require_signature = False
    with pytest.raises(FrozenInstanceError):
        context.authentication = "authenticated"
    decision = evaluate_policy(policy, context, now=100)
    with pytest.raises(FrozenInstanceError):
        decision.action = "allow"


def test_custom_suspicious_signal_is_observed_only_after_security_checks():
    policy = Policy("balanced", suspicious_signals=("custom_risk",))
    context = PolicyContext(authentication="authenticated", verification="verified", attestation="verified", attestation_expires=101, risk_signals=("custom_risk",))
    assert evaluate_policy(policy, context, now=100) == PolicyDecision("step_up", "RISK_DETECTED", "balanced")


@pytest.mark.parametrize("context", [
    PolicyContext(),
    PolicyContext(verification="verified", attestation="verified", attestation_expires=101),
])
def test_omitted_authentication_never_permits_basic_signature_optout(context):
    decision = evaluate_policy(Policy("basic", require_signature=False), context, now=100)
    assert decision == PolicyDecision("deny", "AUTHENTICATION_REQUIRED", "basic")
