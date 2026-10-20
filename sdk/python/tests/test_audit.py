"""Audit output must not copy request or caller-supplied payload fields."""
import json

import pytest

from appguard.audit import AuditError, AuditUnavailable, JsonAuditSink, audit_event
from appguard.policy import PolicyContext, PolicyDecision, evaluate_policy


def test_audit_event_has_only_explicit_fields_and_redacted_context():
    context = PolicyContext(authentication="authenticated", verification="verified", attestation="verified", attestation_expires=101, risk_signals=("debugger", "private_signal"))
    decision = evaluate_policy("balanced", context, now=100)
    event = audit_event(decision, event_id="event-1", app_id="test-app", now=100, context=context)
    assert event == {"schema_version": "appguard-audit-v0", "event_id": "event-1", "app_id": "test-app",
                     "at": 100, "action": "step_up", "code": "RISK_DETECTED", "profile": "balanced",
                     "risk_count": 2, "attestation_state": "verified"}
    assert "private_signal" not in json.dumps(event)


def test_audit_without_context_does_not_invent_attestation_evidence():
    event = audit_event(PolicyDecision("allow", "ALLOWED", "basic"), event_id="e", app_id="a", now=0)
    assert set(event) == {"schema_version", "event_id", "app_id", "at", "action", "code", "profile"}


@pytest.mark.parametrize("kwargs", [
    {"event_id": "SECRET token"}, {"app_id": "a" * 129}, {"now": True},
    {"now": -1}, {"now": 1000000000000000}, {"context": {"token": "SECRET"}},
    {"decision": {"action": "allow", "token": "SECRET"}},
])
def test_audit_rejects_untyped_or_malformed_metadata_without_echo(kwargs):
    args = {"decision": PolicyDecision("allow", "ALLOWED", "basic"), "event_id": "e", "app_id": "a", "now": 100}
    args.update(kwargs)
    with pytest.raises(AuditError, match="^INVALID_AUDIT_EVENT$") as failure:
        audit_event(**args)
    assert "SECRET" not in repr(failure.value)


def test_audit_revalidates_decisions_to_prevent_payload_in_codes():
    decision = PolicyDecision("allow", "ALLOWED", "basic")
    object.__setattr__(decision, "code", "SECRET")
    with pytest.raises(AuditError, match="^INVALID_AUDIT_EVENT$"):
        audit_event(decision, event_id="e", app_id="a", now=100)


def test_sink_delivers_only_json_allowlist():
    lines = []
    sink = JsonAuditSink(lines.append)
    sink.emit(PolicyDecision("deny", "RATE_LIMITED", "strict"), event_id="e", app_id="a", now=100)
    assert len(lines) == 1
    assert json.loads(lines[0]) == {"schema_version": "appguard-audit-v0", "event_id": "e", "app_id": "a",
                                  "at": 100, "action": "deny", "code": "RATE_LIMITED", "profile": "strict"}


def test_sink_failure_does_not_expose_callback_secrets():
    def fail(_line):
        raise RuntimeError("SECRET token/body/key")
    sink = JsonAuditSink(fail)
    with pytest.raises(AuditUnavailable, match="^AUDIT_UNAVAILABLE$") as failure:
        sink.emit(PolicyDecision("allow", "ALLOWED", "basic"), event_id="e", app_id="a", now=100)
    assert "SECRET" not in repr(failure.value)
    assert failure.value.__context__ is None


def test_sink_requires_callable():
    with pytest.raises(AuditError, match="^INVALID_AUDIT_EVENT$"):
        JsonAuditSink({"token": "SECRET"})
