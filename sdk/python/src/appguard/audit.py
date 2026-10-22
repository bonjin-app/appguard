"""Allowlisted v0 audit events; no subject, token, body, nonce, key, or IP fields."""
import inspect
import json
import re
from collections.abc import Callable
from concurrent.futures import Future
from types import CoroutineType

from .policy import PolicyContext, PolicyDecision, PolicyError, _time, _valid_decision


class AuditError(ValueError):
    def __init__(self):
        self.code = "INVALID_AUDIT_EVENT"
        super().__init__(self.code)


class AuditUnavailable(Exception):
    def __init__(self):
        self.code = "AUDIT_UNAVAILABLE"
        super().__init__(self.code)


def _identifier(value):
    return type(value) is str and re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", value) is not None


def audit_event(decision: PolicyDecision, *, event_id: str, app_id: str, now: int,
                context: PolicyContext | None = None) -> dict:
    """Construct a fresh event from explicit fields, never copy arbitrary mappings.

    Identifiers must be opaque application/event IDs, never credentials or user
    identifiers. Attestation state records the caller verdict, not provider proof.
    """
    if (not _valid_decision(decision) or not _identifier(event_id)
            or not _identifier(app_id) or not _time(now)):
        raise AuditError()
    if context is not None:
        if type(context) is not PolicyContext:
            raise AuditError()
        invalid = False
        try:
            context.__post_init__()
        except PolicyError:
            invalid = True
        if invalid:
            raise AuditError()
    event = {"schema_version": "appguard-audit-v0", "event_id": event_id, "app_id": app_id,
             "at": now, "action": decision.action, "code": decision.code, "profile": decision.profile}
    if context is not None:
        event["risk_count"] = len(context.risk_signals)
        event["attestation_state"] = context.attestation
    return event


class JsonAuditSink:
    """Send one compact JSON string to an injected callback; owns no I/O or state.

    The callback must complete synchronously. Awaitable/Future results and callback
    failures raise a fixed redacted error; this sink never schedules async work.
    The host application decides how audit availability affects request processing
    and manages storage/retention. Returned unstarted native coroutines transfer
    ownership to the sink; all other async objects remain host-owned.
    """

    def __init__(self, callback: Callable[[str], object]):
        if not callable(callback):
            raise AuditError()
        self._callback = callback

    def emit(self, decision: PolicyDecision, *, event_id: str, app_id: str, now: int,
             context: PolicyContext | None = None) -> None:
        event = audit_event(decision, event_id=event_id, app_id=app_id, now=now, context=context)
        failed = False
        try:
            result = self._callback(json.dumps(event, separators=(",", ":"), sort_keys=True))
            if inspect.isawaitable(result) or isinstance(result, Future):
                failed = True
                # Close only a native coroutine that has never run. Never invoke
                # arbitrary host cleanup, cancel Futures, or resume async work.
                if type(result) is CoroutineType and inspect.getcoroutinestate(result) == inspect.CORO_CREATED:
                    result.close()
        except Exception:
            failed = True
        # Raise outside the handler so the exception does not retain secret data
        # from a callback exception through __context__ or a chained traceback.
        if failed:
            raise AuditUnavailable()
