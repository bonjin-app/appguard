import { options, validContext, validDecision, validTime } from './policy.js';
export class AuditError extends Error {
  constructor() { super('INVALID_AUDIT_EVENT'); this.name='AuditError'; this.code='INVALID_AUDIT_EVENT'; }
}
export class AuditUnavailable extends Error {
  constructor() { super('AUDIT_UNAVAILABLE'); this.name='AuditUnavailable'; this.code='AUDIT_UNAVAILABLE'; }
}
const identifier = value => typeof value === 'string' && /^[A-Za-z0-9._:-]{1,128}$/.test(value);
/** IDs must be opaque application/event identifiers, never credentials or user IDs. */
export function auditEvent(decision, input) {
  try {
    if (!validDecision(decision) || !options(input,['event_id','app_id','now','context'])) throw new Error();
    const {event_id,app_id,now,context=null}=input;
    if (!identifier(event_id) || !identifier(app_id) || !validTime(now) || (context !== null && !validContext(context))) throw new Error();
    const event={schema_version:'appguard-audit-v0',event_id,app_id,at:now,action:decision.action,code:decision.code,profile:decision.profile};
    if (context !== null) { event.risk_count=context.risk_signals.length; event.attestation_state=context.attestation; }
    return Object.freeze(event);
  } catch { throw new AuditError(); }
}
export class JsonAuditSink {
  #callback;
  constructor(callback) { if (typeof callback !== 'function') throw new AuditError(); this.#callback=callback; Object.freeze(this); }
  /** Always await emit: both synchronous and asynchronous callbacks are supported. */
  async emit(decision, input) {
    const event=auditEvent(decision,input);
    try { await this.#callback(JSON.stringify(event)); }
    catch { throw new AuditUnavailable(); }
  }
}
