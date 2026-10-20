/** Pure server policy. Only applications can supply trusted verification verdicts. */
const profiles = ['basic', 'balanced', 'strict'];
const denialCodes = ['AUTHENTICATION_REQUIRED', 'AUTHENTICATION_INVALID', 'REQUEST_REJECTED', 'VERIFICATION_UNAVAILABLE', 'SIGNATURE_REQUIRED', 'ATTESTATION_REJECTED', 'RATE_LIMITED'];
const observationCodes = ['ATTESTATION_MISSING', 'ATTESTATION_UNSUPPORTED', 'ATTESTATION_UNAVAILABLE', 'ATTESTATION_EXPIRED', 'RISK_DETECTED'];
const policies = new WeakSet(), contexts = new WeakSet(), decisions = new WeakSet();
const observation = profile => ({basic:'observe', balanced:'step_up', strict:'deny'})[profile];
export class PolicyError extends Error {
  constructor(code = 'INVALID_POLICY') {
    const fixed = ['INVALID_POLICY', 'INVALID_POLICY_CONTEXT', 'INVALID_POLICY_DECISION'].includes(code) ? code : 'INVALID_POLICY';
    super(fixed); this.name = 'PolicyError'; this.code = fixed;
  }
}
export const validTime = value => Number.isInteger(value) && value >= 0 && value <= 999999999999999;
export function options(value, keys) {
  return value !== null && typeof value === 'object' && [Object.prototype, null].includes(Object.getPrototypeOf(value)) && Reflect.ownKeys(value).every(key => keys.includes(key));
}
function signals(value) {
  if (!Array.isArray(value)) throw new Error();
  const length = value.length;
  if (!Number.isInteger(length) || length < 0 || length > 32) throw new Error();
  // Read at most 32 indexed values once; an overridden iterator is not trusted.
  const copy = [];
  for (let i = 0; i < length; i++) copy.push(value[i]);
  if (new Set(copy).size !== copy.length) throw new Error();
  if (!copy.every(code => typeof code === 'string' && /^[a-z][a-z0-9_]{0,63}$/.test(code))) throw new Error();
  return Object.freeze(copy);
}
export class Policy {
  constructor(input = {}) {
    try {
      if (new.target !== Policy || !options(input, ['profile', 'require_signature', 'suspicious_signals'])) throw new Error();
      const {profile = 'basic', require_signature = true, suspicious_signals = ['debugger','root','hook','tamper']} = input;
      if (!profiles.includes(profile) || typeof require_signature !== 'boolean' || (!require_signature && profile !== 'basic')) throw new Error();
      this.profile = profile; this.require_signature = require_signature; this.suspicious_signals = signals(suspicious_signals);
      policies.add(this); Object.freeze(this);
    } catch { throw new PolicyError(); }
  }
}
export class PolicyContext {
  constructor(input = {}) {
    try {
      if (new.target !== PolicyContext || !options(input, ['authentication','verification','attestation','attestation_expires','risk_signals','rate_limited'])) throw new Error();
      const {authentication='missing',verification='missing',attestation='missing',attestation_expires=null,risk_signals=[],rate_limited=false}=input;
      if (!['authenticated','missing','invalid'].includes(authentication) || !['verified','missing','rejected','unavailable'].includes(verification) || !['verified','missing','unsupported','rejected','unavailable'].includes(attestation) || (attestation_expires !== null && !validTime(attestation_expires)) || typeof rate_limited !== 'boolean') throw new Error();
      this.authentication=authentication; this.verification=verification; this.attestation=attestation; this.attestation_expires=attestation_expires; this.risk_signals=signals(risk_signals); this.rate_limited=rate_limited;
      contexts.add(this); Object.freeze(this);
    } catch { throw new PolicyError('INVALID_POLICY_CONTEXT'); }
  }
}
export class PolicyDecision {
  constructor(action, code, profile) {
    if (new.target !== PolicyDecision || !profiles.includes(profile) || !(denialCodes.includes(code) ? action === 'deny' : observationCodes.includes(code) ? action === observation(profile) : code === 'ALLOWED' && action === 'allow')) throw new PolicyError('INVALID_POLICY_DECISION');
    this.action=action; this.code=code; this.profile=profile; decisions.add(this); Object.freeze(this);
  }
}
export const validContext = context => contexts.has(context);
export const validDecision = decision => decisions.has(decision);
export function evaluatePolicy(profile, context, input) {
  const policy = typeof profile === 'string' ? new Policy({profile}) : profile;
  if (!policies.has(policy)) throw new PolicyError();
  let now;
  try { if (!options(input, ['now'])) throw new Error(); now=input.now; if (!validTime(now) || !validContext(context)) throw new Error(); }
  catch { throw new PolicyError('INVALID_POLICY_CONTEXT'); }
  const deny = code => new PolicyDecision('deny',code,policy.profile);
  const observe = code => new PolicyDecision(observation(policy.profile),code,policy.profile);
  if (context.authentication === 'missing') return deny('AUTHENTICATION_REQUIRED');
  if (context.authentication === 'invalid') return deny('AUTHENTICATION_INVALID');
  if (context.verification === 'rejected') return deny('REQUEST_REJECTED');
  if (context.verification === 'unavailable') return deny('VERIFICATION_UNAVAILABLE');
  if (context.attestation === 'rejected') return deny('ATTESTATION_REJECTED');
  if (context.verification === 'missing' && policy.require_signature) return deny('SIGNATURE_REQUIRED');
  if (context.rate_limited) return deny('RATE_LIMITED');
  if (context.attestation !== 'verified') return observe({missing:'ATTESTATION_MISSING',unsupported:'ATTESTATION_UNSUPPORTED',unavailable:'ATTESTATION_UNAVAILABLE'}[context.attestation]);
  if (context.attestation_expires === null || now >= context.attestation_expires) return observe('ATTESTATION_EXPIRED');
  if (context.risk_signals.some(code=>policy.suspicious_signals.includes(code))) return observe('RISK_DETECTED');
  return new PolicyDecision('allow','ALLOWED',policy.profile);
}
