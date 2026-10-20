import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { Policy, PolicyContext, PolicyDecision, PolicyError, evaluatePolicy, auditEvent, AuditError, AuditUnavailable, JsonAuditSink } from '../src/index.js';
const vectors = JSON.parse(readFileSync(new URL('../../../conformance/v0/policy.json', import.meta.url)));
assert.equal(vectors.length, 42);
for (const row of vectors) test(`policy corpus: ${row.id}`, () => {
  assert.deepEqual({...evaluatePolicy(new Policy(row.policy), new PolicyContext(row.context), {now:row.now})}, row.expected);
});
const fresh = {authentication:'authenticated', verification:'verified', attestation:'verified', attestation_expires:101};
const fixed = code => error => error.code === code && error.message === code && !error.cause && !String(error).includes('SECRET');
test('defaults fail closed, only Basic signature optout, step_up blocks processing', () => {
  for (const profile of ['basic','balanced','strict']) {
    assert.equal(evaluatePolicy(profile, new PolicyContext(), {now:100}).code,'AUTHENTICATION_REQUIRED');
    assert.equal(evaluatePolicy(profile, new PolicyContext({...fresh, authentication:'missing'}), {now:100}).action,'deny');
  }
  assert.equal(evaluatePolicy(new Policy({require_signature:false}),new PolicyContext(),{now:100}).action,'deny');
  assert.equal(evaluatePolicy('balanced',new PolicyContext({...fresh,attestation:'missing'}),{now:100}).action,'step_up');
});
test('policy configuration rejects coercion, unknowns and bounded signals', () => {
  for (const input of [null, [], {profile:'SECRET'}, {require_signature:0}, {profile:'strict',require_signature:false}, {profile:'balanced',require_signature:false}, {suspicious_signals:['root','root']}, {suspicious_signals:['SECRET token']}, {suspicious_signals:Array.from({length:33},(_,i)=>'r'+i)}, {token:'SECRET'}])
    assert.throws(()=>new Policy(input),fixed('INVALID_POLICY'));
});
test('context rejects malformed states, clocks and hints with fixed errors', () => {
  for (const input of [null,[],{authentication:'SECRET'}, {verification:[]}, {attestation:'SECRET'}, {attestation_expires:true}, {attestation_expires:-1}, {attestation_expires:1e15}, {attestation_expires:1.5}, {risk_signals:'root'}, {risk_signals:['root','root']}, {risk_signals:['x'.repeat(65)]}, {risk_signals:['SECRET token']}, {risk_signals:Array.from({length:33},(_,i)=>'r'+i)}, {rate_limited:1}, {token:'SECRET'}])
    assert.throws(()=>new PolicyContext(input),fixed('INVALID_POLICY_CONTEXT'));
  for (const now of [true,-1,1e15,1.5,'SECRET',null]) assert.throws(()=>evaluatePolicy('basic',new PolicyContext(),{now}),fixed('INVALID_POLICY_CONTEXT'));
  assert.throws(()=>evaluatePolicy({},new PolicyContext(),{now:1}),fixed('INVALID_POLICY'));
  assert.throws(()=>evaluatePolicy('basic',{}, {now:1}),fixed('INVALID_POLICY_CONTEXT'));
});
test('state uses immutable copies and cannot be forged with prototype', () => {
  const signals=['custom_risk']; const p=new Policy({suspicious_signals:signals}); const c=new PolicyContext({...fresh,risk_signals:signals}); signals[0]='root';
  assert.deepEqual(p.suspicious_signals,['custom_risk']); assert.deepEqual(c.risk_signals,['custom_risk']);
  assert.throws(()=>c.risk_signals.push('root'),TypeError); assert.throws(()=>{c.authentication='missing'},TypeError);
  const d=evaluatePolicy(p,c,{now:100}); assert.equal(d.code,'RISK_DETECTED'); assert.throws(()=>{d.action='allow'},TypeError);
  assert.throws(()=>evaluatePolicy(Object.create(Policy.prototype),c,{now:100}),fixed('INVALID_POLICY'));
  assert.throws(()=>new PolicyDecision('allow','RATE_LIMITED','basic'),fixed('INVALID_POLICY_DECISION'));
});
test('explicit precedence, expiry equality and custom hints', () => {
  assert.equal(evaluatePolicy('strict',new PolicyContext({...fresh,verification:'rejected',attestation:'rejected',rate_limited:true}),{now:100}).code,'REQUEST_REJECTED');
  assert.equal(evaluatePolicy('basic',new PolicyContext({...fresh,verification:'missing',attestation:'rejected'}),{now:100}).code,'ATTESTATION_REJECTED');
  assert.equal(evaluatePolicy('basic',new PolicyContext(fresh),{now:101}).code,'ATTESTATION_EXPIRED');
  assert.equal(evaluatePolicy('strict',new PolicyContext({...fresh,risk_signals:['verified']}),{now:100}).code,'ALLOWED');
});
const decision=new PolicyDecision('allow','ALLOWED','basic');
const meta={event_id:'event-1',app_id:'test-app',now:100};
test('audit is an explicit allowlist, immutable and redacted', () => {
  const event=auditEvent(decision,{...meta,context:new PolicyContext({...fresh,risk_signals:['private_signal']})});
  assert.deepEqual({...event},{schema_version:'appguard-audit-v0',event_id:'event-1',app_id:'test-app',at:100,action:'allow',code:'ALLOWED',profile:'basic',risk_count:1,attestation_state:'verified'});
  assert.ok(!JSON.stringify(event).includes('private_signal')); assert.ok(Object.isFrozen(event));
  assert.equal(Object.keys(auditEvent(decision,meta)).length,7);
  for (const m of [{...meta,event_id:'SECRET token'},{...meta,app_id:'a'.repeat(129)},{...meta,now:true},{...meta,context:{token:'SECRET'}},{...meta,token:'SECRET'}]) assert.throws(()=>auditEvent(decision,m),fixed('INVALID_AUDIT_EVENT'));
  for (const d of [{action:'allow',code:'SECRET',profile:'basic'},Object.create(PolicyDecision.prototype)]) assert.throws(()=>auditEvent(d,meta),fixed('INVALID_AUDIT_EVENT'));
});
test('audit sink awaits sync and async callbacks and redacts both failure paths', async () => {
  const lines=[]; await new JsonAuditSink(line=>lines.push(line)).emit(decision,meta); assert.deepEqual(JSON.parse(lines[0]),auditEvent(decision,meta));
  await new JsonAuditSink(async line=>{lines.push(line)}).emit(decision,meta); assert.equal(lines.length,2);
  for (const callback of [()=>{throw new Error('SECRET token')},async()=>{throw new Error('SECRET token')},()=>({then(){throw new Error('SECRET')}})]) await assert.rejects(new JsonAuditSink(callback).emit(decision,meta),fixed('AUDIT_UNAVAILABLE'));
  assert.throws(()=>new JsonAuditSink({}),fixed('INVALID_AUDIT_EVENT'));
});
test('signal and identifier grammars require the entire string including final newline', () => {
  assert.throws(()=>new Policy({suspicious_signals:['root\n']}),fixed('INVALID_POLICY'));
  assert.throws(()=>new PolicyContext({risk_signals:['root\n']}),fixed('INVALID_POLICY_CONTEXT'));
  assert.throws(()=>auditEvent(decision,{...meta,event_id:'e\n'}),fixed('INVALID_AUDIT_EVENT'));
  assert.throws(()=>auditEvent(decision,{...meta,app_id:'a\n'}),fixed('INVALID_AUDIT_EVENT'));
});
test('signal validation copies bounded indexed values without trusting array iterators', () => {
  const hints=['root','hook']; let calls=0;
  hints[Symbol.iterator]=function*(){ calls++; yield 'safe'; yield calls===1?'other':'safe'; };
  const context=new PolicyContext({risk_signals:hints});
  assert.deepEqual(context.risk_signals,['root','hook']);
  assert.equal(calls,0);
});
