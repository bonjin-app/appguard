import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';

const entry = new URL('../src/index.js', import.meta.url).href;
// Run prototype pollution in disposable processes; never affect the test runner.
function probe(field, expression, body) {
  const result = spawnSync(process.execPath, ['--input-type=module', '--eval', `
    import assert from 'node:assert/strict';
    import { Policy, PolicyContext, evaluatePolicy, auditEvent } from ${JSON.stringify(entry)};
    const policy = new Policy();
    const context = new PolicyContext({authentication:'authenticated',verification:'verified',attestation:'verified',attestation_expires:101});
    const decision = evaluatePolicy(policy, context, {now:100});
    Object.defineProperty(Object.prototype, ${JSON.stringify(field)}, {value:${expression},writable:true,configurable:true});
    ${body}
  `], { encoding: 'utf8', timeout: 5000 });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
}
const rejects = (operation, code) => `assert.throws(() => ${operation}, error => error.code === '${code}' && error.message === '${code}' && error.cause === undefined);`;

for (const [field, value] of [['profile', "'basic'"], ['require_signature', 'false'], ['suspicious_signals', '[]']]) {
  test(`policy rejects inherited ${field}`, () => probe(field, value, rejects('new Policy()', 'INVALID_POLICY')));
}
for (const [field, value] of [
  ['authentication', "'authenticated'"], ['verification', "'verified'"],
  ['attestation', "'verified'"], ['attestation_expires', '101'],
  ['risk_signals', '[]'], ['rate_limited', 'false'],
]) {
  test(`context rejects inherited ${field}`, () => probe(field, value, rejects('new PolicyContext()', 'INVALID_POLICY_CONTEXT')));
}
test('evaluation rejects inherited now', () => probe('now', '100', rejects('evaluatePolicy(policy, context, {})', 'INVALID_POLICY_CONTEXT')));

for (const [field, value] of [['event_id', "'event-1'"], ['app_id', "'app'"], ['now', '100'], ['context', 'context']]) {
  test(`audit rejects inherited ${field}`, () => probe(field, value, `
    const metadata = {event_id:'event-1', app_id:'app', now:100};
    delete metadata[${JSON.stringify(field)}];
    ${rejects('auditEvent(decision, metadata)', 'INVALID_AUDIT_EVENT')}
  `));
}

test('own values and null-prototype inputs keep explicit security behavior', () => probe('require_signature', 'false', `
  const required = new Policy({profile:'basic', require_signature:true});
  const defaults = new Policy({require_signature:undefined});
  const missing = new PolicyContext({authentication:'authenticated',attestation:'verified',attestation_expires:101});
  for (const p of [required, defaults]) assert.equal(evaluatePolicy(p, missing, {now:100}).code, 'SIGNATURE_REQUIRED');
  const input = Object.assign(Object.create(null), {profile:'basic',require_signature:false});
  const optional = new Policy(input);
  assert.equal(evaluatePolicy(optional, missing, {now:100}).code, 'ALLOWED');
  assert.equal(input.require_signature, false);
  assert.equal(Object.isFrozen(input), false);
  assert.equal(Object.prototype.require_signature, false);
  const metadata = Object.assign(Object.create(null), {event_id:'event-1',app_id:'app',now:100});
  assert.equal(auditEvent(decision, metadata).event_id, 'event-1');
`));

test('unrelated inherited names do not alter valid defaults', () => probe('unrelated_appguard_test', "'ignored'", `
  assert.equal(new Policy().require_signature, true);
  assert.equal(evaluatePolicy(policy, new PolicyContext(), {now:100}).code, 'AUTHENTICATION_REQUIRED');
`));
