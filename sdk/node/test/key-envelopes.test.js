import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { ECDH } from 'node:crypto';
import { verifyRequest, InMemoryReplayStore } from '../src/index.js';

const cases = JSON.parse(readFileSync(new URL('../../../conformance/v0/public-key-pem.json', import.meta.url)));
const vector = JSON.parse(readFileSync(new URL('../../../conformance/v0/requests.json', import.meta.url)))[0];
assert.equal(cases.length, 23);
function fixture() {
  const store = new InMemoryReplayStore(); let claims = 0;
  return {
    get claims() { return claims; },
    verify(pem) {
      return verifyRequest({...vector.request, body:Buffer.from(vector.request.body_b64, 'base64')}, vector.parameters,
        Buffer.from(vector.signature_b64, 'base64'), {...vector.context, key:{...vector.key, public_key_pem:pem},
          replay:{claim(...args) { claims++; return store.claim(...args); }}});
    },
  };
}
for (const row of cases) test(`single key envelope: ${row.id}`, async () => {
  const input = fixture();
  if (row.expected_code === 'VERIFIED') assert.equal((await input.verify(row.pem)).code, 'VERIFIED');
  else {
    await assert.rejects(input.verify(row.pem), error => error.code === 'KEY_REJECTED' && error.message === 'KEY_REJECTED');
    assert.equal(input.claims, 0);
    assert.equal((await input.verify(vector.key.public_key_pem)).code, 'VERIFIED');
  }
  assert.equal(input.claims, 1);
});
test('compressed point compatibility', async () => {
  const der = Buffer.from(vector.key.public_key_pem.split('\n').slice(1,-2).join(''), 'base64');
  const point = ECDH.convertKey(der.subarray(-65), 'prime256v1', undefined, undefined, 'compressed');
  const spki = Buffer.concat([Buffer.from('3039301306072a8648ce3d020106082a8648ce3d030107032200', 'hex'), point]);
  const pem = `-----BEGIN PUBLIC KEY-----\n${spki.toString('base64')}\n-----END PUBLIC KEY-----\n`;
  const input = fixture();
  assert.equal((await input.verify(pem)).code, 'VERIFIED');
  assert.equal(input.claims, 1);
});
