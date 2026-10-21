import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { verifyRequest } from '../src/index.js';

const vector = JSON.parse(readFileSync(new URL('../../../conformance/v0/requests.json', import.meta.url)))[0];
const expected = { app_id: 'test-app', key_id: 'test-key', expires: 1700000120, code: 'VERIFIED' };
function fixture() {
  return {
    request: { ...structuredClone(vector.request), body: Buffer.from(vector.request.body_b64, 'base64') },
    parameters: { ...vector.parameters }, key: { ...vector.key },
  };
}
function verify(input, replay) {
  return verifyRequest(input.request, input.parameters, Buffer.from(vector.signature_b64, 'base64'), {
    ...vector.context, key: input.key, replay,
  });
}

for (const changed of ['key', 'expiry']) test(`verified ${changed} remains bound while replay is pending`, { timeout: 2000 }, async () => {
  const input = fixture(); let entered, release;
  const started = new Promise(resolve => { entered = resolve; });
  const pending = new Promise(resolve => { release = resolve; });
  let claim;
  const operation = verify(input, { claim(scope, times) { claim = { scope, times }; entered(); return pending; } });
  await started;
  if (changed === 'key') input.key.key_id = 'replacement-key';
  else input.parameters.expires = 1701000120;
  release(true);
  const result = await operation;
  assert.deepEqual(claim, { scope: ['test-app', 'test-key', 'AAECAwQFBgcICQoLDA0ODw'], times: { now: 1700000000, expires: 1700000120 } });
  assert.deepEqual(result, expected);
  assert.throws(() => { result.expires = 0; }, TypeError);
  // Preserve caller ownership: take a result snapshot, do not freeze/rewrite inputs.
  assert.equal(input.key.key_id, changed === 'key' ? 'replacement-key' : 'test-key');
  assert.equal(input.parameters.expires, changed === 'expiry' ? 1701000120 : 1700000120);
});

test('synchronous replay callback cannot replace already verified result metadata', async () => {
  const input = fixture(); let claim;
  const result = await verify(input, { claim(scope, times) {
    claim = { scope, times };
    input.key.key_id = 'replacement-key'; input.parameters.expires = 1701000120;
    return true;
  } });
  assert.deepEqual(claim, { scope: ['test-app', 'test-key', 'AAECAwQFBgcICQoLDA0ODw'], times: { now: 1700000000, expires: 1700000120 } });
  assert.deepEqual(result, expected);
});

for (const [response, code] of [[false, 'REPLAY_DETECTED'], [1, 'REPLAY_STORE_UNAVAILABLE'], ['throw', 'REPLAY_STORE_UNAVAILABLE']]) {
  test(`capturing result metadata never bypasses unsuccessful replay: ${String(response)}`, async () => {
    const input = fixture();
    await assert.rejects(verify(input, { async claim() {
      input.key.key_id = 'replacement-key'; input.parameters.expires = 1701000120;
      await Promise.resolve();
      if (response === 'throw') throw new Error('PRIVATE_BACKEND_ERROR');
      return response;
    } }), error => error.code === code && error.message === code);
  });
}
