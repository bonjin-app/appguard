import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { buildSignatureBase, verifyRequest, parseSignatures, InMemoryReplayStore } from '../src/index.js';
const vectors = JSON.parse(readFileSync(new URL('../../../conformance/v0/requests.json', import.meta.url)));
const wire = JSON.parse(readFileSync(new URL('../../../conformance/v0/http.json', import.meta.url)));
for (const v of vectors) test(`core corpus: ${v.id}`, async () => {
  const request = { ...v.request, body: Buffer.from(v.request.body_b64, 'base64') };
  const signature = Buffer.from(v.signature_b64, 'base64');
  if (v.expected_signature_base === null) {
    assert.throws(() => buildSignatureBase(request, v.parameters, { origin: v.context.origin }));
  } else assert.equal(buildSignatureBase(request, v.parameters, { origin: v.context.origin }).toString(), v.expected_signature_base);
  let replay = new InMemoryReplayStore({ capacity: v.replay_store === 'full' ? 1 : 10000 });
  if (v.replay_store === 'full') await replay.claim(['occupied', 'occupied', 'occupied'], { now: 0, expires: 999999999999999 });
  if (v.replay_store === 'unavailable') replay = { claim() { throw new Error('private failure'); } };
  const codes = [];
  for (const expected of v.expected_codes) {
    try { codes.push((await verifyRequest(request, v.parameters, signature, { ...v.context, key: v.key, replay })).code); }
    catch (error) { codes.push(error.code ?? error.message); }
  }
  assert.deepEqual(codes, v.expected_codes);
});
for (const v of wire) test(`HTTP corpus: ${v.id}`, () => {
  let parsed;
  try { parsed = parseSignatures(v.headers); }
  catch (error) { assert.equal(error.code, v.expected_code); return; }
  assert.equal(v.expected_code, 'PARSED');
  assert.deepEqual(parsed.parameters, v.expected.parameters);
  assert.equal(parsed.signature.toString('base64'), v.expected.signature_b64);
});
