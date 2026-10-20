// Test-only native client interoperability. No private material is consumed.
import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';
import { verifyRequest, parseSignatures, InMemoryReplayStore } from '../sdk/node/src/index.js';

const v = JSON.parse(readFileSync(0, 'utf8'));
const request = { ...v.request, body: Buffer.from(v.request.body_b64, 'base64') };
const signature = Buffer.from(v.signature_b64, 'base64');
const parsed = parseSignatures(request.headers);
assert.deepEqual(parsed.parameters, v.parameters);
assert.deepEqual(parsed.signature, signature);
const context = { ...v.context, key: v.key, replay: new InMemoryReplayStore() };
assert.equal((await verifyRequest(request, v.parameters, signature, context)).code, 'VERIFIED');
await assert.rejects(() => verifyRequest(request, v.parameters, signature, context), { code: 'REPLAY_DETECTED' });
for (const changed of [
  { ...request, body: Buffer.concat([request.body, Buffer.from('!')]) },
  { ...request, target: '/different-target' },
  { ...request, headers: request.headers.map(([k, value]) => [k, k.toLowerCase() === 'authorization' ? 'Bearer OTHER_TOKEN' : value]) },
]) {
  await assert.rejects(() => verifyRequest(changed, v.parameters, signature, { ...context, replay: new InMemoryReplayStore() }));
}
console.log('NODE_NATIVE_CLIENT_VERIFIED_REPLAY_AND_MUTATIONS_REJECTED');
