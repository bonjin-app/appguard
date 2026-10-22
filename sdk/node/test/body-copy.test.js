import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const probe = fileURLToPath(new URL('fixtures/body-copy-probe.mjs', import.meta.url));
for (const kind of ['express', 'fastify', 'nest']) {
  for (const fault of ['range', 'error', 'verification']) {
    // Removing copy exception handling must terminate the unprotected child,
    // rather than let the middleware reject one request and serve the retry.
    test(`${kind}: ${fault} body copy failure rejects safely and leaves nonce unused`, () => {
      const result = spawnSync(process.execPath, [probe, kind, fault], { encoding: 'utf8', timeout: 15000 });
      assert.equal(result.error, undefined);
      assert.equal(result.status, 0, result.stderr || result.stdout);
      assert.deepEqual(JSON.parse(result.stdout.trim()), { kind, fault, shape: 'binary', injected: 1,
        survived: true, accepted: true, replayRejected: true });
    });
  }
  for (const shape of ['empty', 'maximum']) {
    test(`${kind}: normal ${shape} signed body remains exact`, () => {
      const result = spawnSync(process.execPath, [probe, kind, 'none', shape], { encoding: 'utf8', timeout: 15000 });
      assert.equal(result.error, undefined);
      assert.equal(result.status, 0, result.stderr || result.stdout);
      assert.deepEqual(JSON.parse(result.stdout.trim()), { kind, fault: 'none', shape, injected: 0,
        survived: true, accepted: true, replayRejected: true });
    });
  }
}
