import { createPublicKey, verify } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { ALGORITHM, buildSignatureBase, validateContentDigest, validateIdentifier, validInteger } from './canonical.js';
import { reject, VerificationError } from './errors.js';
// Shared with adapter construction; not part of the public package exports.
export function validateReplayTimeoutMs(value = 10000) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 2147483647) throw new TypeError('replayTimeoutMs must be an integer in 1..2147483647');
  return value;
}
async function claimReplay(replay, scope, times, timeoutMs) {
  const deadline = performance.now() + timeoutMs;
  let timer;
  const timeout = new Promise((_, fail) => {
    // Keep direct-core callers alive until the deadline even without other I/O.
    timer = setTimeout(() => fail(new VerificationError('REPLAY_STORE_UNAVAILABLE')), timeoutMs);
  });
  try {
    const claimed = await Promise.race([
      Promise.resolve().then(() => {
        if (performance.now() >= deadline) reject('REPLAY_STORE_UNAVAILABLE');
        return replay.claim(scope, times);
      }),
      timeout,
    ]);
    // A blocking callback can finish before the timer gets an event-loop turn.
    if (performance.now() >= deadline) reject('REPLAY_STORE_UNAVAILABLE');
    return claimed;
  } finally {
    clearTimeout(timer);
  }
}
function loadKey(pem) {
  if (typeof pem === 'string') pem = Buffer.from(pem, 'utf8');
  if (!Buffer.isBuffer(pem) || pem.length < 1 || pem.length > 4096) reject('KEY_REJECTED');
  // latin1 preserves every byte; ascii decoding would mask high-bit input.
  const text = pem.toString('latin1');
  const match = /^-----BEGIN PUBLIC KEY-----\r?\n([A-Za-z0-9+/=\r\n]+)-----END PUBLIC KEY-----[ \t\r\n]*$/.exec(text);
  if (!match || match[0].length !== text.length) reject('KEY_REJECTED');
  const encoded = match[1].replace(/[\r\n]/g, '');
  const der = Buffer.from(encoded, 'base64');
  if (der.toString('base64') !== encoded) reject('KEY_REJECTED');
  try {
    const key = createPublicKey({ key: der, format: 'der', type: 'spki' });
    if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') reject('KEY_REJECTED');
    // OpenSSL accepts a first key while ignoring trailing DER/BER material.
    if (!der.equals(key.export({ format: 'der', type: 'spki' }))) reject('KEY_REJECTED');
    return key;
  } catch { reject('KEY_REJECTED'); }
}
export async function verifyRequest(request, parameters, signature, { origin, app_id, subject, key, now, replay, replayTimeoutMs }) {
  const timeoutMs = validateReplayTimeoutMs(replayTimeoutMs);
  validateIdentifier(app_id); validateIdentifier(subject);
  const base = buildSignatureBase(request, parameters, { origin });
  if (!validInteger(now) || parameters.created >= parameters.expires || parameters.expires - parameters.created > 120 || parameters.created > now + 30 || now >= parameters.expires) reject('INVALID_TIME');
  const signedApp = request.headers.find(([name]) => name.toLowerCase() === 'appguard-app-id')[1];
  if (!key || key.revoked !== false || key.app_id !== app_id || signedApp !== app_id || key.subject !== subject || key.key_id !== parameters.key_id || key.algorithm !== ALGORITHM) reject('KEY_REJECTED');
  const publicKey = loadKey(key.public_key_pem);
  validateContentDigest(request);
  if (!Buffer.isBuffer(signature) || signature.length !== 64) reject('INVALID_SIGNATURE');
  try { if (!verify('sha256', base, { key: publicKey, dsaEncoding: 'ieee-p1363' }, signature)) reject('INVALID_SIGNATURE'); }
  catch { reject('INVALID_SIGNATURE'); }
  const result = Object.freeze({ app_id, key_id: key.key_id, expires: parameters.expires, code: 'VERIFIED' });
  let claimed;
  try { claimed = await claimReplay(replay, [app_id, result.key_id, parameters.nonce], { expires: result.expires, now }, timeoutMs); }
  catch { reject('REPLAY_STORE_UNAVAILABLE'); }
  if (claimed === false) reject('REPLAY_DETECTED');
  if (claimed !== true) reject('REPLAY_STORE_UNAVAILABLE');
  return result;
}
