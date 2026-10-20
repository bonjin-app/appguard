import { createPublicKey, verify } from 'node:crypto';
import { ALGORITHM, buildSignatureBase, validateContentDigest, validateIdentifier, validInteger } from './canonical.js';
import { reject } from './errors.js';
function loadKey(pem) {
  if (typeof pem === 'string') pem = Buffer.from(pem, 'utf8');
  if (!Buffer.isBuffer(pem) || pem.length < 1 || pem.length > 4096 || !pem.toString('ascii').startsWith('-----BEGIN PUBLIC KEY-----')) reject('KEY_REJECTED');
  try {
    const key = createPublicKey(pem);
    if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') reject('KEY_REJECTED');
    return key;
  } catch { reject('KEY_REJECTED'); }
}
export async function verifyRequest(request, parameters, signature, { origin, app_id, subject, key, now, replay }) {
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
  let claimed;
  try { claimed = await replay.claim([app_id, key.key_id, parameters.nonce], { expires: parameters.expires, now }); }
  catch { reject('REPLAY_STORE_UNAVAILABLE'); }
  if (claimed === false) reject('REPLAY_DETECTED');
  if (claimed !== true) reject('REPLAY_STORE_UNAVAILABLE');
  return Object.freeze({ app_id, key_id: key.key_id, expires: parameters.expires, code: 'VERIFIED' });
}
