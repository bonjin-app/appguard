import { createHash, timingSafeEqual } from 'node:crypto';
import { reject } from './errors.js';
export const ALGORITHM = 'ecdsa-p256-sha256';
export const TAG = 'appguard-request-v0';
export const COMPONENTS = Object.freeze(['@method', '@target-uri', 'content-type', 'content-digest', 'authorization', 'appguard-app-id']);
export const COVERED = COMPONENTS.map(n => `"${n}"`).join(' ');
const TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
export const IDENTIFIER = /^[A-Za-z0-9._:-]{1,128}$/;
const CORE_SINGLETONS = new Set([...COMPONENTS.slice(2), 'content-encoding']);
export const WIRE_SINGLETONS = new Set([...CORE_SINGLETONS, 'signature-input', 'signature', 'content-length', 'transfer-encoding', 'host']);
export const validInteger = value => Number.isSafeInteger(value) && value >= 0 && value <= 999999999999999;
export function validateIdentifier(value) { if (typeof value !== 'string' || !IDENTIFIER.test(value)) reject(); }
export function validateNonce(nonce) {
  if (typeof nonce !== 'string' || !/^[A-Za-z0-9_-]{22}$/.test(nonce) || Buffer.from(nonce, 'base64url').toString('base64url') !== nonce) reject();
}
export function validateOrigin(origin) {
  if (typeof origin !== 'string' || origin.length > 512) reject();
  const m = /^https:\/\/([a-z0-9.-]+)(?::([1-9][0-9]{0,4}))?$/.exec(origin);
  if (!m || m[1].length > 253 || m[1].split('.').some(l => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(l)) || (m[2] && (Number(m[2]) > 65535 || Number(m[2]) === 443))) reject();
}
export function validateTarget(target) {
  if (typeof target !== 'string' || target.length > 8192 || target.startsWith('//') || !/^\/[A-Za-z0-9._~!$&'()*+,;=:@/?%\-]*$/.test(target) || /%(?![0-9A-Fa-f]{2})/.test(target)) reject();
  const decode = text => text.replace(/%([0-9A-Fa-f]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
  if (/[\x00-\x1f\x7f\\]/.test(decode(target)) || decode(target.split('?', 1)[0]).split('/').some(s => s === '.' || s === '..')) reject();
}
export function headerMap(headers, singletons = CORE_SINGLETONS) {
  if (!Array.isArray(headers) || headers.length > 64) reject();
  const result = new Map();
  let size = 0;
  for (const pair of headers) {
    if (!Array.isArray(pair) || pair.length !== 2) reject();
    const [name, value] = pair;
    if (typeof name !== 'string' || typeof value !== 'string' || !TOKEN.test(name) || !/^[\x20-\x7e]*$/.test(value) || value.startsWith(' ') || value.endsWith(' ')) reject();
    size += name.length + value.length;
    if (size > 16384) reject();
    const lower = name.toLowerCase();
    if (singletons.has(lower) && result.has(lower)) reject();
    result.set(lower, value);
  }
  return result;
}
export function digestBytes(value) {
  if (typeof value !== 'string' || !/^sha-256=:[A-Za-z0-9+/]{43}=:$/.test(value)) reject();
  const base64 = value.slice(9, -1), decoded = Buffer.from(base64, 'base64');
  if (decoded.length !== 32 || decoded.toString('base64') !== base64) reject();
  return decoded;
}
export function validateRequest(request) {
  if (!request || !Buffer.isBuffer(request.body) || request.body.length > 1048576 || typeof request.method !== 'string' || request.method.length > 32 || request.method !== request.method.toUpperCase() || !TOKEN.test(request.method)) reject();
  validateTarget(request.target);
  const headers = headerMap(request.headers);
  if (COMPONENTS.slice(2).some(n => !headers.has(n)) || !headers.get('content-type') || (headers.has('content-encoding') && headers.get('content-encoding') !== 'identity') || !/^Bearer [A-Za-z0-9._~+/-]+=*$/i.test(headers.get('authorization'))) reject();
  validateIdentifier(headers.get('appguard-app-id'));
  digestBytes(headers.get('content-digest'));
  return headers;
}
export function validateParameters(p) {
  if (!p || typeof p !== 'object') reject();
  if (p.algorithm !== ALGORITHM || p.tag !== TAG) reject('UNSUPPORTED_PROFILE');
  validateIdentifier(p.key_id);
  validateNonce(p.nonce);
  if (!validInteger(p.created) || !validInteger(p.expires)) reject('INVALID_TIME');
}
export function serializeParameters(p) {
  return `(${COVERED});created=${p.created};expires=${p.expires};nonce="${p.nonce}";keyid="${p.key_id}";alg="${p.algorithm}";tag="${p.tag}"`;
}
export function buildSignatureBase(request, parameters, { origin }) {
  const headers = validateRequest(request);
  validateOrigin(origin);
  validateParameters(parameters);
  const values = [request.method, origin + request.target, ...COMPONENTS.slice(2).map(n => headers.get(n))];
  return Buffer.from([...COMPONENTS.map((n, i) => `"${n}": ${values[i]}`), `"@signature-params": ${serializeParameters(parameters)}`].join('\n'), 'ascii');
}
export function validateContentDigest(request) {
  const headers = validateRequest(request);
  if (!timingSafeEqual(digestBytes(headers.get('content-digest')), createHash('sha256').update(request.body).digest())) reject('DIGEST_MISMATCH');
}
