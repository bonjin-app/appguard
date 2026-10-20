import { COVERED, headerMap, WIRE_SINGLETONS, validateNonce, ALGORITHM, TAG } from './canonical.js';
import { reject } from './errors.js';
const escape = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const integer = '(0|-?[1-9][0-9]{0,14})';
const INPUT = new RegExp(`^appguard=\\(${escape(COVERED)}\\);created=${integer};expires=${integer};nonce="([A-Za-z0-9_-]{22})";keyid="([A-Za-z0-9._:-]{1,128})";alg="([A-Za-z0-9._:-]{1,64})";tag="([A-Za-z0-9._:-]{1,64})"$`);
export function parseSignatures(headers) {
  const fields = validateFraming(headers);
  const m = INPUT.exec(fields.get('signature-input') ?? '');
  const s = /^appguard=:([A-Za-z0-9+/]{86}==):$/.exec(fields.get('signature') ?? '');
  if (!m || !s) reject();
  validateNonce(m[3]);
  const signature = Buffer.from(s[1], 'base64');
  if (signature.length !== 64 || signature.toString('base64') !== s[1]) reject();
  const parameters = { created: Number(m[1]), expires: Number(m[2]), nonce: m[3], key_id: m[4], algorithm: m[5], tag: m[6] };
  if (parameters.algorithm !== ALGORITHM || parameters.tag !== TAG) reject('UNSUPPORTED_PROFILE');
  return { parameters, signature };
}
export function validateFraming(headers, bodyLength) {
  const fields = headerMap(headers, WIRE_SINGLETONS);
  const length = fields.get('content-length'), encoding = fields.get('transfer-encoding');
  if ((length !== undefined && encoding !== undefined) || (encoding !== undefined && encoding !== 'chunked') || (fields.has('content-encoding') && fields.get('content-encoding') !== 'identity')) reject();
  if (length !== undefined && (!/^(0|[1-9][0-9]*)$/.test(length) || !Number.isSafeInteger(Number(length)) || Number(length) > 1048576)) {
    if (/^(0|[1-9][0-9]*)$/.test(length) && Number(length) > 1048576) reject('INVALID_REQUEST', 413);
    reject();
  }
  if (bodyLength !== undefined && length !== undefined && Number(length) !== bodyLength) reject();
  return fields;
}
