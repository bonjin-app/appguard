import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { generateKeyPairSync } from 'node:crypto';
import { buildSignatureBase, verifyRequest, parseSignatures, InMemoryReplayStore } from '../src/index.js';
const vector = JSON.parse(readFileSync(new URL('../../../conformance/v0/requests.json', import.meta.url)))[0];
function input() {
  const v = structuredClone(vector);
  return { request: { ...v.request, body: Buffer.from(v.request.body_b64, 'base64') }, parameters: v.parameters, signature: Buffer.from(v.signature_b64, 'base64'), options: { ...v.context, key: v.key, replay: new InMemoryReplayStore() } };
}
for (const [name, change, code = 'INVALID_REQUEST'] of [
  ['method ending newline', v => { v.request.method += '\n'; }],
  ['target ending newline', v => { v.request.target += '\n'; }],
  ['origin ending newline', v => { v.options.origin += '\n'; }],
  ['header name ending newline', v => { v.request.headers.push(['X-Test\n', 'v']); }],
  ['header value ending newline', v => { v.request.headers.push(['X-Test', 'v\n']); }],
  ['configured app ending newline', v => { v.options.app_id += '\n'; }],
  ['subject ending newline', v => { v.options.subject += '\n'; }],
  ['key identifier ending newline', v => { v.parameters.key_id += '\n'; }],
  ['encoded dot segment', v => { v.request.target = '/safe/%2e%2E/a'; }],
  ['encoded slash dot segment', v => { v.request.target = '/safe%2f..%2fa'; }],
  ['encoded backslash', v => { v.request.target = '/safe%5ca'; }],
  ['malformed percent escape', v => { v.request.target = '/safe%a'; }],
  ['method lowercase', v => { v.request.method = 'post'; }],
  ['method oversized', v => { v.request.method = 'A'.repeat(33); }],
  ['body not bytes', v => { v.request.body = '{}'; }],
  ['body oversized', v => { v.request.body = Buffer.alloc(1048577); }],
  ['headers not ordered pairs', v => { v.request.headers = {}; }],
  ['header pair malformed', v => { v.request.headers.push(['X-Test']); }],
  ['non-ASCII header', v => { v.request.headers.push(['X-Test', 'é']); }],
  ['header count limit', v => { v.request.headers.push(...Array.from({length:61},()=>['X-Pad','v'])); }],
  ['header byte limit', v => { v.request.headers.push(['X-Pad','a'.repeat(16385)]); }],
  ['HTTP origin', v => { v.options.origin = 'http://api.example.test'; }],
  ['origin default port', v => { v.options.origin += ':443'; }],
  ['origin oversized port', v => { v.options.origin += ':65536'; }],
  ['origin invalid DNS', v => { v.options.origin = 'https://-bad.test'; }],
  ['origin uppercase', v => { v.options.origin = 'https://API.example.test'; }],
  ['created boolean', v => { v.parameters.created = true; }, 'INVALID_TIME'],
  ['created fraction', v => { v.parameters.created += 0.5; }, 'INVALID_TIME'],
  ['clock boolean', v => { v.options.now = true; }, 'INVALID_TIME'],
  ['clock out of range', v => { v.options.now = 1e15; }, 'INVALID_TIME'],
  ['future skew', v => { v.parameters.created = v.options.now + 31; v.parameters.expires = v.options.now + 60; }, 'INVALID_TIME'],
  ['lifetime exceeds 120', v => { v.parameters.expires = v.parameters.created + 121; }, 'INVALID_TIME'],
  ['expiry boundary', v => { v.options.now = v.parameters.expires; }, 'INVALID_TIME'],
  ['wrong key curve', v => { v.options.key.public_key_pem = generateKeyPairSync('ec', {namedCurve:'secp384r1'}).publicKey.export({type:'spki',format:'pem'}); }, 'KEY_REJECTED'],
  ['RSA key', v => { v.options.key.public_key_pem = generateKeyPairSync('rsa', {modulusLength:2048}).publicKey.export({type:'spki',format:'pem'}); }, 'KEY_REJECTED'],
  ['private key supplied', v => { v.options.key.public_key_pem = generateKeyPairSync('ec', {namedCurve:'prime256v1'}).privateKey.export({type:'pkcs8',format:'pem'}); }, 'KEY_REJECTED'],
  ['key malformed', v => { v.options.key.public_key_pem = 'not a key'; }, 'KEY_REJECTED'],
  ['key oversized', v => { v.options.key.public_key_pem = 'a'.repeat(4097); }, 'KEY_REJECTED'],
  ['revoked not false', v => { v.options.key.revoked = 0; }, 'KEY_REJECTED'],
  ['signature wrong type', v => { v.signature = v.signature.toString('base64'); }, 'INVALID_SIGNATURE'],
  ['signature wrong scalar', v => { v.signature = Buffer.alloc(64); }, 'INVALID_SIGNATURE'],
]) test(`strict runtime: ${name}`, async () => {
  const v = input(); change(v);
  await assert.rejects(verifyRequest(v.request, v.parameters, v.signature, v.options), {code});
});
test('digest/signature failures never claim nonces', async () => {
  for (const tamper of [v => { v.request.body = Buffer.from('bad'); }, v => { v.signature[0] ^= 1; }]) {
    const v = input(); let claims = 0; v.options.replay = {claim: () => { claims++; return true; }}; tamper(v);
    await assert.rejects(verifyRequest(v.request, v.parameters, v.signature, v.options)); assert.equal(claims, 0);
  }
});
