/** No keys or cryptography live here. The native SDK validates and signs. */
export type HardwareRequirement = 'any' | 'hardware' | 'strongbox';
export interface KeyOptions { alias: string; hardwareRequirement: HardwareRequirement }
export interface PublicKeyResult { publicKeyPem: string; backing: string }
export interface PrepareInput extends KeyOptions {
  origin: string; method: string; target: string; body: Uint8Array;
  contentType: string; authorization: string; appId: string; keyId: string;
  created: number; expires: number; nonce: string;
}
export interface PreparedRequest {
  origin: string; method: string; target: string; bodyBase64: string; keyId: string;
  headers: [string, string][];
}
export interface EnrollmentChallenge {
  appId: string; origin: string; subject: string; keyId: string;
  publicKeySha256: string; nonce: string; expires: number;
}
export interface EnrollmentInput extends KeyOptions {
  challenge: EnrollmentChallenge;
  expectedAppId: string; expectedOrigin: string; expectedSubject: string; expectedKeyId: string;
}
export interface EnrollmentResult { proofBase64: string; clientDataHashBase64: string; googleRequestHash: string }
export type AppGuardErrorCode = 'APPGUARD_INVALID_INPUT' | 'APPGUARD_KEY_UNAVAILABLE' | 'APPGUARD_UNSUPPORTED' | 'APPGUARD_OPERATION_FAILED' | 'APPGUARD_NATIVE_UNAVAILABLE';
export class AppGuardError extends Error {
  readonly code: AppGuardErrorCode;
  constructor(code: AppGuardErrorCode) { super(code); this.name = 'AppGuardError'; this.code = code; }
}
/** Internal boundary seam, used to exercise the real encoding/parser without device keys. */
export interface NativeBridge { invoke(operation: string, payload: string): Promise<string> }
const MAX_JSON = 1500000;
const MAX_BODY = 1048576;
const nativeCodes = new Set(['APPGUARD_INVALID_INPUT','APPGUARD_KEY_UNAVAILABLE','APPGUARD_UNSUPPORTED','APPGUARD_OPERATION_FAILED']);
const fail = (code: AppGuardErrorCode): never => { throw new AppGuardError(code); };
function utf8Size(value: string): number {
  let n = 0;
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c < 128) n++;
    else if (c < 2048) n += 2;
    else if (c >= 0xd800 && c <= 0xdbff && i + 1 < value.length && value.charCodeAt(i+1) >= 0xdc00 && value.charCodeAt(i+1) <= 0xdfff) { n += 4; i++; }
    else n += 3;
  }
  return n;
}
const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
function encodeBody(bytes: Uint8Array): string {
  if (!(bytes instanceof Uint8Array) || bytes.length > MAX_BODY) return fail('APPGUARD_INVALID_INPUT');
  const chunks: string[] = [];
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i], b = bytes[i+1] ?? 0, c = bytes[i+2] ?? 0;
    chunks.push(alphabet[a >> 2] + alphabet[((a & 3) << 4) | (b >> 4)] + (i+1 < bytes.length ? alphabet[((b & 15) << 2) | (c >> 6)] : '=') + (i+2 < bytes.length ? alphabet[c & 63] : '='));
  }
  return chunks.join('');
}
function record(value: unknown): value is Record<string, unknown> { return typeof value === 'object' && value !== null && !Array.isArray(value); }
function fields(value: unknown, names: string[]): value is Record<string, unknown> {
  return record(value) && Object.keys(value).length === names.length && names.every(n => Object.hasOwn(value,n));
}
function strings(value: Record<string, unknown>, names: string[]): boolean { return names.every(n => typeof value[n] === 'string'); }
function canonicalBody(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > 1398104 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) return false;
  const padding = value.endsWith('==') ? 2 : value.endsWith('=') ? 1 : 0;
  if (value.length / 4 * 3 - padding > MAX_BODY) return false;
  return padding === 0 || (alphabet.indexOf(value[value.length-padding-1]) & (padding === 2 ? 15 : 3)) === 0;
}
function validResult(operation: string, value: unknown): boolean {
  if (operation === 'publicKey') return fields(value,['publicKeyPem','backing']) && strings(value,['publicKeyPem','backing']);
  if (operation === 'enrollmentProof') return fields(value,['proofBase64','clientDataHashBase64','googleRequestHash']) && strings(value,['proofBase64','clientDataHashBase64','googleRequestHash']);
  return fields(value,['origin','method','target','bodyBase64','keyId','headers']) && strings(value,['origin','method','target','keyId']) && canonicalBody(value.bodyBase64) && Array.isArray(value.headers) && value.headers.every(p => Array.isArray(p) && p.length === 2 && p.every(s => typeof s === 'string'));
}
export function createClient(loadNative: () => NativeBridge | null) {
  async function invoke<T>(operation: string, input: unknown): Promise<T> {
    let payload: string;
    try { payload = JSON.stringify(input); if (typeof payload !== 'string' || utf8Size(payload) > MAX_JSON) return fail('APPGUARD_INVALID_INPUT'); }
    catch { return fail('APPGUARD_INVALID_INPUT'); }
    let native: NativeBridge | null;
    try { native = loadNative(); if (!native || typeof native.invoke !== 'function') return fail('APPGUARD_NATIVE_UNAVAILABLE'); }
    catch { return fail('APPGUARD_NATIVE_UNAVAILABLE'); }
    let response: unknown;
    try {
      const json = await native.invoke(operation,payload);
      if (typeof json !== 'string' || utf8Size(json) > MAX_JSON) return fail('APPGUARD_OPERATION_FAILED');
      response = JSON.parse(json);
    } catch { return fail('APPGUARD_OPERATION_FAILED'); }
    if (record(response) && response.ok === false && record(response.error) && typeof response.error.code === 'string' && nativeCodes.has(response.error.code)) return fail(response.error.code as AppGuardErrorCode);
    if (!fields(response,['ok','result']) || response.ok !== true || !validResult(operation,response.result)) return fail('APPGUARD_OPERATION_FAILED');
    return response.result as T;
  }
  return {
    publicKey: (input: KeyOptions) => invoke<PublicKeyResult>('publicKey',input),
    prepare: async (input: PrepareInput): Promise<PreparedRequest> => {
      let payload: Record<string, unknown>;
      try { const {body,...rest} = input; payload = {...rest,bodyBase64:encodeBody(body)}; }
      catch { return fail('APPGUARD_INVALID_INPUT'); }
      return invoke<PreparedRequest>('prepare',payload);
    },
    enrollmentProof: (input: EnrollmentInput) => invoke<EnrollmentResult>('enrollmentProof',input),
  };
}
