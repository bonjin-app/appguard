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
export interface LocalRiskOptions {
  readonly expectedAppId?: string;
  readonly androidSignerSha256?: readonly string[];
  readonly protectedResources?: Readonly<Record<string, string>>;
}
export type LocalRiskState = 'detected' | 'not_observed' | 'unavailable' | 'not_configured';
export type LocalRiskCheckCode = 'debugger_attached' | 'debug_build' | 'root_artifact' | 'hook_artifact' | 'app_identity_mismatch' | 'app_signer_mismatch' | 'bundle_resource_mismatch';
export type LocalRiskSignal = 'debugger' | 'root' | 'hook' | 'tamper' | 'local_checks_unavailable';
export interface LocalRiskCheck { readonly code: LocalRiskCheckCode; readonly state: LocalRiskState }
export interface LocalRiskReport {
  readonly schema: 'appguard-local-risk-v0';
  readonly platform: 'android' | 'ios';
  readonly checks: readonly LocalRiskCheck[];
  readonly riskSignals: readonly LocalRiskSignal[];
}
export type AppGuardErrorCode = 'APPGUARD_INVALID_INPUT' | 'APPGUARD_KEY_UNAVAILABLE' | 'APPGUARD_UNSUPPORTED' | 'APPGUARD_OPERATION_FAILED' | 'APPGUARD_NATIVE_UNAVAILABLE';
export class AppGuardError extends Error {
  readonly code: AppGuardErrorCode;
  constructor(code: AppGuardErrorCode) { super(code); this.name = 'AppGuardError'; this.code = code; }
}
/** Internal boundary seam, used to exercise the real encoding/parser without device keys. */
export interface NativeBridge { invoke(operation: string, payload: string): Promise<string> }
const MAX_JSON = 1500000;
const MAX_BODY = 1048576;
const nativeCodes = new Set(['APPGUARD_INVALID_INPUT','APPGUARD_KEY_UNAVAILABLE','APPGUARD_UNSUPPORTED','APPGUARD_OPERATION_FAILED','APPGUARD_NATIVE_UNAVAILABLE']);
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
const androidChecks: readonly LocalRiskCheckCode[] = ['debugger_attached','debug_build','root_artifact','hook_artifact','app_identity_mismatch','app_signer_mismatch','bundle_resource_mismatch'];
const iosChecks: readonly LocalRiskCheckCode[] = ['debugger_attached','root_artifact','hook_artifact','app_identity_mismatch','bundle_resource_mismatch'];
const signalOrder: readonly LocalRiskSignal[] = ['debugger','root','hook','tamper','local_checks_unavailable'];
function riskOptions(input: unknown): LocalRiskOptions {
  if (!record(input) || Object.getPrototypeOf(input) !== Object.prototype && Object.getPrototypeOf(input) !== null || Reflect.ownKeys(input).some(k => typeof k !== 'string' || !['expectedAppId','androidSignerSha256','protectedResources'].includes(k))) return fail('APPGUARD_INVALID_INPUT');
  const result: {expectedAppId?: string; androidSignerSha256?: string[]; protectedResources?: Record<string,string>} = {};
  if (Object.hasOwn(input,'expectedAppId')) {
    const id = input.expectedAppId;
    if (typeof id !== 'string' || id.length > 255 || !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(id) || /[^A-Za-z0-9._-]/.test(id)) return fail('APPGUARD_INVALID_INPUT');
    result.expectedAppId = id;
  }
  const hash = (v: unknown): v is string => typeof v === 'string' && v.length === 64 && /^[a-f0-9]{64}$/.test(v);
  if (Object.hasOwn(input,'androidSignerSha256')) {
    const pins = input.androidSignerSha256;
    if (!Array.isArray(pins)) return fail('APPGUARD_INVALID_INPUT');
    const count = pins.length;
    if (count > 8) return fail('APPGUARD_INVALID_INPUT');
    const copy: string[] = [];
    for (let i = 0; i < count; i++) { const pin = pins[i]; if (!hash(pin) || copy.includes(pin)) return fail('APPGUARD_INVALID_INPUT'); copy.push(pin); }
    result.androidSignerSha256 = copy;
  }
  if (Object.hasOwn(input,'protectedResources')) {
    const resources = input.protectedResources;
    if (!record(resources) || Object.getPrototypeOf(resources) !== Object.prototype && Object.getPrototypeOf(resources) !== null) return fail('APPGUARD_INVALID_INPUT');
    const keys = Reflect.ownKeys(resources);
    if (keys.length > 8) return fail('APPGUARD_INVALID_INPUT');
    const copy: Record<string,string> = Object.create(null);
    for (const key of keys) {
      if (typeof key !== 'string' || key.length > 256 || !key.split('/').every(part => part.length <= 128 && /^[A-Za-z0-9_-][A-Za-z0-9._-]*$/.test(part) && !/[^A-Za-z0-9._-]/.test(part))) return fail('APPGUARD_INVALID_INPUT');
      const pin = resources[key]; if (!hash(pin)) return fail('APPGUARD_INVALID_INPUT'); copy[key] = pin;
    }
    result.protectedResources = copy;
  }
  return result;
}
function riskReport(value: unknown): LocalRiskReport {
  if (!fields(value,['schema','platform','checks','riskSignals']) || value.schema !== 'appguard-local-risk-v0' || (value.platform !== 'android' && value.platform !== 'ios')) return fail('APPGUARD_OPERATION_FAILED');
  const codes = value.platform === 'android' ? androidChecks : iosChecks;
  const required = value.platform === 'android' ? 4 : 3;
  if (!Array.isArray(value.checks) || value.checks.length !== codes.length || !Array.isArray(value.riskSignals)) return fail('APPGUARD_OPERATION_FAILED');
  const signals = new Set<LocalRiskSignal>();
  const checks = value.checks.map((check: unknown, i: number): LocalRiskCheck => {
    if (!fields(check,['code','state']) || check.code !== codes[i] || !['detected','not_observed','unavailable','not_configured'].includes(check.state as string) || i < required && check.state === 'not_configured') return fail('APPGUARD_OPERATION_FAILED');
    const code = codes[i]; const state = check.state as LocalRiskState;
    if (state === 'unavailable') signals.add('local_checks_unavailable');
    if (state === 'detected') signals.add(code === 'debugger_attached' || code === 'debug_build' ? 'debugger' : code === 'root_artifact' ? 'root' : code === 'hook_artifact' ? 'hook' : 'tamper');
    return Object.freeze({code,state});
  });
  const ordered = signalOrder.filter(s => signals.has(s));
  const actualSignals = value.riskSignals;
  if (actualSignals.length !== ordered.length || !ordered.every((s,i) => actualSignals[i] === s)) return fail('APPGUARD_OPERATION_FAILED');
  return Object.freeze({schema:'appguard-local-risk-v0',platform:value.platform,checks:Object.freeze(checks),riskSignals:Object.freeze(ordered)});
}
export function createClient(loadNative: () => NativeBridge | null) {
  async function invoke<T>(operation: string, input: unknown): Promise<T> {
    let payload: string;
    try { payload = JSON.stringify(input); if (typeof payload !== 'string' || utf8Size(payload) > (operation === 'scanLocalRisk' ? 8192 : MAX_JSON)) return fail('APPGUARD_INVALID_INPUT'); }
    catch { return fail('APPGUARD_INVALID_INPUT'); }
    let native: NativeBridge | null;
    try { native = loadNative(); if (!native || typeof native.invoke !== 'function') return fail('APPGUARD_NATIVE_UNAVAILABLE'); }
    catch { return fail('APPGUARD_NATIVE_UNAVAILABLE'); }
    let response: unknown;
    try {
      const json = await native.invoke(operation,payload);
      if (typeof json !== 'string' || utf8Size(json) > (operation === 'scanLocalRisk' ? 4096 : MAX_JSON)) return fail('APPGUARD_OPERATION_FAILED');
      response = JSON.parse(json);
    } catch { return fail('APPGUARD_OPERATION_FAILED'); }
    if (record(response) && response.ok === false && record(response.error) && typeof response.error.code === 'string' && nativeCodes.has(response.error.code)) return fail(response.error.code as AppGuardErrorCode);
    if (operation === 'scanLocalRisk') {
      if (!fields(response,['ok','result']) || response.ok !== true) return fail('APPGUARD_OPERATION_FAILED');
      return riskReport(response.result) as T;
    }
    if (!fields(response,['ok','result']) || response.ok !== true || !validResult(operation,response.result)) return fail('APPGUARD_OPERATION_FAILED');
    return response.result as T;
  }
  return {
    scanLocalRisk: (options: LocalRiskOptions = {}): Promise<LocalRiskReport> => {
      let snapshot: LocalRiskOptions;
      try { snapshot = riskOptions(options); } catch { return Promise.reject(new AppGuardError('APPGUARD_INVALID_INPUT')); }
      return invoke<LocalRiskReport>('scanLocalRisk',snapshot);
    },
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
