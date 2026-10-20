import type { IncomingMessage, ServerResponse, Server } from 'node:http';
import type { Readable } from 'node:stream';
export type CoreCode = 'INVALID_REQUEST' | 'UNSUPPORTED_PROFILE' | 'INVALID_TIME' | 'KEY_REJECTED' | 'DIGEST_MISMATCH' | 'INVALID_SIGNATURE' | 'REPLAY_DETECTED' | 'REPLAY_STORE_UNAVAILABLE';
export type ErrorCode = CoreCode | 'AUTHENTICATION_REQUIRED' | 'IDENTITY_UNAVAILABLE' | 'KEY_RESOLVER_UNAVAILABLE';
export class VerificationError extends Error {
  readonly code: ErrorCode;
  readonly status: number;
  constructor(code: ErrorCode, status?: number);
}
export const ALGORITHM: 'ecdsa-p256-sha256';
export const TAG: 'appguard-request-v0';
export type HeaderPair = readonly [name: string, value: string];
export interface RequestInput { method: string; target: string; headers: readonly HeaderPair[]; body: Buffer; }
export interface SignatureParameters { created: number; expires: number; nonce: string; key_id: string; algorithm: string; tag: string; }
export interface KeyRecord { app_id: string; key_id: string; subject: string; public_key_pem: Buffer | string; algorithm: string; revoked: boolean; }
export interface VerificationResult { readonly app_id: string; readonly key_id: string; readonly expires: number; readonly code: 'VERIFIED'; }
export interface ReplayTimes { expires: number; now: number; }
export type ReplayScope = readonly [app_id: string, key_id: string, nonce: string];
export interface ReplayStore { claim(scope: ReplayScope, times: ReplayTimes): boolean | Promise<boolean>; }
export class InMemoryReplayStore implements ReplayStore {
  /** Explicit volatile single-process development choice. Never a production default. */
  constructor(options?: { capacity?: number });
  claim(scope: ReplayScope, times: ReplayTimes): boolean;
}
export interface RedisCommandClient { sendCommand(command: string[]): Promise<unknown>; }
export class RedisReplayStore implements ReplayStore {
  constructor(client: RedisCommandClient);
  claim(scope: ReplayScope, times: ReplayTimes): Promise<boolean>;
}
export function redisReplayKey(scope: ReplayScope): string;
export function serializeParameters(parameters: SignatureParameters): string;
export function buildSignatureBase(request: RequestInput, parameters: SignatureParameters, options: { origin: string }): Buffer;
export function parseSignatures(headers: readonly HeaderPair[]): { parameters: SignatureParameters; signature: Buffer };
export function validateFraming(headers: readonly HeaderPair[], bodyLength?: number): Map<string, string>;
export interface VerificationOptions { origin: string; app_id: string; subject: string; key: KeyRecord; now: number; replay: ReplayStore; }
export function verifyRequest(request: RequestInput, parameters: SignatureParameters, signature: Buffer, options: VerificationOptions): Promise<VerificationResult>;
export interface Identity { subject: string; key: KeyRecord | null; }
export interface IdentityContext { readonly method: string; readonly target: string; readonly headers: readonly HeaderPair[]; readonly parameters: Readonly<SignatureParameters>; }
export interface KeyContext extends IdentityContext { readonly subject: string; readonly app_id: string; readonly key_id: string; }
export interface CommonAdapterOptions { app_id: string; origin: string; replay: ReplayStore; clock?: () => number; allowInsecureTransport?: boolean; bodyTimeoutMs?: number; }
export type AdapterOptions = CommonAdapterOptions & (
  { identityResolver(context: IdentityContext): Identity | null | false | Promise<Identity | null | false>; keyResolver?: never } |
  { identityResolver(context: IdentityContext): string | null | false | Promise<string | null | false>; keyResolver(context: KeyContext): KeyRecord | null | undefined | Promise<KeyRecord | null | undefined> }
);
export interface AppGuardRequest { readonly appguard: VerificationResult; readonly appguardRawBody: Buffer; readonly appguardTarget: string; }
export type VerifiedIncomingMessage = IncomingMessage & AppGuardRequest;
export type GuardMiddleware = (req: IncomingMessage, res: ServerResponse, next: () => void) => void;
/** Install first at the application root, before parsers, routers or rewrites. */
export function expressMiddleware(options: AdapterOptions): GuardMiddleware;
/** Nest Express: bodyParser:false; install before application parsers and routes. */
export const nestMiddleware: typeof expressMiddleware;
/** Synchronously install before all other Fastify hooks and route definitions. */
export function installFastify(server: { server: Server; addHook: (...args: any[]) => unknown }, options: AdapterOptions): void;
