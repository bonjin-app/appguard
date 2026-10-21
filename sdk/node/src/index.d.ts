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
export interface VerificationOptions {
  origin: string; app_id: string; subject: string; key: KeyRecord; now: number; replay: ReplayStore;
  /** Replay claim deadline, default 10000; integer 1..2147483647. Does not cancel backend work. */
  replayTimeoutMs?: number;
}
export function verifyRequest(request: RequestInput, parameters: SignatureParameters, signature: Buffer, options: VerificationOptions): Promise<VerificationResult>;
export interface Identity { subject: string; key: KeyRecord | null; }
export interface IdentityContext { readonly method: string; readonly target: string; readonly headers: readonly HeaderPair[]; readonly parameters: Readonly<SignatureParameters>; }
export interface KeyContext extends IdentityContext { readonly subject: string; readonly app_id: string; readonly key_id: string; }
export interface CommonAdapterOptions {
  app_id: string; origin: string; replay: ReplayStore; clock?: () => number; allowInsecureTransport?: boolean;
  /** Body capture timeout, default 30000; integer 1..2147483647. */
  bodyTimeoutMs?: number;
  /** Total identity/key lookup deadline, default 10000; integer 1..2147483647. Does not cancel host callbacks. */
  identityTimeoutMs?: number;
  /** Replay claim deadline after signature verification, default 10000; integer 1..2147483647. */
  replayTimeoutMs?: number;
}
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

export type PolicyProfile = 'basic' | 'balanced' | 'strict';
export type AuthenticationState = 'authenticated' | 'missing' | 'invalid';
export type RequestVerificationState = 'verified' | 'missing' | 'rejected' | 'unavailable';
export type AttestationState = 'verified' | 'missing' | 'unsupported' | 'rejected' | 'unavailable';
export type PolicyAction = 'allow' | 'observe' | 'step_up' | 'deny';
export type PolicyDecisionCode = 'AUTHENTICATION_REQUIRED' | 'AUTHENTICATION_INVALID' | 'REQUEST_REJECTED' | 'VERIFICATION_UNAVAILABLE' | 'SIGNATURE_REQUIRED' | 'ATTESTATION_REJECTED' | 'RATE_LIMITED' | 'ATTESTATION_MISSING' | 'ATTESTATION_UNSUPPORTED' | 'ATTESTATION_UNAVAILABLE' | 'ATTESTATION_EXPIRED' | 'RISK_DETECTED' | 'ALLOWED';
export class PolicyError extends Error {
  readonly code: 'INVALID_POLICY' | 'INVALID_POLICY_CONTEXT' | 'INVALID_POLICY_DECISION';
  constructor(code?: 'INVALID_POLICY' | 'INVALID_POLICY_CONTEXT' | 'INVALID_POLICY_DECISION');
}
export interface PolicyOptions { profile?: PolicyProfile; require_signature?: boolean; suspicious_signals?: readonly string[]; }
export class Policy {
  private readonly policyBrand: never;
  readonly profile: PolicyProfile;
  readonly require_signature: boolean;
  readonly suspicious_signals: readonly string[];
  constructor(options?: PolicyOptions);
}
export interface PolicyContextOptions { authentication?: AuthenticationState; verification?: RequestVerificationState; attestation?: AttestationState; attestation_expires?: number | null; risk_signals?: readonly string[]; rate_limited?: boolean; }
export class PolicyContext {
  private readonly contextBrand: never;
  readonly authentication: AuthenticationState;
  readonly verification: RequestVerificationState;
  readonly attestation: AttestationState;
  readonly attestation_expires: number | null;
  readonly risk_signals: readonly string[];
  readonly rate_limited: boolean;
  constructor(options?: PolicyContextOptions);
}
export class PolicyDecision {
  private readonly decisionBrand: never;
  readonly action: PolicyAction;
  readonly code: PolicyDecisionCode;
  readonly profile: PolicyProfile;
  constructor(action: PolicyAction, code: PolicyDecisionCode, profile: PolicyProfile);
}
/** observe permits processing; step_up requires a separate trusted flow before processing. */
export function evaluatePolicy(policy: PolicyProfile | Policy, context: PolicyContext, options: { now: number }): PolicyDecision;
export interface AuditMetadata { event_id: string; app_id: string; now: number; context?: PolicyContext | null; }
export interface AuditEvent { readonly schema_version: 'appguard-audit-v0'; readonly event_id: string; readonly app_id: string; readonly at: number; readonly action: PolicyAction; readonly code: PolicyDecisionCode; readonly profile: PolicyProfile; readonly risk_count?: number; readonly attestation_state?: AttestationState; }
export class AuditError extends Error { readonly code: 'INVALID_AUDIT_EVENT'; constructor(); }
export class AuditUnavailable extends Error { readonly code: 'AUDIT_UNAVAILABLE'; constructor(); }
export function auditEvent(decision: PolicyDecision, metadata: AuditMetadata): Readonly<AuditEvent>;
export class JsonAuditSink {
  constructor(callback: (json: string) => unknown | Promise<unknown>);
  /** Await delivery; sync and async callback failures reject with AUDIT_UNAVAILABLE. */
  emit(decision: PolicyDecision, metadata: AuditMetadata): Promise<void>;
}
