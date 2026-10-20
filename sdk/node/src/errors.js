const CODES = new Set(['INVALID_REQUEST', 'UNSUPPORTED_PROFILE', 'INVALID_TIME', 'KEY_REJECTED', 'DIGEST_MISMATCH', 'INVALID_SIGNATURE', 'REPLAY_DETECTED', 'REPLAY_STORE_UNAVAILABLE', 'AUTHENTICATION_REQUIRED', 'IDENTITY_UNAVAILABLE', 'KEY_RESOLVER_UNAVAILABLE']);
export class VerificationError extends Error {
  constructor(code, status) {
    if (!CODES.has(code)) code = 'INVALID_REQUEST';
    super(code);
    this.name = 'VerificationError';
    this.code = code;
    this.status = status ?? ({ INVALID_REQUEST: 400, AUTHENTICATION_REQUIRED: 401, IDENTITY_UNAVAILABLE: 503, KEY_RESOLVER_UNAVAILABLE: 503, REPLAY_STORE_UNAVAILABLE: 503 }[code] ?? 403);
  }
}
export const reject = (code = 'INVALID_REQUEST', status) => { throw new VerificationError(code, status); };
