import { createHash } from 'node:crypto';
import { validateIdentifier, validateNonce, validInteger } from './canonical.js';
import { VerificationError } from './errors.js';
const unavailable = () => { throw new VerificationError('REPLAY_STORE_UNAVAILABLE'); };
function deadline(scope, { expires, now }) {
  if (!Array.isArray(scope) || scope.length !== 3 || scope.some(s => typeof s !== 'string' || s.length < 1 || s.length > 128) || !validInteger(now) || !validInteger(expires) || now >= expires) unavailable();
}
/** Volatile, single-process development store. Never silently installed by adapters. */
export class InMemoryReplayStore {
  #claims = new Map(); #capacity;
  constructor({ capacity = 10000 } = {}) {
    if (!Number.isSafeInteger(capacity) || capacity < 1) throw new TypeError('capacity must be a positive integer');
    this.#capacity = capacity;
  }
  claim(scope, times) {
    deadline(scope, times);
    for (const [key, expires] of this.#claims) if (expires <= times.now) this.#claims.delete(key);
    const key = JSON.stringify(scope);
    if (this.#claims.has(key)) return false;
    if (this.#claims.size >= this.#capacity) unavailable();
    this.#claims.set(key, times.expires);
    return true;
  }
}
export function redisReplayKey(scope) {
  try {
    if (!Array.isArray(scope) || scope.length !== 3) unavailable();
    validateIdentifier(scope[0]); validateIdentifier(scope[1]); validateNonce(scope[2]);
  } catch { unavailable(); }
  return `appguard:v0:replay:${createHash('sha256').update(JSON.stringify(scope), 'utf8').digest('hex')}`;
}
/** Long-lived injected node-redis client. Uses one atomic command, never SETNX/EXPIRE. */
export class RedisReplayStore {
  #client;
  constructor(client) {
    if (!client || typeof client.sendCommand !== 'function') throw new TypeError('Redis client must implement sendCommand');
    this.#client = client;
  }
  async claim(scope, times) {
    try {
      deadline(scope, times);
      const ttl = times.expires - times.now;
      if (ttl < 1 || ttl > 150) unavailable();
      const result = await this.#client.sendCommand(['SET', redisReplayKey(scope), '1', 'NX', 'EX', String(ttl)]);
      if (result === 'OK') return true;
      if (result === null) return false;
    } catch { unavailable(); }
    unavailable();
  }
}
