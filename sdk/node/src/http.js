import { Readable } from 'node:stream';
import { performance } from 'node:perf_hooks';
import { validateIdentifier, validateOrigin, validateRequest } from './canonical.js';
import { parseSignatures, validateFraming } from './wire.js';
import { verifyRequest, validateReplayTimeoutMs } from './verify.js';
import { VerificationError, reject } from './errors.js';
const LIMIT = 1048576;
const ORIGINAL = new WeakMap();
const CAPTURING_SERVERS = new WeakSet();
const BODY_EVENTS = new Set(['data', 'end', 'readable', 'error', 'close', 'aborted']);
export function validateOptions(options) {
  if (!options || typeof options !== 'object') throw new TypeError('AppGuard security options are required');
  validateIdentifier(options.app_id); validateOrigin(options.origin);
  if (!options.replay || typeof options.replay.claim !== 'function' || typeof options.identityResolver !== 'function' || (options.keyResolver !== undefined && typeof options.keyResolver !== 'function') || (options.clock !== undefined && typeof options.clock !== 'function') || (options.allowInsecureTransport !== undefined && typeof options.allowInsecureTransport !== 'boolean')) throw new TypeError('AppGuard trusted callbacks and replay store are required');
  const bodyTimeoutMs = options.bodyTimeoutMs === undefined ? 30000 : options.bodyTimeoutMs;
  const identityTimeoutMs = options.identityTimeoutMs === undefined ? 10000 : options.identityTimeoutMs;
  const replayTimeoutMs = validateReplayTimeoutMs(options.replayTimeoutMs);
  for (const [name, value] of [['bodyTimeoutMs', bodyTimeoutMs], ['identityTimeoutMs', identityTimeoutMs]]) {
    if (!Number.isSafeInteger(value) || value < 1 || value > 2147483647) throw new TypeError(`${name} must be an integer in 1..2147483647`);
  }
  return Object.freeze({ ...options, clock: options.clock ?? (() => Math.floor(Date.now() / 1000)), bodyTimeoutMs, identityTimeoutMs, replayTimeoutMs });
}
function snapshot(req, options) {
  const original = ORIGINAL.get(req);
  if (options.requireNativeEvidence && !original) reject();
  if (original && (req.url !== original.target || req.method !== original.method || !Array.isArray(req.rawHeaders) || req.rawHeaders.length !== original.rawHeaders.length || req.rawHeaders.some((value,index) => value !== original.rawHeaders[index]))) reject();
  // Public stream flags expose preceding parsers/consumers; never wait on an exhausted stream.
  if (!req || !Array.isArray(req.rawHeaders) || req.rawHeaders.length % 2 || typeof req.url !== 'string' || typeof req.method !== 'string' || req.body !== undefined || req.readableEnded || req.destroyed || req.readableDidRead || req.readableEncoding || req.readableFlowing !== null || req.listenerCount('data') || req.listenerCount('readable') || (req.originalUrl !== undefined && req.originalUrl !== req.url) || req.baseUrl) reject();
  if (!options.allowInsecureTransport && req.socket?.encrypted !== true) reject();
  const headers = [];
  for (let i = 0; i < req.rawHeaders.length; i += 2) headers.push(Object.freeze([req.rawHeaders[i], req.rawHeaders[i + 1]]));
  Object.freeze(headers);
  const metadata = parseSignatures(headers);
  validateFraming(headers);
  // Check syntax and profile limits before allocating/capturing the body.
  const request = { method: req.method, target: req.url, headers, body: Buffer.alloc(0) };
  validateRequest(request);
  return { request, metadata };
}
function capture(req, timeoutMs) {
  return new Promise((resolve, rejectPromise) => {
    let size = 0, settled = false;
    const chunks = [];
    const clean = () => { clearTimeout(timer); req.removeListener('data', data); req.removeListener('end', end); req.removeListener('error', fail); req.removeListener('aborted', fail); req.removeListener('close', close); };
    const finish = (error, value) => { if (settled) return; settled = true; clean(); if (error) { req.pause(); rejectPromise(error); } else resolve(value); };
    const fail = () => finish(new VerificationError('INVALID_REQUEST'));
    const data = chunk => {
      if (!Buffer.isBuffer(chunk)) { fail(); return; }
      size += chunk.length;
      if (size > LIMIT) { finish(new VerificationError('INVALID_REQUEST', 413)); return; }
      chunks.push(chunk);
    };
    const end = () => { if (!req.complete || req.aborted) fail(); else finish(null, Buffer.concat(chunks, size)); };
    const close = () => { if (!req.readableEnded) fail(); };
    const timer = setTimeout(fail, timeoutMs); timer.unref();
    req.on('error', fail); req.on('aborted', fail); req.on('close', close); req.on('end', end); req.on('data', data);
  });
}
async function authenticate(request, metadata, options) {
  const context = Object.freeze({ method: request.method, target: request.target, headers: request.headers, parameters: Object.freeze({ ...metadata.parameters }) });
  const deadline = performance.now() + options.identityTimeoutMs;
  let active = true, timer, phase = 'IDENTITY_UNAVAILABLE';
  const checkpoint = () => { if (!active || performance.now() >= deadline) reject(phase); };
  const resolve = async () => {
    let identity;
    try { identity = await options.identityResolver(context); } catch { reject('IDENTITY_UNAVAILABLE'); }
    checkpoint();
    if (identity === null || identity === undefined || identity === false) reject('AUTHENTICATION_REQUIRED');
    let subject;
    try { subject = typeof identity === 'string' ? identity : identity.subject; validateIdentifier(subject); } catch { reject('IDENTITY_UNAVAILABLE'); }
    checkpoint();
    let key;
    if (options.keyResolver) {
      phase = 'KEY_RESOLVER_UNAVAILABLE';
      checkpoint();
      try { key = await options.keyResolver(Object.freeze({ ...context, subject, app_id: options.app_id, key_id: metadata.parameters.key_id })); }
      catch { reject('KEY_RESOLVER_UNAVAILABLE'); }
    } else {
      try { if (!('key' in identity)) reject('IDENTITY_UNAVAILABLE'); key = identity.key; } catch { reject('IDENTITY_UNAVAILABLE'); }
    }
    checkpoint();
    if (key === null || key === undefined) return { subject, key: null };
    if (typeof key !== 'object') reject(phase);
    try {
      key = { app_id: key.app_id, key_id: key.key_id, subject: key.subject, algorithm: key.algorithm, revoked: key.revoked, public_key_pem: key.public_key_pem };
      if (['app_id', 'key_id', 'subject', 'algorithm'].some(field => typeof key[field] !== 'string') || typeof key.revoked !== 'boolean' || (typeof key.public_key_pem !== 'string' && !Buffer.isBuffer(key.public_key_pem))) throw new TypeError();
      if (Buffer.isBuffer(key.public_key_pem)) key.public_key_pem = Buffer.from(key.public_key_pem);
      Object.freeze(key);
    } catch { reject(phase); }
    checkpoint();
    return { subject, key };
  };
  const timeout = new Promise((_, fail) => {
    timer = setTimeout(() => { active = false; fail(new VerificationError(phase)); }, options.identityTimeoutMs);
    timer.unref();
  });
  try {
    return await Promise.race([resolve(), timeout]);
  } finally {
    active = false;
    clearTimeout(timer);
  }
}
async function enforce(req, options) {
  const { request, metadata } = snapshot(req, options);
  request.body = await capture(req, options.bodyTimeoutMs);
  validateFraming(request.headers, request.body.length);
  const { subject, key } = await authenticate(request, metadata, options);
  let now;
  try { now = options.clock(); } catch { reject('INVALID_TIME'); }
  const result = await verifyRequest(request, metadata.parameters, metadata.signature, { origin: options.origin, app_id: options.app_id, subject, key, now, replay: options.replay, replayTimeoutMs: options.replayTimeoutMs });
  return { request, result };
}
function errorResponse(res, error) {
  const failure = error instanceof VerificationError ? error : new VerificationError('INVALID_REQUEST');
  if (res.destroyed || res.writableEnded) return;
  res.statusCode = failure.status;
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Connection', 'close');
  res.end(JSON.stringify({ code: failure.code }));
}
function attach(req, { request, result }) {
  Object.defineProperties(req, {
    appguard: { value: result, enumerable: true },
    appguardRawBody: { value: Buffer.from(request.body), enumerable: false },
    appguardTarget: { value: request.target, enumerable: false },
  });
}
function replayRequest(req, body) {
  // Delegate public readable operations to a fresh bounded byte stream. No private
  // IncomingMessage state is reset; headers, socket, identity and request object stay intact.
  const stream = Readable.from(body.length ? [body] : [], { objectMode: false });
  for (const name of ['on', 'once', 'addListener', 'prependListener', 'prependOnceListener', 'removeListener', 'off', 'removeAllListeners', 'listeners', 'rawListeners', 'listenerCount']) {
    const original = req[name].bind(req);
    req[name] = function (event, ...args) {
      const value = BODY_EVENTS.has(event) ? stream[name](event, ...args) : original(event, ...args);
      return value === stream ? req : value;
    };
  }
  for (const name of ['read', 'pipe', 'unpipe', 'pause', 'resume', 'isPaused', 'setEncoding']) req[name] = stream[name].bind(stream);
  req[Symbol.asyncIterator] = stream[Symbol.asyncIterator].bind(stream);
  for (const name of ['readable', 'readableEnded', 'readableAborted', 'readableDidRead', 'readableEncoding', 'readableFlowing', 'readableLength', 'readableObjectMode', 'destroyed']) Object.defineProperty(req, name, { configurable: true, get: () => stream[name] });
}
/** Install first at the Express application root, before all body parsers/rewrites. */
export function expressMiddleware(options) {
  const config = validateOptions(options);
  return function appguard(req, res, next) {
    enforce(req, config).then(verified => {
      attach(req, verified);
      replayRequest(req, verified.request.body);
      next();
    }, error => errorResponse(res, error)).catch(error => errorResponse(res, error));
  };
}
/** Nest/Express global middleware; create Nest with bodyParser:false and install first. */
export const nestMiddleware = expressMiddleware;
/** Install synchronously on the intended Fastify instance before other hooks/routes. */
export function installFastify(fastify, options) {
  const config = Object.freeze({ ...validateOptions(options), requireNativeEvidence: true });
  if (!fastify.server || typeof fastify.server.prependListener !== 'function') throw new TypeError('Fastify native HTTP server is required');
  if (!CAPTURING_SERVERS.has(fastify.server)) {
    CAPTURING_SERVERS.add(fastify.server);
    fastify.server.prependListener('request', req => {
      if (!ORIGINAL.has(req)) ORIGINAL.set(req, Object.freeze({ target: req.url, method: req.method, rawHeaders: Object.freeze([...req.rawHeaders]) }));
    });
  }
  const verified = new WeakMap();
  fastify.addHook('onRequest', async (request, reply) => {
    try {
      const result = await enforce(request.raw, config);
      attach(request, result); attach(request.raw, result);
      verified.set(request, result.request.body);
    } catch (error) {
      const failure = error instanceof VerificationError ? error : new VerificationError('INVALID_REQUEST');
      reply.header('Connection', 'close').header('Cache-Control', 'no-store').code(failure.status).send({ code: failure.code });
    }
  });
  fastify.addHook('preParsing', async (request, reply, payload) => {
    if (!verified.has(request) || payload !== request.raw) {
      reply.code(400).send({ code: 'INVALID_REQUEST' }); return payload;
    }
    const body = verified.get(request); verified.delete(request);
    const stream = Readable.from(body.length ? [body] : [], { objectMode: false });
    stream.receivedEncodedLength = body.length;
    return stream;
  });
}
