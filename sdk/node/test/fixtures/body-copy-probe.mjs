import 'reflect-metadata';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import express from 'express';
import Fastify from 'fastify';
import { NestFactory } from '@nestjs/core';
import { Module, Controller, Post, Req } from '@nestjs/common';

const sdk = await import(process.env.APPGUARD_TEST_SDK_IMPORT ?? new URL('../../src/index.js', import.meta.url).href);
const { expressMiddleware, nestMiddleware, installFastify, buildSignatureBase,
  serializeParameters, InMemoryReplayStore, VerificationError } = sdk;
const [kind, fault, shape = 'binary'] = process.argv.slice(2);
const body = shape === 'empty' ? Buffer.alloc(0) : shape === 'maximum' ? Buffer.alloc(1048576, 0xa5)
  : Buffer.from([0, 255, 128, 13, 10, 0, ...Buffer.from('copy 世界')]);
const target = '/copy?x=%2f&x=%2F&empty';
const now = 1700000000;
const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const key = { app_id: 'copy-app', key_id: 'copy-key', subject: 'copy-user', algorithm: 'ecdsa-p256-sha256',
  revoked: false, public_key_pem: publicKey.export({ type: 'spki', format: 'pem' }) };
const parameters = { created: now, expires: now + 120, nonce: randomBytes(16).toString('base64url'),
  key_id: key.key_id, algorithm: key.algorithm, tag: 'appguard-request-v0' };
const headers = [['Content-Type', 'application/octet-stream'],
  ['Content-Digest', `sha-256=:${createHash('sha256').update(body).digest('base64')}:`],
  ['Authorization', 'Bearer TEST_ONLY_COPY_TOKEN'], ['AppGuard-App-Id', key.app_id]];
const base = buildSignatureBase({ method: 'POST', target, headers, body }, parameters, { origin: 'https://api.example.test' });
headers.push(['Signature-Input', `appguard=${serializeParameters(parameters)}`],
  ['Signature', `appguard=:${sign('sha256', base, { key: privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64')}:`]);
const counts = { identity: 0, key: 0, clock: 0, replay: 0, parser: 0, downstream: 0 };
const store = new InMemoryReplayStore();
const options = { app_id: key.app_id, origin: 'https://api.example.test', allowInsecureTransport: true,
  identityResolver: () => { counts.identity++; return key.subject; },
  keyResolver: () => { counts.key++; return key; }, clock: () => { counts.clock++; return now; },
  replay: { claim(...args) { counts.replay++; return store.claim(...args); } } };
const downstream = req => {
  counts.downstream++;
  assert.deepEqual(req.appguardRawBody, body);
  assert.deepEqual(req.body, body);
  assert.equal(req.appguardTarget, target);
  return { code: req.appguard.code, digest: createHash('sha256').update(req.body).digest('hex'), length: req.body.length };
};
let server, close;
if (kind === 'fastify') {
  const app = Fastify({ logger: false, forceCloseConnections: true });
  installFastify(app, options);
  app.addContentTypeParser('application/octet-stream', { parseAs: 'buffer' }, (req, bytes, done) => {
    counts.parser++; done(null, bytes);
  });
  app.post('/copy', req => downstream(req));
  await app.ready(); server = app.server; close = () => app.close();
} else if (kind === 'nest') {
  class Endpoint { run(req) { return downstream(req); } }
  Controller('/copy')(Endpoint); Post()(Endpoint.prototype, 'run', Object.getOwnPropertyDescriptor(Endpoint.prototype, 'run'));
  Req()(Endpoint.prototype, 'run', 0);
  class App {}
  Module({ controllers: [Endpoint] })(App);
  const app = await NestFactory.create(App, { logger: false, bodyParser: false });
  app.use(nestMiddleware(options)); app.use((req, res, next) => { counts.parser++; next(); });
  app.use(express.raw({ type: () => true, limit: '2mb' }));
  await app.init(); server = app.getHttpServer(); close = () => app.close();
} else {
  assert.equal(kind, 'express');
  const app = express(); app.use(expressMiddleware(options));
  app.use((req, res, next) => { counts.parser++; next(); }); app.use(express.raw({ type: () => true, limit: '2mb' }));
  app.use((req, res) => res.json(downstream(req)));
  server = http.createServer(app); close = () => new Promise(resolve => server.close(resolve));
}
const observations = [];
let currentEnd, injected = 0, copies = 0;
const originalConcat = Buffer.concat;
server.prependListener('request', req => {
  const descriptor = Object.getOwnPropertyDescriptor(req, 'emit'), emit = req.emit;
  const observation = { req, descriptor, chunks: [] };
  observations.push(observation);
  const captureStarted = (event, listener) => {
    if (event !== 'data') return;
    observation.captureOwned = Object.fromEntries(['end', 'error', 'aborted', 'close']
      .map(name => [name, req.listeners(name).at(-1)]));
    observation.captureOwned.data = listener;
    req.removeListener('newListener', captureStarted);
  };
  req.on('newListener', captureStarted);
  req.emit = function(event, ...args) {
    if (event === 'data') observation.chunks.push(args[0]);
    const previous = currentEnd;
    if (event === 'end') currentEnd = observation;
    try { return Reflect.apply(emit, this, [event, ...args]); }
    finally { currentEnd = previous; }
  };
});
Buffer.concat = function(chunks, length) {
  // Inject only at the SDK's native end-event copy of the exact observed chunks.
  if (currentEnd && length === body.length && chunks.length === currentEnd.chunks.length &&
      chunks.every((chunk, index) => chunk === currentEnd.chunks[index])) {
    copies++;
    if (fault !== 'none' && injected === 0) {
      injected++;
      Buffer.concat = originalConcat;
      if (fault === 'range') throw new RangeError('TEST_ONLY_COPY_SECRET');
      if (fault === 'verification') throw new VerificationError('REPLAY_DETECTED', 499);
      assert.equal(fault, 'error');
      throw new Error('TEST_ONLY_COPY_SECRET');
    }
  }
  return Reflect.apply(originalConcat, this, [chunks, length]);
};
const request = () => new Promise((resolve, reject) => {
  const client = http.request({ host: '127.0.0.1', port: server.address().port, path: target, method: 'POST', agent: false,
    headers: [...headers, ['Host', 'localhost'], ['Content-Length', String(body.length)]].flat() }, res => {
    const chunks = []; res.on('data', chunk => chunks.push(chunk));
    res.on('end', () => {
      try { resolve({ status: res.statusCode, headers: res.headers, body: JSON.parse(originalConcat(chunks).toString()) }); }
      catch (error) { reject(error); }
    });
  });
  client.setTimeout(4000, () => client.destroy(new Error('HARNESS_TIMEOUT')));
  client.on('error', reject); client.end(body);
});
try {
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  if (fault !== 'none') {
    const failure = await request();
    assert.equal(injected, 1, 'the final native body copy fault must actually run');
    assert.equal(failure.status, 400); assert.deepEqual(failure.body, { code: 'INVALID_REQUEST' });
    assert.equal(failure.headers['cache-control'], 'no-store'); assert.equal(failure.headers.connection, 'close');
    assert.deepEqual(counts, { identity: 0, key: 0, clock: 0, replay: 0, parser: 0, downstream: 0 });
    await new Promise(resolve => setImmediate(resolve));
    const { req, captureOwned } = observations[0];
    for (const [event, listener] of Object.entries(captureOwned)) {
      assert.equal(typeof listener, 'function'); assert.equal(req.listeners(event).includes(listener), false);
    }
    assert.equal(req.isPaused(), true); assert.equal(Object.hasOwn(req, 'appguard'), false);
    assert.equal(Object.hasOwn(req, 'appguardRawBody'), false);
  }
  Buffer.concat = originalConcat;
  // A failed copy cannot consume the signed nonce; this fresh context reuses it.
  const accepted = await request();
  assert.equal(accepted.status, kind === 'nest' ? 201 : 200);
  assert.deepEqual(accepted.body, { code: 'VERIFIED', digest: createHash('sha256').update(body).digest('hex'), length: body.length });
  assert.deepEqual(counts, { identity: 1, key: 1, clock: 1, replay: 1, parser: 1, downstream: 1 });
  const replay = await request(); assert.equal(replay.status, 403); assert.deepEqual(replay.body, { code: 'REPLAY_DETECTED' });
  assert.deepEqual(counts, { identity: 2, key: 2, clock: 2, replay: 2, parser: 1, downstream: 1 });
  assert.equal(copies, fault === 'none' ? 0 : 1);
  console.log(JSON.stringify({ kind, fault, shape, injected, survived: true, accepted: true, replayRejected: true }));
} finally {
  Buffer.concat = originalConcat;
  for (const { req, descriptor } of observations) {
    if (descriptor) Object.defineProperty(req, 'emit', descriptor); else delete req.emit;
  }
  server.closeAllConnections(); await close();
  assert.equal(Buffer.concat, originalConcat);
}
