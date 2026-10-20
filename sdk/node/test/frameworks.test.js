import 'reflect-metadata';
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import {readFileSync} from 'node:fs';
import net from 'node:net';
import { once } from 'node:events';
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import express from 'express';
import Fastify from 'fastify';
import { NestFactory } from '@nestjs/core';
import { Module, Controller, Post, Req } from '@nestjs/common';
import { expressMiddleware, nestMiddleware, installFastify, buildSignatureBase, serializeParameters, InMemoryReplayStore } from '../src/index.js';
const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const key = { app_id: 'test-app', key_id: 'test-key', subject: 'test-user', public_key_pem: publicKey.export({ type: 'spki', format: 'pem' }), algorithm: 'ecdsa-p256-sha256', revoked: false };
const now = 1700000000;
// Test-only self-signed localhost transport certificate; never production credentials.
const tls = {key:readFileSync(new URL('./fixtures/localhost-key.pem',import.meta.url)),cert:readFileSync(new URL('./fixtures/localhost-cert.pem',import.meta.url))};
function signed({ body = Buffer.from('{"hello":"世界"}'), target = '/echo?b=2&a=1&x=%2f&x=%2F&empty', method = 'POST', contentType = 'application/json', nonce = randomBytes(16).toString('base64url') } = {}) {
  const p = { created: now, expires: now + 120, nonce, key_id: key.key_id, algorithm: key.algorithm, tag: 'appguard-request-v0' };
  const headers = [['Content-Type', contentType], ['Content-Digest', `sha-256=:${createHash('sha256').update(body).digest('base64')}:`], ['Authorization', 'Bearer TEST_ONLY_TOKEN'], ['AppGuard-App-Id', 'test-app']];
  const base = buildSignatureBase({ method, target, headers, body }, p, { origin: 'https://api.example.test' });
  return { body, target, method, headers: [...headers, ['Signature-Input', `appguard=${serializeParameters(p)}`], ['Signature', `appguard=:${sign('sha256', base, { key: privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64')}:`]] };
}
const options = extra => ({ app_id: 'test-app', origin: 'https://api.example.test', replay: new InMemoryReplayStore(), identityResolver: async () => ({ subject: 'test-user', key }), clock: () => now, allowInsecureTransport: true, ...extra });
const echo = req => ({ body: req.body, raw: req.appguardRawBody.toString('base64'), target: req.appguardTarget, code: req.appguard.code });
async function server(kind, opts, before, { secure = false, rewrite = false } = {}) {
  let srv, close;
  if (kind === 'express') {
    const app = express();
    if (before) app.use(before);
    app.use(expressMiddleware(opts));
    if (rewrite) app.use((req,res,next) => { req.url='/echo'; next(); });
    app.use(express.raw({type:'application/octet-stream',limit:'2mb'}));
    app.use(express.json({ limit: '2mb' }));
    app.use((req, res) => res.json(echo(req)));
    srv = secure ? https.createServer(tls, app) : http.createServer(app);
  } else if (kind === 'fastify') {
    const app = Fastify({ logger: false, bodyLimit: 2 * 1024 * 1024, ...(secure ? {https:tls} : {}) });
    app.addContentTypeParser('application/octet-stream',{parseAs:'buffer'},(req,body,done)=>done(null,body));
    if (before) app.addHook('onRequest', before);
    installFastify(app, opts);
    if (rewrite) app.addHook('preHandler',async req => {req.raw.url='/rewritten';});
    app.post('/echo', async req => echo(req));
    app.post('/echo/', async req => echo(req));
    await app.ready(); srv = app.server; close = () => app.close();
  } else {
    class EchoController { echo(req) { return echo(req); } }
    Controller('echo')(EchoController);
    Post()(EchoController.prototype, 'echo', Object.getOwnPropertyDescriptor(EchoController.prototype, 'echo'));
    Req()(EchoController.prototype, 'echo', 0);
    class AppModule {}
    Module({ controllers: [EchoController] })(AppModule);
    const app = await NestFactory.create(AppModule, { logger: false, bodyParser: false, ...(secure ? {httpsOptions:tls} : {}) });
    if (before) app.use(before);
    app.use(nestMiddleware(opts));
    if (rewrite) app.use((req,res,next) => {req.url='/echo';next();});
    app.use(express.raw({type:'application/octet-stream',limit:'2mb'}));
    app.use(express.json({ limit: '2mb' }));
    await app.init(); srv = app.getHttpServer(); close = () => app.close();
  }
  await new Promise(resolve => srv.listen(0, '127.0.0.1', resolve));
  return { port: srv.address().port, close: close ?? (() => new Promise(resolve => srv.close(resolve))) };
}
function send(port, packet, { chunks, headers = packet.headers, body = packet.body, target = packet.target, secure = false } = {}) {
  return new Promise((resolve, reject) => {
    const req = (secure ? https : http).request({ host: '127.0.0.1', port, rejectUnauthorized:false, path: target, method: packet.method, headers: [...headers, ['Host', 'localhost']].flat(), timeout: 3000 }, res => {
      const parts = []; res.on('data', c => parts.push(c)); res.on('end', () => { try { resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(parts).toString()) }); } catch (error) { reject(new Error(`Non-JSON HTTP ${res.statusCode}: ${Buffer.concat(parts).toString()}`)); } });
    });
    req.on('error', reject); req.on('timeout', () => req.destroy(new Error('test timeout')));
    if (chunks) { for (const chunk of chunks) req.write(chunk); req.end(); } else req.end(body);
  });
}
for (const kind of ['express', 'fastify', 'nest']) {
  test(`${kind}: unsigned requests to unknown paths are protected`, async () => {
    const s=await server(kind,options());const p=signed({target:'/not-registered'});
    try {assert.deepEqual(await send(s.port,p,{headers:[]}),{status:400,body:{code:'INVALID_REQUEST'}});}finally{await s.close();}
  });
  test(`${kind}: JSON downstream sees exact verified body and raw query`, async () => {
    const s = await server(kind, options());
    try { const p = signed(); const r = await send(s.port, p); assert.equal(r.status, kind === 'nest' ? 201 : 200); assert.deepEqual(r.body, { body: { hello: '世界' }, raw: p.body.toString('base64'), target: p.target, code: 'VERIFIED' }); }
    finally { await s.close(); }
  });
  for (const [name, mutate, extra, status, code] of [
    ['tampered body', (p) => ({ body: Buffer.from('{"hello":"tamper"}') }), {}, 403, 'DIGEST_MISMATCH'],
    ['tampered target', () => ({ target: '/echo?a=1&b=2' }), {}, 403, 'INVALID_SIGNATURE'],
    ['missing signature', p => ({ headers: p.headers.filter(([n]) => n !== 'Signature') }), {}, 400, 'INVALID_REQUEST'],
    ['duplicate signature', p => ({ headers: [...p.headers, p.headers.at(-1)] }), {}, 400, 'INVALID_REQUEST'],
    ['duplicate authorization', p => ({ headers: [...p.headers, p.headers[2]] }), {}, 400, 'INVALID_REQUEST'],
    ['insecure transport ignores forwarding', p => ({ headers: [...p.headers, ['X-Forwarded-Proto', 'https']] }), { allowInsecureTransport: false }, 400, 'INVALID_REQUEST'],
    ['authentication rejection', () => ({}), { identityResolver: async () => null }, 401, 'AUTHENTICATION_REQUIRED'],
    ['identity exception', () => ({}), { identityResolver: async () => { throw new Error('secret'); } }, 503, 'IDENTITY_UNAVAILABLE'],
    ['identity getter exception', () => ({}), { identityResolver: async () => ({ get subject() { throw new Error('secret'); } }) }, 503, 'IDENTITY_UNAVAILABLE'],
    ['key getter exception', () => ({}), { identityResolver: async () => ({ subject: 'test-user', key: { get app_id() { throw new Error('secret'); } } }) }, 503, 'IDENTITY_UNAVAILABLE'],
    ['key resolver invalid contract', () => ({}), { identityResolver: async () => 'test-user', keyResolver: async () => ({}) }, 503, 'KEY_RESOLVER_UNAVAILABLE'],
    ['invalid identity contract', () => ({}), { identityResolver: async () => ({ subject: '' }) }, 503, 'IDENTITY_UNAVAILABLE'],
    ['key resolver exception', () => ({}), { identityResolver: async () => 'test-user', keyResolver: async () => { throw new Error('secret'); } }, 503, 'KEY_RESOLVER_UNAVAILABLE'],
    ['expired unknown key keeps core check order', () => ({}), { clock: () => now + 120, identityResolver: async () => 'test-user', keyResolver: async () => null }, 403, 'INVALID_TIME'],
    ['unknown key lookup null', () => ({}), { identityResolver: async () => 'test-user', keyResolver: async () => null }, 403, 'KEY_REJECTED'],
    ['unknown key lookup undefined', () => ({}), { identityResolver: async () => 'test-user', keyResolver: async () => undefined }, 403, 'KEY_REJECTED'],
    ['combined identity unknown key', () => ({}), { identityResolver: async () => ({subject:'test-user',key:null}) }, 403, 'KEY_REJECTED'],
    ['invalid key binding', () => ({}), { identityResolver: async () => ({ subject: 'test-user', key: { ...key, revoked: true } }) }, 403, 'KEY_REJECTED'],
    ['store exception', () => ({}), { replay: { claim: async () => { throw new Error('secret'); } } }, 503, 'REPLAY_STORE_UNAVAILABLE'],
    ['store invalid contract', () => ({}), { replay: { claim: async () => 'yes' } }, 503, 'REPLAY_STORE_UNAVAILABLE'],
    ['body limit', () => ({ body: Buffer.alloc(1048577) }), {}, 413, 'INVALID_REQUEST'],
    ['body limit from content-length', p => ({ headers: [...p.headers, ['Content-Length', '1048577']], body: Buffer.alloc(0) }), {}, 413, 'INVALID_REQUEST'],
  ]) test(`${kind}: ${name}`, async () => {
    let claims = 0;
    const opts = options({ replay: { claim: () => { claims++; return true; } }, ...extra });
    const s = await server(kind, opts);
    try { const p = signed(); const r = await send(s.port, p, mutate(p)); assert.deepEqual(r, { status, body: { code } }); if (!name.startsWith('store')) assert.equal(claims, 0); }
    finally { await s.close(); }
  });
  test(`${kind}: 32 concurrent identical requests allow one handler`, async () => {
    const s = await server(kind, options());
    try { const p = signed(); const results = await Promise.all(Array.from({ length: 32 }, () => send(s.port, p))); assert.equal(results.filter(r => r.body.code === 'VERIFIED').length, 1); assert.equal(results.filter(r => r.body.code === 'REPLAY_DETECTED').length, 31); }
    finally { await s.close(); }
  });
  test(`${kind}: bytes split at every UTF-8 boundary and one-byte chunks`, async () => {
    const s = await server(kind, options());
    try { const p = signed(); const r = await send(s.port, p, { chunks: [...p.body].map(b => Buffer.from([b])) }); assert.equal(r.body.raw, p.body.toString('base64')); assert.deepEqual(r.body.body, { hello: '世界' }); }
    finally { await s.close(); }
  });
  test(`${kind}: direct HTTPS is accepted with secure transport defaults`, async () => {
    const s=await server(kind,options({allowInsecureTransport:false}),undefined,{secure:true});
    try { assert.equal((await send(s.port,signed(),{secure:true})).body.code,'VERIFIED'); } finally {await s.close();}
  });
  test(`${kind}: exact binary bytes reach downstream parsers`, async () => {
    const s=await server(kind,options());const p=signed({body:Buffer.from([0,1,2,128,255,0]),contentType:'application/octet-stream'});
    try {const r=await send(s.port,p);assert.equal(r.body.raw,p.body.toString('base64'));assert.deepEqual(r.body.body,{type:'Buffer',data:[0,1,2,128,255,0]});} finally {await s.close();}
  });
  test(`${kind}: explicit empty query remains signed`, async () => {
    const s=await server(kind,options());const p=signed({target:'/echo?'});
    try {const r=await send(s.port,p);assert.equal(r.body.target,'/echo?');assert.equal(r.body.code,'VERIFIED');} finally {await s.close();}
  });
  test(`${kind}: verified original evidence survives downstream route rewriting`, async () => {
    const s=await server(kind,options(),undefined,{rewrite:true}); const p=signed();
    try {const r=await send(s.port,p);assert.equal(r.body.target,p.target);assert.equal(r.body.code,'VERIFIED');} finally {await s.close();}
  });
  test(`${kind}: rewriting target before verification rejects lost original evidence`, async () => {
    const before=kind==='fastify'?async req=>{req.raw.url='/echo?rewritten=1';}:(req,res,next)=>{req.url='/echo?rewritten=1';next();};
    const s=await server(kind,options(),before);const p=signed({target:'/echo?rewritten=1'});
    try {assert.deepEqual(await send(s.port,p,{target:'/echo?original=2'}),{status:400,body:{code:'INVALID_REQUEST'}});}finally{await s.close();}
  });
  test(`${kind}: clock read occurs after asynchronous authentication`, async () => {
    let clock = now;
    const s = await server(kind, options({ clock: () => clock, identityResolver: async () => { await Promise.resolve(); clock = now + 120; return { subject: 'test-user', key }; } }));
    try { assert.deepEqual(await send(s.port, signed()), { status: 403, body: { code: 'INVALID_TIME' } }); } finally { await s.close(); }
  });
  test(`${kind}: consumed body fails closed promptly`, async () => {
    let called = 0;
    const consume = kind === 'fastify' ? async req => { for await (const _ of req.raw) {} } : express.json();
    const s = await server(kind, options({ identityResolver: () => { called++; return { subject: 'test-user', key }; } }), consume);
    try { assert.deepEqual(await send(s.port, signed()), { status: 400, body: { code: 'INVALID_REQUEST' } }); assert.equal(called, 0); } finally { await s.close(); }
  });
  test(`${kind}: incomplete body times out before authentication`, async () => {
    let authenticated=0;const s=await server(kind,options({bodyTimeoutMs:30,identityResolver:()=>{authenticated++;return {subject:'test-user',key};}}));
    try {const p=signed();const socket=net.connect(s.port,'127.0.0.1');await once(socket,'connect');let response='';socket.on('data',c=>{response+=c.toString();});socket.on('error',()=>{});socket.setTimeout(2000,()=>socket.destroy());
      socket.write(`POST ${p.target} HTTP/1.1\r\nHost: localhost\r\n${p.headers.map(([n,v])=>`${n}: ${v}`).join('\r\n')}\r\nContent-Length: ${p.body.length}\r\n\r\nx`);
      await once(socket,'close');assert.match(response,/HTTP\/1\.1 400/);assert.match(response,/"code":"INVALID_REQUEST"/);assert.equal(authenticated,0);
    }finally{await s.close();}
  });
  test(`${kind}: missing raw-header evidence rejects`, async () => {
    const before=kind==='fastify'?async req=>{req.raw.rawHeaders=undefined;}:(req,res,next)=>{req.rawHeaders=undefined;next();};
    const s=await server(kind,options(),before);try{assert.deepEqual(await send(s.port,signed()),{status:400,body:{code:'INVALID_REQUEST'}});}finally{await s.close();}
  });
  test(`${kind}: partial prior consumption rejects promptly`, async () => {
    const before=kind==='fastify'?async req=>{await once(req.raw,'data');req.raw.pause();}:(req,res,next)=>{req.once('data',()=>{req.pause();next();});};
    const s=await server(kind,options(),before);try{assert.deepEqual(await send(s.port,signed()),{status:400,body:{code:'INVALID_REQUEST'}});}finally{await s.close();}
  });
  test(`${kind}: truncated/disconnected body does not authenticate or claim`, async () => {
    let authenticated = 0;
    const s = await server(kind, options({ identityResolver: () => { authenticated++; return { subject: 'test-user', key }; } }));
    try {
      const p = signed();
      const socket = net.connect(s.port, '127.0.0.1'); await once(socket, 'connect');
      socket.on('error', () => {}); socket.resume(); socket.setTimeout(2000, () => socket.destroy());
      socket.end(`POST ${p.target} HTTP/1.1\r\nHost: localhost\r\n${p.headers.map(([n,v]) => `${n}: ${v}`).join('\r\n')}\r\nContent-Length: ${p.body.length + 10}\r\n\r\nx`);
      await once(socket, 'close'); await new Promise(r => setImmediate(r)); assert.equal(authenticated, 0);
    } finally { await s.close(); }
  });
}
test('adapters require all security configuration at installation', () => {
  for (const make of [expressMiddleware, nestMiddleware]) {
    for (const name of ['app_id', 'origin', 'replay', 'identityResolver']) { const o = options(); delete o[name]; assert.throws(() => make(o)); }
  }
});
