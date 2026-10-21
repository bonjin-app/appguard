import 'reflect-metadata';
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { readFileSync } from 'node:fs';
import express from 'express';
import Fastify from 'fastify';
import { NestFactory } from '@nestjs/core';
import { Module, Controller, Post } from '@nestjs/common';
import { expressMiddleware, nestMiddleware, installFastify, InMemoryReplayStore } from '../src/index.js';

const vector = JSON.parse(readFileSync(new URL('../../../conformance/v0/requests.json', import.meta.url)))[0];
const key = vector.key;
const identity = { subject: vector.context.subject, key };
const path = vector.request.target.split('?')[0];
const headers = [...vector.request.headers,
  ['Signature-Input', 'appguard=' + vector.expected_signature_base.split('"@signature-params": ')[1]],
  ['Signature', 'appguard=:' + vector.signature_b64 + ':']];
const turn = () => new Promise(resolve => setImmediate(resolve));
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
function block(ms) { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); }
function configuration(extra = {}) {
  return { app_id:vector.context.app_id, origin:vector.context.origin, clock:()=>vector.context.now,
    replay:new InMemoryReplayStore(), identityResolver:()=>identity, allowInsecureTransport:true, ...extra };
}
async function serve(kind, extra = {}) {
  let claims = 0, downstream = 0, close;
  const store = new InMemoryReplayStore();
  const options = configuration({identityTimeoutMs:40, ...extra,
    replay:{claim(...args) { claims++; return store.claim(...args); }}});
  const done = () => { downstream++; return {code:'VERIFIED'}; };
  let server;
  if (kind === 'fastify') {
    const app = Fastify({logger:false, forceCloseConnections:true});
    installFastify(app, options); app.post(path, done); await app.ready();
    server = app.server; close = () => app.close();
  } else if (kind === 'nest') {
    class Endpoint { run() { return done(); } }
    Controller(path)(Endpoint); Post()(Endpoint.prototype, 'run', Object.getOwnPropertyDescriptor(Endpoint.prototype, 'run'));
    class App {}
    Module({controllers:[Endpoint]})(App);
    const app = await NestFactory.create(App, {logger:false, bodyParser:false});
    app.use(nestMiddleware(options)); await app.init();
    server = app.getHttpServer(); close = () => app.close();
  } else {
    const app = express(); app.use(expressMiddleware(options)); app.use((req,res) => res.json(done()));
    server = http.createServer(app); close = () => new Promise(resolve => server.close(resolve));
  }
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return { port:server.address().port, get claims() { return claims; }, get downstream() { return downstream; },
    async close() { server.closeAllConnections(); await close(); } };
}
function send(server) {
  return new Promise((resolve,reject) => {
    const req = http.request({host:'127.0.0.1', port:server.port, path:vector.request.target,
      method:vector.request.method, headers:[...headers,['Host','localhost']].flat(), agent:false}, res => {
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => { try { resolve({status:res.statusCode, body:JSON.parse(Buffer.concat(chunks).toString())}); } catch(error) { reject(error); } });
    });
    req.setTimeout(3000, () => req.destroy(new Error('HARNESS_TIMEOUT: SDK did not finish authentication')));
    req.on('error', reject); req.end(Buffer.from(vector.request.body_b64,'base64'));
  });
}
function unavailable(response, phase) {
  assert.deepEqual(response, {status:503, body:{code:phase === 'identity' ? 'IDENTITY_UNAVAILABLE' : 'KEY_RESOLVER_UNAVAILABLE'}});
}
for (const kind of ['express','fastify','nest']) {
  for (const phase of ['identity','key']) {
    test(`${kind}: hanging ${phase} callback has a deadline`, async () => {
      const extra = phase === 'identity' ? {identityResolver:()=>new Promise(()=>{})}
        : {identityResolver:()=>identity.subject, keyResolver:()=>new Promise(()=>{})};
      const server = await serve(kind, extra);
      try { unavailable(await send(server), phase); assert.equal(server.claims,0); assert.equal(server.downstream,0); }
      finally { await server.close(); }
    });
    for (const outcome of ['resolve','reject']) {
      test(`${kind}: late ${phase} ${outcome} cannot continue verification`, async () => {
        const pending = deferred(); let lookups = 0;
        const extra = phase === 'identity' ? {identityResolver:()=>pending.promise, keyResolver:()=>{lookups++; return key;}}
          : {identityResolver:()=>identity.subject, keyResolver:()=>{lookups++; return pending.promise;}};
        const server = await serve(kind, extra);
        try {
          unavailable(await send(server), phase);
          if (outcome === 'reject') pending.reject(new Error('SYNTHETIC_PRIVATE_AUTH_ERROR'));
          else pending.resolve(phase === 'identity' ? identity.subject : key);
          await turn(); await turn();
          assert.equal(lookups, phase === 'identity' ? 0 : 1);
          assert.equal(server.claims,0); assert.equal(server.downstream,0);
        } finally { pending.resolve(phase === 'identity' ? identity.subject : key); await turn(); await server.close(); }
      });
    }
  }
  test(`${kind}: synchronous callback overrun is rejected before key lookup`, async () => {
    let lookups = 0;
    const server = await serve(kind, {identityResolver:()=>{block(80); return identity.subject;}, keyResolver:()=>{lookups++;return key;}});
    try { unavailable(await send(server),'identity'); assert.equal(lookups,0); assert.equal(server.claims,0); assert.equal(server.downstream,0); }
    finally { await server.close(); }
  });
  test(`${kind}: identity and key lookup share one total deadline`, async () => {
    const server = await serve(kind, {identityTimeoutMs:100, identityResolver:()=>{block(60); return identity.subject;}, keyResolver:()=>{block(60);return key;}});
    try {
      const response = await send(server);
      assert.equal(response.status,503);
      assert.ok(['IDENTITY_UNAVAILABLE','KEY_RESOLVER_UNAVAILABLE'].includes(response.body.code));
      assert.equal(server.claims,0); assert.equal(server.downstream,0);
    } finally { await server.close(); }
  });
  test(`${kind}: default deadline preserves successful verification`, async () => {
    const server = await serve(kind, {identityTimeoutMs:undefined});
    try { const response=await send(server); assert.equal(response.status,kind==='nest'?201:200); assert.deepEqual(response.body,{code:'VERIFIED'}); assert.equal(server.claims,1); assert.equal(server.downstream,1); }
    finally { await server.close(); }
  });
  test(`${kind}: blocked authentication does not block another request`, async () => {
    const pending=deferred(), started=deferred(); let calls=0;
    const server=await serve(kind,{identityTimeoutMs:500, identityResolver:()=>{if(++calls===1){started.resolve();return pending.promise;}return identity;}});
    try {
      const first=send(server); // Observe rejection immediately, including on pre-repair source.
      const observed=first.then(value=>({value}),error=>({error}));
      await started.promise;
      const second=await send(server); assert.equal(second.status,kind==='nest'?201:200);
      const result=await observed; assert.ifError(result.error); unavailable(result.value,'identity');
      pending.resolve(identity); await turn(); await turn();
      assert.equal(server.claims,1); assert.equal(server.downstream,1);
    } finally { pending.resolve(identity); await turn(); await server.close(); }
  });
}
for (const name of ['identityTimeoutMs','bodyTimeoutMs']) {
  for (const value of [0,-1,NaN,Infinity,0.5,'20',true,null,2147483648,Number.MAX_SAFE_INTEGER]) {
    test(`timeout option ${name} rejects ${String(value)}`, () => {
      for (const make of [expressMiddleware,nestMiddleware]) assert.throws(()=>make(configuration({[name]:value})),TypeError);
      assert.throws(()=>installFastify({server:http.createServer(),addHook(){}},configuration({[name]:value})),TypeError);
    });
  }
}
