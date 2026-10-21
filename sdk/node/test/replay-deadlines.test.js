import 'reflect-metadata';
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { readFileSync } from 'node:fs';
import { spawn } from 'node:child_process';
import express from 'express';
import Fastify from 'fastify';
import { NestFactory } from '@nestjs/core';
import { Module, Controller, Post } from '@nestjs/common';
import { verifyRequest, VerificationError, InMemoryReplayStore, expressMiddleware, nestMiddleware, installFastify } from '../src/index.js';

const vector = JSON.parse(readFileSync(new URL('../../../conformance/v0/requests.json', import.meta.url)))[0];
const request = { ...vector.request, body:Buffer.from(vector.request.body_b64, 'base64') };
const signature = Buffer.from(vector.signature_b64, 'base64');
const path = vector.request.target.split('?')[0];
const headers = [...vector.request.headers,
  ['Signature-Input', 'appguard=' + vector.expected_signature_base.split('"@signature-params": ')[1]],
  ['Signature', 'appguard=:' + vector.signature_b64 + ':']];
const turn = () => new Promise(resolve => setImmediate(resolve));
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve=yes; reject=no; });
  return { promise, resolve, reject };
}
function block(ms) { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); }
function core(claim, extra={}) {
  return verifyRequest(request, vector.parameters, signature, {...vector.context, key:vector.key,
    replay:{claim}, replayTimeoutMs:40, ...extra});
}
async function bounded(promise, ms=3000) {
  let timer;
  try { return await Promise.race([promise, new Promise((_,reject) => {
    timer=setTimeout(()=>reject(new Error('HARNESS_TIMEOUT: replay verification did not settle')),ms);
  })]); } finally { clearTimeout(timer); }
}
function unavailable(error) {
  assert.ok(error instanceof VerificationError);
  assert.equal(error.code,'REPLAY_STORE_UNAVAILABLE');
  assert.equal(error.status,503);
  assert.equal(error.message,'REPLAY_STORE_UNAVAILABLE');
  assert.equal(error.cause,undefined);
  return true;
}
function configuration(claim, extra={}) {
  return {app_id:vector.context.app_id, origin:vector.context.origin, clock:()=>vector.context.now,
    identityResolver:()=>({subject:vector.context.subject,key:vector.key}),
    allowInsecureTransport:true, replay:{claim}, replayTimeoutMs:40, ...extra};
}
async function serve(kind, claim, extra={}) {
  let claims=0, downstream=0, close, server;
  const options=configuration((...args)=>{claims++;return claim(...args);},extra);
  const done=()=>{downstream++;return {code:'VERIFIED'};};
  if(kind==='fastify') {
    const app=Fastify({logger:false,forceCloseConnections:true});
    installFastify(app,options);app.post(path,done);await app.ready();
    server=app.server;close=()=>app.close();
  } else if(kind==='nest') {
    class Endpoint { run() { return done(); } }
    Controller(path)(Endpoint);Post()(Endpoint.prototype,'run',Object.getOwnPropertyDescriptor(Endpoint.prototype,'run'));
    class App {}
    Module({controllers:[Endpoint]})(App);
    const app=await NestFactory.create(App,{logger:false,bodyParser:false});
    app.use(nestMiddleware(options));await app.init();server=app.getHttpServer();close=()=>app.close();
  } else {
    const app=express();app.use(expressMiddleware(options));app.use((req,res)=>res.json(done()));
    server=http.createServer(app);close=()=>new Promise(resolve=>server.close(resolve));
  }
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  return {port:server.address().port,get claims(){return claims;},get downstream(){return downstream;},
    async close(){server.closeAllConnections();await close();}};
}
function send(server) {
  return new Promise((resolve,reject)=>{
    const req=http.request({host:'127.0.0.1',port:server.port,path:vector.request.target,
      method:vector.request.method,headers:[...headers,['Host','localhost']].flat(),agent:false},res=>{
      const chunks=[];res.on('data',chunk=>chunks.push(chunk));
      res.on('end',()=>{try{resolve({status:res.statusCode,body:JSON.parse(Buffer.concat(chunks).toString())});}catch(error){reject(error);}});
    });
    req.setTimeout(3000,()=>req.destroy(new Error('HARNESS_TIMEOUT: replay HTTP verification did not settle')));
    req.on('error',reject);req.end(request.body);
  });
}
const unavailableResponse={status:503,body:{code:'REPLAY_STORE_UNAVAILABLE'}};

for(const outcome of ['pending','true','false','reject']) {
  test(`core: ${outcome} late replay outcome cannot authorize verification`,async()=>{
    const pending=deferred();
    try {
      await assert.rejects(bounded(core(()=>pending.promise)),unavailable);
      if(outcome==='reject')pending.reject(new Error('PRIVATE_REPLAY_BACKEND_FAILURE'));
      else if(outcome!=='pending')pending.resolve(outcome==='true');
      await turn();await turn();
    } finally {pending.resolve(true);await turn();}
  });
}
test('core: synchronous successful claim overrun fails closed',async()=>{
  await assert.rejects(core(()=>{block(80);return true;}),unavailable);
});
for(const extra of [{}, {replayTimeoutMs:undefined}, {replayTimeoutMs:1000}, {replayTimeoutMs:2147483647}]) {
  test(`core: immediate successful replay claim with ${JSON.stringify(extra)}`,async()=>{
    assert.equal((await core(()=>true,extra)).code,'VERIFIED');
  });
}
for(const [name,claim,code] of [
  ['false',()=>false,'REPLAY_DETECTED'], ['malformed',()=>({claimed:true}),'REPLAY_STORE_UNAVAILABLE'],
  ['throw',()=>{throw new Error('PRIVATE_REPLAY_BACKEND_FAILURE');},'REPLAY_STORE_UNAVAILABLE'],
  ['reject',()=>Promise.reject(new Error('PRIVATE_REPLAY_BACKEND_FAILURE')),'REPLAY_STORE_UNAVAILABLE']
]) {
  test(`core: immediate ${name} preserves fixed replay result`,async()=>{
    await assert.rejects(core(claim),error=>{if(code==='REPLAY_STORE_UNAVAILABLE')return unavailable(error);
      assert.equal(error.code,code);assert.equal(error.status,403);return true;});
  });
}
test('core: invalid signature never invokes the replay store',async()=>{
  let calls=0;
  await assert.rejects(verifyRequest(request,vector.parameters,Buffer.alloc(64),{...vector.context,key:vector.key,
    replay:{claim(){calls++;return true;}},replayTimeoutMs:40}),{code:'INVALID_SIGNATURE'});
  assert.equal(calls,0);
});
test('core: one pending claim does not block an independent request',async()=>{
  const pending=deferred(),started=deferred();let calls=0;
  const claim=()=>{if(++calls===1){started.resolve();return pending.promise;}return true;};
  const first=bounded(core(claim,{replayTimeoutMs:200})).then(value=>({value}),error=>({error}));
  try {
    await started.promise;assert.equal((await core(claim,{replayTimeoutMs:200})).code,'VERIFIED');
    unavailable((await first).error);assert.equal(calls,2);
  } finally {pending.resolve(true);await turn();}
});

test('core: timeout does not roll back a nonce consumed by a late backend claim',async()=>{
  const gate=deferred(),store=new InMemoryReplayStore();let backend;
  try {
    await assert.rejects(bounded(core((scope,times)=>{
      backend=gate.promise.then(()=>store.claim(scope,times));return backend;
    })),unavailable);
    gate.resolve();assert.equal(await backend,true);
    await assert.rejects(core((scope,times)=>store.claim(scope,times)),{code:'REPLAY_DETECTED',status:403});
  } finally {gate.resolve();await backend;}
});

for(const kind of ['express','fastify','nest']) {
  for(const outcome of ['pending','true','false','reject']) {
    test(`${kind}: ${outcome} late replay outcome never reaches downstream`,async()=>{
      const pending=deferred();const server=await serve(kind,()=>pending.promise);
      try {
        assert.deepEqual(await send(server),unavailableResponse);
        if(outcome==='reject')pending.reject(new Error('PRIVATE_REPLAY_BACKEND_FAILURE'));
        else if(outcome!=='pending')pending.resolve(outcome==='true');
        await turn();await turn();assert.equal(server.claims,1);assert.equal(server.downstream,0);
      } finally {pending.resolve(true);await turn();await server.close();}
    });
  }
  test(`${kind}: synchronous successful replay claim overrun fails closed`,async()=>{
    const server=await serve(kind,()=>{block(80);return true;});
    try {assert.deepEqual(await send(server),unavailableResponse);assert.equal(server.downstream,0);}
    finally {await server.close();}
  });
  test(`${kind}: replay budget starts after identity authentication`,async()=>{
    const server=await serve(kind,()=>true,{identityTimeoutMs:1000,identityResolver:()=>{
      block(80);return {subject:vector.context.subject,key:vector.key};
    }});
    try {assert.equal((await send(server)).status,kind==='nest'?201:200);assert.equal(server.downstream,1);}
    finally {await server.close();}
  });
  for(const extra of [{replayTimeoutMs:1000},{replayTimeoutMs:undefined}]) {
    test(`${kind}: successful replay verification with ${JSON.stringify(extra)}`,async()=>{
      const server=await serve(kind,()=>true,extra);
      try {assert.deepEqual(await send(server),{status:kind==='nest'?201:200,body:{code:'VERIFIED'}});assert.equal(server.downstream,1);}
      finally {await server.close();}
    });
  }
  for(const [name,claim,expected] of [
    ['false',()=>false,{status:403,body:{code:'REPLAY_DETECTED'}}],
    ['malformed',()=>null,unavailableResponse],
    ['throw',()=>{throw new Error('PRIVATE_REPLAY_BACKEND_FAILURE');},unavailableResponse],
    ['reject',()=>Promise.reject(new Error('PRIVATE_REPLAY_BACKEND_FAILURE')),unavailableResponse]
  ]) {
    test(`${kind}: immediate ${name} preserves fixed replay result`,async()=>{
      const server=await serve(kind,claim);
      try {assert.deepEqual(await send(server),expected);assert.equal(server.downstream,0);}
      finally {await server.close();}
    });
  }
  test(`${kind}: one pending replay claim does not block an independent request`,async()=>{
    const pending=deferred(),started=deferred();let calls=0;
    const server=await serve(kind,()=>{if(++calls===1){started.resolve();return pending.promise;}return true;},{replayTimeoutMs:200});
    try {
      const first=send(server).then(value=>({value}),error=>({error}));await started.promise;
      assert.equal((await send(server)).status,kind==='nest'?201:200);
      const result=await first;assert.ifError(result.error);assert.deepEqual(result.value,unavailableResponse);
      pending.resolve(true);await turn();await turn();assert.equal(server.downstream,1);assert.equal(server.claims,2);
    } finally {pending.resolve(true);await turn();await server.close();}
  });
}
for(const value of [null,0,-1,NaN,Infinity,0.5,'40',true,2147483648,Number.MAX_SAFE_INTEGER]) {
  test(`core: invalid replayTimeoutMs ${String(value)} rejects before claiming`,async()=>{
    let calls=0;
    await assert.rejects(core(()=>{calls++;return true;},{replayTimeoutMs:value}),TypeError);
    assert.equal(calls,0);
  });
  for(const kind of ['express','nest','fastify']) {
    test(`${kind}: invalid replayTimeoutMs ${String(value)} throws at installation`,()=>{
      const options=configuration(()=>true,{replayTimeoutMs:value});
      if(kind==='fastify')assert.throws(()=>installFastify({server:http.createServer(),addHook(){}},options),TypeError);
      else assert.throws(()=>(kind==='nest'?nestMiddleware:expressMiddleware)(options),TypeError);
    });
  }
}
// A fresh process has no HTTP server or watchdog to keep an unref'ed SDK timer alive.
async function probe(extra, timeout, success=false) {
  const script=`import {readFileSync} from 'node:fs';
    import {verifyRequest,VerificationError} from ${JSON.stringify(import.meta.resolve('../src/index.js'))};
    const v=JSON.parse(readFileSync(new URL(${JSON.stringify(new URL('../../../conformance/v0/requests.json',import.meta.url).href)})))[0];
    try { await verifyRequest({...v.request,body:Buffer.from(v.request.body_b64,'base64')},v.parameters,Buffer.from(v.signature_b64,'base64'),
      {...v.context,key:v.key,replay:{claim:()=>${success?'true':'new Promise(()=>{})'}},...${JSON.stringify(extra)}});
      ${success?"console.log('VERIFIED');":'process.exitCode=1;'}
    } catch(error) { if(!(error instanceof VerificationError)||error.code!=='REPLAY_STORE_UNAVAILABLE'||error.status!==503||error.message!=='REPLAY_STORE_UNAVAILABLE')throw error;
      console.log('BOUNDED_REPLAY_REJECTION'); }`;
  return new Promise((resolve,reject)=>{
    const child=spawn(process.execPath,['--unhandled-rejections=strict','--input-type=module','--eval',script],{stdio:['ignore','pipe','pipe']});
    let stdout='',stderr='';child.stdout.on('data',chunk=>stdout+=chunk);child.stderr.on('data',chunk=>stderr+=chunk);
    const timer=setTimeout(()=>child.kill('SIGKILL'),timeout);
    child.on('error',error=>{clearTimeout(timer);reject(error);});
    child.on('close',(code,signal)=>{clearTimeout(timer);resolve({code,signal,stdout,stderr});});
  });
}
test('core: replay deadline keeps a standalone CLI alive until fixed rejection',async()=>{
  const result=await probe({replayTimeoutMs:40},3000);
  assert.equal(result.code,0,result.stderr);assert.equal(result.signal,null);assert.equal(result.stdout.trim(),'BOUNDED_REPLAY_REJECTION');
});
test('core: omitted replay deadline bounds a hanging claim at the 10 second default',async()=>{
  const before=performance.now();
  const result=await probe({},process.env.APPGUARD_REPLAY_RED==='1'?3000:13000);
  assert.equal(result.code,0,result.stderr);assert.equal(result.signal,null);assert.equal(result.stdout.trim(),'BOUNDED_REPLAY_REJECTION');
  assert.ok(performance.now()-before>=9500,'default must preserve the documented 10 second budget');
});
test('core: settled replay claim clears its long deadline timer',async()=>{
  const result=await probe({replayTimeoutMs:2147483647},3000,true);
  assert.equal(result.code,0,result.stderr);assert.equal(result.signal,null);assert.equal(result.stdout.trim(),'VERIFIED');
});
