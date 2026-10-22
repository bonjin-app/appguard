import 'reflect-metadata';
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { performance } from 'node:perf_hooks';
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import express from 'express';
import Fastify from 'fastify';
import { NestFactory } from '@nestjs/core';
import { Module, Controller, Post, Req } from '@nestjs/common';
import { expressMiddleware, nestMiddleware, installFastify, buildSignatureBase, serializeParameters, InMemoryReplayStore } from '../src/index.js';

const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve:'prime256v1' });
const key = { app_id:'body-app', key_id:'body-key', subject:'body-user', algorithm:'ecdsa-p256-sha256', revoked:false,
  public_key_pem:publicKey.export({type:'spki',format:'pem'}) };
const now = 1700000000;
const budget = 10000;
const bodyEvents = ['data','end','error','aborted','close'];
const turn = () => new Promise(resolve => setImmediate(resolve));
function signed() {
  const body = Buffer.from([0,1,2,128,255,0,...Buffer.from('deadline 世界')]);
  const target = '/body?x=%2f&x=%2F&empty';
  const parameters = {created:now,expires:now+120,nonce:randomBytes(16).toString('base64url'),key_id:key.key_id,
    algorithm:key.algorithm,tag:'appguard-request-v0'};
  const headers = [['Content-Type','application/octet-stream'],
    ['Content-Digest',`sha-256=:${createHash('sha256').update(body).digest('base64')}:`],
    ['Authorization','Bearer TEST_ONLY_BODY_TOKEN'],['AppGuard-App-Id',key.app_id]];
  const base = buildSignatureBase({method:'POST',target,headers,body},parameters,{origin:'https://api.example.test'});
  return {body,target,headers:[...headers,['Signature-Input',`appguard=${serializeParameters(parameters)}`],
    ['Signature',`appguard=:${sign('sha256',base,{key:privateKey,dsaEncoding:'ieee-p1363'}).toString('base64')}:`]]};
}
async function serve(kind, {probe, bodyTimeoutMs=budget} = {}) {
  const counts = {identity:0,key:0,clock:0,replay:0,hooks:0,parsers:0,downstream:0};
  const observations = [];
  const store = new InMemoryReplayStore();
  const options = {app_id:key.app_id,origin:'https://api.example.test',allowInsecureTransport:true,bodyTimeoutMs,
    identityResolver:()=>{counts.identity++;return key.subject;},keyResolver:()=>{counts.key++;return key;},
    clock:()=>{counts.clock++;return now;},replay:{claim(...args){counts.replay++;return store.claim(...args);}}};
  const done = req => {
    counts.downstream++;
    return {code:req.appguard.code,raw:req.appguardRawBody.toString('base64'),parsed:req.body.toString('base64'),target:req.appguardTarget};
  };
  let server, close;
  if (kind === 'fastify') {
    const app = Fastify({logger:false,forceCloseConnections:true,bodyLimit:2*1048576});
    installFastify(app,options);
    app.addHook('onRequest',async()=>{counts.hooks++;});
    app.addContentTypeParser('application/octet-stream',{parseAs:'buffer'},(req,body,done)=>{counts.parsers++;done(null,body);});
    app.post('/body',req=>done(req));
    await app.ready(); server=app.server; close=()=>app.close();
  } else if (kind === 'nest') {
    class Endpoint { run(req) { return done(req); } }
    Controller('/body')(Endpoint); Post()(Endpoint.prototype,'run',Object.getOwnPropertyDescriptor(Endpoint.prototype,'run'));
    Req()(Endpoint.prototype,'run',0);
    class App {}
    Module({controllers:[Endpoint]})(App);
    const app = await NestFactory.create(App,{logger:false,bodyParser:false});
    app.use(nestMiddleware(options)); app.use((req,res,next)=>{counts.parsers++;next();});
    app.use(express.raw({type:()=>true,limit:'2mb'}));
    await app.init(); server=app.getHttpServer(); close=()=>app.close();
  } else {
    const app = express(); app.use(expressMiddleware(options));
    app.use((req,res,next)=>{counts.parsers++;next();}); app.use(express.raw({type:()=>true,limit:'2mb'}));
    app.use((req,res)=>res.json(done(req)));
    server=http.createServer(app); close=()=>new Promise(resolve=>server.close(resolve));
  }
  // Observe and wrap native dispatch without adding a body consumer before the guard.
  server.prependListener('request',req=>{
    const observation={req,listeners:Object.fromEntries(bodyEvents.map(event=>[event,req.listenerCount(event)]))};
    observations.push(observation);
    const captureStarted=event=>{
      if(event!=='data')return;
      observation.captureEnd=req.listeners('end').at(-1);
      req.removeListener('newListener',captureStarted);
    };
    req.on('newListener',captureStarted);
    probe?.watch(req);
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  return {port:server.address().port,counts,observations,async close(){server.closeAllConnections();await close();}};
}
function start(server, request, {body=request.body,incomplete=false,chunked=false} = {}) {
  let client;
  const result = new Promise((resolve,reject)=>{
    client=http.request({host:'127.0.0.1',port:server.port,path:request.target,method:'POST',agent:false,
      headers:[...request.headers,['Host','localhost'],chunked?['Transfer-Encoding','chunked']:['Content-Length',String(body.length)]].flat()},res=>{
      const chunks=[];res.on('data',chunk=>chunks.push(chunk));res.on('end',()=>{
        try { resolve({status:res.statusCode,body:JSON.parse(Buffer.concat(chunks).toString())}); }
        catch(error) { reject(error); }
      });
    });
    client.setTimeout(3000,()=>client.destroy(new Error('HARNESS_TIMEOUT: body deadline did not settle')));
    client.on('error',reject);
    if(incomplete)client.write(body.subarray(0,1));else client.end(body);
  });
  const observed=result.then(value=>({value}),error=>({error}));
  return {client,result,observed};
}
function monotonicProbe(request, phase, elapsed) {
  const nowDescriptor=Object.getOwnPropertyDescriptor(performance,'now');
  const originalNow=performance.now;
  const originalConcat=Buffer.concat;
  const requests=[];
  let time=1000, reached=0, copies=0, reachedAt;
  const advance=()=>{reached++;reachedAt=time;time+=elapsed;};
  Object.defineProperty(performance,'now',{configurable:true,value:()=>time});
  Buffer.concat=function(chunks,length) {
    const result=Reflect.apply(originalConcat,this,[chunks,length]);
    if(copies===0 && length===request.body.length && result.equals(request.body)) {
      copies++;
      if(phase==='copy')advance();
      if(phase==='handoff')queueMicrotask(advance);
      if(phase==='framing') {
        const nativeLength=result.length;
        let read=false;
        // Return the genuine copied bytes and length; only the clock's progress is synthetic.
        Object.defineProperty(result,'length',{configurable:true,get(){if(!read){read=true;advance();}return nativeLength;}});
      }
    }
    return result;
  };
  return {
    watch(req) {
      const descriptor=Object.getOwnPropertyDescriptor(req,'emit'),emit=req.emit;
      requests.push({req,descriptor});
      let data=false,end=false,bytes=0;
      req.emit=function(event,...args) {
        if(event==='data') {
          bytes+=args[0].length;
          if(!data){data=true;if(phase==='data')advance();}
          if(phase==='limit'&&bytes>1048576&&reached===0)advance();
        }
        if(event==='end'&&!end){end=true;if(phase==='end')advance();}
        return Reflect.apply(emit,this,[event,...args]);
      };
    },
    assertReached(expectedCopies) {
      assert.equal(reached,1,`the ${phase} boundary must actually run`);
      assert.equal(reachedAt,1000,`the ${phase} probe must start before the body deadline`);
      assert.equal(copies,expectedCopies,'the real final body copy must run only when capture reaches it');
    },
    restore() {
      Buffer.concat=originalConcat;
      if(nowDescriptor)Object.defineProperty(performance,'now',nowDescriptor);else {delete performance.now;assert.equal(performance.now,originalNow);}
      for(const {req,descriptor} of requests){if(descriptor)Object.defineProperty(req,'emit',descriptor);else delete req.emit;}
    },
  };
}
function stopped(server) {
  assert.deepEqual(server.counts,{identity:0,key:0,clock:0,replay:0,hooks:0,parsers:0,downstream:0});
}
async function cleaned(server) {
  await turn();
  for(const {req,listeners,captureEnd} of server.observations) {
    // Node adds its own end listener after request dispatch; check the SDK-owned one directly.
    assert.equal(typeof captureEnd,'function','the body capture end listener must be observed');
    assert.equal(req.listeners('end').includes(captureEnd),false,'body capture end listener must be cleaned');
    for(const event of bodyEvents.filter(event=>event!=='end'))assert.ok(req.listenerCount(event)<=listeners[event],`body ${event} listeners must be cleaned`);
  }
}
function verified(kind,response,request,server) {
  assert.deepEqual(response,{status:kind==='nest'?201:200,body:{code:'VERIFIED',raw:request.body.toString('base64'),
    parsed:request.body.toString('base64'),target:request.target}});
  assert.deepEqual(server.counts,{identity:1,key:1,clock:1,replay:1,hooks:kind==='fastify'?1:0,parsers:1,downstream:1});
}
for(const kind of ['express','fastify','nest']) {
  for(const phase of ['data','end','copy','handoff','framing']) {
    // Removing a deadline gate at this boundary must allow a signed expired request through.
    test(`${kind}: body deadline at ${phase} rejects before any trusted callbacks`,async()=>{
      const request=signed(),probe=monotonicProbe(request,phase,budget);
      let server;
      try {
        server=await serve(kind,{probe});
        const response=await start(server,request).result;
        assert.deepEqual(response,{status:400,body:{code:'INVALID_REQUEST'}});
        probe.assertReached(['data','end'].includes(phase)?0:1);
        stopped(server);await cleaned(server);
      } finally {probe.restore();if(server)await server.close();}
    });
    test(`${kind}: body just inside ${phase} deadline preserves signed binary bytes`,async()=>{
      const request=signed(),probe=monotonicProbe(request,phase,budget-1);
      let server;
      try {
        server=await serve(kind,{probe});
        const response=await start(server,request).result;
        probe.assertReached(1);verified(kind,response,request,server);
      } finally {probe.restore();if(server)await server.close();}
    });
  }
  test(`${kind}: final body copy beyond the deadline cannot authenticate`,async()=>{
    const request=signed(),probe=monotonicProbe(request,'copy',budget+1);
    let server;
    try {
      server=await serve(kind,{probe});const response=await start(server,request).result;
      probe.assertReached(1);assert.deepEqual(response,{status:400,body:{code:'INVALID_REQUEST'}});
      stopped(server);await cleaned(server);
    } finally {probe.restore();if(server)await server.close();}
  });
  for(const expired of [false,true]) {
    test(`${kind}: ${expired?'expired':'unexpired'} oversized chunked body returns ${expired?400:413}`,async()=>{
      const request=signed(),probe=monotonicProbe(request,'limit',expired?budget:0);
      let server;
      try {
        server=await serve(kind,{probe});
        const response=await start(server,request,{body:Buffer.alloc(1048577),chunked:true}).result;
        probe.assertReached(0);assert.deepEqual(response,{status:expired?400:413,body:{code:'INVALID_REQUEST'}});
        stopped(server);await cleaned(server);
      } finally {probe.restore();if(server)await server.close();}
    });
  }
  test(`${kind}: incomplete body timer rejects and cleans capture before authentication`,async()=>{
    const request=signed(),server=await serve(kind,{bodyTimeoutMs:50});
    const pending=start(server,request,{incomplete:true});
    try {
      assert.deepEqual(await pending.result,{status:400,body:{code:'INVALID_REQUEST'}});
      stopped(server);await cleaned(server);
    } finally {pending.client.destroy();await pending.observed;await server.close();}
  });
  test(`${kind}: expired body does not reuse its deadline for the next request`,async()=>{
    const first=signed(),probe=monotonicProbe(first,'copy',budget);
    let server;
    try {
      server=await serve(kind,{probe});
      assert.deepEqual(await start(server,first).result,{status:400,body:{code:'INVALID_REQUEST'}});
      probe.assertReached(1);stopped(server);await cleaned(server);
      // The next request starts after the first deadline and receives its own full budget.
      const second=signed();verified(kind,await start(server,second).result,second,server);
    } finally {probe.restore();if(server)await server.close();}
  });
}
