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
import { expressMiddleware, nestMiddleware, installFastify } from '../src/index.js';

const vector=JSON.parse(readFileSync(new URL('../../../conformance/v0/requests.json',import.meta.url)))[0];
const path=vector.request.target.split('?')[0];
const headers=[...vector.request.headers,
  ['Signature-Input','appguard='+vector.expected_signature_base.split('"@signature-params": ')[1]],
  ['Signature','appguard=:'+vector.signature_b64+':']];
function deferred(){let resolve,reject;const promise=new Promise((yes,no)=>{resolve=yes;reject=no;});return {promise,resolve,reject};}
const turn=()=>new Promise(resolve=>setImmediate(resolve));
async function drain(){for(let n=0;n<8;n++)await turn();}
async function bounded(promise){let timer;try{return await Promise.race([promise,new Promise((_,reject)=>{
  timer=setTimeout(()=>reject(new Error('HARNESS_TIMEOUT: disconnect lifecycle did not settle')),3000);
})]);}finally{clearTimeout(timer);}}
async function serve(kind,extra={}){
  const counts={identity:0,key:0,replay:0,hooks:0,parsers:0,downstream:0};
  const observations=[];
  const identity=extra.identityResolver??(async()=>vector.context.subject);
  const key=extra.keyResolver??(async()=>vector.key);
  const claim=extra.claim??(async()=>true);
  const options={app_id:vector.context.app_id,origin:vector.context.origin,clock:()=>vector.context.now,
    allowInsecureTransport:true,identityTimeoutMs:10000,replayTimeoutMs:10000,...extra,
    identityResolver:(context)=>{counts.identity++;return identity(context);},
    keyResolver:(context)=>{counts.key++;return key(context);},
    replay:{claim(...args){counts.replay++;return claim(...args);}}};
  const done=()=>{counts.downstream++;return {code:'VERIFIED'};};
  let server,close;
  if(kind==='fastify'){
    const app=Fastify({logger:false,forceCloseConnections:true});installFastify(app,options);
    app.addHook('onRequest',async()=>{counts.hooks++;if(extra.afterGuardHook)await extra.afterGuardHook();});
    app.addHook('preParsing',async(req,reply,payload)=>{counts.parsers++;return payload;});
    app.post(path,done);await app.ready();server=app.server;close=()=>app.close();
  }else if(kind==='nest'){
    class Endpoint{run(){return done();}}
    Controller(path)(Endpoint);Post()(Endpoint.prototype,'run',Object.getOwnPropertyDescriptor(Endpoint.prototype,'run'));
    class App{}Module({controllers:[Endpoint]})(App);
    const app=await NestFactory.create(App,{logger:false,bodyParser:false});
    app.use(nestMiddleware(options));app.use((req,res,next)=>{counts.parsers++;next();});
    await app.init();server=app.getHttpServer();close=()=>app.close();
  }else{
    const app=express();app.use(expressMiddleware(options));
    app.use((req,res,next)=>{counts.parsers++;next();});app.use((req,res)=>res.json(done()));
    server=http.createServer(app);close=()=>new Promise(resolve=>server.close(resolve));
  }
  // Native observers do not consume the signed body or change SDK callbacks.
  server.prependListener('request',(req,res)=>{
    const closed=deferred(),bodyClosed=deferred();
    const observation={req,res,closed:closed.promise,bodyClosed:bodyClosed.promise,bodyComplete:false};
    res.once('close',()=>closed.resolve());
    req.once('close',()=>{observation.bodyComplete=req.complete&&req.readableEnded;bodyClosed.resolve();});
    observations.push(observation);
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  return {port:server.address().port,counts,observations,async close(){server.closeAllConnections();await close();}};
}
function start(server,agent=false){
  let req;
  const result=new Promise((resolve,reject)=>{
    req=http.request({host:'127.0.0.1',port:server.port,path:vector.request.target,method:vector.request.method,
      headers:[...headers,['Host','localhost']].flat(),agent},res=>{
      const chunks=[];res.on('data',chunk=>chunks.push(chunk));res.on('end',()=>{
        try{resolve({status:res.statusCode,body:JSON.parse(Buffer.concat(chunks).toString())});}catch(error){reject(error);}
      });
    });
    req.setTimeout(3000,()=>req.destroy(new Error('HARNESS_TIMEOUT: HTTP request did not settle')));
    req.on('error',reject);req.end(Buffer.from(vector.request.body_b64,'base64'));
  });
  // Observe immediately, including intentional client cancellation.
  const observed=result.then(value=>({value}),error=>({error}));
  return {req,result,observed};
}
function assertStopped(server,phase){
  assert.equal(server.counts.identity,1);
  assert.equal(server.counts.key,phase==='identity'?0:1);
  assert.equal(server.counts.replay,phase==='replay'?1:0);
  assert.equal(server.counts.hooks,0);assert.equal(server.counts.parsers,0);assert.equal(server.counts.downstream,0);
}
for(const kind of ['express','fastify','nest']){
  for(const phase of ['identity','key','replay']){
    for(const outcome of ['resolve','reject']){
      test(`${kind}: observed disconnect during ${phase} stops continuation after late ${outcome}`,async()=>{
        const pending=deferred(),started=deferred();
        const callback=()=>{started.resolve();return pending.promise;};
        const extra=phase==='identity'?{identityResolver:callback}:phase==='key'?{keyResolver:callback}:{claim:callback};
        const server=await serve(kind,extra);const client=start(server);
        try{
          await bounded(started.promise);const observation=server.observations[0];
          client.req.destroy();await bounded(observation.closed);await client.observed;
          if(outcome==='reject')pending.reject(new Error('PRIVATE_LATE_CALLBACK_FAILURE'));
          else pending.resolve(phase==='identity'?vector.context.subject:phase==='key'?vector.key:true);
          await drain();assertStopped(server,phase);
        }finally{pending.resolve(phase==='identity'?vector.context.subject:phase==='key'?vector.key:true);await drain();await server.close();}
      });
    }
  }
  test(`${kind}: completed request body with async authentication and keepalive stays healthy`,async()=>{
    const pending=deferred(),started=deferred();let calls=0;
    const server=await serve(kind,{identityResolver:()=>{if(++calls===1){started.resolve();return pending.promise;}return Promise.resolve(vector.context.subject);},
      keyResolver:async()=>{await turn();return vector.key;},claim:async()=>{await turn();return true;}});
    const agent=new http.Agent({keepAlive:true,maxSockets:1});const first=start(server,agent);
    try{
      await bounded(started.promise);const observation=server.observations[0];await bounded(observation.bodyClosed);
      assert.equal(observation.bodyComplete,true);assert.equal(observation.res.destroyed,false);assert.equal(observation.req.socket.destroyed,false);
      pending.resolve(vector.context.subject);
      assert.deepEqual(await first.result,{status:kind==='nest'?201:200,body:{code:'VERIFIED'}});
      const socket=observation.req.socket;assert.deepEqual(await start(server,agent).result,{status:kind==='nest'?201:200,body:{code:'VERIFIED'}});
      assert.equal(server.observations[1].req.socket,socket);assert.equal(server.counts.downstream,2);
    }finally{pending.resolve(vector.context.subject);agent.destroy();await first.observed;await server.close();}
  });
  test(`${kind}: canceling one request does not cancel another`,async()=>{
    const pending=deferred(),started=deferred();let calls=0;
    const server=await serve(kind,{claim:()=>{if(++calls===1){started.resolve();return pending.promise;}return true;}});
    const first=start(server);
    try{
      await bounded(started.promise);first.req.destroy();await bounded(server.observations[0].closed);await first.observed;
      assert.deepEqual(await start(server).result,{status:kind==='nest'?201:200,body:{code:'VERIFIED'}});
      pending.resolve(true);await drain();assert.equal(server.counts.downstream,1);
      assert.equal(server.counts.parsers,1);if(kind==='fastify')assert.equal(server.counts.hooks,1);
    }finally{pending.resolve(true);await drain();await server.close();}
  });
  test(`${kind}: a response ended by the host before SDK dispatch stops continuation`,async()=>{
    let server;
    server=await serve(kind,{identityResolver:()=>{
      server.observations[0].res.end(JSON.stringify({code:'HOST_ENDED'}));return vector.context.subject;
    }});
    try{
      assert.deepEqual(await start(server).result,{status:200,body:{code:'HOST_ENDED'}});
      await bounded(server.observations[0].closed);await drain();assertStopped(server,'identity');
    }finally{await server.close();}
  });
  test(`${kind}: live replay backend rejection keeps the fixed unavailable response`,async()=>{
    const server=await serve(kind,{claim:()=>Promise.reject(new Error('PRIVATE_BACKEND_FAILURE'))});
    try{assert.deepEqual(await start(server).result,{status:503,body:{code:'REPLAY_STORE_UNAVAILABLE'}});assert.equal(server.counts.downstream,0);}
    finally{await server.close();}
  });
}

test('fastify: disconnect during a later onRequest hook stops subsequent parsers and route',async()=>{
  const pending=deferred(),started=deferred();
  const server=await serve('fastify',{afterGuardHook:()=>{started.resolve();return pending.promise;}});
  const client=start(server);
  try{
    await bounded(started.promise);assert.equal(server.counts.hooks,1);
    client.req.destroy();await bounded(server.observations[0].closed);await client.observed;
    pending.resolve();await drain();
    assert.equal(server.counts.identity,1);assert.equal(server.counts.key,1);assert.equal(server.counts.replay,1);
    assert.equal(server.counts.parsers,0);assert.equal(server.counts.downstream,0);
  }finally{pending.resolve();await drain();await server.close();}
});

async function resourceProbe(kind){
  const script=`import 'reflect-metadata';import http from 'node:http';import {readFileSync} from 'node:fs';
    import express from 'express';import Fastify from 'fastify';import {NestFactory} from '@nestjs/core';
    import {Module,Controller,Post} from '@nestjs/common';
    import {expressMiddleware,nestMiddleware,installFastify} from ${JSON.stringify(import.meta.resolve('../src/index.js'))};
    const vector=JSON.parse(readFileSync(new URL(${JSON.stringify(new URL('../../../conformance/v0/requests.json',import.meta.url).href)})))[0];
    const path=vector.request.target.split('?')[0];const headers=${JSON.stringify(headers)};
    ${deferred.toString()} ${bounded.toString()} ${serve.toString()} ${start.toString()}
    const started=deferred();const server=await serve(${JSON.stringify(kind)},{replayTimeoutMs:2147483647,
      claim:()=>{started.resolve();return new Promise(()=>{});}});
    const client=start(server);await bounded(started.promise);client.req.destroy();
    await bounded(server.observations[0].closed);await client.observed;await server.close();
    console.log('DISCONNECTED_SERVER_CLOSED');`;
  return new Promise((resolve,reject)=>{
    const child=spawn(process.execPath,['--unhandled-rejections=strict','--input-type=module','--eval',script],
      {cwd:new URL('.',import.meta.url),stdio:['ignore','pipe','pipe']});
    let stdout='',stderr='';child.stdout.on('data',chunk=>stdout+=chunk);child.stderr.on('data',chunk=>stderr+=chunk);
    const timer=setTimeout(()=>child.kill('SIGKILL'),3000);
    child.on('error',error=>{clearTimeout(timer);reject(error);});
    child.on('close',(code,signal)=>{clearTimeout(timer);resolve({code,signal,stdout,stderr});});
  });
}
for(const kind of ['express','fastify','nest']){
  test(`${kind}: disconnect clears a hanging replay wait so a standalone server process exits`,async()=>{
    const result=await resourceProbe(kind);assert.equal(result.stdout.trim(),'DISCONNECTED_SERVER_CLOSED',result.stderr);
    assert.equal(result.code,0,result.stderr||`child killed by ${result.signal}`);assert.equal(result.signal,null);
  });
}
