const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createClient, AppGuardError } = require('../build/client.js');
const common = { alias: 'install', hardwareRequirement: 'any' };
const request = { ...common, origin:'https://api.example', method:'POST', target:'/v0/a%2Fb?', body:new Uint8Array([0,255,128,13,10]), contentType:'application/octet-stream', authorization:'Bearer SECRET', appId:'app', keyId:'key', created:1, expires:2, nonce:'AAAAAAAAAAAAAAAAAAAAAA' };
const prepared = { origin:request.origin, method:request.method,target:request.target, bodyBase64:'AP+ADQo=',keyId:'key',headers:[['Authorization','Bearer SECRET'],['X-AppGuard','x']] };
const ok = result => JSON.stringify({ok:true,result});
const rejectsCode = (fn, code) => assert.rejects(fn, e => e instanceof AppGuardError && e.code === code && e.message === code && !e.stack.includes('NATIVE_SECRET'));
test('prepare preserves binary body, exact empty query, authorization and ordered headers', async () => {
 let observed;
 const client=createClient(() => ({invoke:async (operation,payload)=>{observed={operation,payload:JSON.parse(payload)};return ok(prepared);}}));
 assert.deepEqual(await client.prepare(request),prepared);
 assert.equal(observed.operation,'prepare');
 const { body, ...fields }=request;
 assert.deepEqual(observed.payload,{...fields,bodyBase64:'AP+ADQo='});
});
test('publicKey forwards the two common fields', async()=>{
 const result={publicKeyPem:'PUBLIC PEM',backing:'android-keystore'};
 const c=createClient(()=>({invoke:async(op,payload)=>{assert.equal(op,'publicKey');assert.deepEqual(JSON.parse(payload),common);return ok(result);}}));
 assert.deepEqual(await c.publicKey(common),result);
});
test('enrollmentProof preserves challenge and explicit expected identity',async()=>{
 const input={...common,challenge:{appId:'app',origin:'https://api.example',subject:'user',keyId:'key',publicKeySha256:'hash',nonce:'nonce',expires:2},expectedAppId:'app',expectedOrigin:'https://api.example',expectedSubject:'user',expectedKeyId:'key'};
 const result={proofBase64:'AA==',clientDataHashBase64:'AA==',googleRequestHash:'hash'};
 const c=createClient(()=>({invoke:async(op,payload)=>{assert.equal(op,'enrollmentProof');assert.deepEqual(JSON.parse(payload),input);return ok(result);}}));
 assert.deepEqual(await c.enrollmentProof(input),result);
});
test('native module missing and loader exceptions are fixed unavailable errors',async()=>{
 await rejectsCode(()=>createClient(()=>null).publicKey(common),'APPGUARD_NATIVE_UNAVAILABLE');
 await rejectsCode(()=>createClient(()=>{throw Error('NATIVE_SECRET')}).publicKey(common),'APPGUARD_NATIVE_UNAVAILABLE');
});
test('native throw text and unknown native codes are redacted',async()=>{
 await rejectsCode(()=>createClient(()=>({invoke:async()=>{throw Error('NATIVE_SECRET')}})).publicKey(common),'APPGUARD_OPERATION_FAILED');
 await rejectsCode(()=>createClient(()=>({invoke:async()=>JSON.stringify({ok:false,error:{code:'NATIVE_SECRET'}})})).publicKey(common),'APPGUARD_OPERATION_FAILED');
});
for (const code of ['APPGUARD_INVALID_INPUT','APPGUARD_KEY_UNAVAILABLE','APPGUARD_UNSUPPORTED','APPGUARD_OPERATION_FAILED']) test(`fixed native code ${code}`,async()=>{
 await rejectsCode(()=>createClient(()=>({invoke:async()=>JSON.stringify({ok:false,error:{code,message:'NATIVE_SECRET'}})})).publicKey(common),code);
});
test('malformed, oversized and wrong-shape native responses reject safely',async()=>{
 for(const response of ['NATIVE_SECRET','x'.repeat(1500001),ok({publicKeyPem:5,backing:'x'}),JSON.stringify({ok:'yes',result:{}}),ok({publicKeyPem:'x',backing:'y',privateKey:'NATIVE_SECRET'})]) {
 await rejectsCode(()=>createClient(()=>({invoke:async()=>response})).publicKey(common),'APPGUARD_OPERATION_FAILED');
 }
});
test('oversized bytes and serialized input reject before native invocation',async()=>{
 let calls=0;const c=createClient(()=>({invoke:async()=>{calls++;return ok(prepared)}}));
 await rejectsCode(()=>c.prepare({...request,body:new Uint8Array(1048577)}),'APPGUARD_INVALID_INPUT');
 await rejectsCode(()=>c.publicKey({...common,alias:'🌼'.repeat(400000)}),'APPGUARD_INVALID_INPUT');
 assert.equal(calls,0);
});
test('empty body and all 256 byte values encode canonically without text conversion',async()=>{
 for(const body of [new Uint8Array(),Uint8Array.from({length:256},(_,i)=>i)]) {
 const base64=Buffer.from(body).toString('base64');
 const c=createClient(()=>({invoke:async(_,payload)=>{assert.equal(JSON.parse(payload).bodyBase64,base64);return ok({...prepared,bodyBase64:base64})}}));
 assert.equal((await c.prepare({...request,body})).bodyBase64,base64);
 }
});
test('invalid ordered header response is rejected',async()=>{
 await rejectsCode(()=>createClient(()=>({invoke:async()=>ok({...prepared,headers:{Authorization:'secret'}})})).prepare(request),'APPGUARD_OPERATION_FAILED');
});
test('maximum binary body round trips within the JSON bound',async()=>{
 const body=new Uint8Array(1048576);const bodyBase64=Buffer.from(body).toString('base64');
 const c=createClient(()=>({invoke:async(_,payload)=>{assert.equal(JSON.parse(payload).bodyBase64,bodyBase64);return ok({...prepared,bodyBase64});}}));
 assert.equal((await c.prepare({...request,body})).bodyBase64,bodyBase64);
});
test('noncanonical and oversized response body base64 reject with fixed errors',async()=>{
 for(const bodyBase64 of ['AB==','AAF=','!AAA','AAA','AA==\n',Buffer.alloc(1048577).toString('base64')]) {
  await rejectsCode(()=>createClient(()=>({invoke:async()=>ok({...prepared,bodyBase64})})).prepare(request),'APPGUARD_OPERATION_FAILED');
 }
});
