const {test}=require('node:test');
const assert=require('node:assert/strict');
const {createClient,AppGuardError}=require('../build/client.js');
const vectors=require('../../../conformance/v0/local-risk-bridge.json').reports;
const report=vectors[0].report,ok=result=>JSON.stringify({ok:true,result});
const reject=(fn,code)=>assert.rejects(fn,e=>e instanceof AppGuardError&&e.code===code&&e.message===code&&!JSON.stringify(e).includes('PRIVATE'));
for(const v of vectors) test(`risk conformance ${v.id}`,async()=>{const c=createClient(()=>({invoke:async()=>ok(v.report)}));if(v.valid) assert.deepEqual(await c.scanLocalRisk(),v.report);else await reject(()=>c.scanLocalRisk(),'APPGUARD_OPERATION_FAILED');});
test('risk defaults, mapping, synchronous snapshot and immutable result',async()=>{
 let release,seen;const gate=new Promise(r=>release=r),c=createClient(()=>({invoke:async(op,payload)=>{assert.equal(op,'scanLocalRisk');seen=JSON.parse(payload);await gate;return ok(report)}}));
 const options={expectedAppId:'co.example.app',androidSignerSha256:['a'.repeat(64)],protectedResources:{'assets/pin.json':'b'.repeat(64)}};
 const pending=c.scanLocalRisk(options);options.expectedAppId='changed';options.androidSignerSha256.push('c'.repeat(64));options.protectedResources['assets/pin.json']='c'.repeat(64);
 assert.deepEqual(seen,{expectedAppId:'co.example.app',androidSignerSha256:['a'.repeat(64)],protectedResources:{'assets/pin.json':'b'.repeat(64)}});release();const value=await pending;
 for(const v of [value,value.checks,value.checks[0],value.riskSignals]) assert(Object.isFrozen(v));assert.notEqual(value,report);
 let payload;await createClient(()=>({invoke:async(_,p)=>{payload=p;return ok(report)}})).scanLocalRisk();assert.equal(payload,'{}');
});
test('risk invalid input rejected before native lookup',async()=>{
 let calls=0;const c=createClient(()=>{calls++;return {invoke:async()=>ok(report)}}),pin='a'.repeat(64);
 const values=[null,[],1,'PRIVATE',{unexpected:true},{expectedAppId:null},{expectedAppId:''},{expectedAppId:1},{expectedAppId:'a'.repeat(256)},{expectedAppId:'é'},{expectedAppId:'.app'},{expectedAppId:'a\n'},{androidSignerSha256:null},{androidSignerSha256:{}},{androidSignerSha256:[null]},{androidSignerSha256:[pin,pin]},{androidSignerSha256:['A'.repeat(64)]},{androidSignerSha256:Array.from({length:9},(_,i)=>String(i).repeat(64))},{protectedResources:null},{protectedResources:[]},{protectedResources:{'../a':pin}},{protectedResources:{'/a':pin}},{protectedResources:{'a//b':pin}},{protectedResources:{'a\\b':pin}},{protectedResources:{'.hidden':pin}},{protectedResources:{['a'.repeat(129)]:pin}},{protectedResources:{a:null}},{protectedResources:{a:'PRIVATE'}},{protectedResources:Object.fromEntries(Array.from({length:9},(_,i)=>['a'+i,pin]))},{toJSON(){return {}}},Object.defineProperty({},'expectedAppId',{enumerable:true,get(){throw Error('PRIVATE')}})];
 for(const value of values) await reject(()=>c.scanLocalRisk(value),'APPGUARD_INVALID_INPUT');assert.equal(calls,0);
});
test('risk maximum valid config',async()=>{const pin='a'.repeat(64);await createClient(()=>({invoke:async()=>ok(report)})).scanLocalRisk({expectedAppId:'a'.repeat(255),androidSignerSha256:Array.from({length:8},(_,i)=>String(i).repeat(64)),protectedResources:Object.fromEntries(Array.from({length:8},(_,i)=>[`${i}${'a'.repeat(127)}/${'b'.repeat(127)}`,pin]))});});
test('risk fixed errors and exact 4096 UTF8 envelope limit',async()=>{
 await reject(()=>createClient(()=>null).scanLocalRisk(),'APPGUARD_NATIVE_UNAVAILABLE');await reject(()=>createClient(()=>{throw Error('PRIVATE')}).scanLocalRisk(),'APPGUARD_NATIVE_UNAVAILABLE');
 for(const code of ['APPGUARD_UNSUPPORTED','APPGUARD_NATIVE_UNAVAILABLE','APPGUARD_INVALID_INPUT','APPGUARD_OPERATION_FAILED']) await reject(()=>createClient(()=>({invoke:async()=>JSON.stringify({ok:false,error:{code,message:'PRIVATE'}})})).scanLocalRisk(),code);
 await reject(()=>createClient(()=>({invoke:async()=>{throw Error('PRIVATE')}})).scanLocalRisk(),'APPGUARD_OPERATION_FAILED');
 const base=ok(report),exact=base+' '.repeat(4096-Buffer.byteLength(base));assert.deepEqual(await createClient(()=>({invoke:async()=>exact})).scanLocalRisk(),report);
 for(const response of [exact+' ',base+'🌼'.repeat(1024),'PRIVATE',ok(null),JSON.stringify({ok:true,result:report,extra:'PRIVATE'})]) await reject(()=>createClient(()=>({invoke:async()=>response})).scanLocalRisk(),'APPGUARD_OPERATION_FAILED');
});

test('risk ignores caller array iterators and rejects sparse pins',async()=>{
 const pins=['a'.repeat(64)];pins[Symbol.iterator]=function*(){yield 'PRIVATE'};
 await createClient(()=>({invoke:async(_,p)=>{assert.deepEqual(JSON.parse(p).androidSignerSha256,['a'.repeat(64)]);return ok(report)}})).scanLocalRisk({androidSignerSha256:pins});
 await reject(()=>createClient(()=>{throw Error('must not load')}).scanLocalRisk({androidSignerSha256:new Array(1)}),'APPGUARD_INVALID_INPUT');
});
test('risk error envelope UTF8 bytes are bounded before parsing',async()=>{
 const code='APPGUARD_UNSUPPORTED',base=JSON.stringify({ok:false,error:{code,message:'🌼'.repeat(900)}});
 const exact=base+' '.repeat(4096-Buffer.byteLength(base));
 await reject(()=>createClient(()=>({invoke:async()=>exact})).scanLocalRisk(),code);
 await reject(()=>createClient(()=>({invoke:async()=>exact+' '})).scanLocalRisk(),'APPGUARD_OPERATION_FAILED');
});
