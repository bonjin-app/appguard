const {test}=require('node:test');
const assert=require('node:assert/strict');
const Module=require('node:module');
test('public package binds Expo AppGuard native module and fails explicitly when absent',async()=>{
 const original=Module._load;let module=null;
 Module._load=function(name,...rest){
  if(name==='expo') return {requireOptionalNativeModule:n=>{assert.equal(n,'AppGuard');return module;}};
  return original.call(this,name,...rest);
 };
 try {
  const api=require('../build/index.js');
  await assert.rejects(()=>api.publicKey({alias:'i',hardwareRequirement:'any'}),e=>e.code==='APPGUARD_NATIVE_UNAVAILABLE');
  module={invoke:async(op,payload)=>{
   assert.equal(op,'publicKey');assert.deepEqual(JSON.parse(payload),{alias:'i',hardwareRequirement:'any'});
   return JSON.stringify({ok:true,result:{publicKeyPem:'public',backing:'keychain'}});
  }};
  assert.deepEqual(await api.publicKey({alias:'i',hardwareRequirement:'any'}),{publicKeyPem:'public',backing:'keychain'});
  assert.equal(typeof api.prepare,'function');assert.equal(typeof api.enrollmentProof,'function');
 } finally {Module._load=original;}
});
