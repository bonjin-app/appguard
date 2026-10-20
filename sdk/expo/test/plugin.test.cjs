const {test}=require('node:test');
const assert=require('node:assert/strict');
const plugin=require('../app.plugin.cjs');
async function apply(gradle=[],pod={}) {
 const c=plugin({name:'fixture',slug:'fixture'});
 const android=await c.mods.android.gradleProperties({...c,modResults:gradle,modRequest:{}});
 const ios=await c.mods.ios.podfileProperties({...c,modResults:pod,modRequest:{}});
 return {gradle:android.modResults,pod:ios.modResults};
}
test('plugin supplies supported OS minimums',async()=>{
 const c=await apply();
 assert.deepEqual(c.gradle,[{type:'property',key:'android.minSdkVersion',value:'26'}]);
 assert.equal(c.pod['ios.deploymentTarget'],'16.4');
});
test('plugin preserves higher targets and unrelated properties',async()=>{
 const gradle=[{type:'comment',value:'keep'},{type:'property',key:'android.minSdkVersion',value:'30'},{type:'property',key:'other',value:'yes'}];
 const pod={'ios.deploymentTarget':'17.2',unrelated:'yes'};
 assert.deepEqual(await apply(gradle,pod),{gradle,pod});
});
test('plugin raises lower targets and remains idempotent',async()=>{
 const a=await apply([{type:'property',key:'android.minSdkVersion',value:'21'}],{'ios.deploymentTarget':'15.0'});
 const b=await apply(a.gradle,a.pod);
 assert.deepEqual(b,a);assert.equal(a.gradle[0].value,'26');assert.equal(a.pod['ios.deploymentTarget'],'16.4');
});
test('plugin rejects malformed configured targets',async()=>{
 await assert.rejects(()=>apply([{type:'property',key:'android.minSdkVersion',value:'unknown'}]),/APPGUARD_INVALID_MIN_SDK/);
 await assert.rejects(()=>apply([],{'ios.deploymentTarget':'unknown'}),/APPGUARD_INVALID_IOS_TARGET/);
});
test('plugin cannot leave a later duplicate Android minimum below the required level',async()=>{
 const c=await apply([{type:'property',key:'android.minSdkVersion',value:'30'},{type:'property',key:'android.minSdkVersion',value:'21'}]);
 assert.deepEqual(c.gradle.map(p=>p.value),['30','30']);
});
