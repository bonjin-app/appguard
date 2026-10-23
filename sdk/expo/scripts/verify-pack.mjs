import { execFileSync } from 'node:child_process';
import { readFileSync, mkdtempSync, mkdirSync, rmSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
// Run guarded staging/build exactly once, including for direct invocation of this file.
execFileSync('npm',['run','prepack'],{cwd:root,stdio:['ignore','inherit','inherit']});
const pack = JSON.parse(execFileSync('npm',['pack','--ignore-scripts','--json'],{cwd:root,encoding:'utf8',stdio:['ignore','pipe','inherit']}))[0];
mkdirSync(path.join(root,'.tools'),{recursive:true});
const scratch = mkdtempSync(path.join(root,'.tools/relocated-'));
try {
  execFileSync('tar',['-xzf',path.join(root,pack.filename),'-C',scratch]);
  const pkg = path.join(scratch,'package');
  const metadata=JSON.parse(readFileSync(path.join(pkg,'package.json')));
  assert.equal(metadata.license,'Apache-2.0');
  assert.equal(metadata.private,true);
  assert.match(readFileSync(path.join(pkg,'LICENSE'),'utf8'),/Apache License/);
  const names = pack.files.map(file=>file.path);
  for (const name of ['build/index.js','build/client.js','build/index.d.ts','app.plugin.cjs','AppGuardApple.podspec','ios/AppGuardExpo.podspec','expo-module.config.json','PROVENANCE.json','vendor/android/LICENSE','vendor/apple/LICENSE']) assert.ok(names.includes(name),name);
  assert.ok(!names.some(n=>/^(node_modules|\.tools|\.evidence|example|test)\//.test(n) || /^(ios|android)\/(build|\.gradle)\//.test(n)));
  assert.ok(!names.some(n=>/\.web\./.test(n)));
  assert.ok(names.includes('vendor/apple/Sources/AppGuardApple/Resources/PrivacyInfo.xcprivacy'));
  for (const [name,hash] of Object.entries(JSON.parse(readFileSync(path.join(pkg,'PROVENANCE.json'))).files)) {
    assert.ok(!name.includes('..'));
    assert.equal(createHash('sha256').update(readFileSync(path.join(pkg,name))).digest('hex'),hash);
  }
  const module=JSON.parse(readFileSync(path.join(pkg,'expo-module.config.json')));
  for(const name of module.apple.podspecPath) assert.ok(existsSync(path.join(pkg,name)));
  // Execute the actual built client from the relocated tar, without repository imports.
  const {createClient}=await import(path.join(pkg,'build/client.js'));
  const result=await createClient(()=>({invoke:async(operation,payload)=>{
    assert.equal(operation,'publicKey');assert.deepEqual(JSON.parse(payload),{alias:'install',hardwareRequirement:'any'});
    return JSON.stringify({ok:true,result:{publicKeyPem:'public',backing:'keychain'}});
  }})).publicKey({alias:'install',hardwareRequirement:'any'});
  assert.equal(result.publicKeyPem,'public');
  const report={schema:'appguard-local-risk-v0',platform:'ios',checks:[
    {code:'debugger_attached',state:'unavailable'},
    {code:'root_artifact',state:'unavailable'},
    {code:'hook_artifact',state:'unavailable'},
    {code:'app_identity_mismatch',state:'not_configured'},
    {code:'bundle_resource_mismatch',state:'not_configured'},
  ],riskSignals:['local_checks_unavailable']};
  const risk=await createClient(()=>({invoke:async(operation,payload)=>{
    assert.equal(operation,'scanLocalRisk'); assert.equal(payload,'{}');
    return JSON.stringify({ok:true,result:report});
  }})).scanLocalRisk();
  assert.deepEqual(risk,report); assert.ok(Object.isFrozen(risk.checks[0]));
  assert.match(readFileSync(path.join(pkg,'build/index.d.ts'),'utf8'),/scanLocalRisk/);
  assert.match(readFileSync(path.join(pkg,'build/client.d.ts'),'utf8'),/LocalRiskReport/);
  console.log(`Packed/relocated client verified: ${pack.files.length} files; ${pack.shasum}`);
} finally { rmSync(scratch,{recursive:true,force:true}); }
