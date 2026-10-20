import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
const root = fileURLToPath(new URL('..', import.meta.url));
const destination = resolve(root, 'artifacts');
mkdirSync(destination, { recursive: true });
const packed = JSON.parse(execFileSync('npm', ['pack', '--ignore-scripts', '--json', '--pack-destination', destination], { cwd: root, encoding: 'utf8' }))[0];
const install = mkdtempSync(join(tmpdir(), 'appguard-node-isolated-'));
try {
writeFileSync(resolve(install, 'package.json'), JSON.stringify({ name:'appguard-isolated-smoke', private:true, type:'module' }));
execFileSync('npm', ['install', '--ignore-scripts', '--no-audit', '--no-fund', '--package-lock=false', resolve(destination, packed.filename)], { cwd: install, stdio: 'pipe' });
const script = `import assert from 'node:assert/strict';
import { generateKeyPairSync, createHash, randomBytes, sign } from 'node:crypto';
import { buildSignatureBase, verifyRequest, InMemoryReplayStore, parseSignatures, serializeParameters, expressMiddleware } from '@appguard/server';
const p={created:1700000000,expires:1700000120,nonce:randomBytes(16).toString('base64url'),key_id:'key',algorithm:'ecdsa-p256-sha256',tag:'appguard-request-v0'};
const body=Buffer.from('{}');
const req={method:'POST',target:'/v1?b=2&a=1',body,headers:[['Content-Type','application/json'],['Content-Digest','sha-256=:'+createHash('sha256').update(body).digest('base64')+':'],['Authorization','Bearer test'],['AppGuard-App-Id','app']]};
const {privateKey,publicKey}=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
const signature=sign('sha256',buildSignatureBase(req,p,{origin:'https://api.example.test'}),{key:privateKey,dsaEncoding:'ieee-p1363'});
const wire=parseSignatures([...req.headers,['Signature-Input','appguard='+serializeParameters(p)],['Signature','appguard=:'+signature.toString('base64')+':']]);
const key={app_id:'app',key_id:'key',subject:'user',algorithm:p.algorithm,revoked:false,public_key_pem:publicKey.export({type:'spki',format:'pem'})};
assert.equal((await verifyRequest(req,wire.parameters,wire.signature,{origin:'https://api.example.test',app_id:'app',subject:'user',key,now:p.created,replay:new InMemoryReplayStore()})).code,'VERIFIED');
assert.equal(typeof expressMiddleware({app_id:'app',origin:'https://api.example.test',replay:new InMemoryReplayStore(),identityResolver:()=>({subject:'user',key})}),'function');
console.log('Isolated packed ESM import, native signature, parser, replay and middleware factory passed');`;
writeFileSync(resolve(install, 'smoke.mjs'), script);
const output = execFileSync(process.execPath, ['smoke.mjs'], { cwd: install, encoding:'utf8' });
assert.match(output, /passed/); process.stdout.write(output);
process.stdout.write(`Packed ${packed.files.length} files: ${packed.filename}\n`);

} finally { rmSync(install, { recursive:true, force:true }); }
