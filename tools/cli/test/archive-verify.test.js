import {test} from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {randomBytes,createCipheriv} from 'node:crypto';
import * as vault from '../src/vault.js';

async function fixture(t) {
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'appguard-verify-'));
  t.after(()=>fs.rm(root,{recursive:true,force:true}));
  const source=path.join(root,'source'),keyFile=path.join(root,'key');
  await fs.mkdir(path.join(source,'nested'),{recursive:true,mode:0o700});
  await fs.writeFile(path.join(source,'mapping.txt'),'secret',{mode:0o600});
  await fs.writeFile(path.join(source,'nested/binary.symbol'),Buffer.from([0,255,10,1]),{mode:0o640});
  await fs.writeFile(path.join(source,'empty.symbol'),'',{mode:0o600});
  await fs.mkdir(path.join(root,'project'),{mode:0o700});
  await fs.writeFile(path.join(root,'project/gradlew'),'#!/bin/sh\nprintf executed > execution-marker\n',{mode:0o700});
  await fs.writeFile(keyFile,randomBytes(32),{mode:0o600});
  const retained=await vault.archive({source,vault:path.join(root,'vault'),keyFile,buildId:'verify-001'});
  return {root,keyFile,archiveFile:retained.archiveFile,buildId:'verify-001'};
}

// Reads can update atime. All other relevant bytes, modes, names and times stay unchanged.
async function snapshot(root) {
  const result=[];
  async function visit(relative='') {
    const file=path.join(root,relative),st=await fs.lstat(file);
    result.push({name:relative,mode:st.mode,size:st.size,mtime:st.mtimeMs,ctime:st.ctimeMs,
      ...(st.isFile()?{bytes:(await fs.readFile(file)).toString('hex')}:{})});
    if(st.isDirectory()) for(const name of (await fs.readdir(file)).sort()) await visit(path.join(relative,name));
  }
  await visit();return result;
}

async function authenticated(f,payload) {
  const key=await fs.readFile(f.keyFile),iv=randomBytes(12);
  try {
    const cipher=createCipheriv('aes-256-gcm',key,iv);
    cipher.setAAD(Buffer.from(JSON.stringify(['appguard-vault-v0',f.buildId])));
    const ciphertext=Buffer.concat([cipher.update(JSON.stringify(payload)),cipher.final()]);
    return {schemaVersion:'appguard-vault-v0',buildId:f.buildId,iv:iv.toString('base64'),
      tag:cipher.getAuthTag().toString('base64'),ciphertext:ciphertext.toString('base64')};
  } finally {key.fill(0);}
}

function requireVerifier() {assert.equal(typeof vault.verifyArchive,'function','verifyArchive must be available');}

test('verification returns only authenticated counts including zero-byte files without changing inputs',async t=>{
  requireVerifier();
  const f=await fixture(t),before=await snapshot(f.root);
  assert.deepEqual(await vault.verifyArchive(f),{verified:true,buildId:'verify-001',fileCount:3,plaintextBytes:10});
  assert.deepEqual(await snapshot(f.root),before);
  const restored=await vault.restore({...f,destination:path.join(f.root,'restored')});
  assert.equal(restored.buildId,'verify-001');assert.equal(restored.fileCount,3);assert.equal(restored.plaintextBytes,10);
  assert.deepEqual(await fs.readFile(path.join(f.root,'restored/empty.symbol')),Buffer.alloc(0));
});

test('verification rejects changed authentication fields and wrong keys without writes',async t=>{
  requireVerifier();
  const f=await fixture(t),original=JSON.parse(await fs.readFile(f.archiveFile,'utf8'));
  for(const field of ['buildId','schemaVersion','iv','tag','ciphertext']) await t.test(field,async()=>{
    const envelope={...original};
    envelope[field]=field==='buildId'?'other-valid-build':field==='schemaVersion'?'appguard-vault-v1':
      (envelope[field][0]==='A'?'B':'A')+envelope[field].slice(1);
    await fs.writeFile(f.archiveFile,JSON.stringify(envelope));
    const before=await snapshot(f.root);
    await assert.rejects(vault.verifyArchive(f),{code:'ARCHIVE_REJECTED'});
    assert.deepEqual(await snapshot(f.root),before);
  });
  await t.test('wrong key',async()=>{
    await fs.writeFile(f.archiveFile,JSON.stringify(original));await fs.writeFile(f.keyFile,randomBytes(32));
    const before=await snapshot(f.root);
    await assert.rejects(vault.verifyArchive(f),{code:'ARCHIVE_REJECTED'});
    assert.deepEqual(await snapshot(f.root),before);
  });
});

test('verification and restore reject authenticated malicious manifests before any plaintext write',async t=>{
  requireVerifier();
  const f=await fixture(t),valid={path:'first.symbol',bodyBase64:'AA=='};
  const manifests=[
    ['late traversal',{files:[valid,{path:'../escape',bodyBase64:'AA=='}]}],
    ['absolute path',{files:[valid,{path:'/absolute',bodyBase64:'AA=='}]}],
    ['backslash',{files:[valid,{path:'dir\\escape',bodyBase64:'AA=='}]}],
    ['reserved portable name',{files:[valid,{path:'NUL.txt',bodyBase64:'AA=='}]}],
    ['trailing dot',{files:[valid,{path:'trailing.',bodyBase64:'AA=='}]}],
    ['case collision',{files:[{path:'Mapping',bodyBase64:'AA=='},{path:'mapping',bodyBase64:'AA=='}]}],
    ['unicode collision',{files:[{path:'café',bodyBase64:'AA=='},{path:'cafe\u0301',bodyBase64:'AA=='}]}],
    ['prefix conflict',{files:[{path:'a/child',bodyBase64:'AA=='},{path:'A',bodyBase64:'AA=='}]}],
    ['duplicate path',{files:[valid,valid]}],
    ['noncanonical padding',{files:[valid,{path:'late',bodyBase64:'AA'}]}],
    ['noncanonical trailing bits',{files:[valid,{path:'late',bodyBase64:'AB=='}]}],
    ['extra entry field',{files:[valid,{path:'late',bodyBase64:'AA==',extra:'secret'}]}],
    ['invalid entry type',{files:[valid,null]}],
    ['extra payload field',{files:[valid],extra:'secret'}],
    ['empty files',{files:[]}],
    ['nonarray files',{files:{}}],
    ['too many files',{files:Array.from({length:1001},(_,i)=>({path:`file-${i}`,bodyBase64:''}))}],
  ];
  for(const [name,payload] of manifests) await t.test(name,async()=>{
    await fs.writeFile(f.archiveFile,JSON.stringify(await authenticated(f,payload)));
    const before=await snapshot(f.root),destination=path.join(f.root,'plaintext-output');
    await assert.rejects(vault.verifyArchive(f),{code:'ARCHIVE_REJECTED'});
    await assert.rejects(vault.restore({...f,destination}),{code:'ARCHIVE_REJECTED'});
    await assert.rejects(fs.lstat(destination),{code:'ENOENT'});
    assert.deepEqual(await snapshot(f.root),before);
  });
});

test('verification rejects malformed or noncanonical envelopes',async t=>{
  requireVerifier();
  const f=await fixture(t),original=JSON.parse(await fs.readFile(f.archiveFile,'utf8'));
  const cases=[
    ['invalid JSON','PRIVATE_INVALID_JSON'],
    ['extra field',JSON.stringify({...original,extra:'PRIVATE_FIELD'})],
    ['array envelope','[]'],
    ['invalid build ID',JSON.stringify({...original,buildId:'../PRIVATE_ID'})],
    ['noncanonical IV',JSON.stringify({...original,iv:original.iv+'\n'})],
    ['short tag',JSON.stringify({...original,tag:'AA=='})],
    ['noncanonical ciphertext',JSON.stringify({...original,ciphertext:original.ciphertext+'\n'})],
  ];
  for(const [name,contents] of cases) await t.test(name,async()=>{
    await fs.writeFile(f.archiveFile,contents);
    const before=await snapshot(f.root);
    await assert.rejects(vault.verifyArchive(f),{code:'ARCHIVE_REJECTED'});
    assert.deepEqual(await snapshot(f.root),before);
  });
});

test('verification enforces regular bounded archive and private exact-length key inputs',async t=>{
  requireVerifier();
  const f=await fixture(t);
  const directory=path.join(f.root,'directory');await fs.mkdir(directory);
  const archiveLink=path.join(f.root,'archive-link'),keyLink=path.join(f.root,'key-link');
  await fs.symlink(f.archiveFile,archiveLink);await fs.symlink(f.keyFile,keyLink);
  const oversized=path.join(f.root,'oversized');
  const handle=await fs.open(oversized,'wx',0o600);try {await handle.truncate(128*1024*1024+1);} finally {await handle.close();}
  for(const [name,input,code] of [
    ['archive symlink',{archiveFile:archiveLink},'UNSAFE_PATH'],
    ['archive directory',{archiveFile:directory},'INVALID_FILE'],
    ['archive too large',{archiveFile:oversized},'ARCHIVE_TOO_LARGE'],
    ['key symlink',{keyFile:keyLink},'UNSAFE_PATH'],
    ['key directory',{keyFile:directory},'INVALID_FILE'],
  ]) await t.test(name,()=>assert.rejects(vault.verifyArchive({...f,...input}),{code}));
  for(const length of [0,31,33]) await t.test(`key length ${length}`,async()=>{
    const keyFile=path.join(f.root,`key-${length}`);await fs.writeFile(keyFile,randomBytes(length),{mode:0o600});
    await assert.rejects(vault.verifyArchive({...f,keyFile}),{code:length===33?'ARCHIVE_TOO_LARGE':'INVALID_KEY_FILE'});
  });
  await t.test('public POSIX key',{skip:process.platform==='win32'},async()=>{
    await fs.chmod(f.keyFile,0o640);
    await assert.rejects(vault.verifyArchive(f),{code:'UNSAFE_PERMISSIONS'});
  });
});
