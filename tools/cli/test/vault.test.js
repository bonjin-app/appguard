import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {randomBytes,createCipheriv} from 'node:crypto';
import {archive,restore,validatePortablePaths} from '../src/vault.js';

async function fixture(t) {
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'appguard-vault-'));
  t.after(()=>fs.rm(root,{recursive:true,force:true}));
  await fs.mkdir(path.join(root,'source/nested'),{recursive:true,mode:0o700});
  await fs.writeFile(path.join(root,'source','mapping.txt'),'private-mapping-secret\n');
  await fs.writeFile(path.join(root,'source/nested','binary.symbol'),Buffer.from([0,255,10,1]));
  const keyFile=path.join(root,'key');
  await fs.writeFile(keyFile,randomBytes(32),{mode:0o600});
  return {root,source:path.join(root,'source'),vault:path.join(root,'vault'),keyFile,buildId:'release-001'};
}
test('authenticated archive round-trips nested binary mappings with private output',async t=>{
  const f=await fixture(t);
  const result=await archive(f);
  assert.equal(result.fileCount,2);
  const encrypted=await fs.readFile(result.archiveFile);
  assert.equal(encrypted.includes(Buffer.from('private-mapping-secret')),false);
  assert.equal((await fs.stat(result.archiveFile)).mode&0o777,0o600);
  assert.equal((await fs.stat(f.vault)).mode&0o777,0o700);
  const destination=path.join(f.root,'restored');
  await restore({archiveFile:result.archiveFile,destination,keyFile:f.keyFile});
  assert.equal((await fs.stat(destination)).mode&0o777,0o700);
  assert.equal((await fs.stat(path.join(destination,'nested','binary.symbol'))).mode&0o777,0o600);
  assert.deepEqual(await fs.readFile(path.join(destination,'nested','binary.symbol')),Buffer.from([0,255,10,1]));
  assert.equal(await fs.readFile(path.join(f.source,'mapping.txt'),'utf8'),'private-mapping-secret\n');
  await assert.rejects(archive(f),{code:'ARCHIVE_EXISTS'});
  await assert.rejects(restore({archiveFile:result.archiveFile,destination,keyFile:f.keyFile}),{code:'DESTINATION_EXISTS'});
});
test('tampering and wrong key fail without creating plaintext destination',async t=>{
  const f=await fixture(t);
  const result=await archive(f);
  const original=await fs.readFile(result.archiveFile,'utf8');
  for(const field of ['buildId','iv','tag','ciphertext']) {
    const obj=JSON.parse(original);
    obj[field]=obj[field].startsWith('A')?'B'+obj[field].slice(1):'A'+obj[field].slice(1);
    await fs.writeFile(result.archiveFile,JSON.stringify(obj));
    const destination=path.join(f.root,`restore-${field}`);
    await assert.rejects(restore({archiveFile:result.archiveFile,destination,keyFile:f.keyFile}));
    await assert.rejects(fs.stat(destination),{code:'ENOENT'});
  }
  await fs.writeFile(result.archiveFile,original);
  await fs.writeFile(f.keyFile,randomBytes(32));
  await assert.rejects(restore({archiveFile:result.archiveFile,destination:path.join(f.root,'wrong'),keyFile:f.keyFile}),{code:'ARCHIVE_REJECTED'});
});
test('symlink source/key, unsafe IDs and public key/vault permissions reject',async t=>{
  const f=await fixture(t);
  await fs.symlink(f.keyFile,path.join(f.source,'link'));
  await assert.rejects(archive(f),{code:'UNSAFE_PATH'});
  await fs.unlink(path.join(f.source,'link'));
  await assert.rejects(archive({...f,buildId:'../outside'}),{code:'INVALID_BUILD_ID'});
  await fs.chmod(f.keyFile,0o644);
  await assert.rejects(archive(f),{code:'UNSAFE_PERMISSIONS'});
  await fs.chmod(f.keyFile,0o600);
  await fs.mkdir(f.vault,{mode:0o755});
  await assert.rejects(archive(f),{code:'UNSAFE_PERMISSIONS'});
  await fs.chmod(f.vault,0o700);
  const link=path.join(f.root,'key-link');
  await fs.symlink(f.keyFile,link);
  await assert.rejects(archive({...f,keyFile:link}),{code:'UNSAFE_PATH'});
});
test('oversized input, special files and vault inside source reject before archiving',async t=>{
  const f=await fixture(t);
  await assert.rejects(archive({...f,vault:path.join(f.source,'vault')}),{code:'UNSAFE_PATH'});
  const big=await fs.open(path.join(f.source,'large'),'w');
  await big.truncate(64*1024*1024+1); await big.close();
  await assert.rejects(archive(f),{code:'ARCHIVE_TOO_LARGE'});
  assert.deepEqual(await fs.readdir(f.vault).catch(e=>e.code==='ENOENT'?[]:Promise.reject(e)),[]);
});
test('authenticated hostile manifests cannot traverse or create partial plaintext',async t=>{
  const f=await fixture(t),result=await archive(f),key=await fs.readFile(f.keyFile);
  const bodies=[
    [{path:'../escape',bodyBase64:'AA=='}],
    [{path:'/absolute',bodyBase64:'AA=='}],
    [{path:'dir\\escape',bodyBase64:'AA=='}],
    [{path:'file',bodyBase64:'AA=='},{path:'file/child',bodyBase64:'AA=='}],
    [{path:'Mapping',bodyBase64:'AA=='},{path:'mapping',bodyBase64:'AA=='}],
    [{path:'valid',bodyBase64:'AA'}],
    [{path:'NUL.txt',bodyBase64:'AA=='}],
  ];
  for(let i=0;i<bodies.length;i++) {
    const iv=randomBytes(12),cipher=createCipheriv('aes-256-gcm',key,iv);
    cipher.setAAD(Buffer.from(JSON.stringify(['appguard-vault-v0',f.buildId])));
    const ciphertext=Buffer.concat([cipher.update(JSON.stringify({files:bodies[i]})),cipher.final()]);
    await fs.writeFile(result.archiveFile,JSON.stringify({schemaVersion:'appguard-vault-v0',buildId:f.buildId,iv:iv.toString('base64'),tag:cipher.getAuthTag().toString('base64'),ciphertext:ciphertext.toString('base64')}));
    const destination=path.join(f.root,'unsafe-'+i);
    await assert.rejects(restore({archiveFile:result.archiveFile,destination,keyFile:f.keyFile}),{code:'ARCHIVE_REJECTED'});
    await assert.rejects(fs.stat(destination),{code:'ENOENT'});
  }
  await assert.rejects(fs.stat(path.join(f.root,'escape')),{code:'ENOENT'});
});
test('invalid key lengths reject',async t=>{
  const f=await fixture(t);
  for(const length of [0,31,33]) {
    await fs.writeFile(f.keyFile,randomBytes(length));
    await assert.rejects(archive(f));
  }
});
test('shared archive/restore path validator rejects unrecoverable portable conflicts',()=>{
  for(const names of [['Map','map'],['a/x','A'],['café','cafe\u0301'],['same','same'],['valid','../outside'],['file','file/child']])
    assert.throws(()=>validatePortablePaths(names),{code:'ARCHIVE_REJECTED'});
  assert.doesNotThrow(()=>validatePortablePaths(['a/mapping.txt','b/symbols','plain.symbol']));
});
