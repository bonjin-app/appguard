import { test } from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {fileURLToPath} from 'node:url';
import {randomBytes} from 'node:crypto';

const bin=fileURLToPath(new URL('../bin/appguard.js',import.meta.url));
function run(...args) {const p=spawnSync(process.execPath,[bin,...args],{encoding:'utf8'}); return {...p,json:JSON.parse(p.status===0?p.stdout:p.stderr)};}
test('actual CLI setup, doctor, policy and dry-run produce truthful JSON',async t=>{
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'appguard-command-'));
  t.after(()=>fs.rm(root,{force:true,recursive:true}));
  await fs.mkdir(path.join(root,'app'));await fs.writeFile(path.join(root,'app/build.gradle'),'');
  const init=run('init','--project',root,'--app-id','test-cli');
  assert.equal(init.status,0);assert.equal(init.json.config.profile,'balanced');
  const doctor=run('doctor','--project',root);
  assert.equal(doctor.status,0);assert.equal(doctor.json.buildVerified,false);assert.equal(doctor.json.providerConfigured,'not_checked');
  const dry=run('build','--project',root,'--dry-run');
  assert.equal(dry.status,0);assert.equal(dry.json.executed,false);assert.deepEqual(dry.json.args,[':app:assembleRelease']);
  const policy=path.join(root,'policy.json');await fs.writeFile(policy,'{"profile":"strict","requireSignature":true}');
  assert.equal(run('policy','validate','--file',policy).json.valid,true);
  assert.equal(run('init','--project',root,'--app-id','test-cli').json.error.code,'CONFIG_EXISTS');
});
test('CLI rejects unknown/duplicate options and never prints raw parser errors',()=>{
  for(const args of [['nope'],['doctor','--unknown','secret-token'],['init','--app-id','one','--app-id','two'],['policy','validate','--file','/no/such/SECRET']]) {
    const result=run(...args);assert.equal(result.status,1);assert.match(result.json.error.code,/^[A-Z_]+$/);assert.equal(JSON.stringify(result.json).includes('SECRET'),false);assert.equal(JSON.stringify(result.json).includes('secret-token'),false);
  }
});
test('CLI archive and restore work through subprocess with caller-owned key',async t=>{
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'appguard-vault-command-'));t.after(()=>fs.rm(root,{force:true,recursive:true}));
  const source=path.join(root,'source'),key=path.join(root,'key'),vault=path.join(root,'vault');
  await fs.mkdir(source);await fs.writeFile(path.join(source,'mapping.txt'),'fixture');await fs.writeFile(key,randomBytes(32),{mode:0o600});
  const a=run('archive','--source',source,'--vault',vault,'--key-file',key,'--build-id','build001');
  assert.equal(a.status,0);
  const destination=path.join(root,'restore');
  const r=run('restore','--archive',a.json.archiveFile,'--destination',destination,'--key-file',key);
  assert.equal(r.status,0);assert.equal(await fs.readFile(path.join(destination,'mapping.txt'),'utf8'),'fixture');
});

test('CLI malformed project text fails with a fixed error and preserves source bytes', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'appguard-input-command-'));
  t.after(() => fs.rm(root, {force: true, recursive: true}));
  await fs.mkdir(path.join(root, 'app'));
  await fs.writeFile(path.join(root, 'app/build.gradle'), 'plugins {}\n');
  const original = Buffer.concat([Buffer.from('PRIVATE_INPUT_MARKER\n'), Buffer.from([0xff])]);
  await fs.writeFile(path.join(root, '.gitignore'), original);
  const result = run('init', '--project', root, '--app-id', 'demo');
  assert.equal(result.status, 1);
  assert.deepEqual(result.json, {error: {code: 'INVALID_FILE'}});
  assert.equal(result.stdout, '');
  assert.equal(result.stderr.includes('PRIVATE_INPUT_MARKER'), false);
  assert.equal(result.stderr.includes(root), false);
  assert.deepEqual(await fs.readFile(path.join(root, '.gitignore')), original);
  await assert.rejects(fs.lstat(path.join(root, 'appguard.json')), {code: 'ENOENT'});
});

test('CLI verify-archive reports only authenticated counts without writing project or plaintext files',async t=>{
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'appguard-verify-command-'));
  t.after(()=>fs.rm(root,{force:true,recursive:true}));
  const source=path.join(root,'source'),key=path.join(root,'PRIVATE_KEY'),vault=path.join(root,'vault');
  await fs.mkdir(source);await fs.writeFile(path.join(source,'PRIVATE_MAPPING'),'secret',{mode:0o640});
  await fs.writeFile(path.join(source,'empty'),'');await fs.writeFile(key,randomBytes(32),{mode:0o600});
  const a=run('archive','--source',source,'--vault',vault,'--key-file',key,'--build-id','build-verify');
  assert.equal(a.status,0);
  async function snapshot() {
    const entries=[];
    async function walk(relative='') {
      const file=path.join(root,relative),st=await fs.lstat(file);
      entries.push({name:relative,mode:st.mode,size:st.size,mtime:st.mtimeMs,ctime:st.ctimeMs,
        ...(st.isFile()?{bytes:(await fs.readFile(file)).toString('hex')}:{})});
      if(st.isDirectory()) for(const name of (await fs.readdir(file)).sort()) await walk(path.join(relative,name));
    }
    await walk();return entries;
  }
  const before=await snapshot();
  const result=run('verify-archive','--archive',a.json.archiveFile,'--key-file',key);
  assert.equal(result.status,0);assert.equal(result.stderr,'');
  assert.deepEqual(result.json,{verified:true,buildId:'build-verify',fileCount:2,plaintextBytes:6});
  assert.equal(result.stdout,JSON.stringify(result.json)+'\n');
  assert.deepEqual(await snapshot(),before);
  assert.ok(run('--help').json.commands.includes('verify-archive --archive FILE --key-file FILE'));
  await fs.writeFile(a.json.archiveFile,'PRIVATE_MALFORMED_ARCHIVE');
  const rejected=run('verify-archive','--archive',a.json.archiveFile,'--key-file',key);
  assert.equal(rejected.status,1);assert.equal(rejected.stdout,'');
  assert.deepEqual(rejected.json,{error:{code:'ARCHIVE_REJECTED'}});
  assert.equal(rejected.stderr,JSON.stringify(rejected.json)+'\n');
  assert.equal(rejected.stderr.includes(root),false);assert.equal(rejected.stderr.includes('PRIVATE'),false);
});

test('CLI verify-archive rejects malformed options with fixed errors and no raw arguments',()=>{
  for(const args of [[],['--archive','PRIVATE_ARCHIVE'],['--key-file','PRIVATE_KEY'],
    ['--archive','PRIVATE_ARCHIVE','--key-file','PRIVATE_KEY','--destination','PRIVATE_DESTINATION'],
    ['--archive','PRIVATE_ARCHIVE','--archive','OTHER_ARCHIVE','--key-file','PRIVATE_KEY'],
    ['--archive','--key-file','PRIVATE_KEY'],['--archive','','--key-file','PRIVATE_KEY'],
    ['PRIVATE_POSITIONAL'],['--archive','PRIVATE_ARCHIVE','--key-file','PRIVATE_KEY','--help']]) {
    const result=run('verify-archive',...args);
    assert.equal(result.status,1);assert.equal(result.stdout,'');
    assert.deepEqual(result.json,{error:{code:'INVALID_ARGUMENTS'}});
    assert.equal(result.stderr,'{"error":{"code":"INVALID_ARGUMENTS"}}\n');
  }
  const unreadable=run('verify-archive','--archive','/no/such/PRIVATE_ARCHIVE','--key-file','/no/such/PRIVATE_KEY');
  assert.equal(unreadable.status,1);assert.equal(unreadable.stdout,'');
  assert.deepEqual(unreadable.json,{error:{code:'OPERATION_FAILED'}});
  assert.equal(unreadable.stderr,'{"error":{"code":"OPERATION_FAILED"}}\n');
});
