import {test} from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';

const bin=process.env.APPGUARD_CLI_BIN??fileURLToPath(new URL('../bin/appguard.js',import.meta.url));
const posix=process.platform!=='win32';
function cli(root,command,args=[]) {return spawnSync(process.execPath,[bin,command,'--project',root,...args],{encoding:'utf8'});}
async function write(root,name,bytes='') {const file=path.join(root,name);await fs.mkdir(path.dirname(file),{recursive:true});await fs.writeFile(file,bytes);return file;}
async function fixture(t) {
  const temporary=await fs.mkdtemp(path.join(os.tmpdir(),'appguard expo links '));t.after(()=>fs.rm(temporary,{recursive:true,force:true}));
  const root=await fs.realpath(temporary);await write(root,'package.json','{"dependencies":{"expo":"57"}}');
  const init=cli(root,'init',['--app-id','link-fixture']);assert.equal(init.status,0,init.stderr);
  return root;
}
async function stub(root,relative,exitCode=0) {
  const source=`const fs=require('node:fs');fs.writeFileSync('run-receipt.json',JSON.stringify({cwd:process.cwd(),script:fs.realpathSync(process.argv[1]),args:process.argv.slice(2)}));process.exitCode=${exitCode};\n`;
  const file=await write(root,relative,source);await fs.chmod(file,0o600);return file;
}
async function snapshot(root) {
  const entries={};
  async function walk(directory) {for(const item of await fs.readdir(directory,{withFileTypes:true})) {
    const file=path.join(directory,item.name),key=path.relative(root,file),stat=await fs.lstat(file);
    entries[key]={mode:stat.mode};
    if(item.isDirectory())await walk(file);else if(item.isSymbolicLink())entries[key].link=await fs.readlink(file);else entries[key].bytes=(await fs.readFile(file)).toString('base64');
  }}
  await walk(root);return entries;
}
function expoCheck(result) {assert.equal(result.stderr,'');return JSON.parse(result.stdout).checks.find(check=>check.id==='expo_cli');}

for(const absolute of [false,true]) for(const exitCode of [0,7]) {
  test(`local pnpm Expo package link is diagnosed without execution and builds with exit ${exitCode} (${absolute?'absolute':'relative'} link)`,{skip:!posix},async t=>{
    const root=await fixture(t),directory='node_modules/.pnpm/expo@57.0.0_peer@1/node_modules/expo';
    const script=await stub(root,directory+'/bin/cli',exitCode);
    await fs.symlink(absolute?path.join(root,directory):'.pnpm/expo@57.0.0_peer@1/node_modules/expo',path.join(root,'node_modules/expo'));
    const before=await snapshot(root),doctor=cli(root,'doctor',['--check']);
    assert.equal(doctor.status,0,doctor.stdout);assert.deepEqual(expoCheck(doctor),{id:'expo_cli',status:'pass',code:'READY'});
    assert.equal(JSON.parse(doctor.stdout).buildVerified,false);assert.deepEqual(await snapshot(root),before);
    const dry=cli(root,'build',['--dry-run']);assert.equal(dry.status,0);assert.equal(JSON.parse(dry.stdout).executed,false);assert.deepEqual(await snapshot(root),before);
    const build=cli(root,'build');assert.equal(build.status,exitCode,build.stderr);assert.equal(build.stderr,'');
    const result=JSON.parse(build.stdout);assert.equal(result.executed,true);assert.equal(result.exitCode,exitCode);assert.equal(result.args[0],script);
    assert.deepEqual(JSON.parse(await fs.readFile(path.join(root,'run-receipt.json'),'utf8')),{cwd:root,script,args:['export','--platform','all','--output-dir',path.join(root,'dist')]});
    assert.equal(await fs.readlink(path.join(root,'node_modules/expo')),absolute?path.join(root,directory):'.pnpm/expo@57.0.0_peer@1/node_modules/expo');
  });
}

test('ordinary npm Expo installation still runs a readable non-executable CLI',async t=>{
  const root=await fixture(t),script=await stub(root,'node_modules/expo/bin/cli');
  assert.equal(cli(root,'doctor',['--check']).status,0);const build=cli(root,'build');assert.equal(build.status,0,build.stderr);
  assert.equal(JSON.parse(build.stdout).args[0],script);assert.equal(JSON.parse(await fs.readFile(path.join(root,'run-receipt.json'),'utf8')).script,script);
});

for(const shape of ['external','prefix-sibling','dependency-root','dependency-root-link','bin-link','entry-link','loop']) {
  test(`Expo resolution rejects ${shape} before tool execution with fixed diagnostics`,{skip:!posix},async t=>{
    const root=await fixture(t),outside=await fs.mkdtemp(path.join(os.tmpdir(),'PRIVATE_EXPO_DESTINATION_'));t.after(()=>fs.rm(outside,{recursive:true,force:true}));
    await stub(outside,'bin/cli');await fs.mkdir(path.join(root,'node_modules'),{recursive:true});
    if(shape==='external')await fs.symlink(outside,path.join(root,'node_modules/expo'));
    if(shape==='prefix-sibling') {await stub(root,'node_modules-private/expo/bin/cli');await fs.symlink('../node_modules-private/expo',path.join(root,'node_modules/expo'));}
    if(shape==='dependency-root') {await stub(root,'node_modules/bin/cli');await fs.symlink('.',path.join(root,'node_modules/expo'));}
    if(shape==='dependency-root-link') {await fs.rmdir(path.join(root,'node_modules'));await fs.symlink(outside,path.join(root,'node_modules'));await fs.mkdir(path.join(outside,'expo/bin'),{recursive:true});await stub(outside,'expo/bin/cli');}
    if(shape==='bin-link') {await fs.mkdir(path.join(root,'node_modules/expo'));await fs.symlink(path.join(outside,'bin'),path.join(root,'node_modules/expo/bin'));}
    if(shape==='entry-link') {await fs.mkdir(path.join(root,'node_modules/expo/bin'),{recursive:true});await fs.symlink(path.join(outside,'bin/cli'),path.join(root,'node_modules/expo/bin/cli'));}
    if(shape==='loop')await fs.symlink('expo',path.join(root,'node_modules/expo'));
    const before=await snapshot(root),externalBefore=await snapshot(outside),doctor=cli(root,'doctor',['--check']);
    assert.equal(doctor.status,2);assert.deepEqual(expoCheck(doctor),{id:'expo_cli',status:'fail',code:'UNSAFE_PATH'});
    assert.equal(doctor.stdout.includes(outside),false);assert.equal(doctor.stdout.includes('PRIVATE_EXPO'),false);assert.deepEqual(await snapshot(root),before);assert.deepEqual(await snapshot(outside),externalBefore);
    const build=cli(root,'build');assert.equal(build.status,1);assert.equal(build.stdout,'');assert.deepEqual(JSON.parse(build.stderr),{error:{code:'UNSAFE_PATH'}});
    await assert.rejects(fs.stat(path.join(root,'run-receipt.json')),{code:'ENOENT'});assert.deepEqual(await snapshot(outside),externalBefore);
  });
}

for(const shape of ['missing','dangling','missing-entry','directory-entry']) {
  test(`Expo ${shape} remains unavailable without accidental execution`,{skip:!posix},async t=>{
    const root=await fixture(t);
    if(shape==='dangling') {await fs.mkdir(path.join(root,'node_modules'));await fs.symlink('.pnpm/missing/expo',path.join(root,'node_modules/expo'));}
    if(shape==='missing-entry') {await fs.mkdir(path.join(root,'node_modules/.pnpm/expo/node_modules/expo'),{recursive:true});await fs.symlink('.pnpm/expo/node_modules/expo',path.join(root,'node_modules/expo'));}
    if(shape==='directory-entry')await fs.mkdir(path.join(root,'node_modules/expo/bin/cli'),{recursive:true});
    const before=await snapshot(root),doctor=cli(root,'doctor',['--check']);assert.equal(doctor.status,2);
    assert.equal(expoCheck(doctor).code,shape==='directory-entry'?'NOT_REGULAR_FILE':'MISSING');assert.deepEqual(await snapshot(root),before);
    const build=cli(root,'build');assert.equal(build.status,1);assert.equal(build.stdout,'');assert.deepEqual(JSON.parse(build.stderr),{error:{code:'BUILD_TOOL_MISSING'}});
    await assert.rejects(fs.stat(path.join(root,'run-receipt.json')),{code:'ENOENT'});
  });
}

test('pnpm linked package retains readable-file diagnosis and missing-tool dry run', {skip:!posix || process.getuid?.()===0},async t=>{
  const root=await fixture(t),directory='node_modules/.pnpm/expo/node_modules/expo';
  const script=await stub(root,directory+'/bin/cli');await fs.symlink('.pnpm/expo/node_modules/expo',path.join(root,'node_modules/expo'));
  await fs.chmod(script,0o000);
  try {
    const doctor=cli(root,'doctor',['--check']);assert.equal(doctor.status,2);assert.deepEqual(expoCheck(doctor),{id:'expo_cli',status:'fail',code:'UNREADABLE'});
    await assert.rejects(fs.stat(path.join(root,'run-receipt.json')),{code:'ENOENT'});
  } finally {await fs.chmod(script,0o600);}
  await fs.unlink(script);
  const dry=cli(root,'build',['--dry-run']);assert.equal(dry.status,0);assert.equal(JSON.parse(dry.stdout).executed,false);assert.equal(JSON.parse(dry.stdout).args[0],path.join(root,'node_modules/expo/bin/cli'));
  await assert.rejects(fs.stat(path.join(root,'run-receipt.json')),{code:'ENOENT'});
});
