import {test} from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {initialize,inspect} from '../src/project.js';

const bin=fileURLToPath(new URL('../bin/appguard.js',import.meta.url));
const posix=process.platform!=='win32';
async function fixture(t,platform='expo') {
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'appguard-doctor-'));
  t.after(()=>fs.rm(root,{recursive:true,force:true}));
  const source=platform==='expo'?'package.json':platform==='flutter'?'pubspec.yaml':'app/build.gradle';
  await write(root,source,platform==='expo'?'{"dependencies":{"expo":"57"}}':platform==='flutter'?'flutter:\n':'plugins {}\n');
  await initialize(root,{appId:'doctor-fixture'});
  return root;
}
async function write(root,name,text='') {const file=path.join(root,name);await fs.mkdir(path.dirname(file),{recursive:true});await fs.writeFile(file,text);return file;}
function cli(root,args=[],env=process.env) {return spawnSync(process.execPath,[bin,'doctor','--project',root,...args],{encoding:'utf8',env});}
function check(report,id) {assert.ok(Array.isArray(report.checks),'report must contain local checks');const c=report.checks.find(c=>c.id===id);assert.ok(c,`missing check ${id}`);return c;}
async function snapshot(root) {
  const result={};
  async function walk(dir) {for(const entry of await fs.readdir(dir,{withFileTypes:true})) {const file=path.join(dir,entry.name),key=path.relative(root,file),st=await fs.lstat(file);result[key]={mode:st.mode};if(entry.isDirectory())await walk(file);else if(entry.isSymbolicLink())result[key].link=await fs.readlink(file);else result[key].bytes=(await fs.readFile(file)).toString('base64');}}
  await walk(root);return result;
}

test('doctor report and --check expose the same missing prerequisite without executing or writing',async t=>{
  const root=await fixture(t),before=await snapshot(root);
  const report=await inspect(root);
  assert.equal(report.localChecksPassed,false);
  assert.deepEqual(report.checks,[{id:'expo_cli',status:'fail',code:'MISSING'}]);
  assert.equal(report.configurationValid,true);assert.equal(report.platform,'expo');assert.equal(report.appId,'doctor-fixture');assert.equal(report.profile,'balanced');assert.equal(report.protectionConfigured,true);
  assert.equal(report.sdkInstalled,'not_checked');assert.equal(report.providerConfigured,'not_checked');assert.equal(report.buildVerified,false);
  const normal=cli(root),strict=cli(root,['--check']);
  assert.equal(normal.status,0);assert.equal(strict.status,2);assert.equal(normal.stderr,'');assert.equal(strict.stderr,'');
  assert.deepEqual(JSON.parse(normal.stdout),report);assert.equal(strict.stdout,normal.stdout);
  assert.deepEqual(await snapshot(root),before);
});

test('Expo requires a local regular CLI file but no executable bit and never runs its contents',async t=>{
  const root=await fixture(t),marker=path.join(root,'EXECUTED');
  const file=await write(root,'node_modules/expo/bin/cli',`require('node:fs').writeFileSync(${JSON.stringify(marker)},'bad');`);
  await fs.chmod(file,0o600);
  const before=await snapshot(root),report=await inspect(root);
  assert.deepEqual(check(report,'expo_cli'),{id:'expo_cli',status:'pass',code:'READY'});assert.equal(report.localChecksPassed,true);
  const run=cli(root,['--check']);assert.equal(run.status,0);assert.equal(run.stderr,'');assert.equal(JSON.parse(run.stdout).buildVerified,false);
  assert.deepEqual(await snapshot(root),before);
  await fs.rm(file);await fs.mkdir(file);
  assert.equal(check(await inspect(root),'expo_cli').code,'NOT_REGULAR_FILE');
  assert.equal(cli(root,['--check']).status,2);
});

test('Expo rejects leaf and ancestor symlinks without leaking their private destination', {skip:!posix},async t=>{
  for(const ancestor of [false,true]) {
    const root=await fixture(t),outside=await fs.mkdtemp(path.join(os.tmpdir(),'PRIVATE_TOOL_DESTINATION-'));
    t.after(()=>fs.rm(outside,{recursive:true,force:true}));
    await write(outside,'bin/cli','PRIVATE_CONTENT');
    if(ancestor) {await fs.mkdir(path.join(root,'node_modules'));await fs.symlink(outside,path.join(root,'node_modules/expo'));}
    else {await fs.mkdir(path.join(root,'node_modules/expo/bin'),{recursive:true});await fs.symlink(path.join(outside,'bin/cli'),path.join(root,'node_modules/expo/bin/cli'));}
    const before=await snapshot(root),run=cli(root,['--check']);
    assert.equal(run.status,2);assert.equal(run.stderr,'');assert.equal(check(JSON.parse(run.stdout),'expo_cli').code,'UNSAFE_PATH');
    assert.equal(run.stdout.includes(outside),false);assert.equal(run.stdout.includes('PRIVATE_'),false);assert.deepEqual(await snapshot(root),before);
  }
});

test('Android checks the exact sidecar and apply line plus executable regular wrapper', {skip:!posix},async t=>{
  const root=await fixture(t,'android');
  assert.equal(check(await inspect(root),'android_gradle_wrapper').code,'MISSING');
  const wrapper=await write(root,'gradlew','#!/bin/sh\ntouch EXECUTED\n');
  await fs.chmod(wrapper,0o600);
  assert.equal(check(await inspect(root),'android_gradle_wrapper').code,'NOT_EXECUTABLE');
  await fs.chmod(wrapper,0o700);
  assert.equal((await inspect(root)).localChecksPassed,true);assert.equal(cli(root,['--check']).status,0);
  await assert.rejects(fs.stat(path.join(root,'EXECUTED')),{code:'ENOENT'});
  const original=await fs.readFile(path.join(root,'app/appguard-release.gradle'),'utf8');
  await fs.writeFile(path.join(root,'app/appguard-release.gradle'),original+'// changed\n');
  assert.deepEqual(check(await inspect(root),'android_protection'),{id:'android_protection',status:'fail',code:'PROTECTION_NOT_CONFIGURED'});
  assert.equal(cli(root).status,0);assert.equal(cli(root,['--check']).status,2);
  await fs.writeFile(path.join(root,'app/appguard-release.gradle'),original);
  await fs.writeFile(path.join(root,'app/build.gradle'),'plugins {}\n');
  assert.equal((await inspect(root)).protectionConfigured,false);
  await fs.rm(wrapper);await fs.mkdir(wrapper);
  assert.equal(check(await inspect(root),'android_gradle_wrapper').code,'NOT_REGULAR_FILE');
  await fs.rmdir(wrapper);await fs.symlink('app/build.gradle',wrapper);
  assert.equal(check(await inspect(root),'android_gradle_wrapper').code,'UNSAFE_PATH');
});

test('Flutter PATH resolution follows order, skips unusable entries, accepts tool symlinks, and never executes', {skip:!posix},async t=>{
  const root=await fixture(t,'flutter');
  const first=await write(root,'first/flutter','#!/bin/sh\ntouch EXECUTED\n');await fs.chmod(first,0o600);
  await fs.mkdir(path.join(root,'directory/flutter'),{recursive:true});
  const target=await write(root,'sdk/flutter','#!/bin/sh\ntouch EXECUTED\n');await fs.chmod(target,0o700);
  await fs.mkdir(path.join(root,'linked'));await fs.symlink(target,path.join(root,'linked/flutter'));
  const before=await snapshot(root);
  const env={...process.env,PATH:['first','directory','missing','linked'].join(path.delimiter)};
  const run=cli(root,['--check'],env),report=JSON.parse(run.stdout);
  assert.equal(run.status,0);assert.equal(run.stderr,'');assert.deepEqual(check(report,'flutter_cli'),{id:'flutter_cli',status:'pass',code:'READY'});
  assert.equal(report.localChecksPassed,true);assert.equal(report.sdkInstalled,'not_checked');assert.equal(report.buildVerified,false);
  assert.deepEqual(await snapshot(root),before);
  for(const entry of ['first','directory','missing']) {
    const failed=cli(root,['--check'],{...env,PATH:entry});
    assert.equal(failed.status,2);assert.equal(failed.stderr,'');assert.equal(check(JSON.parse(failed.stdout),'flutter_cli').status,'fail');
  }
});

test('Flutter resolves empty PATH entries from the target project and leaves an unset PATH unchecked', {skip:!posix},async t=>{
  const root=await fixture(t,'flutter');
  const tool=await write(root,'flutter','#!/bin/sh\ntouch EXECUTED\n');await fs.chmod(tool,0o700);
  for(const value of ['',`${path.delimiter}/PRIVATE_MISSING_PATH`,root]) {
    const run=cli(root,['--check'],{...process.env,PATH:value});assert.equal(run.status,0);assert.equal(run.stderr,'');assert.equal(JSON.parse(run.stdout).localChecksPassed,true);
  }
  const env={...process.env};delete env.PATH;
  const run=cli(root,['--check'],env);assert.equal(run.status,2);assert.deepEqual(check(JSON.parse(run.stdout),'flutter_cli'),{id:'flutter_cli',status:'not_checked',code:'PATH_NOT_SET'});
  await assert.rejects(fs.stat(path.join(root,'EXECUTED')),{code:'ENOENT'});
});

test('doctor keeps malformed arguments and config on fixed stderr exit one',async t=>{
  const root=await fixture(t);
  for(const args of [['--check','--check'],['--check','PRIVATE_VALUE'],['--unknown','PRIVATE_VALUE']]) {
    const run=cli(root,args);assert.equal(run.status,1);assert.equal(run.stdout,'');assert.deepEqual(JSON.parse(run.stderr),{error:{code:'INVALID_ARGUMENTS'}});
  }
  await fs.writeFile(path.join(root,'appguard.json'),'PRIVATE_MALFORMED_CONFIG');
  const run=cli(root,['--check']);assert.equal(run.status,1);assert.equal(run.stdout,'');assert.deepEqual(JSON.parse(run.stderr),{error:{code:'INVALID_CONFIG'}});
});

test('Windows unsupported local launch checks cannot pass --check', {skip:posix},async t=>{
  for(const platform of ['android','flutter']) {
    const root=await fixture(t,platform),run=cli(root,['--check']);
    assert.equal(run.status,2);assert.equal(run.stderr,'');
    const report=JSON.parse(run.stdout);assert.equal(report.localChecksPassed,false);
    assert.equal(check(report,platform==='android'?'android_gradle_wrapper':'flutter_cli').code,'PLATFORM_UNSUPPORTED');
  }
});

// These catch mode-bit-only checks and a Node entrypoint that exists but cannot
// actually be read. Root can bypass file permissions, so it cannot prove this.
test('local tool readiness respects effective read and execute permissions', {skip:!posix || process.getuid?.()===0},async t=>{
  const expo=await fixture(t),file=await write(expo,'node_modules/expo/bin/cli','// private tool');
  await fs.chmod(file,0o000);
  t.after(()=>fs.chmod(file,0o600).catch(()=>{}));
  const denied=cli(expo,['--check']);
  assert.equal(denied.status,2);assert.equal(denied.stderr,'');
  assert.deepEqual(check(JSON.parse(denied.stdout),'expo_cli'),{id:'expo_cli',status:'fail',code:'UNREADABLE'});
  const android=await fixture(t,'android'),wrapper=await write(android,'gradlew','#!/bin/sh\n');
  await fs.chmod(wrapper,0o610); // owner lacks execute even though the group bit is set
  assert.equal(check(await inspect(android),'android_gradle_wrapper').code,'NOT_EXECUTABLE');
});

test('Flutter unreadable search directories and broken symlinks fail with redacted diagnostics', {skip:!posix || process.getuid?.()===0},async t=>{
  const root=await fixture(t,'flutter');
  const hidden=path.join(root,'PRIVATE_PATH_CONTENT');
  await fs.mkdir(hidden);await write(root,'PRIVATE_PATH_CONTENT/flutter','PRIVATE_TOOL_CONTENT');
  await fs.chmod(hidden,0o000);
  try {
  const denied=cli(root,['--check'],{...process.env,PATH:hidden});
  assert.equal(denied.status,2);assert.equal(denied.stderr,'');
  assert.deepEqual(check(JSON.parse(denied.stdout),'flutter_cli'),{id:'flutter_cli',status:'fail',code:'UNREADABLE'});
  assert.equal(denied.stdout.includes('PRIVATE'),false);assert.equal(denied.stdout.includes(root),false);
  } finally {await fs.chmod(hidden,0o700);}
  await fs.mkdir(path.join(root,'broken'));await fs.symlink('missing-private-target',path.join(root,'broken/flutter'));
  const broken=cli(root,['--check'],{...process.env,PATH:'broken'});
  assert.equal(broken.status,2);assert.equal(check(JSON.parse(broken.stdout),'flutter_cli').code,'MISSING');
});
