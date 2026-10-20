import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { initialize } from '../src/project.js';
import { buildPlan, executeBuild } from '../src/build.js';

async function fixture(t, files) {
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'appguard-build-'));
  t.after(()=>fs.rm(root,{recursive:true,force:true}));
  for(const [name,text] of Object.entries(files)) {
    await fs.mkdir(path.dirname(path.join(root,name)),{recursive:true});
    await fs.writeFile(path.join(root,name),text);
  }
  await initialize(root,{appId:'demo'});
  return fs.realpath(root);
}
test('Android plan uses exact local wrapper and release task; changed config fails closed',async t=>{
  const root=await fixture(t,{'app/build.gradle':''});
  let plan=await buildPlan(root);
  assert.equal(plan.command,path.join(root,'gradlew'));
  assert.deepEqual(plan.args,[':app:assembleRelease']);
  await fs.writeFile(path.join(root,'app/appguard-release.gradle'),'// off');
  await assert.rejects(buildPlan(root),{code:'PROTECTION_NOT_CONFIGURED'});
});
test('Flutter plan enables release obfuscation with separate private symbol path',async t=>{
  const root=await fixture(t,{'pubspec.yaml':'flutter:\n'});
  const plan=await buildPlan(root);
  assert.equal(plan.command,'flutter');
  assert.deepEqual(plan.args,['build','apk','--release','--obfuscate',`--split-debug-info=${path.join(root,'.appguard','symbols')}`]);
});
test('Expo uses installed local CLI and production export without source maps',async t=>{
  const root=await fixture(t,{'package.json':'{"dependencies":{"expo":"57"}}'});
  const plan=await buildPlan(root);
  assert.equal(plan.command,process.execPath);
  assert.deepEqual(plan.args,[path.join(root,'node_modules/expo/bin/cli'),'export','--platform','all','--output-dir',path.join(root,'dist')]);
});
test('execute runs without shell and propagates child failure; private symbol directory is private',async t=>{
  const root=await fixture(t,{'app/build.gradle':''});
  await fs.writeFile(path.join(root,'gradlew'),'#!/bin/sh\nprintf "%s\\n" "$@" > args.txt\nexit 7\n',{mode:0o700});
  const result=await executeBuild(root);
  assert.equal(result.exitCode,7);
  assert.equal(await fs.readFile(path.join(root,'args.txt'),'utf8'),':app:assembleRelease\n');
  assert.equal((await fs.stat(path.join(root,'.appguard'))).mode&0o777,0o700);
});
