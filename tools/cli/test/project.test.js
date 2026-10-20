import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { initialize, inspect, validatePolicy } from '../src/project.js';

async function fixture(t, files) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'appguard-cli-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  for (const [file, text] of Object.entries(files)) {
    await fs.mkdir(path.dirname(path.join(root, file)), { recursive: true });
    await fs.writeFile(path.join(root, file), text);
  }
  return root;
}
test('Android init preserves content, adds release protection and is idempotent', async t => {
  const root = await fixture(t, {'app/build.gradle.kts': 'plugins { id("com.android.application") }\n', '.gitignore': 'build/'});
  const result = await initialize(root, { appId: 'test-app' });
  assert.equal(result.config.platform, 'android');
  assert.equal(result.config.profile, 'balanced');
  const build = await fs.readFile(path.join(root, 'app/build.gradle.kts'), 'utf8');
  assert.ok(build.startsWith('plugins { id("com.android.application") }\n'));
  assert.match(build, /apply\(from = "appguard-release.gradle"\)/);
  assert.match(await fs.readFile(path.join(root, 'app/appguard-release.gradle'), 'utf8'), /minifyEnabled true/);
  assert.match(await fs.readFile(path.join(root, '.gitignore'), 'utf8'), /build\/\n\.appguard\//);
  const before = await fs.readFile(path.join(root, 'appguard.json'));
  await assert.rejects(initialize(root, {appId: 'test-app'}), {code: 'CONFIG_EXISTS'});
  assert.deepEqual(await fs.readFile(path.join(root, 'appguard.json')), before);
  const report = await inspect(root);
  assert.equal(report.configurationValid, true);
  assert.equal(report.protectionConfigured, true);
  assert.equal(report.sdkInstalled, 'not_checked');
});
test('Expo and Flutter detection and ambiguous native projects require explicit selection', async t => {
  const expo = await fixture(t, {'package.json': JSON.stringify({dependencies:{expo:'57.0.0'}}), 'app/build.gradle': ''});
  assert.equal((await initialize(expo, {appId:'expo-app'})).config.platform, 'expo');
  const flutter = await fixture(t, {'pubspec.yaml':'name: demo\ndependencies:\n  flutter:\n    sdk: flutter\n'});
  assert.equal((await initialize(flutter, {appId:'dart-app'})).config.platform, 'flutter');
  const multi = await fixture(t, {'pubspec.yaml':'flutter:\n', 'package.json':'{"dependencies":{"expo":"57"}}'});
  await assert.rejects(initialize(multi, {appId:'demo'}), {code:'PLATFORM_AMBIGUOUS'});
  assert.equal((await initialize(multi, {appId:'demo',platform:'flutter'})).config.platform,'flutter');
});
test('invalid options and symlink targets reject without writes', async t => {
  const root = await fixture(t, {'app/build.gradle':''});
  for (const options of [{appId:'../secret'}, {appId:'ok',profile:'weak'}, {appId:'ok',platform:'unity'}, {appId:'ok',extra:true}]) {
    await assert.rejects(initialize(root,options));
  }
  const elsewhere = await fixture(t, {'settings':'preserve'});
  await fs.symlink(path.join(elsewhere, 'settings'), path.join(root, '.gitignore'));
  await assert.rejects(initialize(root,{appId:'ok'}), {code:'UNSAFE_PATH'});
  assert.equal(await fs.readFile(path.join(elsewhere,'settings'),'utf8'),'preserve');
  await assert.rejects(fs.stat(path.join(root, 'appguard.json')), {code:'ENOENT'});
});
test('sidecar collision rejects transaction before config or build changes', async t => {
  const root=await fixture(t, {'app/build.gradle':'keep', 'app/appguard-release.gradle':'custom'});
  await assert.rejects(initialize(root,{appId:'demo'}), {code:'CONFIG_EXISTS'});
  assert.equal(await fs.readFile(path.join(root,'app/build.gradle'),'utf8'),'keep');
  await assert.rejects(fs.stat(path.join(root,'appguard.json')),{code:'ENOENT'});
});
test('doctor checks actual sidecar content; config validation rejects ambiguous types', async t => {
  const root=await fixture(t, {'app/build.gradle':''});
  await initialize(root,{appId:'demo'});
  await fs.writeFile(path.join(root,'app/appguard-release.gradle'),'// disabled');
  assert.equal((await inspect(root)).protectionConfigured,false);
  for(const profile of ['basic','balanced','strict']) assert.equal(validatePolicy({profile,requireSignature:true}).valid,true);
  assert.equal(validatePolicy({profile:'basic',requireSignature:false}).valid,true);
  for(const value of [{profile:'balanced',requireSignature:false},{profile:'strict',requireSignature:'true'},{profile:'balanced',extra:true},null])
    assert.throws(()=>validatePolicy(value),{code:'INVALID_POLICY'});
});
