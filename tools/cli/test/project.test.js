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

test('malformed UTF8 ignore files reject before project or backup writes', async t => {
  const invalid = [
    Buffer.from([0xff]), Buffer.from([0xc0, 0xaf]), Buffer.from([0x80]),
    Buffer.from([0xe2, 0x82]), Buffer.from([0xed, 0xa0, 0x80]),
    Buffer.from([0xf4, 0x90, 0x80, 0x80]),
  ];
  for (const bytes of invalid) {
    const original = Buffer.concat([Buffer.from('# preserve original\r\n'), bytes]);
    const root = await fixture(t, {'app/build.gradle': 'plugins {}\r\n', '.gitignore': original});
    await assert.rejects(initialize(root, {appId: 'demo'}), {code: 'INVALID_FILE'});
    assert.deepEqual(await fs.readFile(path.join(root, '.gitignore')), original);
    assert.equal(await fs.readFile(path.join(root, 'app/build.gradle'), 'utf8'), 'plugins {}\r\n');
    for (const name of ['appguard.json', 'app/appguard-release.gradle', '.appguard', '.appguard-init.lock'])
      await assert.rejects(fs.lstat(path.join(root, name)), {code: 'ENOENT'});
  }
});

test('malformed detected project files reject without silently decoding replacement characters', async t => {
  for (const [name, prefix] of [
    ['app/build.gradle', '// app\n'], ['app/build.gradle.kts', '// app\n'],
    ['package.json', '{"dependencies":{"expo":"57"},"description":"'],
    ['pubspec.yaml', 'flutter:\n# '],
  ]) {
    const original = Buffer.concat([Buffer.from(prefix), Buffer.from([0xff]), Buffer.from(name === 'package.json' ? '"}' : '\n')]);
    const root = await fixture(t, {[name]: original, '.gitignore': 'keep/\n'});
    await assert.rejects(initialize(root, {appId: 'demo'}), {code: 'INVALID_FILE'});
    assert.deepEqual(await fs.readFile(path.join(root, name)), original);
    assert.equal(await fs.readFile(path.join(root, '.gitignore'), 'utf8'), 'keep/\n');
    for (const file of ['appguard.json', '.appguard', '.appguard-init.lock'])
      await assert.rejects(fs.lstat(path.join(root, file)), {code: 'ENOENT'});
  }
});

test('valid BOM Unicode replacement characters and CRLF retain byte-identical original backups', async t => {
  const build = Buffer.from('\uFEFF// 한글 😀 \uFFFD\r\nplugins {}\r\n');
  const ignore = Buffer.from('\uFEFF# café e\u0301 \uFFFD\r\nbuild/\r\n');
  const root = await fixture(t, {'app/build.gradle': build, '.gitignore': ignore});
  const outcome = await initialize(root, {appId: 'demo'});
  const manifest = JSON.parse(await fs.readFile(path.join(outcome.backupDirectory, 'manifest.json'), 'utf8'));
  for (const [name, bytes] of [['app/build.gradle', build], ['.gitignore', ignore]]) {
    const after = await fs.readFile(path.join(root, name));
    assert.deepEqual(after.subarray(0, bytes.length), bytes);
    const index = manifest.findIndex(entry => entry.name === name && entry.existed);
    assert.notEqual(index, -1);
    assert.deepEqual(await fs.readFile(path.join(outcome.backupDirectory, `${index}.original`)), bytes);
  }
  assert.equal((await inspect(root)).protectionConfigured, true);
});
