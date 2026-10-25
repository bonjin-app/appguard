'use strict';
// Ordinary owned file fixtures only. No package payload is evaluated or unpacked.
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {createHash} = require('node:crypto');
const {verifyConsumer} = require('../verify-backports.cjs');
const sha = data => createHash('sha256').update(data).digest('hex');
const sri = data => 'sha512-' + createHash('sha512').update(data).digest('base64');
const repository = path.resolve(__dirname,'../../..');
function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'appguard-installed-fixture-'));
  try {
  const consumer = path.join(root, 'sdk/expo');
  const backports = path.join(root, 'tools/dependency-backports');
  const write = (file, data) => {fs.mkdirSync(path.dirname(file), {recursive:true}); fs.writeFileSync(file, data);};
  const json = (file, value) => write(file, JSON.stringify(value));
  const packages = {}; const overrides = {}; const rootDev = {}; const records = [];
  for (const [id, version] of [['braces','3.0.3'], ['node-forge','1.4.0']]) {
    const fork = {name:'@appguard/' + id, version:version + '-appguard.1'};
    const payload = {'package.json':JSON.stringify({...fork, private:true, main:'index.js'}),
      'index.js':'// ordinary fixture, never executed\n', LICENSE:'ordinary retained license\n'};
    const pins = data => ({sha256:sha(data), size:Buffer.byteLength(data)});
    const inputs = {}; const result_files = {};
    for (const [name, data] of Object.entries(payload)) {
      write(path.join(consumer, 'node_modules', id, name), data);
      result_files['package/' + name] = pins(data);
    }
    for (const [name, data] of Object.entries({'LICENSE':payload.LICENSE, 'original-package.json':'{}',
      'source.patch':'ordinary source change\n', 'provenance.json':'{}', 'replacements/package.json':payload['package.json']})) {
      const nameIn = id + '/' + name; write(path.join(backports, nameIn), data); inputs[nameIn] = pins(data);
    }
    const upstreamBytes = 'ordinary upstream fixture ' + id;
    const archiveBytes = 'ordinary derivative fixture ' + id;
    const archivePath = `archives/appguard-${id}-${fork.version}.tgz`;
    write(path.join(backports, archivePath), archiveBytes);
    write(path.join(backports, id, 'upstream.tgz'), upstreamBytes);
    records.push({id, fork, inputs, result_files, provenance:id+'/provenance.json',
      upstream:{name:id,version,url:`https://registry.npmjs.org/${id}/-/${id}-${version}.tgz`,path:id+'/upstream.tgz',...pins(upstreamBytes),integrity:sri(upstreamBytes)},
      archive:{path:archivePath,...pins(archiveBytes),integrity:sri(archiveBytes)},
      replacements:[{path:'package/package.json',input:id+'/replacements/package.json'}]});
    rootDev[id] = 'file:../../tools/dependency-backports/' + archivePath;
    overrides[id] = '$'+id;
    packages['node_modules/'+id] = {...fork,resolved:rootDev[id],integrity:sri(archiveBytes),dev:true};
  }
  const retained = path.join(repository,'tools/dependency-backports');
  const resolver = JSON.parse(fs.readFileSync(path.join(retained,'manifest.json'))).packages[2];
  records.push(resolver);
  for (const name of [...Object.keys(resolver.inputs),resolver.upstream.path,resolver.archive.path]) {
    write(path.join(backports,name),fs.readFileSync(path.join(retained,name)));
  }
  write(path.join(root,'scripts/dependencies/build-resolver.cjs'),fs.readFileSync(path.join(repository,'scripts/dependencies/build-resolver.cjs')));
  const resolverPayload = {'package.json':'resolver/replacements/package.json','README.md':'resolver/original-readme.md',
    LICENSE:'resolver/LICENSE','LICENSE.md':'resolver/LICENSE','build/index.d.ts':'resolver/original-index.d.ts'};
  for (const name of ['index','utils/dirs','utils/files','utils/workspaces']) resolverPayload['build/'+name+'.js']='resolver/compiled/'+name+'.js';
  for (const [name,input] of Object.entries(resolverPayload)) write(path.join(consumer,'node_modules/resolve-workspace-root',name),fs.readFileSync(path.join(retained,input)));
  rootDev[resolver.id]='file:../../tools/dependency-backports/'+resolver.archive.path;
  overrides[resolver.id]='$'+resolver.id;
  packages['node_modules/'+resolver.id]={...resolver.fork,resolved:rootDev[resolver.id],integrity:resolver.archive.integrity,dev:true,dependencies:{'js-yaml':'4.3.2',micromatch:'4.0.8'}};
  for (const [location, name, dependencies] of [
    ['node_modules/expo','expo',{'@expo/cli':'1.0.0'}],
    ['node_modules/expo/node_modules/@expo/cli','@expo/cli',{'node-forge':'1.4.0','@expo/code-signing-certificates':'1.0.0'}],
    ['node_modules/@expo/code-signing-certificates','@expo/code-signing-certificates',{'node-forge':'1.4.0'}],
    ['node_modules/@expo/config','@expo/config',{'resolve-workspace-root':'^2.0.0'}],
    ['node_modules/@expo/package-manager','@expo/package-manager',{'resolve-workspace-root':'^2.0.0'}]]) {
    packages[location] = {version:'1.0.0',dependencies,dev:true};
    json(path.join(consumer,location,'package.json'), {name,version:'1.0.0',dependencies,main:'index.js'});
    write(path.join(consumer,location,'index.js'), '// never executed\n');
  }
  const review=JSON.parse(fs.readFileSync(path.join(retained,'resolver/dependency-metadata-readback.json')));
  for (const name of ['js-yaml','micromatch']) {
    packages['node_modules/'+name]=review.dependencies[name].lock;
    for (const file of ['package.json','LICENSE']) write(path.join(consumer,'node_modules',name,file),fs.readFileSync(path.join(repository,'sdk/expo/node_modules',name,file)));
    const metadata=JSON.parse(fs.readFileSync(path.join(consumer,'node_modules',name,'package.json')));
    write(path.join(consumer,'node_modules',name,metadata.main || 'index.js'),'// ordinary origin fixture, never executed\n');
  }
  for (const name of ['expo/bin/cli',
    'expo/node_modules/@expo/cli/build/src/utils/codesigning.js',
    'expo/node_modules/@expo/cli/build/src/run/ios/codeSigning/Security.js',
    '@expo/code-signing-certificates/build/main.js','@expo/config/build/paths/paths.js',
    '@expo/package-manager/build/ios/gemfile.js','@expo/package-manager/build/utils/nodeManagers.js']) {
    write(path.join(consumer,'node_modules',name),'// ordinary import-origin fixture, never executed\n');
  }
  const manifest = {schema:1,packages:records};
  const manifestFile = path.join(backports,'manifest.json');
  const manifestHash = () => {json(manifestFile,manifest); return sha(fs.readFileSync(manifestFile));};
  const lock = {name:'@appguard/expo',version:'0.0.0-experimental.1',lockfileVersion:3,packages:{'':{name:'@appguard/expo',version:'0.0.0-experimental.1',devDependencies:{...rootDev}},...packages}};
  const pkg = {name:lock.name,version:lock.version,devDependencies:rootDev,overrides};
  const savePackage = () => json(path.join(consumer,'package.json'),pkg);
  savePackage();
  const saveLock = () => json(path.join(consumer,'package-lock.json'),lock);
  saveLock();
  return {root,consumer,backports,manifest,lock,pkg,write,json,saveLock,savePackage,manifestHash};
  } catch (error) {fs.rmSync(root,{recursive:true,force:true}); throw error;}
}
function runFixture(action) {const f=fixture(); try {action(f);} finally {fs.rmSync(f.root,{recursive:true,force:true});}}
test('accepts complete ordinary payloads and logical consumer origins without executing them', () => runFixture(f => {
  assert.deepEqual(verifyConsumer(f.root,f.manifestHash()), {schema:1,packages:3,installedFiles:15,consumerBindings:10,verified:true});
}));
for (const mutation of ['manifest','archive','source','sri','payload','missing-file','extra-file','lock-path','lock-name','lock-version','lock-location','missing-dependency','consumer-origin','installed-identity','license']) {
  test('rejects ordinary '+mutation+' drift', () => runFixture(f => {
    const manifestPin = f.manifestHash();
    const b=f.manifest.packages[0];
    if (mutation==='manifest') f.write(path.join(f.backports,'manifest.json'),'{}');
    if (mutation==='archive') f.write(path.join(f.backports,b.archive.path),'changed');
    if (mutation==='source') f.write(path.join(f.backports,'braces/source.patch'),'changed');
    if (mutation==='sri') f.lock.packages['node_modules/braces'].integrity='sha512-'+Buffer.alloc(64).toString('base64');
    if (mutation==='payload') f.write(path.join(f.consumer,'node_modules/braces/index.js'),'changed');
    if (mutation==='missing-file') fs.unlinkSync(path.join(f.consumer,'node_modules/braces/LICENSE'));
    if (mutation==='extra-file') f.write(path.join(f.consumer,'node_modules/braces/extra.js'),'extra');
    if (mutation==='lock-path') f.lock.packages['node_modules/braces'].resolved='file:other.tgz';
    if (mutation==='lock-name') f.lock.packages['node_modules/braces'].name='braces';
    if (mutation==='lock-version') f.lock.packages['node_modules/braces'].version='3.0.3';
    if (mutation==='lock-location') {f.lock.packages['node_modules/micromatch/node_modules/braces']=f.lock.packages['node_modules/braces'];delete f.lock.packages['node_modules/braces'];}
    if (mutation==='missing-dependency') fs.rmSync(path.join(f.consumer,'node_modules/node-forge'),{recursive:true});
    if (mutation==='consumer-origin') {
      const from=path.join(f.consumer,'node_modules/braces'); const to=path.join(f.consumer,'node_modules/micromatch/node_modules/braces');
      fs.mkdirSync(path.dirname(to),{recursive:true}); fs.cpSync(from,to,{recursive:true});
    }
    if (mutation==='installed-identity') f.json(path.join(f.consumer,'node_modules/braces/package.json'),{name:'braces',version:'3.0.3'});
    if (mutation==='license') f.write(path.join(f.consumer,'node_modules/node-forge/LICENSE'),'changed');
    f.saveLock();
    assert.throws(() => verifyConsumer(f.root,manifestPin), {message:'installed backport verification failed'});
  }));
}
for (const mutation of ['unknown-schema-key','fork-identity','archive-sri','result-hash','license-pin','dev-flag','peer-flag','optional-flag']) {
  test('rejects reviewed ordinary '+mutation+' mismatch', () => runFixture(f => {
    const b=f.manifest.packages[0];
    if (mutation==='unknown-schema-key') f.manifest.extra=true;
    if (mutation==='fork-identity') b.fork.name='braces';
    if (mutation==='archive-sri') b.archive.integrity='sha512-'+Buffer.alloc(64).toString('base64');
    if (mutation==='result-hash') b.result_files['package/index.js'].sha256='0'.repeat(64);
    if (mutation==='license-pin') b.inputs['braces/LICENSE'].sha256='0'.repeat(64);
    if (mutation==='dev-flag') f.lock.packages['node_modules/braces'].dev=false;
    if (mutation==='peer-flag') f.lock.packages['node_modules/braces'].peer=true;
    if (mutation==='optional-flag') f.lock.packages['node_modules/braces'].optional=true;
    f.saveLock();
    assert.throws(() => verifyConsumer(f.root,f.manifestHash()), {message:'installed backport verification failed'});
  }));
}
test('ordinary fixture remains bound after relocation with identical lock bytes', () => runFixture(f => {
  const pin=f.manifestHash(); const relocated=path.join(f.root,'relocated');
  fs.mkdirSync(relocated);
  fs.cpSync(path.join(f.root,'sdk'),path.join(relocated,'sdk'),{recursive:true});
  fs.cpSync(path.join(f.root,'tools'),path.join(relocated,'tools'),{recursive:true});
  fs.cpSync(path.join(f.root,'scripts'),path.join(relocated,'scripts'),{recursive:true});
  const before=fs.readFileSync(path.join(relocated,'sdk/expo/package-lock.json'));
  assert.equal(verifyConsumer(relocated,pin).verified,true);
  assert.deepEqual(fs.readFileSync(path.join(relocated,'sdk/expo/package-lock.json')),before);
}));

test('rejects a missing actual CLI import origin even when package metadata exists', () => runFixture(f => {
  const pin=f.manifestHash();
  fs.unlinkSync(path.join(f.consumer,'node_modules/expo/node_modules/@expo/cli/build/src/run/ios/codeSigning/Security.js'));
  assert.throws(() => verifyConsumer(f.root,pin), {message:'installed backport verification failed'});
}));

// These regressions protect the proven metadata mechanism: direct dev archive + exact $ reference.
test('rejects former raw archive override policy even with matching direct dev targets', () => runFixture(f => {
  for (const id of ['braces','node-forge']) f.pkg.overrides[id]=f.pkg.devDependencies[id];
  f.savePackage();
  assert.throws(() => verifyConsumer(f.root,f.manifestHash()), {message:'installed backport verification failed'});
}));
for (const id of ['braces','node-forge','resolve-workspace-root']) {
  for (const mutation of ['missing-dev','wrong-dev-file','nonstr-dev','missing-ref','wrong-ref','nonstr-ref','missing-lock-dev','wrong-lock-dev']) {
    test('rejects '+id+' root policy '+mutation, () => runFixture(f => {
      if (mutation==='missing-dev') delete f.pkg.devDependencies[id];
      if (mutation==='wrong-dev-file') f.pkg.devDependencies[id]='file:other.tgz';
      if (mutation==='nonstr-dev') f.pkg.devDependencies[id]={file:'ordinary-fixture'};
      if (mutation==='missing-ref') delete f.pkg.overrides[id];
      if (mutation==='wrong-ref') f.pkg.overrides[id]='$other';
      if (mutation==='nonstr-ref') f.pkg.overrides[id]={'.':'$'+id};
      if (mutation==='missing-lock-dev') delete f.lock.packages[''].devDependencies[id];
      if (mutation==='wrong-lock-dev') f.lock.packages[''].devDependencies[id]='file:other.tgz';
      f.savePackage(); f.saveLock();
      assert.throws(() => verifyConsumer(f.root,f.manifestHash()), {message:'installed backport verification failed'});
    }));
  }
}
test('rejects an absent root devDependencies object', () => runFixture(f => {
  delete f.pkg.devDependencies; f.savePackage();
  assert.throws(() => verifyConsumer(f.root,f.manifestHash()), {message:'installed backport verification failed'});
}));

for (const source of ['@expo/config/build/paths/paths.js','@expo/package-manager/build/ios/gemfile.js','@expo/package-manager/build/utils/nodeManagers.js']) {
  test('requires actual resolver import origin '+source, () => runFixture(f => {
    fs.unlinkSync(path.join(f.consumer,'node_modules',source));
    assert.throws(() => verifyConsumer(f.root,f.manifestHash()), {message:'installed backport verification failed'});
  }));
}
for (const mutation of ['resolver-shadow','resolver-edge','yaml-version','yaml-sri','yaml-license','compiler-script','resolver-original-license','resolver-added-license']) {
  test('rejects resolver origin/metadata drift '+mutation, () => runFixture(f => {
    if (mutation==='resolver-shadow') fs.cpSync(path.join(f.consumer,'node_modules/resolve-workspace-root'),path.join(f.consumer,'node_modules/@expo/package-manager/node_modules/resolve-workspace-root'),{recursive:true});
    if (mutation==='resolver-edge') f.lock.packages['node_modules/@expo/config'].dependencies['resolve-workspace-root']='^1.0.0';
    if (mutation==='yaml-version') f.lock.packages['node_modules/js-yaml'].version='4.3.1';
    if (mutation==='yaml-sri') f.lock.packages['node_modules/js-yaml'].integrity='sha512-'+Buffer.alloc(64).toString('base64');
    if (mutation==='yaml-license') f.write(path.join(f.consumer,'node_modules/js-yaml/LICENSE'),'changed');
    if (mutation==='compiler-script') f.write(path.join(f.root,'scripts/dependencies/build-resolver.cjs'),'changed');
    if (mutation==='resolver-original-license') f.write(path.join(f.consumer,'node_modules/resolve-workspace-root/LICENSE.md'),'changed');
    if (mutation==='resolver-added-license') f.write(path.join(f.consumer,'node_modules/resolve-workspace-root/LICENSE'),'changed');
    f.saveLock();
    assert.throws(() => verifyConsumer(f.root,f.manifestHash()), {message:'installed backport verification failed'});
  }));
}
