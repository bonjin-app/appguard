'use strict';
// Data-only checks: resolving an entrypoint never evaluates candidate exports.
const fs = require('node:fs');
const path = require('node:path');
const {createHash} = require('node:crypto');
const {createRequire} = require('node:module');
const MANIFEST_SHA256 = 'fbc0a7150a52b18c6090b750fa07e333667f7f8e49d5e3e5520059e778599b22';
const ERROR = 'installed backport verification failed';
const VERSIONS = {braces:'3.0.3', 'node-forge':'1.4.0'};
const MAX_BYTES = 32 * 1024 * 1024;
function check(condition) { if (!condition) throw new Error(ERROR); }
function object(value) { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function keys(value, names) {
  check(object(value) && Object.keys(value).sort().join('|') === names.split(' ').sort().join('|'));
}
function relative(name, prefix) {
  check(typeof name === 'string' && /^[A-Za-z0-9_@.+-]+(?:\/[A-Za-z0-9_@.+-]+)*$/.test(name));
  check(name.split('/').every(part => part !== '.' && part !== '..'));
  if (prefix) check(name.startsWith(prefix + '/'));
  return name;
}
function ordinary(root, name) {
  relative(name);
  check(fs.lstatSync(root).isDirectory() && !fs.lstatSync(root).isSymbolicLink());
  let current = root;
  for (const part of name.split('/')) {
    current = path.join(current, part);
    check(!fs.lstatSync(current).isSymbolicLink());
  }
  return current;
}
function read(root, name, cap = MAX_BYTES) {
  const file = ordinary(root, name); const stat = fs.lstatSync(file);
  check(stat.isFile() && stat.size <= cap);
  return fs.readFileSync(file);
}
function hash(data, algorithm='sha256', encoding='hex') {return createHash(algorithm).update(data).digest(encoding);}
function pinned(root, name, pin, withSRI=false) {
  check(object(pin) && Number.isSafeInteger(pin.size) && pin.size >= 0 && pin.size <= MAX_BYTES);
  check(typeof pin.sha256 === 'string' && /^[a-f0-9]{64}$/.test(pin.sha256));
  const bytes = read(root,name);
  check(bytes.length === pin.size && hash(bytes) === pin.sha256);
  if (withSRI) check(pin.integrity === 'sha512-' + hash(bytes,'sha512','base64'));
  return bytes;
}
function json(root,name) {return JSON.parse(read(root,name,2*1024*1024));}
function validateRecord(record) {
  keys(record,'id upstream fork inputs replacements result_files archive provenance');
  const id = record.id; const version = VERSIONS[id]; check(version);
  keys(record.fork,'name version');
  check(record.fork.name === '@appguard/'+id && record.fork.version === version+'-appguard.1');
  keys(record.archive,'path sha256 integrity size');
  check(record.archive.path === `archives/appguard-${id}-${version}-appguard.1.tgz` && record.archive.size <= 16*1024*1024);
  keys(record.upstream,'name version url path sha256 integrity size');
  check(record.upstream.name === id && record.upstream.version === version);
  check(record.upstream.path === id+'/upstream.tgz' && record.upstream.url === `https://registry.npmjs.org/${id}/-/${id}-${version}.tgz`);
  check(record.upstream.size <= 16*1024*1024);
  for (const [inventory,prefix] of [[record.inputs,id],[record.result_files,'package']]) {
    check(object(inventory) && Object.keys(inventory).length >= 1 && Object.keys(inventory).length <= 512);
    let size = 0;
    for (const [name,pin] of Object.entries(inventory)) {
      relative(name,prefix); keys(pin,'sha256 size');
      check(Number.isSafeInteger(pin.size) && pin.size >= 0 && pin.size <= MAX_BYTES && /^[a-f0-9]{64}$/.test(pin.sha256));
      size += pin.size;
    }
    check(size <= MAX_BYTES);
  }
  for (const name of ['LICENSE','original-package.json','source.patch','replacements/package.json','provenance.json']) check(Object.hasOwn(record.inputs,id+'/'+name));
  check(record.provenance === id+'/provenance.json');
  check(Array.isArray(record.replacements) && record.replacements.length >= 1 && record.replacements.length <= 512);
  const seen = new Set();
  for (const replacement of record.replacements) {
    keys(replacement,'path input'); relative(replacement.path,'package');
    check(replacement.path !== 'package/LICENSE' && !seen.has(replacement.path)); seen.add(replacement.path);
    check(Object.hasOwn(record.inputs,replacement.input) && Object.hasOwn(record.result_files,replacement.path));
    check(JSON.stringify(record.inputs[replacement.input]) === JSON.stringify(record.result_files[replacement.path]));
  }
  check(seen.has('package/package.json'));
  for (const key of ['sha256','size']) check(record.inputs[id+'/LICENSE'][key] === record.result_files['package/LICENSE'][key]);
}
function inventory(root) {
  const files = []; let entries = 0;
  function visit(directory, prefix='') {
    check(fs.lstatSync(directory).isDirectory() && !fs.lstatSync(directory).isSymbolicLink());
    for (const name of fs.readdirSync(directory)) {
      check(++entries <= 1024);
      const rel = prefix + name; relative(rel);
      const full = path.join(directory,name); const stat = fs.lstatSync(full);
      check(!stat.isSymbolicLink());
      if (stat.isDirectory()) visit(full,rel+'/');
      else {check(stat.isFile()); files.push(rel); check(files.length <= 512);}
    }
  }
  visit(root); return files.sort();
}
function verify(root, expectedManifestHash) {
  root = fs.realpathSync(root);
  const consumer = path.join(root,'sdk/expo'); const backports = path.join(root,'tools/dependency-backports');
  const manifestBytes = read(backports,'manifest.json',2*1024*1024);
  check(hash(manifestBytes) === expectedManifestHash);
  const manifest = JSON.parse(manifestBytes); keys(manifest,'schema packages');
  check(manifest.schema === 1 && Array.isArray(manifest.packages) && manifest.packages.length === 2);
  check(manifest.packages.map(p=>p.id).join('|') === 'braces|node-forge');
  const pkg = json(consumer,'package.json'); const lock = json(consumer,'package-lock.json');
  check(pkg.name === '@appguard/expo' && lock.name === pkg.name && lock.version === pkg.version && lock.lockfileVersion === 3);
  check(object(lock.packages) && lock.packages[''].name === pkg.name && lock.packages[''].version === pkg.version);
  check(object(pkg.overrides) && object(pkg.devDependencies) && object(lock.packages[''].devDependencies));
  let installedFiles = 0;
  const installed = {};
  for (const record of manifest.packages) {
    validateRecord(record);
    for (const [name,pin] of Object.entries(record.inputs)) pinned(backports,name,pin);
    pinned(backports,record.upstream.path,record.upstream,true);
    pinned(backports,record.archive.path,record.archive,true);
    const expectedResolved = 'file:../../tools/dependency-backports/'+record.archive.path;
    check(pkg.devDependencies[record.id] === expectedResolved && pkg.overrides[record.id] === '$'+record.id);
    check(lock.packages[''].devDependencies[record.id] === expectedResolved);
    const location = 'node_modules/'+record.id;
    const matches = Object.entries(lock.packages).filter(([name,entry]) =>
      name === location || name.endsWith('/'+location) || entry.name === record.fork.name);
    check(matches.length === 1 && matches[0][0] === location);
    const entry = matches[0][1];
    check(entry.name === record.fork.name && entry.version === record.fork.version && entry.resolved === expectedResolved && entry.integrity === record.archive.integrity);
    check(entry.dev === true && entry.optional === undefined && entry.peer === undefined && entry.link === undefined);
    const directory = ordinary(consumer,location); installed[record.id] = directory;
    const expected = Object.keys(record.result_files).map(name=>name.slice('package/'.length)).sort();
    check(JSON.stringify(inventory(directory)) === JSON.stringify(expected));
    for (const name of expected) {pinned(directory,name,record.result_files['package/'+name]); installedFiles++;}
    const metadata = json(directory,'package.json');
    check(metadata.name === record.fork.name && metadata.version === record.fork.version && metadata.private === true);
  }
  function consumerPackage(name, location) {
    const matches = Object.keys(lock.packages).filter(key=>key === 'node_modules/'+name || key.endsWith('/node_modules/'+name));
    check(matches.length === 1 && matches[0] === location);
    const directory = ordinary(consumer,location); const metadata = json(directory,'package.json');
    check(metadata.name === name && metadata.version === lock.packages[location].version);
    return {directory,metadata,locked:lock.packages[location],require:createRequire(path.join(directory,'package.json'))};
  }
  function origin(from, name) {
    // Resolve from the actual importing file, including its nearer node_modules search paths.
    read(from.directory,name,MAX_BYTES);
    return createRequire(path.join(from.directory,name));
  }
  const top = createRequire(path.join(consumer,'package.json'));
  const expo = consumerPackage('expo','node_modules/expo');
  check(top.resolve('expo/package.json') === path.join(expo.directory,'package.json'));
  const cli = consumerPackage('@expo/cli','node_modules/expo/node_modules/@expo/cli');
  const expoOrigin = origin(expo,'bin/cli');
  check(expoOrigin.resolve('@expo/cli/package.json') === path.join(cli.directory,'package.json'));
  check(typeof expo.metadata.dependencies?.['@expo/cli'] === 'string' && expo.metadata.dependencies['@expo/cli'] === expo.locked.dependencies?.['@expo/cli']);
  const signing = consumerPackage('@expo/code-signing-certificates','node_modules/@expo/code-signing-certificates');
  const signingOrigin = origin(cli,'build/src/utils/codesigning.js');
  check(typeof cli.metadata.dependencies?.['@expo/code-signing-certificates'] === 'string' && cli.metadata.dependencies['@expo/code-signing-certificates'] === cli.locked.dependencies?.['@expo/code-signing-certificates']);
  check(signingOrigin.resolve('@expo/code-signing-certificates/package.json') === path.join(signing.directory,'package.json'));
  const micromatch = consumerPackage('micromatch','node_modules/micromatch');
  check(top.resolve('micromatch/package.json') === path.join(micromatch.directory,'package.json'));
  let consumerBindings = 2;
  for (const [from,source,id] of [
    [cli,'build/src/run/ios/codeSigning/Security.js','node-forge'],
    [signing,'build/main.js','node-forge'],[micromatch,'index.js','braces']]) {
    check(typeof from.metadata.dependencies?.[id] === 'string' && from.metadata.dependencies[id] === from.locked.dependencies?.[id]);
    const resolver = origin(from,source);
    check(resolver.resolve(id+'/package.json') === path.join(installed[id],'package.json'));
    const entry = resolver.resolve(id);
    const name = path.relative(installed[id],entry).split(path.sep).join('/');
    check(Object.hasOwn(manifest.packages.find(p=>p.id===id).result_files,'package/'+name));
    consumerBindings++;
  }
  return {schema:1,packages:2,installedFiles,consumerBindings,verified:true};
}
// Explicit roots/pins are for owned fixture tests; CLI always uses fixed repository paths and reviewed pin.
function verifyConsumer(root, expectedManifestHash=MANIFEST_SHA256) {
  try {return verify(root,expectedManifestHash);} catch {throw new Error(ERROR);}
}
module.exports = {verifyConsumer};
if (require.main === module) {
  try {
    check(process.argv.length === 2);
    console.log(JSON.stringify(verifyConsumer(path.resolve(__dirname,'../..'))));
  } catch {console.error(ERROR); process.exitCode=1;}
}
