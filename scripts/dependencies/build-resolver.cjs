'use strict';
// Controlled transpilation of unchanged publisher source; never load its old bundle.
const fs = require('node:fs');
const path = require('node:path');
const {createHash} = require('node:crypto');
const root = path.resolve(__dirname, '../..');
const retained = path.join(root, 'tools/dependency-backports');
const ERROR = 'resolver build verification failed';
const compilerFiles = {
  'package.json': {sha256:'9332e97c30d3e53ed54910b89207ed657fb444066484df6e5b6965bf130865e9',size:3527},
  'lib/typescript.js': {sha256:'569177652966bd528c319171c7dd22860dbf72bde116cbc4f644f1d02bb12e39',size:9144216},
  'LICENSE.txt': {sha256:'a7d00bfd54525bc694b6e32f64c7ebcf5e6b7ae3657be5cc12767bce74654a47',size:9197},
};
const sourcePins = {
  'resolver/src/index.ts': {sha256:'2f8cf6bf8b4dac2720a2834b56400ba28973c0c5dec3123879cf2c9764a0f640',size:5864},
  'resolver/src/utils/dirs.ts': {sha256:'4fc2cc6c11006d5c4b6f30582294efd64126ab1695c5cba9bd52738ed16cef5b',size:1074},
  'resolver/src/utils/files.ts': {sha256:'1727f0d92eebd7fa4ffa4f2dc2970ea3838f15304924f12201ba1a3da2fdcca8',size:814},
  'resolver/src/utils/workspaces.ts': {sha256:'d063b82b49eefdf60fa1a305031b65c87508691f1ba859203ffcc3ccf14c07f9',size:1102},
};
const compilerIntegrity = 'sha512-y2TvuxSZPDyQakkFRPZHKFm+KKVqIisdg9/CZwm9ftvKXLP8NRWj38/ODjNbr43SsoXqNuAisEf1GdCxqWcdBw==';
const mappings = {
  'resolver/src/index.ts': 'resolver/compiled/index.js',
  'resolver/src/utils/dirs.ts': 'resolver/compiled/utils/dirs.js',
  'resolver/src/utils/files.ts': 'resolver/compiled/utils/files.js',
  'resolver/src/utils/workspaces.ts': 'resolver/compiled/utils/workspaces.js',
};
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
function check(value) { if (!value) throw new Error(ERROR); }
function pinned(base, name, pin) {
  check(typeof name === 'string' && /^[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*$/.test(name));
  check(!name.split('/').some(p => p === '.' || p === '..'));
  let current = base;
  for (const part of name.split('/')) {current = path.join(current, part); check(!fs.lstatSync(current).isSymbolicLink());}
  const stat = fs.statSync(current); check(stat.isFile() && stat.size === pin.size && stat.size <= 16*1024*1024);
  const bytes = fs.readFileSync(current); check(hash(bytes) === pin.sha256); return bytes;
}
function compile() {
  const recipe = JSON.parse(fs.readFileSync(path.join(retained, 'resolver/recipe.json')));
  check(process.versions.node === '22.23.2' && recipe.schema === 1 && recipe.compiler.name === 'typescript' && recipe.compiler.version === '6.0.3');
  check(recipe.compiler.integrity === compilerIntegrity);
  check(JSON.stringify(recipe.compiler.files) === JSON.stringify(compilerFiles));
  check(JSON.stringify(recipe.sources) === JSON.stringify(sourcePins));
  check(JSON.stringify(recipe.mapping) === JSON.stringify(mappings));
  check(JSON.stringify(recipe.options) === JSON.stringify({module:'CommonJS',target:'ES2020',esModuleInterop:true}));
  check(recipe.script.path === 'scripts/dependencies/build-resolver.cjs');
  pinned(root, recipe.script.path, recipe.script);
  const compilerRoot = path.join(root, 'sdk/expo/node_modules/typescript');
  for (const [name, pin] of Object.entries(recipe.compiler.files)) pinned(compilerRoot, name, pin);
  const metadata = JSON.parse(fs.readFileSync(path.join(compilerRoot,'package.json')));
  const lock = JSON.parse(fs.readFileSync(path.join(root,'sdk/expo/package-lock.json')));
  check(metadata.name === 'typescript' && metadata.version === '6.0.3');
  check(lock.packages['node_modules/typescript'].version === '6.0.3' && lock.packages['node_modules/typescript'].integrity === recipe.compiler.integrity);
  const ts = require(path.join(compilerRoot, 'lib/typescript.js'));
  const outputs = {};
  for (const [input, output] of Object.entries(mappings)) {
    const source = pinned(retained, input, recipe.sources[input]).toString('utf8');
    const result = ts.transpileModule(source, {fileName:input, reportDiagnostics:true,
      compilerOptions:{module:ts.ModuleKind.CommonJS,target:ts.ScriptTarget.ES2020,esModuleInterop:true}});
    check(!result.diagnostics?.length && !result.sourceMapText);
    const bytes = Buffer.from(result.outputText, 'utf8');
    check(bytes.length === recipe.outputs[output].size && hash(bytes) === recipe.outputs[output].sha256);
    outputs[output] = bytes;
  }
  return {recipe, outputs};
}
function main() {
  const args = process.argv.slice(2);
  check((args.length === 1 && args[0] === '--check') || (args.length === 2 && args[0] === '--output'));
  const {recipe, outputs} = compile();
  if (args[0] === '--check') {
    for (const [name, bytes] of Object.entries(outputs)) check(pinned(retained,name,recipe.outputs[name]).equals(bytes));
  } else {
    const out = path.resolve(args[1]); fs.mkdirSync(out, {mode:0o700});
    for (const [name, bytes] of Object.entries(outputs)) {
      const file = path.join(out,name.slice('resolver/compiled/'.length));
      fs.mkdirSync(path.dirname(file), {recursive:true,mode:0o700});
      fs.writeFileSync(file,bytes,{flag:'wx',mode:0o600});
    }
  }
  console.log(JSON.stringify({verified:true, outputs:4, controlled_transpilation:true,
    publisher_build_reproduced:false, typecheck_verified:false, producer_closure_verified:false, release_ready:false}));
}
try {main();} catch {console.error(ERROR); process.exitCode=1;}
