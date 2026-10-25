"""Normal copied semantic fixtures; these do not prove npm installation/adoption."""
import hashlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
BACKPORTS = ROOT / 'tools/dependency-backports'
NODE = shutil.which('node')
spec = importlib.util.spec_from_file_location('resolver_backport_builder', ROOT / 'scripts/dependencies/build-backports.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class ResolverBackportTests(unittest.TestCase):
    def run_node(self, script, cwd=ROOT):
        self.assertIsNotNone(NODE, 'Node must be installed; no runtime download is supported')
        result = subprocess.run([NODE, '-e', script], cwd=cwd, capture_output=True, text=True, timeout=45)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout

    def semantic_fixture(self, base):
        """Copy exact installed nonaffected bytes; patched braces comes from tracked archive."""
        root = base / 'consumer'
        root.mkdir(mode=0o700)
        modules = root / 'node_modules'
        modules.mkdir(mode=0o700)
        manifest = builder.load_manifest(BACKPORTS)
        lock = json.loads((ROOT / 'sdk/expo/package-lock.json').read_bytes())['packages']
        retained = json.loads((BACKPORTS / 'resolver/runtime-dependencies.json').read_bytes())
        for name, package in retained['packages'].items():
            source = ROOT / 'sdk/expo/node_modules' / name
            self.assertEqual(lock['node_modules/' + name], package['lock'])
            actual = {p.relative_to(source).as_posix() for p in source.rglob('*') if p.is_file()}
            self.assertEqual(actual, set(package['files']))
            for name_in, pin in package['files'].items():
                content = builder.checked_read(source, name_in, pin)
                target = modules / name / name_in
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
                target.chmod(0o600)
        direct = {}
        payloads = {}
        for record in (manifest['packages'][0], manifest['packages'][2]):
            archive = builder.checked_read(BACKPORTS, record['archive']['path'], record['archive'])
            archive_name = Path(record['archive']['path']).name
            (root / 'archives').mkdir(exist_ok=True)
            (root / 'archives' / archive_name).write_bytes(archive)
            direct[record['id']] = 'file:archives/' + archive_name
            payload = builder.upstream_files(archive)
            self.assertEqual({n: builder.digest(v) for n, v in payload.items()}, record['result_files'])
            for name, content in payload.items():
                target = modules / record['id'] / name.removeprefix('package/')
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
                target.chmod(0o600)
            payloads[record['id']] = record['result_files']
        policy = {'name': 'owned-resolver-semantic-fixture', 'private': True, 'devDependencies': direct,
                  'overrides': {name: '$' + name for name in direct}}
        (root / 'package.json').write_text(json.dumps(policy))
        # Verify each fixture's own policy, full copied payload and actual import origins before use.
        self.run_node(r'''
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const {createRequire}=require('node:module'); const root=process.cwd();
const policy=JSON.parse(fs.readFileSync('package.json'));
for(const id of ['braces','resolve-workspace-root']) {
 assert.equal(policy.overrides[id],'$'+id); assert.ok(policy.devDependencies[id].startsWith('file:archives/'));
 const m=require('./node_modules/'+id+'/package.json');assert.equal(m.name,'@appguard/'+id);
}
const from=createRequire(path.join(root,'node_modules/resolve-workspace-root/build/utils/workspaces.js'));
for(const [id,version] of [['js-yaml','4.3.2'],['micromatch','4.0.8']]) {
 assert.equal(from.resolve(id+'/package.json'),path.join(root,'node_modules',id,'package.json'));
 assert.equal(JSON.parse(fs.readFileSync(from.resolve(id+'/package.json'))).version,version);
}
const micromatch=createRequire(path.join(root,'node_modules/micromatch/index.js'));
assert.equal(micromatch.resolve('braces/package.json'),path.join(root,'node_modules/braces/package.json'));
assert.equal(micromatch.resolve('braces'),path.join(root,'node_modules/braces/index.js'));
''', root)
        for ident, inventory in payloads.items():
            directory = modules / ident
            self.assertEqual({p.relative_to(directory).as_posix() for p in directory.rglob('*') if p.is_file()},
                             {n.removeprefix('package/') for n in inventory})
            for name, pin in inventory.items():
                self.assertEqual(builder.digest((directory / name.removeprefix('package/')).read_bytes()), pin)
        return root

    def test_exact_third_record_contract(self):
        manifest = builder.load_manifest(BACKPORTS)
        self.assertEqual([r['id'] for r in manifest['packages']], ['braces', 'node-forge', 'resolve-workspace-root'])
        record = manifest['packages'][2]
        self.assertEqual(record['upstream']['path'], 'resolver/upstream.tgz')
        self.assertEqual(len(record['result_files']), 9)
        payload = builder.upstream_files(builder.assemble_package(BACKPORTS, record))
        metadata = json.loads(payload['package/package.json'])
        self.assertEqual(metadata['files'], ['build'])
        self.assertEqual(metadata['dependencies'], {'js-yaml': '4.3.2', 'micromatch': '4.0.8'})
        self.assertEqual(metadata['main'], 'build/index.js')
        self.assertEqual(metadata['types'], 'build/index.d.ts')
        self.assertEqual(payload['package/LICENSE'], payload['package/LICENSE.md'])
        self.assertEqual(hashlib.sha256(payload['package/build/index.d.ts']).hexdigest(), '4e5e42c6632ef9e9859a8d22b4c71572c2a19f8088a84ccaeab7f2f0a30a623e')
        self.assertNotEqual(hashlib.sha256(payload['package/build/index.js']).hexdigest(), 'ee3be37ce5bce6f0de05ee538653d13f8cbf6a7ec8c8f4ed24466025e5e34f2e')

    def test_independent_four_output_compilation(self):
        with tempfile.TemporaryDirectory() as temp:
            outputs = []
            for suffix in ('first', 'second'):
                target = Path(temp) / suffix
                result = subprocess.run([NODE, str(ROOT / 'scripts/dependencies/build-resolver.cjs'), '--output', str(target)],
                                        cwd=ROOT, capture_output=True, text=True, timeout=45)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(json.loads(result.stdout)['outputs'], 4)
                outputs.append({p.relative_to(target).as_posix(): p.read_bytes() for p in target.rglob('*') if p.is_file()})
            self.assertEqual(outputs[0], outputs[1])
            self.assertEqual(outputs[0], {name.removeprefix('resolver/compiled/'): (BACKPORTS / name).read_bytes()
                                         for name in builder.RESOLVER_OUTPUTS})
            print(json.dumps({'independent_builds': 2, 'outputs_per_build': 4, 'matching_tracked_outputs': True}))

    def test_normal_filesystem_four_export_contracts(self):
        with tempfile.TemporaryDirectory() as temp:
            root = self.semantic_fixture(Path(temp))
            output = self.run_node(r'''
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const api=require('resolve-workspace-root');
assert.deepEqual(Object.keys(api).sort(),['getWorkspaceGlobs','getWorkspaceGlobsAsync','resolveWorkspaceRoot','resolveWorkspaceRootAsync']);
const base=path.join(process.cwd(),'workspaces');fs.mkdirSync(base);
const make=(name)=>{const p=path.join(base,name);fs.mkdirSync(p,{recursive:true});return p;};
const pkg=(root,workspaces)=>fs.writeFileSync(path.join(root,'package.json'),JSON.stringify({private:true,workspaces}));
let cases=0;
async function globs(root,expected,options){assert.deepEqual(api.getWorkspaceGlobs(root,options),expected);assert.deepEqual(await api.getWorkspaceGlobsAsync(root,options),expected);cases++;}
async function resolve(start,expected,options){assert.equal(api.resolveWorkspaceRoot(start,options),expected);assert.equal(await api.resolveWorkspaceRootAsync(start,options),expected);cases++;}
(async()=>{
const absent=make('absent');await globs(absent,null);await resolve(absent,null);
const npm=make('npm');pkg(npm,['packages/*']);const member=make('npm/packages/one');await globs(npm,['packages/*']);await resolve(member,npm);await resolve(npm,npm);await resolve(make('npm/other'),null);
const yarn=make('yarn');pkg(yarn,{packages:['modules/*']});await globs(yarn,['modules/*']);await resolve(make('yarn/modules/one'),yarn);
const pnpm=make('pnpm');fs.writeFileSync(path.join(pnpm,'pnpm-workspace.yaml'),'packages:\n  - packages/*\n  - "!packages/excluded"\n');pkg(pnpm,['apps/*']);
await globs(pnpm,['packages/*','!packages/excluded']);await resolve(make('pnpm/packages/one'),pnpm);await resolve(make('pnpm/packages/excluded'),null);await resolve(make('pnpm/apps/one'),pnpm);
await globs(pnpm,['apps/*'],{pnpmWorkspaces:false});await globs(pnpm,['packages/*','!packages/excluded'],{packageWorkspaces:false});
await resolve(path.join(pnpm,'apps/one'),null,{packageWorkspaces:false});await resolve(path.join(pnpm,'packages/one'),null,{pnpmWorkspaces:false});
await globs(pnpm,null,{packageWorkspaces:false,pnpmWorkspaces:false});await resolve(pnpm,null,{packageWorkspaces:false,pnpmWorkspaces:false});
await globs(pnpm,['packages/*','!packages/excluded'],{packageWorkspaces:true,pnpmWorkspaces:true});
const nested=make('nested');pkg(nested,['packages/**']);const inner=make('nested/packages/inner');pkg(inner,['modules/*']);await resolve(make('nested/packages/inner/modules/one'),inner);await resolve(make('nested/packages/inner/other'),nested);
const invalid=make('invalid');fs.writeFileSync(path.join(invalid,'package.json'),'{ ordinary invalid json');await globs(invalid,null);await resolve(invalid,null);
fs.writeFileSync(path.join(invalid,'pnpm-workspace.yaml'),'packages: [unterminated');await globs(invalid,null);pkg(invalid,['valid/*']);await globs(invalid,['valid/*']);await resolve(make('invalid/valid/one'),invalid);
fs.writeFileSync(path.join(invalid,'pnpm-workspace.yaml'),'packages:\n  - preferred/*\n');fs.writeFileSync(path.join(invalid,'package.json'),'{ invalid');await globs(invalid,['preferred/*']);await resolve(make('invalid/preferred/one'),invalid);
const shape=make('shape');fs.writeFileSync(path.join(shape,'package.json'),'{}');fs.writeFileSync(path.join(shape,'pnpm-workspace.yaml'),'packages: ordinary-scalar');await globs(shape,null);
const directory=make('directory');fs.mkdirSync(path.join(directory,'package.json'));fs.mkdirSync(path.join(directory,'pnpm-workspace.yaml'));await globs(directory,null);await resolve(directory,null);
const regular=path.join(base,'regular-file');fs.writeFileSync(regular,'ordinary');
for(const name of ['getWorkspaceGlobs','resolveWorkspaceRoot'])assert.throws(()=>api[name](regular),{code:'ENOTDIR'});
for(const name of ['getWorkspaceGlobsAsync','resolveWorkspaceRootAsync'])await assert.rejects(api[name](regular),{code:'ENOTDIR'});
const empty=make('empty');pkg(empty,[]);await resolve(empty,empty);await globs(empty,[]);
const old=process.cwd();process.chdir(npm);try{assert.equal(api.resolveWorkspaceRoot(),npm);assert.equal(await api.resolveWorkspaceRootAsync(),npm);assert.deepEqual(api.getWorkspaceGlobs(),['packages/*']);assert.deepEqual(await api.getWorkspaceGlobsAsync(),['packages/*']);}finally{process.chdir(old);}
const workspaces=require('resolve-workspace-root/build/utils/workspaces');assert.equal(workspaces.pathMatchesWorkspaceGlobs(['packages/*'],'packages/one'),true);assert.equal(workspaces.pathMatchesWorkspaceGlobs(['packages/*'],'/packages/one'),false);
const dirs=require('resolve-workspace-root/build/utils/dirs');const seen=[];assert.equal(dirs.searchParentDirs(member,(current,relative)=>{seen.push([current,relative]);if(current===npm)return current;}),npm);assert.deepEqual(seen,[[member,''],[path.dirname(member),'one'],[npm,path.join('packages','one')]]);
const asyncSeen=[];assert.equal(await dirs.searchParentDirsAsync(member,async(current,relative)=>{asyncSeen.push([current,relative]);if(current===npm)return current;}),npm);assert.deepEqual(asyncSeen,seen);
console.log(JSON.stringify({semantic_fixture:'copied',sync_async_cases:cases,read_error_exports:4,exports:4,npm_installation_verified:false}));
})().catch(error=>{console.error(error);process.exitCode=1;});
''', root)
            self.assertEqual(json.loads(output)['exports'], 4)
            self.assertGreaterEqual(json.loads(output)['sync_async_cases'], 30)
            print(output.strip())

    def test_original_declaration_type_consumer(self):
        recipe = json.loads((BACKPORTS / 'resolver/recipe.json').read_bytes())
        for name, pin in recipe['compiler']['files'].items():
            builder.checked_read(ROOT / 'sdk/expo/node_modules/typescript', name, pin)
        with tempfile.TemporaryDirectory() as temp:
            root = self.semantic_fixture(Path(temp))
            (root / 'consumer.ts').write_text('''import { resolveWorkspaceRoot, resolveWorkspaceRootAsync, getWorkspaceGlobs, getWorkspaceGlobsAsync } from 'resolve-workspace-root';
const root: string | null = resolveWorkspaceRoot();
const asyncRoot: Promise<string | null> = resolveWorkspaceRootAsync('.', {pnpmWorkspaces: false});
const globs: string[] | null = getWorkspaceGlobs('.', {packageWorkspaces: true});
const asyncGlobs: Promise<string[] | null> = getWorkspaceGlobsAsync();
// @ts-expect-error async resolution returns a promise
const wrong: string | null = resolveWorkspaceRootAsync();
// @ts-expect-error option values are boolean
getWorkspaceGlobs('.', {pnpmWorkspaces: 'yes'});
void [root, asyncRoot, globs, asyncGlobs, wrong];
''')
            script = 'const ts=require(' + json.dumps(str(ROOT / 'sdk/expo/node_modules/typescript/lib/typescript.js')) + r''');
const program=ts.createProgram(['consumer.ts'],{noEmit:true,strict:true,target:ts.ScriptTarget.ES2020,module:ts.ModuleKind.CommonJS,types:[]});
const diagnostics=ts.getPreEmitDiagnostics(program);
if(diagnostics.length){console.error(diagnostics.map(d=>ts.flattenDiagnosticMessageText(d.messageText,'\n')).join('\n'));process.exitCode=1;}else console.log(JSON.stringify({type_consumer_verified:true,compiler:ts.version}));
'''
            output = self.run_node(script, root)
            self.assertTrue(json.loads(output)['type_consumer_verified'])
            print(output.strip())

    def test_hash_consistent_resolver_policy_mutations_fail(self):
        # Ordinary own metadata/legal mistakes with matching record hashes must fail policy checks.
        for mode in ('retained-license', 'original-license', 'metadata-files', 'source', 'output', 'script'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temp:
                root = Path(temp) / 'tools/dependency-backports'
                shutil.copytree(BACKPORTS, root)
                script = Path(temp) / 'scripts/dependencies/build-resolver.cjs'
                script.parent.mkdir(parents=True)
                shutil.copyfile(ROOT / 'scripts/dependencies/build-resolver.cjs', script)
                record = copy.deepcopy(builder.load_manifest(root)['packages'][2])
                if mode == 'original-license':
                    record['replacements'].append({'path': 'package/LICENSE.md', 'input': 'resolver/source.patch'})
                elif mode == 'script':
                    script.write_bytes(script.read_bytes() + b'\n// ordinary drift\n')
                else:
                    name = {'retained-license': 'resolver/LICENSE', 'metadata-files': 'resolver/replacements/package.json',
                            'source': 'resolver/src/index.ts', 'output': 'resolver/compiled/index.js'}[mode]
                    data = (root / name).read_bytes()
                    if mode == 'metadata-files':
                        value = json.loads(data); value['files'] = ['build/index.js', 'build/index.d.ts']
                        data = json.dumps(value).encode()
                    else:
                        data += b'\nordinary changed bytes\n'
                    (root / name).write_bytes(data)
                    record['inputs'][name] = builder.digest(data)
                    for replacement in record['replacements']:
                        if replacement['input'] == name:
                            record['result_files'][replacement['path']] = builder.digest(data)
                if mode in ('retained-license', 'original-license'):
                    # Normal nine-file payload with internally matching input/result/archive hashes.
                    # Only the original legal-byte policy can authorize these replacements.
                    files = builder.upstream_files((root / record['upstream']['path']).read_bytes())
                    for replacement in record['replacements']:
                        files[replacement['path']] = (root / replacement['input']).read_bytes()
                    record['result_files'] = {n: builder.digest(d) for n, d in files.items()}
                    stream = io.BytesIO()
                    with tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as archive:
                        for name, content in sorted(files.items()):
                            entry = tarfile.TarInfo(name); entry.size = len(content); entry.mode = 0o644
                            archive.addfile(entry, io.BytesIO(content))
                    content = builder.stored_gzip(stream.getvalue())
                    (root / record['archive']['path']).write_bytes(content)
                    record['archive'].update(builder.digest(content), integrity=builder.integrity(content))
                    self.assertEqual(record['result_files'], {n: builder.digest(d) for n, d in builder.upstream_files(content).items()})
                    self.assertEqual(record['archive']['integrity'], builder.integrity(content))
                with self.assertRaisesRegex(builder.BackportError, '^backport verification failed$'):
                    builder.assemble_package(root, record)


if __name__ == '__main__':
    unittest.main()
