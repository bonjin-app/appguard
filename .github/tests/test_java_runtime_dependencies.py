import hashlib
import importlib.util
import json
import os
import subprocess
import tempfile
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT/'scripts/qualification/java_runtime_dependencies.py'
LOCK = ROOT/'scripts/qualification/java-runtime-dependencies.lock'
INSTALLER = ROOT/'scripts/qualification/install_java_runtime_dependencies.sh'
WORKFLOW = ROOT/'.github/workflows/java-native-runtime.yml'


def workflow_step(name):
    lines=WORKFLOW.read_text().splitlines();start=lines.index('      - name: '+name)
    body=[];begin=next(index for index in range(start+1,len(lines)) if lines[index]=='        run: |')
    for line in lines[begin+1:]:
        if line and not line.startswith('          '):break
        body.append(line[10:] if line else '')
    return '\n'.join(body)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class DependencyClosureTests(unittest.TestCase):
    def module(self):
        self.assertTrue(MODULE.is_file(), 'dependency closure validator is required')
        spec = importlib.util.spec_from_file_location('java_dependencies', MODULE)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        return module

    def fixture(self, arch='amd64'):
        module = self.module(); raw = LOCK.read_bytes(); lock = module.parse_lock(raw)
        rows = lock['packages'][arch]
        archives = ''.join('ARCHIVE\t{name}\t{version}\t{architecture}\t{sha256}\t{size}\n'.format(**row) for row in rows)
        installed = ''.join('INSTALLED\t{name}\t{version}\t{architecture}\n'.format(**row) for row in rows)
        installed += 'INSTALLED\tlibc6\t2.41-12+deb13u4\t'+arch+'\n'
        verification = 'VERIFY\tapt-signatures\ttrue\nVERIFY\tarchive-hashes\ttrue\nVERIFY\tinstalled-identities\ttrue\nKEYRING\t' + 'a'*64 + '\n'
        hashes = {'lock':sha(raw), 'keyring':'a'*64, **lock['releases'], 'archives':sha(archives.encode()),
            'installed':sha(installed.encode()), 'verification':sha(verification.encode())}
        protocol = 'CLOSURE\t1\n' + ''.join('HASH\t'+key+'\t'+value+'\n' for key,value in hashes.items())
        protocol += verification + 'ARCHIVES_BEGIN\n' + archives + 'ARCHIVES_END\t8\n'
        protocol += 'INSTALLED_BEGIN\n' + installed + 'INSTALLED_END\t9\nLIVE_BEGIN\n' + installed + 'LIVE_END\t9\nEND\n'
        packages = [dict(name=row['name'],version=row['version'],architecture=row['architecture']) for row in rows]
        packages += [dict(name='libc6:'+arch,version='2.41-12+deb13u4',architecture=arch)]
        return module, raw, lock, protocol, packages

    def test_valid_closure_binds_both_releases_archives_and_complete_live_inventory(self):
        module, raw, lock, protocol, packages = self.fixture()
        result = module.parse_closure(protocol, raw, 'amd64', packages)
        self.assertEqual(result['snapshot'], '20261022T200000Z')
        self.assertEqual(result['sha256']['lock'], sha(raw))
        self.assertEqual(result['sha256']['debian'], lock['releases']['debian'])
        self.assertEqual(len(result['archives']), 8)
        self.assertEqual(len(result['installed_packages']), 9)
        self.assertTrue(result['verified'])

    def test_lock_rejects_missing_duplicate_architecture_version_and_hash_fields(self):
        module, raw, *_ = self.fixture()
        lines = raw.decode().splitlines()
        package = next(line for line in lines if line.startswith('PACKAGE\tamd64\t'))
        variants = [raw.replace((package+'\n').encode(), b''), raw.replace((package+'\n').encode(),(package+'\n'+package+'\n').encode()),
            raw.replace(b'PACKAGE\tamd64\t',b'PACKAGE\ts390x\t',1),
            raw.replace(package.encode(),package.replace(package.split('\t')[3],'1;touch').encode()),
            raw.replace(package.encode(),package.replace(package.split('\t')[5],'x'*64).encode()), raw+b'EXTRA\n']
        for value in variants:
            with self.subTest(value=value[:30]), self.assertRaises(ValueError): module.parse_lock(value)

    def test_manifest_rejects_integrity_signature_missing_duplicate_and_wrong_architecture(self):
        module, raw, _, protocol, packages = self.fixture()
        first = next(line for line in protocol.splitlines() if line.startswith('ARCHIVE\t'))
        variants = [protocol.replace('VERIFY\tapt-signatures\ttrue','VERIFY\tapt-signatures\tfalse'),
            protocol.replace('HASH\tlock\t'+sha(raw),'HASH\tlock\t'+'b'*64),
            protocol.replace('KEYRING\t'+'a'*64,'KEYRING\t'+'b'*64),
            protocol.replace(first+'\n','',1),protocol.replace(first+'\n',first+'\n'+first+'\n',1),
            protocol.replace(first,first.replace('\tamd64\t','\tarm64\t')), protocol+'SECRET\n', protocol[:-1]]
        for value in variants:
            with self.subTest(value=value[:30]), self.assertRaises(ValueError): module.parse_closure(value,raw,'amd64',packages)

    def test_archive_hash_self_consistency_cannot_replace_exact_direct_lock_binding(self):
        module, raw, _, protocol, packages = self.fixture()
        begin = protocol.index('ARCHIVES_BEGIN\n')+len('ARCHIVES_BEGIN\n'); end=protocol.index('ARCHIVES_END\t')
        old = protocol[begin:end]; parts = old.splitlines()[0].split('\t'); original = parts[4]; changed = old.replace(original,'f'*64,1)
        altered = protocol.replace(old,changed).replace(sha(old.encode()),sha(changed.encode()))
        with self.assertRaises(ValueError): module.parse_closure(altered,raw,'amd64',packages)

    def test_live_and_main_inventory_must_match_installed_manifest_exactly(self):
        module, raw, _, protocol, packages = self.fixture()
        changed = [dict(row) for row in packages]; changed[-1]['version']='2.41-OTHER'
        with self.assertRaises(ValueError): module.parse_closure(protocol,raw,'amd64',changed)
        with self.assertRaises(ValueError): module.parse_closure(protocol.replace('LIVE_END\t9','LIVE_END\t8'),raw,'amd64',packages)

    def test_real_shell_lock_validation_rejects_bad_inputs_without_apt_or_install(self):
        self.module()
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'lock'; path.write_bytes(LOCK.read_bytes())
            valid=subprocess.run(['/bin/sh',str(INSTALLER),'check-lock',str(path),'amd64'],capture_output=True,timeout=5)
            self.assertEqual(valid.returncode,0,valid.stderr.decode())
            self.assertEqual(len(valid.stdout.splitlines()),8)
            path.write_bytes(path.read_bytes().replace(b'PACKAGE\tamd64\t',b'PACKAGE\ts390x\t',1))
            invalid=subprocess.run(['/bin/sh',str(INSTALLER),'check-lock',str(path),'amd64'],capture_output=True,timeout=5)
            self.assertNotEqual(invalid.returncode,0)
            self.assertEqual(invalid.stdout,b'')

    def test_real_shell_release_hash_gate_refuses_missing_tampered_or_changed_keyring(self):
        module, raw, lock, _, _ = self.fixture()
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); keyring=root/'keyring'; keyring.write_bytes(b'owned public keyring fixture')
            for repo,digest in lock['releases'].items():
                content=(repo+' owned release fixture\n').encode()
                (root/(repo+'.InRelease')).write_bytes(content)
                raw=raw.replace(digest.encode(),sha(content).encode())
            path=root/'lock';path.write_bytes(raw)
            command=['/bin/sh',str(INSTALLER),'check-releases',str(path),str(root),str(keyring),sha(keyring.read_bytes())]
            valid=subprocess.run(command,capture_output=True,timeout=5)
            self.assertEqual(valid.returncode,0,valid.stderr.decode())
            for mutation in ('tamper','missing','keyring'):
                release=root/'debian.InRelease';release.write_bytes(b'debian owned release fixture\n')
                keyring.write_bytes(b'owned public keyring fixture')
                if mutation=='tamper':release.write_bytes(b'changed release\n')
                elif mutation=='missing':release.unlink()
                else:keyring.write_bytes(b'changed public keyring')
                result=subprocess.run(command,capture_output=True,timeout=5)
                self.assertNotEqual(result.returncode,0,mutation)
                self.assertEqual(result.stdout,b'')

    def test_real_shell_canonical_keyring_ignores_legacy_link_but_refuses_missing_symlink_or_tamper(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);canonical=root/'debian-archive-keyring.pgp'
            content=b'owned public canonical keyring fixture\n';canonical.write_bytes(content)
            legacy=root/'debian-archive-keyring.gpg';legacy.symlink_to(canonical.name)
            command=['/bin/sh',str(INSTALLER),'check-keyring',str(root),sha(content)]
            valid=subprocess.run(command,capture_output=True,timeout=5)
            self.assertEqual(valid.returncode,0,valid.stderr.decode())
            self.assertEqual(valid.stdout,b'')
            for state in ('missing','symlink','tamper'):
                canonical.unlink()
                if state=='symlink':
                    target=root/'other-public-keyring';target.write_bytes(content);canonical.symlink_to(target.name)
                elif state=='tamper':canonical.write_bytes(b'changed public keyring fixture\n')
                rejected=subprocess.run(command,capture_output=True,timeout=5)
                self.assertNotEqual(rejected.returncode,0,state)
                self.assertEqual(rejected.stdout,b'')
                self.assertNotIn(b'owned public',rejected.stderr)
                if not canonical.exists() and not canonical.is_symlink():canonical.write_bytes(content)

    def test_short_malformed_and_bounded_protocols_have_fixed_validation_errors(self):
        module, raw, _, _, packages = self.fixture()
        for value in ('CLOSURE\t1\n','CLOSURE\t1\nHASH\tlock\t'+'a'*64+'\n','x'*262145+'\n'):
            with self.subTest(value=value[:20]), self.assertRaises(ValueError): module.parse_closure(value,raw,'amd64',packages)

    def test_self_consistent_archive_manifests_still_reject_missing_duplicate_or_wrong_architecture(self):
        module, raw, _, protocol, packages = self.fixture()
        begin=protocol.index('ARCHIVES_BEGIN\n')+len('ARCHIVES_BEGIN\n');end=protocol.index('ARCHIVES_END\t')
        original=protocol[begin:end];rows=original.splitlines()
        for changed_rows in (rows[1:],rows+[rows[0]],[rows[0].replace('\tamd64\t','\tarm64\t')]+rows[1:]):
            changed='\n'.join(changed_rows)+'\n'
            altered=protocol.replace(original,changed).replace('ARCHIVES_END\t8','ARCHIVES_END\t'+str(len(changed_rows)))
            altered=altered.replace(sha(original.encode()),sha(changed.encode()))
            with self.subTest(rows=len(changed_rows)), self.assertRaises(ValueError): module.parse_closure(altered,raw,'amd64',packages)

    def test_real_native_workflow_requires_closure_only_for_new_target_and_preserves_exit2(self):
        script=workflow_step('Collect complete inventory and retain unresolved dependencies')
        for runtime,exit_code,expected in [('baseline',0,0),('debian-probe',1,0),('debian-closure',0,0),('debian-closure',2,2),('unknown',0,2)]:
            with self.subTest(runtime=runtime,exit_code=exit_code), tempfile.TemporaryDirectory() as directory:
                state=Path(directory); marker=state/'argv';python=state/'python3'
                python.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$ARGV_MARKER"\nexit "$PROBE_EXIT"\n');python.chmod(0o755)
                (state/'appguard-java-image-id').write_text('sha256:'+'a'*64+'\n')
                env=dict(os.environ,PATH=str(state)+os.pathsep+os.environ['PATH'],RUNNER_TEMP=str(state),
                    APPGUARD_ARCH='amd64',APPGUARD_RUNTIME=runtime,ARGV_MARKER=str(marker),PROBE_EXIT=str(exit_code))
                result=subprocess.run(['bash','-euo','pipefail','-c',script],env=env,capture_output=True,timeout=5)
                self.assertEqual(result.returncode,expected,result.stderr)
                if runtime=='unknown':self.assertFalse(marker.exists())
                else:self.assertEqual('--dependency-closure' in marker.read_text().splitlines(),runtime=='debian-closure')

    def test_arm64_pins_and_readback_work_without_accepting_amd64_substitution(self):
        module, raw, _, protocol, packages = self.fixture('arm64')
        self.assertTrue(module.parse_closure(protocol,raw,'arm64',packages)['verified'])
        with self.assertRaises(ValueError): module.parse_closure(protocol,raw,'amd64',packages)
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'lock';path.write_bytes(raw)
            result=subprocess.run(['/bin/sh',str(INSTALLER),'check-lock',str(path),'arm64'],capture_output=True,timeout=5)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(len(result.stdout.splitlines()),8)

    def test_additional_authenticated_transitive_archive_is_recorded_with_installed_identity(self):
        module, raw, _, protocol, packages = self.fixture()
        begin=protocol.index('ARCHIVES_BEGIN\n')+len('ARCHIVES_BEGIN\n');end=protocol.index('ARCHIVES_END\t')
        original=protocol[begin:end]
        expanded=original+'ARCHIVE\tlibc6\t2.41-12+deb13u4\tamd64\t'+'d'*64+'\t100\n'
        changed=protocol.replace(original,expanded).replace(sha(original.encode()),sha(expanded.encode())).replace('ARCHIVES_END\t8','ARCHIVES_END\t9')
        result=module.parse_closure(changed,raw,'amd64',packages)
        self.assertEqual(len(result['archives']),9)
        packages[-1]['version']='2.41-OTHER'
        with self.assertRaises(ValueError): module.parse_closure(changed,raw,'amd64',packages)

    def test_paired_scan_workflow_preserves_exact_image_order_and_incomplete_exit(self):
        script=workflow_step('Scan paired exact images with one database session')
        for arch in ('amd64','arm64'):
            for exit_code in (0,1,2):
                with self.subTest(arch=arch,exit_code=exit_code), tempfile.TemporaryDirectory() as directory:
                    state=Path(directory);marker=state/'argv';python=state/'python3'
                    python.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$ARGV_MARKER"\nexit "$PROBE_EXIT"\n');python.chmod(0o755)
                    for target,digest in [('baseline','a'),('debian-closure','b')]:
                        (state/('appguard-java-'+target+'-id')).write_text('sha256:'+digest*64+'\n')
                    env=dict(os.environ,PATH=str(state)+os.pathsep+os.environ['PATH'],RUNNER_TEMP=str(state),
                        APPGUARD_ARCH=arch,ARGV_MARKER=str(marker),PROBE_EXIT=str(exit_code))
                    result=subprocess.run(['bash','-euo','pipefail','-c',script],env=env,capture_output=True,timeout=5)
                    self.assertEqual(result.returncode,2 if exit_code==2 else 0,result.stderr)
                    args=marker.read_text().splitlines()
                    self.assertEqual(args[:5],['scripts/qualification/scan_diagnostic_images.py','--image','sha256:'+'a'*64,'--image','sha256:'+'b'*64])
                    self.assertEqual(args[args.index('--platform')+1],'linux/'+arch)

    def test_real_shell_download_gate_checks_actual_bytes_metadata_and_locked_direct_identity(self):
        _, raw, lock, _, _ = self.fixture()
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); state=root/'state';state.mkdir();(state/'archives').mkdir()
            evidence=root/'evidence';evidence.mkdir();tools=root/'tools';tools.mkdir()
            records={}
            for row in lock['packages']['amd64']:
                payload=('owned archive fixture '+row['name']).encode()
                archive=state/'archives'/(row['name']+'.deb');archive.write_bytes(payload)
                raw=raw.replace(row['sha256'].encode(),sha(payload).encode()).replace(('\t'+str(row['size'])+'\n').encode(),('\t'+str(len(payload))+'\n').encode())
                records[row['name']]=dict(row,sha256=sha(payload),size=len(payload))
            # The architecture-independent font must retain equal pins on both architectures.
            font=next(row for row in lock['packages']['arm64'] if row['name']=='fonts-dejavu-core')
            raw=raw.replace(font['sha256'].encode(),records['fonts-dejavu-core']['sha256'].encode())
            path=root/'lock';path.write_bytes(raw)
            metadata=root/'metadata';metadata.write_text(json.dumps(records))
            dispatcher='''import json,os,sys
from pathlib import Path
records=json.loads(Path(os.environ['FIXTURE_METADATA']).read_text());tool=Path(sys.argv[0]).name
if tool=='timeout': os.execvp(sys.argv[2],sys.argv[2:])
elif tool=='stat': print(Path(sys.argv[-1]).stat().st_size)
elif tool=='dpkg-deb':
 row=records[Path(sys.argv[2]).stem];print(row[{'Package':'name','Version':'version','Architecture':'architecture'}[sys.argv[3]]])
else:
 name=sys.argv[-1].split('=',1)[0];row=records[name]
 for key in ('name','version','architecture','sha256','size'): print({'name':'Package','version':'Version','architecture':'Architecture','sha256':'SHA256','size':'Size'}[key]+': '+str(row[key]))
 if os.environ.get('DUPLICATE_METADATA'): print('SHA256: '+row['sha256'])
'''
            for name in ('stat','dpkg-deb','apt-cache','timeout'):
                target=tools/name;target.write_text('#!'+sys.executable+'\n'+dispatcher);target.chmod(0o755)
            env=dict(os.environ,PATH=str(tools)+os.pathsep+os.environ['PATH'],FIXTURE_METADATA=str(metadata))
            command=['/bin/sh',str(INSTALLER),'check-downloads',str(path),'amd64',str(state),str(evidence)]
            valid=subprocess.run(command,env=env,capture_output=True,timeout=10)
            self.assertEqual(valid.returncode,0,valid.stderr.decode())
            manifest=(evidence/'apt-archives.tsv').read_text()
            self.assertEqual(len(manifest.splitlines()),8)
            duplicate=subprocess.run(command,env=dict(env,DUPLICATE_METADATA='1'),capture_output=True,timeout=10)
            self.assertNotEqual(duplicate.returncode,0,'ambiguous authenticated metadata must not reach install')
            archive=state/'archives/fontconfig.deb';archive.write_bytes(b'altered archive bytes')
            invalid=subprocess.run(command,env=env,capture_output=True,timeout=10)
            self.assertNotEqual(invalid.returncode,0)

    def comparison_fixture(self):
        module=self.module(); lock=LOCK.read_bytes(); images={'baseline':'sha256:'+'a'*64,'debian_closure':'sha256:'+'b'*64}
        documents={}
        for role,schema in [('baseline',2),('debian_closure',3)]:
            value=dict(schema=schema,evidence_class='owned_java_runtime_inventory',image_id=images[role],platform='linux/amd64',inventory_complete=True,cleanup=True,
                native_checks_passed=role=='debian_closure',features=dict(passed=True),
                jre_tree_sha256=sha(b'fixed owned whole vendor JRE fixture'),
                release_ready=False,native_binary_coverage=False,coverage_complete=False)
            if schema==3:value['dependency_closure']=dict(verified=True,sha256=dict(lock=sha(lock)))
            documents[role]=json.dumps(value).encode()
        scan=dict(schema=1,evidence_class='diagnostic_image_vulnerability_comparison',platform='linux/amd64',measurement_complete=True,images=[dict(image_id=images[role]) for role in images],
            release_ready=False,external_approval=False,native_binary_coverage=False,coverage_complete=False,complete_resolved_graph=False)
        documents['diagnostic']=json.dumps(scan).encode()
        return module,lock,images,documents

    def test_comparison_binds_same_image_ids_platform_source_and_three_original_report_hashes(self):
        module,lock,images,documents=self.comparison_fixture()
        self.assertTrue(callable(getattr(module,'compare_reports',None)), 'same-image comparison binding is required')
        result=module.compare_reports(documents,images,'linux/amd64',lock)
        self.assertEqual(result['sha256'],{key:sha(raw) for key,raw in documents.items()})
        self.assertEqual(result['image_ids'],images)
        self.assertTrue(result['artifact_bindings_verified'])
        self.assertIs(result['whole_jre_identity_matches'],True)
        self.assertFalse(result['reported_native_results']['baseline']['native_checks_passed'])
        for flag in ('release_ready','external_approval','native_binary_coverage','coverage_complete','complete_resolved_graph'):
            self.assertIs(result[flag],False)

    def test_comparison_refuses_image_architecture_sourcehash_or_incomplete_observation(self):
        module,lock,images,documents=self.comparison_fixture()
        self.assertTrue(callable(getattr(module,'compare_reports',None)), 'same-image comparison binding is required')
        for role,key,value in [('baseline','image_id','sha256:'+'c'*64),('diagnostic','platform','linux/arm64'),
                ('debian_closure','inventory_complete',False),('debian_closure','cleanup',False),('diagnostic','measurement_complete',False),
                ('baseline','evidence_class','unrelated_report'),('diagnostic','schema',True),
                ('debian_closure','dependency_closure',dict(verified=True,sha256=dict(lock='f'*64)))]:
            changed=dict(documents);document=json.loads(changed[role]);document[key]=value;changed[role]=json.dumps(document).encode()
            with self.subTest(role=role,key=key), self.assertRaises(ValueError): module.compare_reports(changed,images,'linux/amd64',lock)

    def test_comparison_refuses_different_missing_and_equally_malformed_whole_jre_digests(self):
        module,lock,images,documents=self.comparison_fixture()
        for role in ('baseline','debian_closure'):
            for missing in (False,True):
                changed=dict(documents);value=json.loads(changed[role])
                if missing:value.pop('jre_tree_sha256')
                else:value['jre_tree_sha256']=sha(b'different whole JRE bytes')
                changed[role]=json.dumps(value).encode()
                with self.subTest(role=role,missing=missing), self.assertRaises(ValueError):
                    module.compare_reports(changed,images,'linux/amd64',lock)
        for digest in (None,True,1,'','a'*63,'A'*64,'z'*64,'sha256:'+'a'*64,'a'*64+'\n'):
            changed=dict(documents)
            for role in ('baseline','debian_closure'):
                value=json.loads(changed[role]);value['jre_tree_sha256']=digest;changed[role]=json.dumps(value).encode()
            with self.subTest(equal_malformed=digest), self.assertRaises(ValueError):
                module.compare_reports(changed,images,'linux/amd64',lock)

    def test_comparison_cli_publishes_private_fixed_summary_and_denies_wrong_scanned_image(self):
        _, _, images, documents=self.comparison_fixture()
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve()
            paths=dict(baseline=root/'native/baseline/java-runtime.json',debian_closure=root/'native/debian-closure/java-runtime.json',
                diagnostic=root/'scan/diagnostic.json')
            for role,path in paths.items():path.parent.mkdir(mode=0o700,parents=True,exist_ok=True);path.write_bytes(documents[role])
            command=[sys.executable,str(MODULE),'compare','--input',str(root),'--output',str(root/'bound'),
                '--baseline-image',images['baseline'],'--closure-image',images['debian_closure'],'--platform','linux/amd64']
            result=subprocess.run(command,capture_output=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)
            saved=root/'bound/comparison.json';self.assertEqual(saved.stat().st_mode & 0o777,0o600)
            self.assertEqual(json.loads(saved.read_text())['sha256'],{key:sha(raw) for key,raw in documents.items()})
            changed=json.loads(documents['diagnostic']);changed['images'].reverse();paths['diagnostic'].write_text(json.dumps(changed))
            command[command.index('--output')+1]=str(root/'denied')
            result=subprocess.run(command,capture_output=True,timeout=10)
            self.assertEqual(result.returncode,2)
            self.assertFalse((root/'denied').exists())

    def test_paired_native_workflow_uses_same_ids_attempts_both_images_and_keeps_exit2(self):
        script=workflow_step('Prepare private diagnostic comparison state')+'\n'+workflow_step('Collect paired native evidence on exact image IDs')
        for fail_baseline in (False,True):
            with self.subTest(fail=fail_baseline), tempfile.TemporaryDirectory() as directory:
                root=Path(directory);marker=root/'argv';python=root/'python3'
                python.write_text('#!/bin/sh\nprintf "%s\\n" "$@" >> "$ARGV_MARKER"\ncase "$*" in *'+ 'sha256:'+'a'*64+'*) exit "$BASELINE_EXIT";; esac\nexit 0\n');python.chmod(0o755)
                for role,digest in [('baseline','a'),('debian-closure','b')]:
                    (root/('appguard-java-'+role+'-id')).write_text('sha256:'+digest*64+'\n')
                env=dict(os.environ,PATH=str(root)+os.pathsep+os.environ['PATH'],RUNNER_TEMP=str(root),APPGUARD_ARCH='amd64',
                    ARGV_MARKER=str(marker),BASELINE_EXIT='2' if fail_baseline else '1')
                result=subprocess.run(['bash','-euo','pipefail','-c',script],env=env,capture_output=True,timeout=5)
                self.assertEqual(result.returncode,2 if fail_baseline else 0,result.stderr)
                args=marker.read_text().splitlines()
                self.assertEqual(args.count('scripts/qualification/inspect_java_runtime.py'),2)
                self.assertEqual(args.count('--dependency-closure'),1)
                self.assertIn('sha256:'+'a'*64,args);self.assertIn('sha256:'+'b'*64,args)


if __name__ == '__main__': unittest.main()
