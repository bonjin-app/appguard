"""Ordinary local profile/lifecycle/binder fixtures; no containers are run."""
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts/qualification'))
import java_runtime_rpm as rpm
import compare_java_ubi_evidence as binder
import test_java_runtime_inventory as inventory_fixtures
import test_java_ubi_evidence as evidence_fixtures

PROFILE='rpm-ubi8-copy-jre-v1'
BASE='sha256:c851eaf99ddf32811fdf8a216c2609cd0e55317ab8c46ecbaa3ea8298532f055'
JRE='sha256:07fa0356cf354c5252947575f42ed42aa6fd921f36438b7bc77ad81c31c537dd'


def red_profile(architecture='amd64'):
    try:return rpm.initial_report(architecture,profile=PROFILE)
    except TypeError:raise AssertionError('new explicit UBI8 profile is not implemented') from None


def digest_tree(row):
    entries=[dict(kind='file',**item) for item in row['files']]
    entries.extend(dict(path=item['path'],kind='symlink',target=item['target']) for item in row['symlinks'])
    row['jre_tree_sha256']=hashlib.sha256(json.dumps(sorted(entries,key=lambda item:item['path']),sort_keys=True,separators=(',',':')).encode()).hexdigest()


class Ubi8ProfileTests(unittest.TestCase):
    def test_cpu_scope_is_separate_unverified_and_legacy_default_is_unchanged(self):
        for architecture in ('amd64','arm64'):
            row=red_profile(architecture)
            self.assertEqual(row['package_profile'],PROFILE)
            self.assertEqual(row['cpu_scope']['required_baseline'],'copied_jre_minimum_unverified')
            self.assertEqual(row['cpu_scope']['declared_base_scope'],'RHEL8_generic_declared_OS_floor_only')
            for flag in ('noble_baseline_preserved','host_instruction_baseline_verified','copied_jre_minimum_cpu_verified',
                    'copied_jre_minimum_glibc_verified','cpu_baseline_approved'):
                self.assertIs(row['cpu_scope'][flag],False)
            old=rpm.initial_report(architecture)
            self.assertEqual(old['package_profile'],'rpm-ubi10-v1')
            self.assertEqual(old['cpu_scope']['required_baseline'],'x86-64-v3' if architecture=='amd64' else 'ARMv8.0-A')
            self.assertNotIn('copied_jre_minimum_cpu_verified',old['cpu_scope'])
        with self.assertRaises(ValueError):rpm.initial_report('amd64',profile='rpm-arbitrary')


class Ubi8LifecycleTests(unittest.TestCase):
    setUpClass=classmethod(inventory_fixtures.RpmRuntimeTests.setUpClass.__func__)
    image=inventory_fixtures.RpmRuntimeTests.image
    record=inventory_fixtures.RpmRuntimeTests.record
    fake=inventory_fixtures.RpmRuntimeTests.fake
    rpm_call=inventory_fixtures.RpmRuntimeTests.rpm_call
    parent_policy_fixture=inventory_fixtures.RpmRuntimeTests.parent_policy_fixture

    def collect(self,*,os_version='8.10',feature_code=0,failed=(),unavailable=(),failure=None,profile=PROFILE,cli=False):
        fake,modes,commands,base=self.rpm_call(feature_code=feature_code,failed=failed,unavailable=unavailable)
        def call(command,**kwargs):
            args=command[3:]
            if failure=='cleanup' and args[0]=='stop':raise ValueError('PRIVATE_ERROR')
            value=base(command,**kwargs)
            if args[:2]==['image','inspect']:
                rows=json.loads(value);rows[0]['Config']['Env']=['PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','container=oci']
                if failure=='unsafe_env':rows[0]['Config']['Env'].append('JAVA_TOOL_OPTIONS=PRIVATE_ERROR')
                return json.dumps(rows)
            if args[0]=='exec':
                mode=args[args.index('AppGuardRuntimeInventory')+1]
                if mode=='tree':value=value.replace('10.1',os_version)
                if failure=='timeout' and mode=='rpm':
                    from spring_containers import CommandFailure
                    raise CommandFailure('timeout',None,b'PRIVATE_ERROR')
                if failure=='cancelled' and mode=='rpm':raise KeyboardInterrupt()
                value=value.replace('2.39','2.28').replace('58.el10','236.el8')
            return value
        with tempfile.TemporaryDirectory() as directory,patch.object(self.m,'bounded_command',side_effect=call), \
                patch('platform.system',return_value='Linux'),patch('platform.machine',return_value='x86_64'):
            output=Path(directory).resolve()/'out'
            if cli:
                with contextlib.redirect_stdout(io.StringIO()) as stdout:
                    code=self.m.main(['--image',self.image,'--platform','linux/amd64','--features','--package-profile',profile,'--output',str(output)])
                self.assertNotIn('PRIVATE_ERROR',stdout.getvalue())
                result=json.loads((output/'java-runtime.json').read_text())
                self.assertEqual(code,0 if result['native_checks_passed'] else 1 if result['measurement_complete'] else 2)
            else:
                try:result=self.m.inspect_runtime(self.image,'linux/amd64',output,features=True,package_profile=profile)
                except ValueError:
                    self.fail('explicit UBI8 collector must accept its profile and publish a typed observation')
            if (output/'rpm-inventory.tsv').exists():
                self.assertEqual((output/'rpm-inventory.tsv').stat().st_mode&0o777,0o600)
        self.assertNotIn('PRIVATE_ERROR',json.dumps(result))
        return result,modes,commands,fake

    def test_copy_base_environment_uses_absolute_java_and_retains_typed_observations(self):
        caller={key:(key in os.environ,os.environ.get(key)) for key in ('HOME','CODEX_HOME')}
        with patch.dict(os.environ,{'JAVA_TOOL_OPTIONS':'HOST_PRIVATE'}):
            result,modes,commands,fake=self.collect()
        self.assertTrue(result['measurement_complete']);self.assertTrue(result['native_checks_passed'])
        self.assertEqual(result['os']['version'],'8.10');self.assertEqual(result['package_profile'],PROFILE)
        self.assertEqual(result['packages'][0]['version'],'2.28')
        self.assertTrue(fake.removed);self.assertEqual(modes[:3],['identity','features','tree'])
        for command,options in commands:
            self.assertTrue(all((key in options['env'])==present and (not present or options['env'][key]==value)
                for key,(present,value) in caller.items()),'caller_home_environment_unverified')
            self.assertTrue('HOST_PRIVATE' not in json.dumps(options['env']),'host_java_environment_unverified')
            if command[3]=='exec':self.assertEqual(command[5],'/opt/java/openjdk/bin/java')
        for flag in ('release_ready','native_binary_coverage','coverage_complete','external_approval','legal_approval','complete_resolved_graph'):
            self.assertIs(result[flag],False)

    def test_exact_os_profile_prevents_cross_major_and_minor_acceptance(self):
        for version in ('8.9','8.10.1','10.1'):
            with self.subTest(version=version):
                result,_,_,_=self.collect(os_version=version)
                self.assertFalse(result['stages']['jre_tree']['complete']);self.assertFalse(result['measurement_complete'])
        result,_,_,_=self.collect(profile='rpm-ubi10-v1')
        self.assertFalse(result['stages']['jre_tree']['complete'])

    def test_feature_failure_is_measured_but_partial_and_late_failures_cannot_pass(self):
        result,_,_,_=self.collect(feature_code=1,failed=('headless_font',))
        self.assertTrue(result['measurement_complete']);self.assertFalse(result['native_checks_passed'])
        for options in (dict(feature_code=2),dict(unavailable=('rpm','linkage')),dict(unavailable=('database-hashes','providers')),
                dict(failure='timeout'),dict(failure='cancelled'),dict(failure='cleanup'),dict(failure='unsafe_env')):
            with self.subTest(options=options):
                result,modes,_,_=self.collect(**options)
                self.assertFalse(result['measurement_complete']);self.assertFalse(result['native_checks_passed'])
                if options.get('feature_code')==2:self.assertEqual(modes,['identity','features'])
                if options.get('failure')!='unsafe_env':self.assertIsNotNone(result['features'])

    def test_actual_cli_dispatch_preserves_zero_one_two_and_owned_cleanup(self):
        for options,expected in (({},True),(dict(feature_code=1,failed=('headless_font',)),False),(dict(feature_code=2),False)):
            with self.subTest(options=options):
                result,_,_,fake=self.collect(cli=True,**options)
                self.assertIs(result['native_checks_passed'],expected)
                self.assertTrue(result['cleanup']);self.assertTrue(fake.removed)

    def test_invalid_options_fail_before_docker_or_output(self):
        for options in ({},{'features':True,'dependency_closure':True}):
            with tempfile.TemporaryDirectory() as directory,patch.object(self.m,'bounded_command') as command:
                output=Path(directory).resolve()/'out'
                with self.assertRaises(ValueError):self.m.inspect_runtime(self.image,'linux/amd64',output,package_profile=PROFILE,**options)
                command.assert_not_called();self.assertFalse(output.exists())


class Ubi8BindingTests(unittest.TestCase):
    def fixture(self):
        rows=evidence_fixtures.UbiEvidenceTests().fixture();rows['ubi'].update(red_profile())
        # Keep the valid original measured stage records; only profile/CPU/OS differ.
        original=evidence_fixtures.UbiEvidenceTests().fixture()['ubi']
        for field in ('stages','features','package_inventory','platform_observation','final_identity_verified'):
            rows['ubi'][field]=original[field]
        rows['ubi']['os'].update(id='rhel',version='8.10')
        rpm.finalize(rows['ubi'])
        for role in ('noble','ubi'):
            rows[role]['files'].append(dict(path='lib/server/classes.jsa',sha256='e'*64,size=123))
            rows[role]['counts']['regular_files']+=1;digest_tree(rows[role])
        return rows

    def compare(self,rows,**options):
        try:return binder.compare_reports({key:(json.dumps(value)+'\n').encode() for key,value in rows.items()},
            {'noble':'sha256:'+'a'*64,'ubi':'sha256:'+'b'*64},'linux/amd64',
            **dict(dict(profile=PROFILE,base_index=BASE,jre_source_index=JRE),**options))
        except TypeError:self.fail('binder must expose explicit fixed UBI8 profile/pin binding')

    def test_fixed_recipe_pins_bind_observations_without_feed_or_cpu_approval(self):
        result=self.compare(self.fixture())
        self.assertEqual(result['evidence_class'],'same_image_ubi8_copy_jre_runtime_diagnostic')
        self.assertEqual(result['package_profile'],PROFILE);self.assertEqual(result['base_index_pins'],dict(noble=JRE,ubi=BASE))
        self.assertEqual(result['jre_source_index_pin'],JRE);self.assertTrue(result['whole_jre_identity_matches'])
        self.assertEqual(result['reported_findings'],dict(noble=31,ubi=0));self.assertFalse(result['collection_complete'])
        for flag in ('release_ready','external_approval','native_binary_coverage','coverage_complete','cpu_baseline_approved','legal_approval','complete_resolved_graph'):
            self.assertIs(result[flag],False)

    def test_profile_pin_os_cpu_and_boolean_type_mismatches_are_denied(self):
        rows=self.fixture()
        for options in (dict(base_index=None),dict(jre_source_index=None),dict(base_index=binder.BASES['ubi']),
                dict(jre_source_index=BASE),dict(profile=rpm.PROFILE),dict(profile='arbitrary')):
            with self.subTest(options=options),self.assertRaises(ValueError):self.compare(rows,**options)
        for field,value in (('package_profile',rpm.PROFILE),('os',dict(id='rhel',version='8.9',architecture='amd64')),
                ('cpu_scope',rpm.initial_report('amd64')['cpu_scope'])):
            changed=copy.deepcopy(rows);changed['ubi'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):self.compare(changed)
        changed=copy.deepcopy(rows);changed['ubi']['cpu_scope']['copied_jre_minimum_cpu_verified']=0
        with self.assertRaises(ValueError):self.compare(changed)

    def test_observed_wrong_os_cannot_hide_in_partial_report_but_missing_observation_can_bind(self):
        rows=self.fixture();rpm.truncate(rows['ubi'])
        self.assertFalse(self.compare(rows)['collection_complete'])
        rows['ubi']['os']['version']='10.1'
        with self.assertRaises(ValueError):self.compare(rows)
        rows['ubi'].pop('os')
        self.assertFalse(self.compare(rows)['collection_complete'])

    def test_every_original_tree_record_participates_in_copy_identity(self):
        rows=self.fixture()
        for path in ('lib/server/classes.jsa','legal/java.base/LICENSE','lib/security/cacerts'):
            changed=copy.deepcopy(rows);record=next(row for row in changed['ubi']['files'] if row['path']==path)
            record['sha256']='f'*64;digest_tree(changed['ubi'])
            with self.subTest(path=path):self.assertFalse(self.compare(changed)['whole_jre_identity_matches'])
        changed=copy.deepcopy(rows);changed['ubi']['files']=[row for row in changed['ubi']['files'] if row['path']!='lib/server/classes.jsa']
        changed['ubi']['counts']['regular_files']-=1;digest_tree(changed['ubi'])
        self.assertFalse(self.compare(changed)['whole_jre_identity_matches'])
        for role in ('noble','ubi'):
            rows[role]['symlinks']=[dict(path='legal/java.logging/LICENSE',target='../java.base/LICENSE',
                target_sha256=hashlib.sha256(b'../java.base/LICENSE').hexdigest(),within_jre=True)]
            rows[role]['counts']['symlinks']=1;digest_tree(rows[role])
        self.assertTrue(self.compare(rows)['whole_jre_identity_matches'])
        rows['ubi']['symlinks'][0].update(target='../java.base/NOTICE',target_sha256=hashlib.sha256(b'../java.base/NOTICE').hexdigest())
        digest_tree(rows['ubi']);self.assertFalse(self.compare(rows)['whole_jre_identity_matches'])

    def test_cli_requires_explicit_pins_binds_originals_and_publishes_only_private_fixed_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();rows=self.fixture()
            paths={key:root/name for key,name in dict(noble='native/noble/java-runtime.json',ubi='native/ubi/java-runtime.json',diagnostic='scan/diagnostic.json').items()}
            for key,path in paths.items():path.parent.mkdir(mode=0o700,parents=True,exist_ok=True);path.write_text(json.dumps(rows[key])+'\n')
            (root/'native/ubi/rpm-inventory.tsv').write_text('glibc\t0\t2.39\t58.el10\tx86_64\tglibc-2.39-58.el10.src.rpm\tLGPL\n')
            args=['--input',str(root),'--output',str(root/'bound'),'--noble-image',rows['noble']['image_id'],'--ubi-image',rows['ubi']['image_id'],
                '--platform','linux/amd64','--ubi-profile',PROFILE,'--ubi-base-index',BASE,'--jre-source-index',JRE]
            with contextlib.redirect_stdout(io.StringIO()):self.assertEqual(binder.main(args),2)
            self.assertTrue((root/'bound/comparison.json').is_file(),'valid partial UBI8 originals must be retained')
            report=json.loads((root/'bound/comparison.json').read_text())
            self.assertTrue(report['artifact_bindings_verified']);self.assertFalse(report['collection_complete'])
            self.assertEqual(report['sha256'],{key:hashlib.sha256(path.read_bytes()).hexdigest() for key,path in paths.items()})
            self.assertIn('compare_java_ubi_evidence.py',report['collector_source_sha256'])
            self.assertIn('../../.github/workflows/java-ubi8-copy-jre.yml',report['collector_source_sha256'])
            self.assertEqual({path.name for path in (root/'bound').iterdir()},{'comparison.json'})
            self.assertEqual((root/'bound/comparison.json').stat().st_mode&0o777,0o600)


if __name__=='__main__':unittest.main()
