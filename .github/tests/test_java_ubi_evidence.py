import copy
import contextlib
import hashlib
import importlib.util
import json
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts/qualification'))


class UbiEvidenceTests(unittest.TestCase):
    def fixture(self):
        import inspect_java_runtime as inventory
        import java_runtime_rpm as rpm
        from test_java_runtime_inventory import inventory as tree,feature_protocol
        from test_java_runtime_rpm import feature
        baseline=dict(inventory.parse_inventory(tree(),'amd64'))
        baseline.update(schema=2,evidence_class='owned_java_runtime_inventory',image_id='sha256:'+'a'*64,platform='linux/amd64',
            features=inventory.parse_features(feature_protocol()),cleanup=True,native_checks_passed=True,
            release_ready=False,native_binary_coverage=False,coverage_complete=False)
        baseline['checks'].update(native_providers_verified=True,runtime_features_passed=True)
        ubi=copy.deepcopy(baseline);ubi.update(rpm.initial_report('amd64'),schema=4,image_id='sha256:'+'b'*64,
            features=feature(),final_identity_verified=True)
        ubi['stages']={name:rpm.status(True,True,'measured',0) for name in rpm.STAGES};rpm.finalize(ubi)
        raw='glibc\t0\t2.39\t58.el10\tx86_64\tglibc-2.39-58.el10.src.rpm\tLGPL\n'
        ubi['packages']=rpm.parse_packages(raw,'amd64');ubi['counts']['os_packages']=1
        ubi['package_inventory']=dict(schema=1,manager='rpm',count=1,query_sha256=hashlib.sha256(raw.encode()).hexdigest(),query_bytes=len(raw.encode()))
        ubi['rpm_database_hashes']=[dict(tag='usr-rpmdb.sqlite',sha256='d'*64,size=128)]
        ubi['platform_observation']=dict(schema=1,uids=[10001]*4,gids=[10001]*4,
            pid1_elf='7f454c4602010100000000000000000002003e00',self_elf='7f454c4602010100000000000000000002003e00',
            java_vendor='Eclipse Adoptium',java_version='17.0.20.1',java_runtime_version='17.0.20.1+1',os_arch='amd64',
            native_identity_verified=True,verified=True,host_os='linux',host_machine='x86_64',daemon_os='linux',daemon_architecture='amd64')
        for elf in ubi['elfs']:
            for dep in elf['dependencies']:
                if dep['resolution']=='os':dep.update(sha256='b'*64,providers=ubi['packages'])
        scan=dict(schema=1,evidence_class='diagnostic_image_vulnerability_comparison',platform='linux/amd64',
            measurement_complete=False,vulnerabilities=31,images=[dict(image_id=baseline['image_id'],vulnerabilities=31,
            finding_details_complete=True,zero_findings_interpretable=False),dict(image_id=ubi['image_id'],vulnerabilities=0,
            finding_details_complete=True,zero_findings_interpretable=False)],release_ready=False,external_approval=False,
            native_binary_coverage=False,coverage_complete=False,complete_resolved_graph=False)
        return dict(noble=baseline,ubi=ubi,diagnostic=scan)

    def compare(self,documents):
        import compare_java_ubi_evidence as m
        return m.compare_reports({key:(json.dumps(value)+'\n').encode() for key,value in documents.items()},
            {'noble':'sha256:'+'a'*64,'ubi':'sha256:'+'b'*64},'linux/amd64')

    def test_partial_feed_retains_counts_and_identity_without_upgrading_coverage(self):
        result=self.compare(self.fixture())
        self.assertTrue(result['artifact_bindings_verified']);self.assertTrue(result['whole_jre_identity_matches'])
        self.assertEqual(result['reported_findings'],{'noble':31,'ubi':0})
        self.assertFalse(result['collection_complete']);self.assertEqual(result['ubi_feed_status'],'unverified')
        for key in ('release_ready','external_approval','native_binary_coverage','coverage_complete','cpu_baseline_approved'):
            self.assertFalse(result[key])

    def test_partial_rpm_keeps_features_but_cannot_claim_whole_tree_equality_when_dropped(self):
        import java_runtime_rpm as rpm
        rows=self.fixture();rpm.truncate(rows['ubi'])
        result=self.compare(rows)
        self.assertTrue(result['reported_native_results']['ubi']['features']['passed'])
        self.assertFalse(result['whole_jre_identity_matches']);self.assertFalse(result['collection_complete'])

    def test_mutated_identity_count_aggregate_and_tree_records_are_refused(self):
        variants=[]
        for role,key,value in (('ubi','image_id','sha256:'+'c'*64),('ubi','measurement_complete',False),
                ('ubi','native_checks_passed',1),('diagnostic','vulnerabilities',30)):
            rows=self.fixture();rows[role][key]=value;variants.append(rows)
        rows=self.fixture();rows['ubi']['files'][0]['sha256']='c'*64;variants.append(rows)
        rows=self.fixture();rows['noble']['files'].append(rows['noble']['files'][0]);variants.append(rows)
        for rows in variants:
            with self.assertRaises(ValueError):self.compare(rows)

    def test_same_declared_digest_cannot_hide_different_original_tree(self):
        rows=self.fixture();next(row for row in rows['ubi']['files'] if row['path']=='release')['sha256']='c'*64
        with self.assertRaises(ValueError):self.compare(rows)
        entries=[dict(path=row['path'],kind='file',sha256=row['sha256'],size=row['size']) for row in rows['ubi']['files']]
        entries.sort(key=lambda row:row['path'])
        rows['ubi']['jre_tree_sha256']=hashlib.sha256(json.dumps(entries,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        self.assertFalse(self.compare(rows)['whole_jre_identity_matches'])

    def test_complete_stage_needs_actual_typed_supporting_records(self):
        for field,value in (('rpm_database_hashes',[]),('package_inventory',None),('packages',[]),('platform_observation',None),('elfs',[])):
            rows=self.fixture();rows['ubi'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):self.compare(rows)

    def test_zero_ubi_or_cpu_approval_cannot_be_promoted_by_contradictory_flags(self):
        rows=self.fixture();rows['diagnostic']['measurement_complete']=True
        with self.assertRaises(ValueError):self.compare(rows)
        rows=self.fixture();rows['ubi']['cpu_scope']['cpu_baseline_approved']=True
        with self.assertRaises(ValueError):self.compare(rows)

    def test_noble_runtime_feature_flag_must_match_observed_features(self):
        from inspect_java_runtime import parse_features
        from test_java_runtime_inventory import feature_protocol
        for feature_passed,flag,native_passed in ((False,True,True),(False,True,False),(True,False,False)):
            rows=self.fixture()
            rows['noble']['features']=parse_features(feature_protocol(failed=() if feature_passed else ('headless_font',)))
            rows['noble']['checks']['runtime_features_passed']=flag
            rows['noble']['native_checks_passed']=native_passed
            with self.subTest(feature_passed=feature_passed,flag=flag,native_passed=native_passed),self.assertRaises(ValueError):
                self.compare(rows)

    def test_consistent_noble_feature_failure_and_legacy_partial_remain_observations(self):
        from inspect_java_runtime import parse_features
        from test_java_runtime_inventory import feature_protocol
        for code in (1,2):
            rows=self.fixture();noble=rows['noble']
            observed=parse_features(feature_protocol(failed=('headless_font',),code=code))
            noble['features']=observed;noble['native_checks_passed']=False
            if code==1:noble['checks']['runtime_features_passed']=False
            else:
                noble['inventory_complete']=False
                noble['checks'].pop('runtime_features_passed')
            result=self.compare(rows)['reported_native_results']['noble']
            self.assertFalse(result['native_checks_passed'])
            self.assertEqual(result['features'],observed)
            self.assertEqual(result['collection_complete'],code==1)

    def cli_fixture(self,root):
        import compare_java_ubi_evidence as module
        rows=self.fixture();raw='glibc\t0\t2.39\t58.el10\tx86_64\tglibc-2.39-58.el10.src.rpm\tLGPL\n'
        paths=dict(noble=root/'native/noble/java-runtime.json',ubi=root/'native/ubi/java-runtime.json',diagnostic=root/'scan/diagnostic.json')
        for name,path in paths.items():
            path.parent.mkdir(parents=True,mode=0o700,exist_ok=True);path.write_text(json.dumps(rows[name])+'\n')
        (root/'native/ubi/rpm-inventory.tsv').write_text(raw)
        args=['--input',str(root),'--output',str(root/'bound'),'--noble-image',rows['noble']['image_id'],
            '--ubi-image',rows['ubi']['image_id'],'--platform','linux/amd64']
        return module,args,paths

    def test_cli_binds_original_hashes_and_raw_rpm_without_upgrading_incomplete_feed(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();module,args,paths=self.cli_fixture(root)
            with contextlib.redirect_stdout(io.StringIO()):self.assertEqual(module.main(args),2)
            result=json.loads((root/'bound/comparison.json').read_text())
            self.assertTrue(result['artifact_bindings_verified']);self.assertFalse(result['collection_complete'])
            self.assertEqual(result['sha256'],{key:hashlib.sha256(path.read_bytes()).hexdigest() for key,path in paths.items()})
            self.assertEqual(len(result['collector_source_sha256']),5)
            self.assertEqual((root/'bound/comparison.json').stat().st_mode&0o777,0o600)

    def test_cli_held_parent_policy_and_original_mutation_roll_back_output(self):
        from test_java_runtime_inventory import RuntimeInventoryTests
        fixture=RuntimeInventoryTests().parent_policy_fixture
        for failure in ('initial_owner','initial_mode','late_owner','late_mode','input_mutation'):
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as directory:
                root=Path(directory).resolve();module,args,paths=self.cli_fixture(root)
                with fixture('owner' if 'owner' in failure else 'mode',deny=failure.startswith('initial')) as (publication,state):
                    original=publication.publish
                    def publish(value):
                        original(value)
                        if failure.startswith('late'):state['deny']=True
                        if failure=='input_mutation':paths['diagnostic'].write_text('SECRET')
                    with patch.object(publication,'publish',new=publish),contextlib.redirect_stdout(io.StringIO()) as stdout:
                        self.assertEqual(module.main(args),2)
                    self.assertFalse((root/'bound').exists());self.assertNotIn('SECRET',stdout.getvalue())


if __name__=='__main__':unittest.main()
