"""Privacy, binding and safe publication tests; no Docker or network."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts/qualification/bind_container_evidence.py'
spec=importlib.util.spec_from_file_location('container_binding',SCRIPT)
module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)


def fixture():
    receipt = dict(schema=1, evidence_class='owned_container_deployment',
        profile='spring-loopback-mtls-containers-v1', observed_at='2026-10-23T00:00:00Z',
        candidate_commit='a'*40, source_matches_commit=True,
        source_sha256={'LICENSE': 'b'*64}, checks={key: True for key in module.CHECKS},
        release_ready=False, external_approval=False, technical_verification=True,
        phase='completed', cleanup=True, limitations=list(module.RECEIPT_LIMITATIONS),
        containers={'image_ids': {role: 'sha256:'+'c'*64 for role in module.ROLES},
            'container_ids': {role:'d'*64 for role in module.ROLES}, 'gateway_port':12345,
            'logging': {role: dict(driver='local', compress=False, max_files=1,
                max_size_bytes=1048576) for role in module.ROLES}})
    raw = json.dumps(receipt).encode()
    status = dict(schema=1,evidence_class='owned_container_image_scan',release_ready=False,
        automated_checks_passed=False,reason='findings_present',
        qualification_sha256=hashlib.sha256(raw).hexdigest(),images={role:dict(
            image_id='sha256:'+'c'*64,report_sha256='e'*64,vulnerabilities=2,
            coverage=dict(os_inventory=True,os_package_count=10,application_package_count=1,
                application_inventory=None if role=='redis' else True,
                native_binary_coverage=False,coverage_complete=False)) for role in module.ROLES},
        scanners=['vuln'],vulnerabilities=6,secrets=None,coverage_complete=False,
        native_binary_coverage=False,complete_resolved_graph=False,coverage_passed=True,
        coverage_limitations=list(module.COVERAGE_LIMITATIONS))
    return raw,json.dumps(status).encode()


class BindingTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve()
        self.receipt=self.root/'in.json'; self.status=self.root/'scan.json'; self.output=self.root/'out'
        self.receipt.write_bytes(fixture()[0]); self.status.write_bytes(fixture()[1])
        self.metadata=dict(repository='bonjin-app/appguard',candidate_commit='a'*40,
            run_id=123,run_attempt=1,event='push',head_branch='main',
            workflow_path='.github/workflows/container-readiness.yml')
    def stage(self):
        return module.stage(self.receipt,self.status,self.output,**self.metadata)
    def test_findings_are_staged_without_mutating_evidence(self):
        result=self.stage()
        self.assertEqual(set(p.name for p in self.output.iterdir()),{'receipt.json','image-status.json','binding.json'})
        self.assertEqual((self.output/'receipt.json').read_bytes(),self.receipt.read_bytes())
        self.assertEqual((self.output/'image-status.json').read_bytes(),self.status.read_bytes())
        binding=json.loads((self.output/'binding.json').read_bytes())
        self.assertEqual(binding['image_status_sha256'],hashlib.sha256(self.status.read_bytes()).hexdigest())
        self.assertEqual(binding['run_id'],123)
        self.assertEqual(self.output.stat().st_mode & 0o777,0o700)
        self.assertTrue(all(p.stat().st_mode & 0o777==0o600 for p in self.output.iterdir()))
        self.assertFalse(result['release_ready'])
    def test_nested_extensions_and_wrong_types_are_denied(self):
        for mutate in [lambda r:r['containers']['logging']['gateway'].update(secret='PRIVATE'),
                       lambda r:r['checks'].update(signed_fidelity=1),
                       lambda r:r.update(observed_at='PRIVATE'),
                       lambda r:r['source_sha256'].update({'secret-token':'a'*64})]:
            r=json.loads(fixture()[0]); mutate(r); self.receipt.write_text(json.dumps(r))
            with self.assertRaises((ValueError,OSError)): self.stage()
            self.assertFalse(self.output.exists())
    def test_hash_image_and_commit_relations_are_required(self):
        for field,value in [('qualification_sha256','0'*64),('images',dict(gateway=dict(image_id='sha256:'+'f'*64,report_sha256='e'*64,vulnerabilities=0,coverage=json.loads(fixture()[1])['images']['gateway']['coverage'])))]:
            s=json.loads(fixture()[1]); s[field]=value; self.status.write_text(json.dumps(s))
            with self.assertRaises(ValueError): self.stage()
        self.status.write_bytes(fixture()[1]); self.metadata['candidate_commit']='f'*40
        with self.assertRaises(ValueError): self.stage()
    def test_metadata_is_typed_and_bounded(self):
        for key,value in [('run_id',True),('run_attempt',0),('candidate_commit','a'*41),
            ('event','PRIVATE'),('repository','elsewhere/private'),('head_branch','private\nsecret')]:
            old=self.metadata[key]; self.metadata[key]=value
            with self.assertRaises(ValueError): self.stage()
            self.metadata[key]=old
    def test_duplicate_nonfinite_oversize_and_fifo_rejected(self):
        for raw in [b'{"schema":1,"schema":1}',b'{"v":NaN}',b' '* (module.MAX_BYTES+1)]:
            self.receipt.write_bytes(raw)
            with self.assertRaises((ValueError,OSError)): self.stage()
        self.receipt.unlink(); os.mkfifo(self.receipt)
        with self.assertRaises((ValueError,OSError)): self.stage()
    def test_symlinks_and_existing_output_denied(self):
        original=self.root/'original'; self.receipt.rename(original); self.receipt.symlink_to(original)
        with self.assertRaises((ValueError,OSError)): self.stage()
        self.receipt.unlink(); original.rename(self.receipt)
        self.output.mkdir(); (self.output/'keep').write_text('preserved')
        with self.assertRaises((ValueError,OSError)): self.stage()
        self.assertEqual((self.output/'keep').read_text(),'preserved')
    def test_input_changed_during_publication_rolls_back(self):
        original=module.Publication.publish
        def mutate(publication):
            original(publication); self.receipt.write_bytes(b'{}')
        with patch.object(module.Publication,'publish',mutate):
            with self.assertRaises(ValueError): self.stage()
        self.assertFalse(self.output.exists())
    def test_invalid_cli_does_not_echo_arguments(self):
        result=subprocess.run([sys.executable,str(SCRIPT),'--PRIVATE-secret'],capture_output=True,timeout=5)
        self.assertEqual(result.returncode,2)
        self.assertNotIn(b'PRIVATE',result.stdout+result.stderr)

    def write_receipt(self,receipt):
        raw=json.dumps(receipt).encode(); self.receipt.write_bytes(raw)
        status=json.loads(fixture()[1]); status['qualification_sha256']=hashlib.sha256(raw).hexdigest()
        self.status.write_text(json.dumps(status))

    def test_fixed_failure_observation_can_be_retained(self):
        receipt=json.loads(fixture()[0]); receipt['technical_verification']=False
        receipt['cleanup']=False; receipt['checks']['owned_container_cleanup']=False
        self.write_receipt(receipt); self.stage()
        self.assertFalse(json.loads((self.output/'receipt.json').read_bytes())['technical_verification'])

    def test_failed_scan_with_partial_fixed_reports_can_be_retained(self):
        # Scan invalidity is an observation, never an operating approval.
        status=json.loads(fixture()[1]); status.update(reason='container_scan_unverified',automated_checks_passed=False)
        status['images'].pop('redis'); status['vulnerabilities']=None
        self.status.write_text(json.dumps(status)); self.stage()
        self.assertFalse(json.loads((self.output/'image-status.json').read_bytes())['automated_checks_passed'])

    def test_publication_ancestor_swap_never_writes_replacement(self):
        parent=self.root/'parent'; parent.mkdir(); self.output=parent/'out'
        moved=self.root/'moved'
        original=module.Publication.publish
        def swap(publication):
            parent.rename(moved); parent.mkdir(); (parent/'sentinel').write_text('preserved')
            original(publication)
        with patch.object(module.Publication,'publish',swap):
            with self.assertRaises(ValueError): self.stage()
        self.assertEqual([p.name for p in parent.iterdir()],['sentinel'])
        self.assertFalse(list(moved.rglob('*.json')))

    def test_stage_source_symlink_swap_is_denied_and_raw_tree_cleared(self):
        moved=self.root/'moved'; target=self.root/'target'; target.mkdir(); (target/'keep').write_text('preserved')
        real_cdll=module.ctypes.CDLL
        class RenameHook:
            def __init__(hook): hook.actual=real_cdll(None,use_errno=True)
            def __getattr__(hook,name):
                actual=getattr(hook.actual,name)
                def rename(parent,source,parent2,destination,flags):
                    stage=self.root/os.fsdecode(source); stage.rename(moved); stage.symlink_to(target,target_is_directory=True)
                    return actual(parent,source,parent2,destination,flags)
                return rename
        with patch.object(module.ctypes,'CDLL',lambda *a,**k:RenameHook()):
            with self.assertRaises(ValueError): self.stage()
        self.assertEqual((target/'keep').read_text(),'preserved')
        self.assertFalse(list(moved.iterdir()))
        self.assertTrue(self.output.is_symlink()) # rejected foreign entry is not deleted

    def test_staged_report_mutation_is_not_late_adopted(self):
        original=module.Publication.publish
        def mutate(publication):
            original(publication)
            fd=os.open('receipt.json',os.O_WRONLY|os.O_TRUNC,dir_fd=publication.stage_fd)
            os.write(fd,b'{}'); os.close(fd)
        with patch.object(module.Publication,'publish',mutate):
            with self.assertRaises(ValueError): self.stage()
        self.assertFalse(self.output.exists())

    def test_deep_and_status_extensions_are_rejected(self):
        self.receipt.write_bytes(b'['*40+b'0'+b']'*40)
        with self.assertRaises(ValueError): self.stage()
        self.receipt.write_bytes(fixture()[0])
        status=json.loads(fixture()[1]); status['images']['gateway']['coverage']['raw']='PRIVATE'
        self.status.write_text(json.dumps(status))
        with self.assertRaises(ValueError): self.stage()
        self.assertFalse(self.output.exists())

    def test_extra_private_entries_before_and_after_publication_are_rejected(self):
        original=module.Publication.publish
        for timing in ('before','after'):
            with self.subTest(timing=timing):
                self.output=self.root/('extra-'+timing)
                def inject(publication):
                    if timing=='after': original(publication)
                    fd=os.open('private-tool.log',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600,dir_fd=publication.stage_fd)
                    os.write(fd,b'PRIVATE-marker'); os.close(fd)
                    if timing=='before': original(publication)
                with patch.object(module.Publication,'publish',inject):
                    with self.assertRaises((ValueError,OSError)): self.stage()
                self.assertFalse(self.output.exists())

    def test_group_or_other_writable_parent_is_rejected_before_staging(self):
        for mode in (0o770,0o707,0o777,0o1777):
            with self.subTest(mode=oct(mode)):
                self.root.chmod(mode)
                try:
                    with self.assertRaises(ValueError): self.stage()
                    self.assertFalse(self.output.exists())
                    self.assertFalse(list(self.root.glob('.appguard-binding-*')))
                finally: self.root.chmod(0o700)

    def test_parent_and_stage_require_current_uid(self):
        # Real descriptors, with a simulated different current UID; no chown required.
        publication=module.Publication(self.output)
        fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)
        publication.parent_fd=publication.stage_fd=fd
        try:
            current=os.getuid()
            with patch.object(module.os,'getuid',return_value=current+1):
                with self.assertRaises(ValueError): publication.check_parent()
                with self.assertRaises(ValueError): publication.check_stage()
        finally: os.close(fd)

    def test_nonprivate_stage_mode_is_rejected_before_writing(self):
        original=module.os.mkdir
        def mkdir(name,mode=0o777,**kwargs):
            original(name,mode,**kwargs)
            if str(name).startswith('.appguard-binding-'):
                os.chmod(name,0o750,dir_fd=kwargs['dir_fd'])
        with patch.object(module.os,'mkdir',mkdir):
            with self.assertRaises(ValueError): self.stage()
        self.assertFalse(self.output.exists())
        self.assertFalse(list(self.root.glob('.appguard-binding-*')))

    def test_literal_sequences_reject_numeric_bools(self):
        with self.assertRaises(ValueError): module.literal([1,2])([True,2])


if __name__=='__main__':
    unittest.main()
