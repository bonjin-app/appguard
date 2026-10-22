"""Native full-topology platform binding; owned fixtures only, no Docker."""
import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import test_spring_containers as qualification
import test_container_image_scan as image_scan
import test_container_evidence_binding as binding


def block(ids, arch='arm64', *, pid1=True):
    value = dict(schema=1, platform='linux/'+arch, host_machine='aarch64' if arch=='arm64' else 'x86_64',
        daemon_architecture=arch, verified=True, images={})
    for role, identifier in ids.items():
        value['images'][role] = dict(image_id=identifier, os='linux', architecture=arch)
        if pid1: value['images'][role]['pid1_elf_machine'] = 183 if arch=='arm64' else 62
    return value


class PlatformTests(unittest.TestCase):
    def observe(self, arch='arm64', change=None, system='Linux', machine=None):
        module = qualification.load_module()
        records = {role: qualification.container(role) for role in qualification.IDS}
        for index, record in enumerate(records.values(), 1): record['Image'] = 'sha256:'+str(index)*64
        class Docker(qualification.FakeDocker):
            def call(inner, args, **kwargs):
                if args[0]=='info':
                    value = dict(OSType='linux', Architecture='aarch64' if arch=='arm64' else 'x86_64')
                    if change: change('daemon', value)
                    return json.dumps(value)
                if args[:2]==['image','inspect']:
                    value = dict(Id=args[2], Os='linux', Architecture=arch)
                    if change: change('image', value)
                    return json.dumps([value])
                if args[0]=='exec':
                    self.assertEqual(args[2:], ['od','-An','-N20','-tx1','/proc/1/exe'])
                    self.assertLessEqual(kwargs['timeout'],5)
                    value = bytearray.fromhex('7f454c460201010000000000000000000200'+('b700' if arch=='arm64' else '3e00'))
                    if change: change('elf', value)
                    return ' '.join(value.hex()[i:i+2] for i in range(0,40,2))+'\n'
                return super().call(args, **kwargs)
        docker = Docker({record['Id']:record for record in records.values()})
        with patch.object(module.host_platform,'system',return_value=system), \
                patch.object(module.host_platform,'machine',return_value=machine or ('aarch64' if arch=='arm64' else 'x86_64')):
            return module.observe_runtime_platform(docker,records,qualification.PROJECT,qualification.OWNER,'linux/'+arch)

    def test_both_native_platforms_bind_all_actual_pid1_headers_and_image_ids(self):
        for arch in ('amd64','arm64'):
            with self.subTest(arch=arch):
                result = self.observe(arch)
                ids = {role:'sha256:'+str(index)*64 for index,role in enumerate(qualification.IDS,1)}
                self.assertEqual(result,block(ids,arch))

    def test_machine_name_alone_cannot_prove_native_execution(self):
        for kwargs in (dict(system='Darwin'),dict(machine='x86_64')):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError): self.observe(**kwargs)
        changes = [('daemon',lambda v:v.update(OSType='windows')),
            ('daemon',lambda v:v.update(Architecture='x86_64')),
            ('image',lambda v:v.update(Id='sha256:'+'f'*64)),
            ('image',lambda v:v.update(Architecture='amd64')),
            ('elf',lambda v:v.__setitem__(0,0)),('elf',lambda v:v.__setitem__(4,1)),
            ('elf',lambda v:v.__setitem__(5,2)),('elf',lambda v:v.__setitem__(18,62))]
        for kind, mutate in changes:
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.observe(change=lambda found,value: mutate(value) if found==kind else None)

    def test_pid1_elf_type_accepts_only_executable_or_shared_object(self):
        for arch in ('amd64','arm64'):
            for elf_type in (0,1,2,3,4,65535):
                def change(kind,value):
                    if kind=='elf':value[16:18]=elf_type.to_bytes(2,'little')
                with self.subTest(arch=arch,elf_type=elf_type):
                    if elf_type in (2,3):self.assertTrue(self.observe(arch,change=change)['verified'])
                    else:
                        with self.assertRaises(ValueError):self.observe(arch,change=change)

    def test_owned_override_fixes_all_service_and_probe_platforms(self):
        module=qualification.load_module()
        legacy=module.qualification_override(Path('/private/owned'),10001,10001,qualification.PROJECT,qualification.OWNER)
        self.assertNotIn('platform',legacy['services']['probe'])
        value=module.qualification_override(Path('/private/owned'),10001,10001,qualification.PROJECT,qualification.OWNER,'linux/arm64')
        self.assertEqual(set(value['services']),{'gateway','backend','redis','probe'})
        for role,row in value['services'].items():
            self.assertEqual(row['platform'],'linux/arm64')
            if role!='probe': self.assertEqual(row['build']['platforms'],['linux/arm64'])

    def scanner(self, *, arch='arm64', change=None):
        case=image_scan.ContainerScanTests();case.setUp();self.addCleanup(case.doCleanups)
        case.data['runtime_platform']=block(case.ids,arch);case.write()
        original=case.runner
        def runner(command, **kwargs):
            if command[0]=='docker' and command[3]=='info':
                value=dict(OSType='linux',Architecture='aarch64' if arch=='arm64' else 'x86_64')
                if change:change('daemon',value)
                return 0,json.dumps(value).encode()
            if command[0]=='docker' and command[3:5]==['image','inspect']:
                value=dict(Id=command[5],Os='linux',Architecture=arch)
                if change:change('image',value)
                return 0,json.dumps([value]).encode()
            return original(command,**kwargs)
        case.runner=runner
        with patch.object(image_scan.module.platform,'system',return_value='Linux'), \
                patch.object(image_scan.module.platform,'machine',return_value='aarch64' if arch=='arm64' else 'x86_64'):
            return case,case.run_scan()

    def test_native_arm_scanner_uses_verified_receipt_and_actual_image_platforms(self):
        case,result=self.scanner()
        self.assertTrue(result['automated_checks_passed'])
        self.assertEqual(result['runtime_platform'],block(case.ids,pid1=False))
        self.assertEqual(result['scanner']['archive_sha256'],'e174dff2a6dba5e3ae41f8d0537a6324405bd08132497340304c6b20e0f16a1f')
        self.assertFalse(result['native_binary_coverage']);self.assertFalse(result['release_ready'])

    def test_native_amd_scanner_has_equally_strict_explicit_binding(self):
        case,result=self.scanner(arch='amd64')
        self.assertTrue(result['automated_checks_passed'])
        self.assertEqual(result['runtime_platform'],block(case.ids,'amd64',pid1=False))

    def test_scanner_rechecks_native_daemon_after_scanning(self):
        seen=0
        def change(kind,value):
            nonlocal seen
            if kind=='daemon':
                seen+=1
                if seen>1:value['Architecture']='x86_64'
        _,result=self.scanner(change=change)
        self.assertFalse(result['automated_checks_passed'])
        self.assertFalse(result['runtime_platform']['verified'])

    def test_publication_time_image_platform_change_aborts_owned_output(self):
        changed=False
        original=image_scan.module.Publication.publish
        def publish(value):
            nonlocal changed
            original(value);changed=True
        def change(kind,value):
            if kind=='image' and changed:value['Architecture']='amd64'
        with patch.object(image_scan.module.Publication,'publish',new=publish), self.assertRaises(ValueError):
            self.scanner(change=change)

    def test_native_scanner_rejects_daemon_and_post_scan_platform_changes(self):
        case,result=self.scanner(change=lambda kind,value:value.update(Architecture='amd64') if kind=='daemon' else None)
        self.assertFalse(result['automated_checks_passed']);self.assertEqual(case.scans,0)
        seen={}
        def change(kind,value):
            if kind=='image':
                seen[value['Id']]=seen.get(value['Id'],0)+1
                if seen[value['Id']]>1:value['Architecture']='amd64'
        _,result=self.scanner(change=change)
        self.assertFalse(result['automated_checks_passed']);self.assertFalse(result['runtime_platform']['verified'])

    def test_scanner_rejects_forged_or_partial_qualified_platform_blocks(self):
        for mutate in (lambda b:b.update(verified=False),lambda b:b.update(host_machine='x86_64'),
                lambda b:b['images']['backend'].update(pid1_elf_machine=62),
                lambda b:b['images'].pop('redis'),lambda b:b.update(secret='PRIVATE')):
            case=image_scan.ContainerScanTests();case.setUp();self.addCleanup(case.doCleanups)
            case.data['runtime_platform']=block(case.ids);mutate(case.data['runtime_platform']);case.write()
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):image_scan.module.validate_receipt(case.receipt)

    def stage(self, mutate=None):
        case=binding.BindingTests();case.setUp();self.addCleanup(case.doCleanups)
        receipt=json.loads(case.receipt.read_bytes());status=binding.detail_fixture()
        ids={role:'sha256:'+str(index)*64 for index,role in enumerate(binding.module.ROLES,1)}
        receipt['containers']['image_ids']=ids;receipt['runtime_platform']=block(ids)
        for role,row in status['images'].items():row['image_id']=ids[role]
        status['runtime_platform']=block(ids,pid1=False)
        status['scanner'].update(platform='Linux-aarch64',archive_sha256='e174dff2a6dba5e3ae41f8d0537a6324405bd08132497340304c6b20e0f16a1f')
        if mutate:mutate(receipt,status)
        raw=json.dumps(receipt).encode();case.receipt.write_bytes(raw)
        status['qualification_sha256']=hashlib.sha256(raw).hexdigest();case.status.write_text(json.dumps(status))
        return case.stage()

    def test_binding_accepts_exact_native_blocks_and_preserves_findings(self):
        self.assertTrue(self.stage()['staged'])

    def test_binding_rejects_cross_artifact_platform_confusion(self):
        for mutate in (lambda r,s:s['runtime_platform'].update(platform='linux/amd64'),
                lambda r,s:r['runtime_platform']['images']['gateway'].update(image_id='sha256:'+'f'*64),
                lambda r,s:s.pop('runtime_platform')):
            with self.subTest(mutate=mutate),self.assertRaises(ValueError):self.stage(mutate)

    def test_false_partial_platform_diagnostics_remain_stageable(self):
        def partial(receipt,status):
            receipt['technical_verification']=False
            for value in (receipt['runtime_platform'],status['runtime_platform']):
                value.update(verified=False,host_machine=None,daemon_architecture=None,images={})
            status.update(automated_checks_passed=False,reason='container_scan_unverified',images={},
                vulnerabilities=None,scanner=None,databases=None,finding_details_complete=False,coverage_passed=False)
        self.assertTrue(self.stage(partial)['staged'])


if __name__=='__main__':unittest.main()
