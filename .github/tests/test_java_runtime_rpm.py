"""Owned protocol fixtures; these do not measure a UBI runtime or feed."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'scripts/qualification'))


def envelope(data, complete=True, reason='measured'):
    return json.dumps(dict(schema=1, complete=complete, reason=reason, data=data))+'\n'


def feature(code=0, failed=(), unentered=()):
    from inspect_java_runtime import FEATURE_CHECKS
    checks = {key: dict(attempted=key not in unentered,
        passed=None if key in unentered else key not in failed) for key in sorted(FEATURE_CHECKS)}
    passed = all(row['attempted'] and row['passed'] is True for row in checks.values())
    return dict(schema=2, checks=checks, checks_passed=passed, result_code=code,
        passed=passed and code == 0)


class RpmTests(unittest.TestCase):
    def module(self):
        import java_runtime_rpm
        return java_runtime_rpm

    def rows(self):
        return 'glibc\t0\t2.39\t58.el10\tx86_64\tglibc-2.39-58.el10.src.rpm\tLGPL-2.1-or-later AND BSD-2-Clause\n'

    def test_rpm_identity_keeps_epoch_release_versions_and_license(self):
        m=self.module(); raw=self.rows()+self.rows().replace('\t0\t','\t2\t').replace('2.39','2.40')
        rows=m.parse_packages(raw, 'amd64')
        self.assertEqual([row['epoch'] for row in rows], [0,2])
        self.assertEqual(rows[0]['release'], '58.el10')
        self.assertIn(' AND ', rows[0]['license'])
        self.assertEqual(len(m.parse_packages(raw.replace('x86_64','aarch64'), 'arm64')),2)

    def test_rpm_refuses_duplicate_nevra_wrong_arch_control_and_truncation(self):
        m=self.module()
        for raw in (self.rows()*2,self.rows().replace('x86_64','i686'),
                self.rows().replace('LGPL','\x00LGPL'),self.rows()[:-1],
                self.rows().replace('\t0\t','\t-1\t'),self.rows().replace('glibc\t','../glibc\t')):
            with self.subTest(raw=raw[:30]),self.assertRaises(ValueError):m.parse_packages(raw,'amd64')

    def test_feature_result_two_retains_observations_but_is_incomplete(self):
        m=self.module(); result,status=m.parse_feature_result(feature(code=2))
        self.assertTrue(result['checks_passed']);self.assertFalse(result['passed'])
        self.assertFalse(status['complete']);self.assertEqual(status['reason'],'resource_unverified')
        result,status=m.parse_feature_result(feature(code=1,failed=('headless_font',)))
        self.assertTrue(status['complete']);self.assertFalse(result['passed'])

    def test_feature_typed_partial_and_contradictions_are_rejected(self):
        m=self.module(); partial=feature(code=2,unentered=('headless_font',))
        self.assertFalse(m.parse_feature_result(partial)[1]['complete'])
        variants=[]
        for path,value in ((('result_code',),True),(('passed',),True),(('checks_passed',),True),
                (('checks','headless_font','passed'),False)):
            row=copy.deepcopy(partial);target=row
            for key in path[:-1]:target=target[key]
            target[path[-1]]=value;variants.append(row)
        for row in variants:
            with self.assertRaises(ValueError):m.parse_feature_result(row)

    def test_env_allowlist_refuses_injection_unknown_empty_and_duplicate(self):
        m=self.module()
        m.validate_environment(['PATH=/opt/java/openjdk/bin:/usr/bin','JAVA_HOME=/opt/java/openjdk','LANG=C.UTF-8'])
        for rows in (['JAVA_TOOL_OPTIONS='],['LD_PRELOAD=SECRET'],['ARBITRARY=value'],['LANG=C','LANG=C']):
            with self.assertRaises(ValueError):m.validate_environment(rows)

    def test_aggregate_matrix_does_not_erase_features_on_cleanup_failure(self):
        m=self.module(); report=m.initial_report('amd64')
        report['stages']={name:m.status(True,True,'measured',0) for name in m.STAGES}
        report.update(features=feature(),checks={'runtime_features_passed':True},cleanup=True,final_identity_verified=True)
        m.finalize(report);self.assertTrue(report['measurement_complete'])
        report['cleanup']=False;m.finalize(report)
        self.assertTrue(report['inventory_complete']);self.assertFalse(report['measurement_complete'])
        self.assertTrue(report['features']['passed']);self.assertFalse(report['native_checks_passed'])
        report['cleanup']=True;report['stages']['rpm_inventory']=m.status(True,False,'tool_unavailable',0)
        m.finalize(report);self.assertFalse(report['inventory_complete']);self.assertTrue(report['features']['passed'])

    def test_parent_parser_requires_exact_envelope_and_safe_reason(self):
        m=self.module()
        self.assertEqual(m.parse_envelope(envelope([]))['data'],[])
        for raw in (envelope([],False,'SECRET'),envelope([]).replace('"schema": 1','"schema": 1,"schema": 1'),
                envelope([]).replace('true','1',1),'SECRET\n'):
            with self.assertRaises(ValueError):m.parse_envelope(raw)


if __name__=='__main__':unittest.main()
