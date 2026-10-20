#!/usr/bin/env python3
"""Receipt gates prevent build-only, partial, wrong-target and stale runtime success."""
import copy
import importlib.util
import hashlib
import tempfile
from pathlib import Path
import unittest
spec=importlib.util.spec_from_file_location('player',Path(__file__).with_name('test-player.py'))
player=importlib.util.module_from_spec(spec);spec.loader.exec_module(player)

class ReceiptTests(unittest.TestCase):
    def setUp(self):
        self.summary={'guid':'a'*32}
        self.value={'schema':'appguard-unity-player-smoke-v1','complete':True,'identifier':player.APP_ID,'buildGuid':'a'*32,'backend':'IL2CPP','development':False,'platform':'Android','frames':2,'framesWhileScansPending':1,'mainThread':1,'cases':[{'name':n,'passed':True} for n in sorted(player.CASES)]}
    def reject(self,value):
        with self.assertRaises(ValueError):player.verify_receipt(value,self.summary,'android')
    def test_complete_matching_release_passes(self):player.verify_receipt(self.value,self.summary,'android')
    def test_simulator_development_engine_is_explicit_tier(self):
        self.value.update(platform='IPhonePlayer',development=True)
        player.verify_receipt(self.value,self.summary,'ios-simulator')
    def test_simulator_cannot_silently_claim_release_engine(self):
        self.value['platform']='IPhonePlayer'
        with self.assertRaises(ValueError):player.verify_receipt(self.value,self.summary,'ios-simulator')
    def test_resolve_only_exact_smoke_activity(self):
        self.assertEqual(player.resolve_activity('priority=0\n'+player.APP_ID+'/com.unity3d.player.UnityPlayerGameActivity\n'),player.APP_ID+'/com.unity3d.player.UnityPlayerGameActivity')
    def test_wrong_missing_or_ambiguous_activity_rejects(self):
        for text in ['', 'other.app/SomeActivity', player.APP_ID+'/A\n'+player.APP_ID+'/B',player.APP_ID+'/Activity;evil']:
            with self.assertRaises(ValueError):player.resolve_activity(text)
    def test_pending_frame_measurement_is_well_formed(self):
        for bad in [-1,None,True,3]:
            changed=copy.deepcopy(self.value);changed['framesWhileScansPending']=bad;self.reject(changed)
    def test_zero_pending_frames_remains_observation_only(self):
        self.value['framesWhileScansPending']=0;player.verify_receipt(self.value,self.summary,'android')
    def test_android_identity_hashes_entire_apk(self):
        with tempfile.TemporaryDirectory() as tmp:
            apk=Path(tmp)/'player.apk';apk.write_bytes(b'apk')
            self.assertEqual(player.artifact_identity(apk,'android'),{'artifact_sha256':hashlib.sha256(b'apk').hexdigest()})
    def test_ios_identity_names_exact_framework_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            app=Path(tmp)/'Player.app';relative='Frameworks/UnityFramework.framework/UnityFramework'
            framework=app/relative;framework.parent.mkdir(parents=True);framework.write_bytes(b'framework')
            identity=player.artifact_identity(app,'ios-simulator')
            self.assertEqual(identity,{'framework_sha256':hashlib.sha256(b'framework').hexdigest(),'framework_relative_path':relative})
            (app/'other').write_bytes(b'not included in framework scope')
            self.assertEqual(player.artifact_identity(app,'ios-simulator'),identity)
            framework.write_bytes(b'changed');self.assertNotEqual(player.artifact_identity(app,'ios-simulator'),identity)
    def test_stale_guid_rejects(self):self.value['buildGuid']='b'*32;self.reject(self.value)
    def test_empty_matching_guid_is_not_provenance(self):
        self.summary['guid']='';self.value['buildGuid']='';self.reject(self.value)
    def test_duplicate_and_missing_cases_reject(self):self.value['cases'][-1]=self.value['cases'][0];self.reject(self.value)
    def test_failed_case_rejects(self):self.value['cases'][0]['passed']=False;self.reject(self.value)
    def test_truthy_case_flag_is_not_success(self):self.value['cases'][0]['passed']=1;self.reject(self.value)
    def test_each_wrong_provenance_field_rejects(self):
        for field,value in [('identifier','other.app'),('platform','IPhonePlayer'),('backend','Mono'),('development',True),('schema','other'),('complete',False)]:
            changed=copy.deepcopy(self.value);changed[field]=value;self.reject(changed)
    def test_runtime_failure_logs_reject(self):
        for text in ['JNI DETECTED ERROR IN APPLICATION', 'FATAL EXCEPTION: Thread', 'Fatal signal 11', 'AndroidJavaException', 'APPGUARD_PLAYER_RESULT FAIL']:
            with self.assertRaises(ValueError):player.verify_runtime_log(text)
    def test_normal_completion_log_passes(self):player.verify_runtime_log('APPGUARD_PLAYER_RESULT PASS')
    def test_no_frames_rejects(self):self.value['frames']=0;self.reject(self.value)
    def test_boolean_frame_count_is_not_evidence(self):self.value['frames']=True;self.reject(self.value)

if __name__=='__main__':unittest.main()
