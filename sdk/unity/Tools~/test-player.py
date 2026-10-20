#!/usr/bin/env python3
"""Build a task-owned IL2CPP consumer; runtime execution uses run-player.py."""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import subprocess

APP_ID='io.appguard.unity.playersmoke'
CASES={'defaults','identity-match','identity-mismatch','resource-match','resource-mismatch','resource-missing','signer-expectation','invalid-config','concurrent-16','repeat-after-concurrency','player-heartbeat'}
FIXTURE=b'AppGuard task-owned deployed fixture\n'*4096

def verify_receipt(value, summary, target):
    if value.get('schema')!='appguard-unity-player-smoke-v1' or value.get('complete') is not True:
        raise ValueError('incomplete receipt')
    if not isinstance(summary.get('guid'),str) or not re.fullmatch(r'[0-9a-fA-F]{32}',summary['guid']):
        raise ValueError('missing build GUID')
    if value.get('identifier')!=APP_ID or value.get('buildGuid')!=summary['guid'] or value.get('backend')!='IL2CPP' or value.get('development') is not (target=='ios-simulator'):
        raise ValueError('receipt provenance mismatch')
    if value.get('platform')!=('Android' if target=='android' else 'IPhonePlayer'):
        raise ValueError('receipt platform mismatch')
    cases=value.get('cases',[])
    if len(cases)!=len(CASES) or {c.get('name') for c in cases}!=CASES or any(c.get('passed') is not True for c in cases):
        raise ValueError('missing, duplicate or failed smoke case')
    if any(type(value.get(k)) is not int or value[k]<=0 for k in ('frames','mainThread')):
        raise ValueError('missing frame/thread evidence')
    pending=value.get('framesWhileScansPending')
    if type(pending) is not int or pending<0 or pending>value['frames']:
        raise ValueError('invalid pending-scan frame measurement')
    return value

def artifact_identity(artifact, target):
    if target=='android':
        return {'artifact_sha256':hashlib.sha256(artifact.read_bytes()).hexdigest()}
    for relative in ('Frameworks/UnityFramework.framework/UnityFramework','UnityFramework.framework/UnityFramework'):
        binary=artifact/relative
        if binary.is_file():
            return {'framework_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'framework_relative_path':relative}
    raise ValueError('UnityFramework binary missing')

def resolve_activity(text):
    candidates=[line.strip() for line in text.splitlines() if line.strip().startswith(APP_ID+'/')]
    if len(candidates)!=1 or not re.fullmatch(re.escape(APP_ID)+r'/[A-Za-z0-9_.$]+',candidates[0]):
        raise ValueError('missing or ambiguous smoke activity')
    return candidates[0]

def verify_runtime_log(text):
    for marker in ('JNI DETECTED ERROR', 'FATAL EXCEPTION', 'Fatal signal', 'AndroidJavaException', 'APPGUARD_PLAYER_RESULT FAIL'):
        if marker in text:raise ValueError('runtime failure marker: '+marker)

def run(command, **kwargs):
    print(' '.join(map(str,command)),flush=True)
    return subprocess.run(list(map(str,command)),check=True,**kwargs)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--unity',required=True,type=Path)
    parser.add_argument('--staged-package',required=True,type=Path)
    parser.add_argument('--work-directory',required=True,type=Path)
    parser.add_argument('--output-directory',required=True,type=Path)
    parser.add_argument('--target',required=True,choices=['android','ios-simulator','ios-device'])
    args=parser.parse_args()
    package=args.staged_package.resolve();work=args.work_directory.resolve();output=args.output_directory.resolve()
    if output.exists():parser.error('output directory must be new; preserve prior evidence')
    if not (package/'SOURCE-MANIFEST.json').is_file():parser.error('requires a staged source package')
    plugin=package/('Plugins/Android/appguard-android.aar' if args.target=='android' else 'Plugins/iOS/AppGuardUnityNative.xcframework')
    if not plugin.exists():parser.error('build staged native plugins first')
    # Only a project explicitly marked by this runner may be reused.
    marker=work/'.appguard-player-project'
    if work.exists() and not marker.is_file():parser.error('work directory is not owned by this runner')
    work.mkdir(parents=True,exist_ok=True);marker.write_text(APP_ID+'\n');output.mkdir(parents=True)
    for folder in ['Assets/Editor','Assets/StreamingAssets','Packages','ProjectSettings']:(work/folder).mkdir(parents=True,exist_ok=True)
    tools=Path(__file__).resolve().parent
    fixture_source=(tools/'PlayerSmoke.cs').read_text().replace('FIXTURE_SHA256',hashlib.sha256(FIXTURE).hexdigest())
    (work/'Assets/PlayerSmoke.cs').write_text(fixture_source)
    shutil.copy2(tools/'PlayerBuild.cs',work/'Assets/Editor/PlayerBuild.cs')
    (work/'Assets/StreamingAssets/appguard-fixture.txt').write_bytes(FIXTURE)
    (work/'Packages/manifest.json').write_text(json.dumps({'dependencies':{'io.appguard.unity':'file:'+str(package),'com.unity.modules.jsonserialize':'1.0.0'}}))
    (work/'ProjectSettings/ProjectVersion.txt').write_text('m_EditorVersion: 6000.3.24f1\n')
    env=dict(os.environ,APPGUARD_PLAYER_TARGET=args.target,APPGUARD_PLAYER_OUTPUT=str(output/('player.apk' if args.target=='android' else 'xcode')),GRADLE_USER_HOME=str(work/'gradle-home'),ANDROID_USER_HOME=str(work/'android-home'))
    if args.target=='android':
        jdk=args.unity.resolve().parents[3]/'PlaybackEngines/AndroidPlayer/OpenJDK'
        key=work/'fixture.keystore'
        if not key.exists():
            run([jdk/'bin/keytool','-genkeypair','-keystore',key,'-storepass','android','-keypass','android','-alias','fixture','-dname','CN=AppGuard Local Fixture','-keyalg','RSA','-validity','3650'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        env['APPGUARD_PLAYER_KEYSTORE']=str(key)
    command=[args.unity,'-batchmode','-nographics','-quit','-projectPath',work,'-buildTarget','Android' if args.target=='android' else 'iOS','-executeMethod','AppGuardPlayerBuild.Build','-logFile',output/'unity.log']
    run(command,env=env,timeout=1800)
    summary=json.loads(Path(env['APPGUARD_PLAYER_OUTPUT']+'.summary.json').read_text())
    if summary['result']!='Succeeded' or summary['backend']!='IL2CPP' or summary['stripping']!='High' or summary['errors']!=0:raise ValueError('build settings/result mismatch')
    (output/'build-receipt.json').write_text(json.dumps({'summary':summary,'staged_manifest_sha256':hashlib.sha256((package/'SOURCE-MANIFEST.json').read_bytes()).hexdigest(),'fixture_sha256':hashlib.sha256(FIXTURE).hexdigest(),'harness_sha256':hashlib.sha256(fixture_source.encode()).hexdigest(),'engine_profile':'Simulator Development engine' if args.target=='ios-simulator' else 'Release engine', 'note':'Build only; runtime execution requires a separate receipt.'},indent=2)+'\n')
    print('PASS: actual Unity IL2CPP player build/export; runtime not inferred',flush=True)

if __name__=='__main__':main()
