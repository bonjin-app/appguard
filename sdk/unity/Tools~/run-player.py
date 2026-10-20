#!/usr/bin/env python3
"""Install/run a smoke artifact only on an explicitly selected virtual device; never infer success from launch."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import time

spec=importlib.util.spec_from_file_location('player',Path(__file__).with_name('test-player.py'))
player=importlib.util.module_from_spec(spec);spec.loader.exec_module(player)

def capture(command,check=True):return subprocess.run(list(map(str,command)),check=check,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--target',choices=['android','ios-simulator'],required=True)
    p.add_argument('--artifact',type=Path,required=True)
    p.add_argument('--build-receipt',type=Path,required=True)
    p.add_argument('--evidence-directory',type=Path,required=True)
    p.add_argument('--android-adb',type=Path)
    p.add_argument('--android-serial')
    p.add_argument('--ios-set',type=Path)
    p.add_argument('--ios-udid')
    args=p.parse_args();artifact=args.artifact.resolve();out=args.evidence_directory.resolve()
    if out.exists():p.error('evidence directory must be new')
    summary=json.loads(args.build_receipt.read_text())['summary']
    if summary.get('target')!=args.target or summary.get('result')!='Succeeded' or summary.get('backend')!='IL2CPP' or summary.get('stripping')!='High' or summary.get('errors')!=0:p.error('invalid build receipt')
    if not artifact.exists():p.error('artifact does not exist')
    if args.target=='android':
        if not args.android_adb or not args.android_serial or not args.android_serial.startswith('emulator-'):p.error('explicit Android emulator adb/serial required')
        prefix=[args.android_adb,'-s',args.android_serial]
        if capture(prefix+['shell','getprop','ro.kernel.qemu']).stdout.strip()!='1':p.error('selected Android device is not an emulator')
        if capture(prefix+['shell','pm','path',player.APP_ID],False).stdout.strip():p.error('smoke app already installed; preserve its state')
    else:
        if not args.ios_set or not args.ios_udid:p.error('explicit Simulator set/UDID required')
        prefix=['xcrun','simctl','--set',args.ios_set]
        if capture(prefix+['get_app_container',args.ios_udid,player.APP_ID,'data'],False).returncode==0:p.error('smoke app already installed; preserve its state')
    out.mkdir(parents=True)
    log=[]
    def run(command):
        r=capture(command,False);log.append({'command':list(map(str,command)),'stdout':r.stdout,'stderr':r.stderr,'returncode':r.returncode});r.check_returncode();return r
    try:
        if args.target=='android':
            artifact_hash=hashlib.sha256(artifact.read_bytes()).hexdigest()
            run(prefix+['install','--no-streaming',artifact])
            resolved=run(prefix+['shell','cmd','package','resolve-activity','--brief','-a','android.intent.action.MAIN','-c','android.intent.category.LAUNCHER','-p',player.APP_ID])
            activity=player.resolve_activity(resolved.stdout)
            launched=run(prefix+['shell','am','start','-W','-n',activity])
            if 'Status: ok' not in launched.stdout:raise ValueError('activity launch not confirmed')
            def read():return capture(prefix+['shell','cat','/sdcard/Android/data/'+player.APP_ID+'/files/appguard-player-result.json'],False)
        else:
            artifact_hash=hashlib.sha256((artifact/'UnityFramework.framework/UnityFramework').read_bytes()).hexdigest() if (artifact/'UnityFramework.framework/UnityFramework').exists() else hashlib.sha256((artifact/'Frameworks/UnityFramework.framework/UnityFramework').read_bytes()).hexdigest()
            run(prefix+['install',args.ios_udid,artifact]);launched=run(prefix+['launch','--stdout='+str(out/'stdout.txt'),'--stderr='+str(out/'stderr.txt'),args.ios_udid,player.APP_ID])
            data=Path(run(prefix+['get_app_container',args.ios_udid,player.APP_ID,'data']).stdout.strip())
            def read():
                path=data/'Documents/appguard-player-result.json'
                return subprocess.CompletedProcess([],0,path.read_text(),'') if path.is_file() else subprocess.CompletedProcess([],1,'','not yet')
        deadline=time.monotonic()+120;last=''
        while time.monotonic()<deadline:
            result=read();last=result.stdout
            if result.returncode==0:
                if len(last.encode())>65536:raise ValueError('oversize receipt')
                try:value=json.loads(last)
                except json.JSONDecodeError:time.sleep(.5);continue
                if value.get('complete') is True:break
            time.sleep(.5)
        else:raise TimeoutError('player result not produced')
        (out/'runtime.json').write_text(last)
        player.verify_receipt(value,summary,args.target)
        time.sleep(.5)
        if args.target=='android':
            pid=run(prefix+['shell','pidof',player.APP_ID]).stdout.strip()
            if not pid.isdigit():raise ValueError('player process not alive')
            logs=run(prefix+['logcat','-d','--pid='+pid,'-t','2000']).stdout
            (out/'player-logcat.txt').write_text(logs)
        else:
            pid=launched.stdout.strip().rsplit(':',1)[-1].strip()
            if not pid.isdigit():raise ValueError('missing Simulator app PID')
            run(['ps','-p',pid,'-o','pid='])
            logs=''.join((out/name).read_text(errors='replace') for name in ('stdout.txt','stderr.txt') if (out/name).is_file())
        player.verify_runtime_log(logs)
        if 'APPGUARD_PLAYER_RESULT PASS '+summary['guid'] not in logs:raise ValueError('matching runtime completion log absent')
        (out/'verified.json').write_text(json.dumps({'target':args.target,'artifact':str(artifact),'artifact_sha256':artifact_hash,'build_guid':summary['guid'],'cases':len(player.CASES),'passed':True,'runtime_development':value['development'],'device':args.android_serial or args.ios_udid,'note':'Virtual player runtime; no physical-device or attestation proof.'},indent=2)+'\n')
        print('PASS:',args.target,len(player.CASES),'runtime cases; build GUID',summary['guid'])
    finally:
        (out/'commands.json').write_text(json.dumps(log,indent=2)+'\n')
        if args.target=='android':
            pid=capture(prefix+['shell','pidof',player.APP_ID],False).stdout.strip()
            if pid and pid.isdigit():(out/'player-logcat.txt').write_text(capture(prefix+['logcat','-d','--pid='+pid,'-t','2000'],False).stdout)

if __name__=='__main__':main()
