#!/usr/bin/env python3
"""Compile staged Swift and call its actual C ABI from C and managed host probes."""
import argparse
import os
from pathlib import Path
import subprocess
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--unity',required=True,type=Path)
p.add_argument('--staged-package',required=True,type=Path)
p.add_argument('--evidence-directory',required=True,type=Path)
a=p.parse_args()
package=Path(__file__).resolve().parents[1]
stage=a.staged_package.resolve();out=a.evidence_directory.resolve();out.mkdir(parents=True,exist_ok=True)
contents=a.unity.resolve().parents[1];project=package/'.tools/project'
rsp=next((project/'Library/Bee/artifacts').glob('*.dag/AppGuard.Unity.rsp'))
def run(cmd,**kw):
    print(' '.join(map(str,cmd)),flush=True)
    subprocess.run(list(map(str,cmd)),check=True,**kw)
sources=sorted((stage/'Native~/Dependencies/apple/Sources/AppGuardApple').glob('*.swift'))+[stage/'Native~/iOS/AppGuardUnity.swift']
library=out/'libAppGuardUnityHost.dylib'
run(['xcrun','swiftc','-parse-as-library','-emit-library','-module-name','AppGuardUnityHost',*sources,'-o',library])
run(['xcrun','clang','-Wall','-Wextra','-Werror',package/'Tools~/test-risk-cabi.c','-o',out/'risk-cabi'])
run([out/'risk-cabi',library])
lines=[x for x in rsp.read_text().splitlines() if not x.startswith(('-out:','-refout:','-target:')) and not (x.startswith('"') and x.endswith('.cs"'))]
# Compile the relocated managed source too, not the original checkout's files.
lines += ['"'+str(x)+'"' for x in sorted((stage/'Runtime').glob('*.cs'))]
lines += ['-target:exe','-out:"'+str(out/'risk-managed.exe')+'"','"'+str(package/'Tools~/test-risk-managed.cs')+'"']
probe=out/'risk-managed.rsp';probe.write_text('\n'.join(lines))
run([contents/'Resources/Scripting/NetCoreRuntime/dotnet','exec',contents/'Resources/Scripting/DotNetSdkRoslyn/csc.dll','@'+str(probe)],cwd=project)
newtonsoft=next((project/'Library/PackageCache').glob('com.unity.nuget.newtonsoft-json@*/Runtime/Newtonsoft.Json.dll'))
env=dict(os.environ,MONO_PATH=str(newtonsoft.parent),DYLD_LIBRARY_PATH=str(out),DYLD_FALLBACK_LIBRARY_PATH=str(out))
run([contents/'Resources/Scripting/MonoBleedingEdge/bin/mono',out/'risk-managed.exe'],env=env)

# Compile the wrapper together with the staged SDK into actual target objects,
# without linking an XCFramework or building a Unity player.
for sdk,target in [('iphoneos','arm64-apple-ios15.0'),('iphonesimulator','arm64-apple-ios15.0-simulator')]:
    sdkpath=subprocess.check_output(['xcrun','--sdk',sdk,'--show-sdk-path'],text=True).strip()
    run(['xcrun','swiftc','-parse-as-library','-whole-module-optimization','-c','-module-name','AppGuardUnityNative','-sdk',sdkpath,'-target',target,*sources,'-o',out/(sdk+'.o')])
