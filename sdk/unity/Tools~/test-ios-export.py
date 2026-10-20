#!/usr/bin/env python3
"""Exercise the iOS export callback with the installed Unity PBX API (no player build)."""
import argparse
import os
from pathlib import Path
import subprocess

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--unity',required=True,type=Path)
parser.add_argument('--staged-package',required=True,type=Path)
args=parser.parse_args()
package=Path(__file__).resolve().parents[1]
project=package/'.tools/project'
evidence=package/'.evidence';evidence.mkdir(exist_ok=True)
contents=args.unity.resolve().parents[1]
rsp=next((project/'Library/Bee/artifacts').glob('*.dag/AppGuard.Unity.Editor.rsp'),None)
if rsp is None: parser.error('run Tools~/test-managed.py first to generate Unity compiler references')
lines=[x for x in rsp.read_text().splitlines() if not x.startswith(('-out:','-refout:','-target:'))]
# Reuse Unity's real references and compile the production postprocessor with iOS enabled.
lines += ['-define:UNITY_IOS','-r:"'+str(contents/'Resources/BuildPipeline/UnityEditor.iOS.Extensions.Xcode.dll')+'"',
          '-target:exe','-out:"'+str(evidence/'ios-export-probe.exe')+'"','"'+str(package/'Tools~/test-ios-export.cs')+'"']
generated=evidence/'ios-export-probe.rsp';generated.write_text('\n'.join(lines))
with (evidence/'local-risk-export.log').open('w') as log:
    subprocess.run([str(contents/'Resources/Scripting/NetCoreRuntime/dotnet'),'exec',str(contents/'Resources/Scripting/DotNetSdkRoslyn/csc.dll'),'@'+str(generated)],cwd=project,stdout=log,stderr=subprocess.STDOUT,check=True)
    env=dict(os.environ,MONO_PATH=os.pathsep.join(str(contents/p) for p in ['Resources/BuildPipeline','Resources/Scripting/Managed','Resources/Scripting/Managed/UnityEngine']))
    subprocess.run([str(contents/'Resources/Scripting/MonoBleedingEdge/bin/mono'),str(evidence/'ios-export-probe.exe'),str(package/'.tools/local-risk-export'),str(args.staged_package.resolve())],env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
print((evidence/'local-risk-export.log').read_text())
