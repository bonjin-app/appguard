#!/usr/bin/env python3
"""Test a package in its own disposable project with an already-installed Unity."""
import argparse
import json
from pathlib import Path
import subprocess
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--unity',required=True,type=Path)
parser.add_argument('--evidence-directory',type=Path)
args=parser.parse_args()
package=Path(__file__).resolve().parents[1]
project=package/'.tools'/'project';evidence=(args.evidence_directory or package/'.evidence').resolve()
for path in [project/'Assets',project/'Packages',project/'ProjectSettings',evidence]:path.mkdir(parents=True,exist_ok=True)
(project/'Packages'/'manifest.json').write_text(json.dumps({'dependencies':{'io.appguard.unity':'file:'+str(package),'com.unity.test-framework':'1.6.0'},'testables':['io.appguard.unity']}))
(project/'ProjectSettings'/'ProjectVersion.txt').write_text('m_EditorVersion: 6000.3.24f1\n')
subprocess.run([str(args.unity),'-batchmode','-nographics','-projectPath',str(project),'-runTests','-testPlatform','EditMode','-testResults',str(evidence/'managed.xml'),'-logFile',str(evidence/'managed.log')],check=True)
# Compile actual JNI and P/Invoke branches using Unity's own response file and
# compiler/reference assemblies. This is compile evidence, not a mobile player.
rsp=next((project/'Library'/'Bee'/'artifacts').glob('*.dag/AppGuard.Unity.rsp'))
contents=args.unity.resolve().parents[1]
for platform in ['ANDROID','IOS']:
    lines=[x for x in rsp.read_text().splitlines() if not x.startswith(('-out:','-refout:','-define:UNITY_EDITOR','-define:UNITY_STANDALONE'))]
    lines += ['-define:UNITY_'+platform,'-out:"'+str(evidence/('AppGuard.Unity.'+platform+'.dll'))+'"']
    generated=evidence/(platform+'.rsp');generated.write_text('\n'.join(lines))
    subprocess.run([str(contents/'Resources/Scripting/NetCoreRuntime/dotnet'),'exec',str(contents/'Resources/Scripting/DotNetSdkRoslyn/csc.dll'),'@'+str(generated)],cwd=project,check=True)
editor=next((project/'Library'/'Bee'/'artifacts').glob('*.dag/AppGuard.Unity.Editor.rsp'))
lines=[x for x in editor.read_text().splitlines() if not x.startswith(('-out:','-refout:'))]
lines+=['-define:UNITY_IOS','-r:"'+str(contents/'Resources/BuildPipeline/UnityEditor.iOS.Extensions.Xcode.dll')+'"','-out:"'+str(evidence/'AppGuard.Unity.Editor.IOS.dll')+'"']
generated=evidence/'EDITOR-IOS.rsp';generated.write_text('\n'.join(lines))
subprocess.run([str(contents/'Resources/Scripting/NetCoreRuntime/dotnet'),'exec',str(contents/'Resources/Scripting/DotNetSdkRoslyn/csc.dll'),'@'+str(generated)],cwd=project,check=True)
print('Editor tests, Android/iOS runtime branches and iOS postprocessor compilation passed')
