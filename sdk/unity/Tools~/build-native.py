#!/usr/bin/env python3
"""Build only staged SDK inputs, with task-local output/caches. Requires Xcode/Android SDK/JDK17."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--platform',choices=['ios','android','all'],required=True)
args=parser.parse_args()
package=Path(__file__).resolve().parents[1]
deps=package/'Native~'/'Dependencies'
if not deps.is_dir(): parser.error('run Tools~/stage.py from the source checkout first')
work=package/'.tools'/'native-build';work.mkdir(parents=True,exist_ok=True)
plugins=package/'Plugins';plugins.mkdir(exist_ok=True)
def run(*cmd,**kwargs): subprocess.run([str(x) for x in cmd],check=True,**kwargs)
if args.platform in ('ios','all'):
    libraries=[]
    sources=sorted((deps/'apple'/'Sources'/'AppGuardApple').glob('*.swift'))+[package/'Native~'/'iOS'/'AppGuardUnity.swift']
    for sdk,targets in [('iphoneos',['arm64-apple-ios15.0']),('iphonesimulator',['arm64-apple-ios15.0-simulator','x86_64-apple-ios15.0-simulator'])]:
        sdkpath=subprocess.check_output(['xcrun','--sdk',sdk,'--show-sdk-path'],text=True).strip()
        archives=[]
        for target in targets:
            output=work/target;output.mkdir(exist_ok=True)
            archive=output/'libAppGuardUnityNative.a'
            run('xcrun','swiftc','-parse-as-library','-O','-emit-library','-static','-module-name','AppGuardUnityNative','-sdk',sdkpath,'-target',target,*sources,'-o',archive)
            archives.append(archive)
        library=work/sdk/'libAppGuardUnityNative.a';library.parent.mkdir(exist_ok=True)
        run('xcrun','lipo','-create',*archives,'-output',library)
        libraries.extend(['-library',str(library)])
    output=plugins/'iOS'/'AppGuardUnityNative.xcframework';output.parent.mkdir(exist_ok=True)
    if output.exists(): shutil.rmtree(output)
    run('xcodebuild','-create-xcframework',*libraries,'-output',output)
if args.platform in ('android','all'):
    android=deps/'android'
    env=dict(os.environ,GRADLE_USER_HOME=str(work/'gradle-home'),ANDROID_USER_HOME=str(work/'android-home'))
    run('sh',android/'gradlew','--no-daemon','-p',android,'assembleRelease',env=env)
    output=plugins/'Android';output.mkdir(exist_ok=True)
    jars=list((android/'build'/'outputs'/'aar').glob('*-release.aar'))
    if len(jars)!=1: raise RuntimeError('expected one release AAR')
    shutil.copy2(jars[0],output/'appguard-android.aar')
print('Local artifacts built; no device execution, signing or publication implied.')
