#!/usr/bin/env python3
"""Create a relocatable local UPM source package; never publish artifacts."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--destination',required=True,type=Path)
parser.add_argument('--source-root',type=Path,default=Path(__file__).resolve().parents[3])
args=parser.parse_args()
package=Path(__file__).resolve().parents[1]
destination=args.destination.resolve()
if destination.exists(): parser.error('destination must not already exist')
if destination == package or (package in destination.parents and package/'.tools' not in destination.parents): parser.error('destination inside source is allowed only under .tools')
root=args.source_root.resolve()
for source in ('sdk/android/src/main','sdk/apple/Sources/AppGuardApple'):
    if not (root/source).is_dir(): parser.error('source root lacks native SDK sources')
shutil.copytree(package,destination,ignore=shutil.ignore_patterns('.tools','.evidence','Plugins','__pycache__'))
deps=destination/'Native~'/'Dependencies'
shutil.copytree(root/'sdk/apple/Sources',deps/'apple'/'Sources')
shutil.copy2(root/'sdk/apple/LICENSE',deps/'apple'/'LICENSE')
android=deps/'android'; android.mkdir(parents=True)
for name in ('src/main','gradle','gradlew','gradlew.bat','settings.gradle','LICENSE'):
    source=root/'sdk/android'/name; target=android/name
    if source.is_dir(): shutil.copytree(source,target)
    else: shutil.copy2(source,target)
# No test signing settings or corpus paths escape the staged package.
(android/'build.gradle').write_text('''plugins { id 'com.android.library' version '8.10.1' }
android {
 namespace 'io.appguard.android'
 compileSdk 36
 defaultConfig { minSdk 26; consumerProguardFiles "consumer-rules.pro" }
 compileOptions { sourceCompatibility JavaVersion.VERSION_17; targetCompatibility JavaVersion.VERSION_17 }
}
''')
shutil.copy2(package/"Native~"/"Android-consumer-rules.pro",android/"consumer-rules.pro")
manifest={str(p.relative_to(destination)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(destination.rglob('*')) if p.is_file()}
(destination/'SOURCE-MANIFEST.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(destination)
