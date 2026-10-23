import re
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
WORKFLOW=ROOT/'.github/workflows/java-ubi-runtime.yml'


class UbiWorkflowTests(unittest.TestCase):
    def source(self):
        self.assertTrue(WORKFLOW.is_file(),'bounded UBI workflow required')
        return WORKFLOW.read_text()

    def test_fixed_matrix_and_false_production_scope(self):
        text=self.source()
        self.assertIn('workflow_dispatch:',text);self.assertNotRegex(text,r'(?m)^  pull_request:')
        self.assertIn('runner: ubuntu-24.04\n',text);self.assertIn('runner: ubuntu-24.04-arm\n',text)
        self.assertIn('timeout-minutes: 90',text);self.assertIn('cancel-in-progress: false',text)
        self.assertIn('contents: read',text);self.assertIn('persist-credentials: false',text)
        self.assertNotIn('setup-qemu',text);self.assertNotIn('inputs.runner',text)
        self.assertIn('--package-profile rpm-ubi10-v1',text)
        self.assertIn('if (( result > 1 )); then failed=2; fi',text)
        self.assertIn('if: always()',text)
        for line in text.splitlines():
            if 'uses:' in line:self.assertRegex(line,r'@[0-9a-f]{40}(?: |$)')

    def test_premerge_bootstrap_is_only_the_owned_evaluation_branch(self):
        trigger=self.source().split('\npermissions:',1)[0].split('\non:\n',1)[1]
        self.assertEqual(trigger,'  push:\n    branches: [codex/ubi-runtime-evaluation]\n  workflow_dispatch:\n')

    def test_same_two_image_ids_flow_through_native_scan_and_binder(self):
        text=self.source()
        for name in ('noble','ubi'):
            self.assertIn('native/$runtime',text)
            self.assertIn('$state/'+name+'-id',text)
        self.assertIn('--image "$noble" --image "$ubi"',text)
        self.assertIn('--noble-image "$noble" --ubi-image "$ubi"',text)
        self.assertIn('rpm-inventory.tsv',text);self.assertIn('trivy-image-*.json',text)
        self.assertNotRegex(text,r'(?m)^\s*(?:export )?(?:HOME|CODEX_HOME)=')
        self.assertNotIn('env HOME=',text)

    def test_actual_bash_syntax_of_every_run_body(self):
        lines=self.source().splitlines();bodies=[]
        for index,line in enumerate(lines):
            if line=='        run: |':
                body=[]
                for row in lines[index+1:]:
                    if row and not row.startswith('          '):break
                    body.append(row[10:])
                bodies.append('\n'.join(body))
        self.assertGreaterEqual(len(bodies),6)
        for body in bodies:
            result=subprocess.run(['/bin/bash','-n'],input=body.encode(),capture_output=True,timeout=5)
            self.assertEqual(result.returncode,0,result.stderr.decode())

    def test_ubi_target_preserves_vendor_files_and_installs_no_tools(self):
        source=(ROOT/'scripts/qualification/java-runtime-probe.Dockerfile').read_text()
        self.assertIn('AS ubi10',source)
        target=source[source.index('FROM eclipse-temurin:17.0.20.1_1-jre-ubi10-minimal'):]
        self.assertIn('@sha256:25c83f52d080115d99d80eaeda67a5221b07b7066ae8248fdd37f6e1c6469aef',target)
        self.assertNotRegex(target,r'(?m)^(RUN|ENV) ')
        self.assertNotIn('/opt/java/openjdk/', '\n'.join(line for line in target.splitlines() if line.startswith('COPY ')))
        self.assertIn('AppGuardRuntimeInventory.java',source)

    def step(self,name):
        lines=self.source().splitlines();begin=lines.index('      - name: '+name)
        start=next(index for index in range(begin+1,len(lines)) if lines[index]=='        run: |')
        body=[]
        for row in lines[start+1:]:
            if row and not row.startswith('          '):break
            body.append(row[10:])
        return '\n'.join(body)

    def test_owned_shell_fixture_keeps_exact_ids_and_runs_both_partial_collectors(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);binary=root/'bin';binary.mkdir();calls=root/'calls'
            program='#!'+sys.executable+'\nimport json,os,sys\nfrom pathlib import Path\n'
            program+='with open(os.environ["OWNED_CALLS"],"a") as stream: stream.write(json.dumps([Path(sys.argv[0]).name,*sys.argv[1:]])+"\\n")\n'
            program+='name=Path(sys.argv[0]).name;args=sys.argv[1:]\n'
            program+='if name=="uname": print("Linux" if args==["-s"] else "x86_64")\n'
            program+='elif name=="timeout": os.execvp(args[1],args[1:])\n'
            program+='elif name=="docker" and "--format" in args:\n'
            program+=' print(("sha256:"+("a" if "noble" in args[-1] else "b")*64) if args[args.index("--format")+1]=="{{.Id}}" else "appguard-ubi-123-1-amd64")\n'
            program+='elif name=="python3": sys.exit(2 if "scan_diagnostic_images.py" in " ".join(args) or "compare_java_ubi_evidence.py" in " ".join(args) or "/ubi" in " ".join(args) else 0)\n'
            for name in ('uname','timeout','docker','python3'):
                file=binary/name;file.write_text(program);file.chmod(0o700)
            env=os.environ.copy();env.update(PATH=str(binary)+os.pathsep+env.get('PATH',''),RUNNER_TEMP=str(root),
                APPGUARD_ARCH='amd64',GITHUB_RUN_ID='123',GITHUB_RUN_ATTEMPT='1',OWNED_CALLS=str(calls))
            steps=(('Prepare private diagnostic state',0),('Build two fixed untouched-JRE diagnostics',0),
                ('Collect independent feature and inventory observations',2),('Scan same two IDs in one frozen database session',2),
                ('Bind originals without approving a production runtime',2))
            for name,expected in steps:
                result=subprocess.run(['/bin/bash','-e','-o','pipefail','-c',self.step(name)],env=env,capture_output=True,timeout=10)
                self.assertEqual(result.returncode,expected,(name,result.stderr.decode()))
            rows=[json.loads(row) for row in calls.read_text().splitlines()]
            collectors=[row for row in rows if row[0]=='python3' and row[1].endswith('inspect_java_runtime.py')]
            self.assertEqual(len(collectors),2)
            self.assertEqual(collectors[0][collectors[0].index('--image')+1],'sha256:'+'a'*64)
            self.assertEqual(collectors[1][collectors[1].index('--image')+1],'sha256:'+'b'*64)
            self.assertNotIn('--package-profile',collectors[0]);self.assertIn('rpm-ubi10-v1',collectors[1])
            scan=next(row for row in rows if row[0]=='python3' and row[1].endswith('scan_diagnostic_images.py'))
            self.assertEqual([scan[index+1] for index,item in enumerate(scan) if item=='--image'],['sha256:'+'a'*64,'sha256:'+'b'*64])


if __name__=='__main__':unittest.main()
