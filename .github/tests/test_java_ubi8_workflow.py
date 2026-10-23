"""Fixed UBI8 recipe plus actual owned shell-stub outcome propagation."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
WORKFLOW=ROOT/'.github/workflows/java-ubi8-copy-jre.yml'


class Ubi8WorkflowTests(unittest.TestCase):
    def source(self):
        self.assertTrue(WORKFLOW.is_file(),'separate bounded UBI8 diagnostic workflow required')
        return WORKFLOW.read_text()

    def step(self,name):
        lines=self.source().splitlines();begin=lines.index('      - name: '+name)
        start=next(index for index in range(begin+1,len(lines)) if lines[index]=='        run: |')
        body=[]
        for row in lines[start+1:]:
            if row and not row.startswith('          '):break
            body.append(row[10:])
        return '\n'.join(body)

    def test_copy_only_target_preserves_final_ubi10_and_entire_jre(self):
        source=(ROOT/'scripts/qualification/java-runtime-probe.Dockerfile').read_text()
        marker='FROM registry.access.redhat.com/ubi8/ubi-minimal@sha256:c851eaf99ddf32811fdf8a216c2609cd0e55317ab8c46ecbaa3ea8298532f055 AS ubi8-copy-jre'
        self.assertIn(marker,source,'fixed official UBI8 copy-only target is missing')
        target=source[source.index(marker):].split('\nFROM ',1)[0]
        operations=[line.split()[0] for line in target.splitlines() if line and not line.startswith('#')]
        self.assertEqual(operations,['FROM','COPY','COPY','COPY','USER','ENTRYPOINT','CMD'])
        self.assertIn('COPY --from=vendor_jre /opt/java/openjdk/ /opt/java/openjdk/',target)
        self.assertIn('COPY --from=probe_build /probe/LICENSE /usr/share/licenses/appguard/LICENSE',target)
        self.assertIn('CMD []',target);self.assertIn('USER 10001:10001',target)
        self.assertIn('ENTRYPOINT ["/opt/java/openjdk/bin/java"]',target)
        self.assertEqual([line.rsplit(' AS ',1)[1] for line in source.splitlines() if line.startswith('FROM ')][-1],'ubi10')

    def test_exact_branch_native_runners_fixed_actions_and_artifact_paths(self):
        text=self.source();trigger=text.split('\npermissions:',1)[0].split('\non:\n',1)[1]
        self.assertEqual(trigger,'  push:\n    branches: [codex/ubi8-copy-jre-evaluation]\n  workflow_dispatch:\n')
        for term in ('runner: ubuntu-24.04\n','runner: ubuntu-24.04-arm\n','timeout-minutes: 90',
                'cancel-in-progress: false','fail-fast: false','contents: read','persist-credentials: false'):
            self.assertIn(term,text)
        self.assertNotIn('setup-qemu',text);self.assertNotIn('inputs.',text)
        for line in text.splitlines():
            if 'uses:' in line:self.assertRegex(line,r'@[0-9a-f]{40}(?: |$)')
        paths=text.split('          path: |\n',1)[1].split('          if-no-files-found:',1)[0].splitlines()
        self.assertEqual(len(paths),9)
        self.assertFalse(any('*' in path for path in paths))
        self.assertTrue(any('/run-status/diagnostic-run-status.json' in path for path in paths))
        self.assertFalse(any('build-' in path or '.log' in path for path in paths))
        self.assertNotRegex(text,r'(?m)^\s*(?:export )?(?:HOME|CODEX_HOME)=')
        for name in ('Collect independent feature and inventory observations','Scan same two IDs in one frozen database session',
                'Bind originals without approving a production runtime'):
            section=text.split('      - name: '+name+'\n',1)[1].split('      - name:',1)[0]
            self.assertIn("if: always() && steps.images.outcome == 'success'",section)
        for name in ('Remove only images with this run ownership and exact ID','Record fixed diagnostic outcomes',
                'Retain original diagnostic observations only'):
            section=text.split('      - name: '+name+'\n',1)[1].split('      - name:',1)[0]
            self.assertIn("if: always() && steps.state.outcome == 'success'",section)

    def test_actual_shell_syntax_for_all_bodies(self):
        text=self.source();lines=text.splitlines();bodies=[]
        for index,line in enumerate(lines):
            if line=='        run: |':
                body=[]
                for row in lines[index+1:]:
                    if row and not row.startswith('          '):break
                    body.append(row[10:])
                bodies.append('\n'.join(body))
        self.assertGreaterEqual(len(bodies),8)
        for body in bodies:
            result=subprocess.run(['/bin/bash','-n'],input=body.encode(),capture_output=True,timeout=5)
            self.assertEqual(result.returncode,0,result.stderr.decode())

    def fixture(self,root,native_exit=1):
        binary=root/'bin';binary.mkdir();calls=root/'calls'
        program='#!'+sys.executable+'\nimport json,os,sys\nfrom pathlib import Path\n'
        program+='name=Path(sys.argv[0]).name;args=sys.argv[1:]\n'
        program+='with open(os.environ["OWNED_CALLS"],"a") as stream:stream.write(json.dumps([name,*args])+"\\n")\n'
        program+='if name=="uname":print("Linux" if args==["-s"] else "x86_64")\n'
        program+='elif name=="timeout":os.execvp(args[1],args[1:])\n'
        program+='elif name=="docker" and "--format" in args:\n'
        program+=' print(("sha256:"+("a" if "noble" in args[-1] else "b")*64) if args[args.index("--format")+1]=="{{.Id}}" else "foreign" if "OWNED_FOREIGN_OWNER" in os.environ else "appguard-ubi8-copy-jre-123-1-amd64")\n'
        program+='elif name=="python3":\n'
        program+=' if args==["-"] and "OWNED_REAL_INLINE" in os.environ:os.execv(sys.executable,[sys.executable,*args])\n'
        program+=' sys.exit(int(os.environ["OWNED_NATIVE_EXIT"]) if "inspect_java_runtime.py" in " ".join(args) else 2 if "scan_diagnostic_images.py" in " ".join(args) or "compare_java_ubi_evidence.py" in " ".join(args) else 0)\n'
        for name in ('uname','timeout','docker','python3'):
            file=binary/name;file.write_text(program);file.chmod(0o700)
        env=os.environ.copy();env.update(PATH=str(binary)+os.pathsep+env.get('PATH',''),RUNNER_TEMP=str(root),
            APPGUARD_ARCH='amd64',GITHUB_SHA='c'*40,GITHUB_RUN_ID='123',GITHUB_RUN_ATTEMPT='1',
            OWNED_CALLS=str(calls),OWNED_NATIVE_EXIT=str(native_exit))
        return env,calls

    def run_step(self,name,env):
        return subprocess.run(['/bin/bash','-e','-o','pipefail','-c',self.step(name)],cwd=ROOT,env=env,capture_output=True,timeout=10)

    def test_owned_fixture_retains_native_one_and_two_collectors_and_exact_scan_bind_ids(self):
        for native_exit in (1,2):
            with self.subTest(native_exit=native_exit),tempfile.TemporaryDirectory() as directory:
                root=Path(directory).resolve();env,calls=self.fixture(root,native_exit)
                for name,code in (('Prepare private diagnostic state',0),('Build two fixed untouched-JRE diagnostics',0),
                        ('Collect independent feature and inventory observations',native_exit),
                        ('Scan same two IDs in one frozen database session',2),('Bind originals without approving a production runtime',2),
                        ('Remove only images with this run ownership and exact ID',0)):
                    result=self.run_step(name,env);self.assertEqual(result.returncode,code,(name,result.stderr.decode()))
                rows=[json.loads(row) for row in calls.read_text().splitlines()]
                collectors=[row for row in rows if row[0]=='python3' and len(row)>1 and row[1].endswith('inspect_java_runtime.py')]
                self.assertEqual(len(collectors),2)
                ids=['sha256:'+'a'*64,'sha256:'+'b'*64]
                self.assertEqual([row[row.index('--image')+1] for row in collectors],ids)
                self.assertNotIn('--package-profile',collectors[0]);self.assertIn('rpm-ubi8-copy-jre-v1',collectors[1])
                build=[row for row in rows if row[0]=='docker' and 'build' in row]
                self.assertEqual([row[row.index('--target')+1] for row in build],['baseline','ubi8-copy-jre'])
                scan=next(row for row in rows if row[0]=='python3' and row[1].endswith('scan_diagnostic_images.py'))
                self.assertEqual([scan[index+1] for index,arg in enumerate(scan) if arg=='--image'],ids)
                bind=next(row for row in rows if row[0]=='python3' and row[1].endswith('compare_java_ubi_evidence.py'))
                self.assertIn('rpm-ubi8-copy-jre-v1',bind);self.assertIn('--ubi-base-index',bind);self.assertIn('--jre-source-index',bind)
                self.assertEqual(bind[bind.index('--noble-image')+1],ids[0]);self.assertEqual(bind[bind.index('--ubi-image')+1],ids[1])
                self.assertEqual((root/'appguard-ubi8-copy-jre-comparison/native-noble-exit').read_text().strip(),str(native_exit))
                self.assertEqual((root/'appguard-ubi8-copy-jre-comparison/native-ubi-exit').read_text().strip(),str(native_exit))

    def test_owned_cleanup_denies_foreign_labels_and_uses_only_run_tags_when_ids_absent(self):
        for foreign in (True,False):
            with self.subTest(foreign=foreign),tempfile.TemporaryDirectory() as directory:
                root=Path(directory).resolve();env,calls=self.fixture(root)
                self.assertEqual(self.run_step('Prepare private diagnostic state',env).returncode,0)
                if foreign:env['OWNED_FOREIGN_OWNER']='1'
                result=self.run_step('Remove only images with this run ownership and exact ID',env)
                self.assertEqual(result.returncode,2 if foreign else 0,result.stderr.decode())
                rows=[json.loads(row) for row in calls.read_text().splitlines()]
                removed=[row for row in rows if row[0]=='docker' and row[3:5]==['image','rm']]
                self.assertEqual(len(removed),0 if foreign else 2)
                probes=[row for row in rows if row[0]=='docker' and '{{.Id}}' in row]
                self.assertEqual([row[-1] for row in probes],['appguard-ubi8-copy-jre-123-1-amd64-noble:owned','appguard-ubi8-copy-jre-123-1-amd64-ubi:owned'])

    def test_fixed_status_writer_runs_with_real_python_and_refuses_unknown_outcomes(self):
        for outcome in ('failure','PRIVATE_ERROR'):
            with self.subTest(outcome=outcome),tempfile.TemporaryDirectory() as directory:
                root=Path(directory).resolve();env,_=self.fixture(root)
                self.assertEqual(self.run_step('Prepare private diagnostic state',env).returncode,0)
                state=root/'appguard-ubi8-copy-jre-comparison'
                for role,letter in (('noble','a'),('ubi','b')):
                    (state/(role+'-id')).write_text('sha256:'+letter*64+'\n');(state/('native-'+role+'-exit')).write_text('1\n')
                for phase in ('scan','bind'):(state/(phase+'-exit')).write_text('2\n')
                env.update(OWNED_REAL_INLINE='1',APPGUARD_IMAGES='success',APPGUARD_NATIVE=outcome,APPGUARD_SCAN='failure',
                    APPGUARD_BIND='failure',APPGUARD_CLEANUP='success')
                result=self.run_step('Record fixed diagnostic outcomes',env)
                path=state/'run-status/diagnostic-run-status.json'
                if outcome=='PRIVATE_ERROR':self.assertNotEqual(result.returncode,0);self.assertFalse(path.exists());continue
                self.assertEqual(result.returncode,0,result.stderr.decode());row=json.loads(path.read_text())
                self.assertEqual(row['native_exit_codes'],dict(noble=1,ubi=1));self.assertEqual(row['step_outcomes']['native'],'failure')
                self.assertEqual(row['image_ids'],dict(noble='sha256:'+'a'*64,ubi='sha256:'+'b'*64))
                self.assertFalse(row['release_ready']);self.assertFalse(row['native_binary_coverage'])
                self.assertEqual(path.stat().st_mode&0o777,0o600);self.assertEqual(path.parent.stat().st_mode&0o777,0o700)
                self.assertNotIn('PRIVATE_ERROR',json.dumps(row))


if __name__=='__main__':unittest.main()
