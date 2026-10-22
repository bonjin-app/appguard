"""Execute the workflow's real shell preflight without a Docker boundary."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


WORKFLOW = Path(__file__).resolve().parents[1] / 'workflows/container-readiness.yml'


def step_script(name):
    lines = WORKFLOW.read_text().splitlines()
    start = lines.index('      - name: ' + name)
    run = next(index for index in range(start + 1, len(lines)) if lines[index] == '        run: |')
    body = []
    for line in lines[run + 1:]:
        if line and not line.startswith('          '):
            break
        body.append(line[10:] if line else '')
    return '\n'.join(body)


def qualification_script():
    return step_script('Build and exercise the owned container deployment')


class ContainerWorkflowTests(unittest.TestCase):
    def run_preflight(self, seconds, concurrency, architecture='amd64'):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            executable = root / 'uv'
            executable.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$ARGV_MARKER"\n')
            executable.chmod(0o755)
            marker = root / 'arguments'
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ['PATH'],
                       JAVA_HOME=str(root), RUNNER_TEMP=str(root), ARGV_MARKER=str(marker),
                       APPGUARD_SOAK_SECONDS=seconds, APPGUARD_SOAK_CONCURRENCY=concurrency, APPGUARD_ARCHITECTURE=architecture)
            result = subprocess.run(['bash', '-euo', 'pipefail', '-c', qualification_script()],
                                    env=env, capture_output=True, text=True, timeout=10)
            return result, marker.read_text().splitlines() if marker.exists() else None

    def test_invalid_inputs_never_reach_the_container_runner(self):
        for seconds, concurrency in [('0', '8'), ('3601', '8'), ('1.5', '8'), ('1e3', '8'),
                                     ('30', '0'), ('30', '33'), ('', '8'), ('-1', '8'),
                                     ('30', '8; exit 0'), ('$(exit 0)', '8')]:
            with self.subTest(seconds=seconds, concurrency=concurrency):
                result, arguments = self.run_preflight(seconds, concurrency)
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(arguments)

    def test_fixed_architectures_are_quoted_and_invalid_choices_never_reach_runner(self):
        for arch in ('amd64','arm64'):
            result,args=self.run_preflight('30','8',arch)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(args[args.index('--platform')+1],'linux/'+arch)
        for arch in ('aarch64','self-hosted','arm64; exit 0',''):
            result,args=self.run_preflight('30','8',arch)
            self.assertNotEqual(result.returncode,0);self.assertIsNone(args)

    def test_accepted_bounds_are_forwarded_as_exact_quoted_arguments(self):
        for seconds, concurrency in [('1', '1'), ('30', '8'), ('1800', '8'), ('3600', '32')]:
            with self.subTest(seconds=seconds, concurrency=concurrency):
                result, arguments = self.run_preflight(seconds, concurrency)
                self.assertEqual(result.returncode, 0, result.stderr)
                position = arguments.index('--soak-seconds')
                self.assertEqual(arguments[position:position + 4],
                                 ['--soak-seconds', seconds, '--soak-concurrency', concurrency])
                self.assertEqual(arguments[:5], ['run', '--frozen', '--project', 'sdk/python', 'python'])

    def test_fixed_artifact_layout_and_step_order(self):
        text=WORKFLOW.read_text()
        names=[line.split('name: ',1)[1] for line in text.splitlines() if line.startswith('      - name: ')]
        self.assertEqual(names,['Checkout exact candidate','Set up Python 3.11','Set up pinned uv 0.13.4',
            'Set up Temurin 17','Frozen tooling and focused container safety tests',
            'Build and exercise the owned container deployment','Scan the exact runtime images without suppressions',
            'Prepare fixed-schema container evidence','Retain fixed-schema operating and image status only'])
        self.assertIn('python3 .github/tests/test_container_evidence_binding.py -v',text)
        upload=text.split('      - name: Retain fixed-schema operating and image status only',1)[1]
        self.assertIn("if: always() && steps.container_evidence.outcome == 'success'",upload)
        self.assertIn('name: owned-container-readiness-${{ github.sha }}-${{ github.run_id }}-${{ github.run_attempt }}',upload)
        paths=upload.split('          path: |\n',1)[1].split('          if-no-files-found:',1)[0]
        self.assertEqual(paths.splitlines(),[
            '            ${{ runner.temp }}/appguard-private-container-evidence/bound/'+name
            for name in ('receipt.json','image-status.json','binding.json')])
        self.assertIn('if-no-files-found: error',upload)
        self.assertNotIn('/status.json',upload)
        stage=text.split('      - name: Prepare fixed-schema container evidence',1)[1].split('      - name:',1)[0]
        self.assertIn('if: always()',stage)
        self.assertIn('id: container_evidence',stage)
        self.assertNotIn('${{',step_script('Prepare fixed-schema container evidence'))

    def test_stage_quotes_metadata_and_propagates_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve(); marker=root/'arguments'
            command=root/'python3'
            command.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$ARGV_MARKER"\nexit 17\n')
            command.chmod(0o755)
            env=dict(os.environ,PATH=str(root)+os.pathsep+os.environ['PATH'],RUNNER_TEMP=str(root),ARGV_MARKER=str(marker),
                APPGUARD_REPOSITORY='bonjin-app/appguard',APPGUARD_COMMIT='a'*40,APPGUARD_RUN_ID='123',
                APPGUARD_RUN_ATTEMPT='1',APPGUARD_EVENT='pull_request',APPGUARD_HEAD_BRANCH='branch; $(exit 0)',
                APPGUARD_WORKFLOW_PATH='.github/workflows/container-readiness.yml')
            result=subprocess.run(['bash','-euo','pipefail','-c',step_script('Prepare fixed-schema container evidence')],
                env=env,capture_output=True,timeout=10)
            self.assertEqual(result.returncode,17)
            args=marker.read_text().splitlines()
            self.assertEqual(args[args.index('--head-branch')+1],'branch; $(exit 0)')
            self.assertEqual(args[args.index('--output')+1],str(root/'appguard-private-container-evidence/bound'))
            self.assertEqual((root/'appguard-private-container-evidence').stat().st_mode & 0o777,0o700)

    def test_preexisting_private_parent_stops_before_producer(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve(); marker=root/'called'
            parent=root/'appguard-private-container-evidence'; parent.mkdir()
            sentinel=parent/'keep'; sentinel.write_text('preserved')
            command=root/'python3'; command.write_text('#!/bin/sh\ntouch "$ARGV_MARKER"\n')
            command.chmod(0o755)
            env=dict(os.environ,PATH=str(root)+os.pathsep+os.environ['PATH'],RUNNER_TEMP=str(root),ARGV_MARKER=str(marker),
                APPGUARD_REPOSITORY='bonjin-app/appguard',APPGUARD_COMMIT='a'*40,APPGUARD_RUN_ID='123',
                APPGUARD_RUN_ATTEMPT='1',APPGUARD_EVENT='push',APPGUARD_HEAD_BRANCH='main',
                APPGUARD_WORKFLOW_PATH='.github/workflows/container-readiness.yml')
            script=step_script('Prepare fixed-schema container evidence')
            self.assertIn('mkdir -m 700 "$RUNNER_TEMP/appguard-private-container-evidence"',script)
            result=subprocess.run(['bash','-euo','pipefail','-c',script],env=env,capture_output=True,timeout=10)
            self.assertNotEqual(result.returncode,0)
            self.assertFalse(marker.exists())
            self.assertEqual(sentinel.read_text(),'preserved')
            upload=WORKFLOW.read_text().split('      - name: Retain fixed-schema operating and image status only',1)[1]
            self.assertIn("if: always() && steps.container_evidence.outcome == 'success'",upload)


if __name__ == '__main__':
    unittest.main()
