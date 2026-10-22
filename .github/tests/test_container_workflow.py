"""Execute the workflow's real shell preflight without a Docker boundary."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


WORKFLOW = Path(__file__).resolve().parents[1] / 'workflows/container-readiness.yml'


def qualification_script():
    lines = WORKFLOW.read_text().splitlines()
    start = lines.index('      - name: Build and exercise the owned container deployment')
    run = next(index for index in range(start + 1, len(lines)) if lines[index] == '        run: |')
    body = []
    for line in lines[run + 1:]:
        if line and not line.startswith('          '):
            break
        body.append(line[10:] if line else '')
    return '\n'.join(body)


class ContainerWorkflowTests(unittest.TestCase):
    def run_preflight(self, seconds, concurrency):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            executable = root / 'uv'
            executable.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$ARGV_MARKER"\n')
            executable.chmod(0o755)
            marker = root / 'arguments'
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ['PATH'],
                       JAVA_HOME=str(root), RUNNER_TEMP=str(root), ARGV_MARKER=str(marker),
                       APPGUARD_SOAK_SECONDS=seconds, APPGUARD_SOAK_CONCURRENCY=concurrency)
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

    def test_accepted_bounds_are_forwarded_as_exact_quoted_arguments(self):
        for seconds, concurrency in [('1', '1'), ('30', '8'), ('1800', '8'), ('3600', '32')]:
            with self.subTest(seconds=seconds, concurrency=concurrency):
                result, arguments = self.run_preflight(seconds, concurrency)
                self.assertEqual(result.returncode, 0, result.stderr)
                position = arguments.index('--soak-seconds')
                self.assertEqual(arguments[position:position + 4],
                                 ['--soak-seconds', seconds, '--soak-concurrency', concurrency])
                self.assertEqual(arguments[:5], ['run', '--frozen', '--project', 'sdk/python', 'python'])


if __name__ == '__main__':
    unittest.main()
