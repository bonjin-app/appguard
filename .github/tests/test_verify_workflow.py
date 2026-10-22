"""Exercise safety-sensitive workflow shell blocks without provisioning services."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / '.github/workflows/verify.yml'


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


class WorkflowShellTests(unittest.TestCase):
    def run_step(self, name, setup):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp).resolve()
            bin_path = base / 'bin'
            bin_path.mkdir()
            env = dict(os.environ, RUNNER_TEMP=str(base), GITHUB_ENV=str(base / 'github-env'),
                       PATH=str(bin_path) + os.pathsep + os.environ['PATH'], STEP_MARKER=str(base / 'marker'))
            setup(base, bin_path)
            result = subprocess.run(['bash', '-euo', 'pipefail', '-c', step_script(name)],
                                    env=env, capture_output=True, text=True, timeout=15)
            marker = (base / 'marker').read_text() if (base / 'marker').exists() else ''
            return result, marker, (base / 'github-env').exists()

    def executable(self, path, text):
        path.write_text('#!/bin/bash\nset -euo pipefail\n' + text)
        path.chmod(0o755)

    def test_invalid_redis_archive_never_extracts_builds_or_exports_runtime(self):
        def setup(base, bin_path):
            self.executable(bin_path / 'curl', 'while [[ $# -gt 0 ]]; do if [[ "$1" == --output ]]; then printf tampered > "$2"; exit 0; fi; shift; done\nexit 2\n')
            for name in ['tar', 'make']:
                self.executable(bin_path / name, 'echo unexpected >> "$STEP_MARKER"\n')
        result, marker, exported = self.run_step('Build owned Redis 7.2.16 from checksum-pinned source', setup)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(marker, '')
        self.assertFalse(exported)
        self.assertIn('checksum', result.stderr.lower())

    def test_relative_php_extension_path_never_runs_live_probe(self):
        def setup(base, bin_path):
            self.executable(bin_path / 'php', 'printf "relative/redis.so"\n')
            self.executable(bin_path / 'python3', 'echo unexpected >> "$STEP_MARKER"\n')
        result, marker, _ = self.run_step('Actual pinned ext-redis independent-process integration', setup)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(marker, '')

    def test_php_probe_receives_only_explicit_absolute_module(self):
        def setup(base, bin_path):
            extension = base / 'installed/redis.so'
            extension.parent.mkdir()
            extension.write_text('fake module for orchestration test')
            self.executable(bin_path / 'php', 'if [[ "${4:-}" == -- ]]; then exit 0; fi\nprintf %s ' + repr(str(extension)) + '\n')
            self.executable(bin_path / 'python3', 'printf "%s\\n" "$@" > "$STEP_MARKER"\n')
        result, marker, exported = self.run_step('Actual pinned ext-redis independent-process integration', setup)
        self.assertTrue(exported)
        self.assertEqual(result.returncode, 0, result.stderr)
        args = marker.splitlines()
        self.assertEqual(args[:4], ['sdk/php/tests/redis_integration.py', 'php', '-n', '-d'])
        self.assertTrue(args[4].startswith('extension=/'))
        self.assertTrue(args[4].endswith('/redis.so'))

    def test_packaged_redis_dependencies_load_before_redis_without_php_ini(self):
        def setup(base, bin_path):
            installed = base / 'installed'
            installed.mkdir()
            for name in ['igbinary', 'msgpack', 'redis']:
                (installed / (name + '.so')).write_text('orchestration fixture')
            self.executable(bin_path / 'php',
                'if [[ "$*" == *phpversion* ]]; then\n'
                '  [[ "$*" == *"igbinary.so"* && "$*" == *"msgpack.so"* && "$*" == *"redis.so"* ]];\n'
                'elif [[ "${4:-}" == -- ]]; then printf "%s/%s.so" ' + repr(str(installed)) + ' "$5";\n'
                'else printf %s ' + repr(str(installed / 'redis.so')) + '; fi\n')
            self.executable(bin_path / 'python3', 'printf "%s\\n" "$@" > "$STEP_MARKER"\n')
        result, marker, exported = self.run_step('Actual pinned ext-redis independent-process integration', setup)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(exported)
        args = marker.splitlines()
        self.assertEqual(args[:3], ['sdk/php/tests/redis_integration.py', 'php', '-n'])
        self.assertEqual([Path(value.removeprefix('extension=')).name for value in args if value.startswith('extension=')],
                         ['igbinary.so', 'msgpack.so', 'redis.so'])


if __name__ == '__main__':
    unittest.main()
