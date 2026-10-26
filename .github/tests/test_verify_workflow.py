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
    def assert_forge_contract(self, script):
        for required in ('umask 077', 'mktemp -d "$RUNNER_TEMP/appguard-forge.XXXXXX"',
                         'test_forge_producer.py', '--prepare "$forge_state/prepared"',
                         '--verify-prepared "$forge_state/prepared"', '--verify-tools "$forge_state/prepared"',
                         '--build "$forge_state/prepared"', '--output "$forge_state/output"',
                         '--node "$forge_node"', '--npm-package "$forge_npm_package"',
                         'update-notifier=false', 'offline=true', 'NPM_CONFIG_USERCONFIG=',
                         'NPM_CONFIG_GLOBALCONFIG=', 'NPM_CONFIG_CACHE=',
                         'ci --ignore-scripts --offline=false --registry=https://registry.npmjs.org/',
                         '22.23.2', '10.9.8', "['name'] == 'npm'", "'bin/npm-cli.js'",
                         'NODE_OPTIONS', 'NODE_PATH', '-I -S -B'):
            self.assertIn(required, script)
        self.assertEqual(script.count('--offline=false'), 1)
        ordered = ['test_forge_producer.py', '--prepare', '--verify-prepared',
                   'ci --ignore-scripts', '--verify-tools', '--build']
        self.assertEqual([script.index(value) for value in ordered],
                         sorted(script.index(value) for value in ordered))
        self.assertNotRegex(script, r'(?i)(?:\b(?:CODEX_HOME|HOME)\s*=|npm\s+(?:install|config)|\bnpx\b|legacy-provider|\brm\s|\btrap\s)')

    def test_forge_supported_workflow_contract_and_mutations(self):
        script = step_script('Fresh retained Forge producer verification')
        self.assert_forge_contract(script)
        syntax = subprocess.run(['bash', '-n'], input=script, text=True, capture_output=True,
                                env=dict(os.environ), timeout=15)
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        for required in ('--prepare', '--verify-prepared', '--verify-tools', '--build',
                         '--ignore-scripts', 'offline=true', 'update-notifier=false',
                         '--npm-package', 'test_forge_producer.py', "'bin/npm-cli.js'",
                         '22.23.2', '10.9.8', 'NPM_CONFIG_CACHE=', 'NPM_CONFIG_GLOBALCONFIG='):
            with self.subTest(required=required), self.assertRaises(AssertionError):
                self.assert_forge_contract(script.replace(required, 'REMOVED'))
        for forbidden in ('\nexport HOME=/tmp/other', '\nexport CODEX_HOME=/tmp/other',
                          '\nnpm install -g npm', '\nnpx webpack', '\nNODE_OPTIONS=--openssl-legacy-provider'):
            with self.subTest(forbidden=forbidden), self.assertRaises(AssertionError):
                self.assert_forge_contract(script + forbidden)
        job = WORKFLOW.read_text().split('  javascript-clients:', 1)[1].split('  apple:', 1)[0]
        self.assertIn('actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97', job)
        self.assertIn("python-version: '3.11'", job)

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

    def test_packaging_step_runs_real_mode_and_propagates_failure(self):
        for exit_code in (0, 17):
            with self.subTest(exit_code=exit_code):
                def setup(base, bin_path):
                    self.executable(bin_path / 'uv', 'exit 0\n')
                    self.executable(bin_path / 'python3',
                                    'printf "%s\\n" "$@" > "$STEP_MARKER"\n'
                                    + 'exit ' + str(exit_code) + '\n')
                result, marker, exported = self.run_step(
                    'Hash-locked Python wheel and clean consumer', setup)
                self.assertEqual(result.returncode, exit_code)
                self.assertFalse(exported)
                args = marker.splitlines()
                self.assertEqual(args[0], '.github/tests/test_python_package.py')
                self.assertIn('--verify-packaging', args)
                uv = Path(args[args.index('--uv') + 1])
                python = Path(args[args.index('--python') + 1])
                evidence = Path(args[args.index('--evidence') + 1])
                self.assertEqual(uv.name, 'uv')
                self.assertEqual(python.name, 'python3')
                self.assertTrue(uv.is_absolute() and python.is_absolute())
                self.assertEqual(uv.parent, python.parent)
                self.assertEqual(evidence, uv.parent.parent / 'appguard-python-package')

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
