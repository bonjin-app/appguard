import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / 'candidate.py'


class CandidateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()
        self.repo = self.base / 'repo'
        self.repo.mkdir()
        self.git('init', '-q')
        self.git('config', 'user.email', 'test@example.invalid')
        self.git('config', 'user.name', 'Test')
        self.write('README.md', 'candidate\n')
        self.write('LICENSE', 'Apache-2.0\n')
        self.write('sdk/node/package.json', '{"name":"test","version":"1.0.0"}')
        self.write('sdk/node/package-lock.json', '{"lockfileVersion":3,"packages":{}}')
        self.commit()

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.repo), *args])

    def write(self, name, content):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)

    def commit(self):
        self.git('add', '.')
        self.git('commit', '-qm', 'fixture')

    def run_candidate(self, out='candidate'):
        return subprocess.run(['python3', str(SCRIPT), '--repo', str(self.repo), '--output', str(self.base / out)], capture_output=True, text=True)

    def test_deterministic_snapshot_manifest_and_inventory(self):
        a = self.run_candidate('a')
        self.assertEqual(a.returncode, 0, a.stderr)
        b = self.run_candidate('b')
        self.assertEqual(b.returncode, 0, b.stderr)
        for path in (self.base / 'a').rglob('*'):
            if path.is_file():
                self.assertEqual(path.read_bytes(), (self.base / 'b' / path.relative_to(self.base / 'a')).read_bytes())
        manifest = json.loads((self.base / 'a/manifest.json').read_text())
        for name, digest in manifest['sha256'].items():
            self.assertEqual(hashlib.sha256((self.base / 'a' / name).read_bytes()).hexdigest(), digest)
        inventory = json.loads((self.base / 'a/dependency-coverage.json').read_text())
        self.assertFalse(inventory['complete_resolved_graph'])
        self.assertTrue(any(x['path'] == 'sdk/node/package-lock.json' for x in inventory['inputs']))
        with tarfile.open(self.base / 'a/source.tar.gz') as archive:
            self.assertIn('appguard/LICENSE', archive.getnames())

    def test_native_resolution_gaps_are_explicit(self):
        self.write('sdk/apple/Package.swift', '// swift-tools-version: 5.9\n')
        self.commit()
        result = self.run_candidate()
        self.assertEqual(result.returncode, 0, result.stderr)
        inventory = json.loads((self.base / 'candidate/dependency-coverage.json').read_text())
        project = next(item for item in inventory['projects'] if item['manifest'] == 'sdk/apple/Package.swift')
        self.assertEqual(project['resolution_coverage'], 'no_recorded_lockfile')
        self.assertEqual(project['recorded_lockfiles'], [])

    def test_deployment_sources_included_and_deployment_credentials_excluded(self):
        self.write('deploy/spring-ingress/Dockerfile.gateway', 'FROM example@sha256:fixed\n')
        self.write('deploy/spring-ingress/compose.json', '{"services":{}}\n')
        self.write('deploy/spring-ingress/.env', 'PRIVATE_TEST_VALUE\n')
        self.write('deploy/spring-ingress/server.key', 'PRIVATE_TEST_VALUE\n')
        self.commit()
        run = self.run_candidate()
        self.assertEqual(run.returncode, 0, run.stderr)
        source = self.base / 'candidate/source/deploy/spring-ingress'
        self.assertTrue((source / 'Dockerfile.gateway').is_file())
        self.assertTrue((source / 'compose.json').is_file())
        self.assertFalse((source / '.env').exists())
        self.assertFalse((source / 'server.key').exists())

    def test_normative_protocol_and_runnable_examples_included_without_private_outputs(self):
        self.write('protocol/request-v0.md', '# Normative protocol\n')
        self.write('examples/python-ingress/server.py', 'print("ingress example")\n')
        self.write('examples/python-ingress/.env', 'PRIVATE=fixture')
        self.write('examples/python-ingress/tls.key', 'private fixture')
        self.commit()
        result = self.run_candidate()
        self.assertEqual(result.returncode, 0, result.stderr)
        source = self.base / 'candidate/source'
        self.assertEqual((source / 'protocol/request-v0.md').read_text(), '# Normative protocol\n')
        self.assertEqual((source / 'examples/python-ingress/server.py').read_text(), 'print("ingress example")\n')
        self.assertFalse((source / 'examples/python-ingress/.env').exists())
        self.assertFalse((source / 'examples/python-ingress/tls.key').exists())
        manifest = json.loads((self.base / 'candidate/manifest.json').read_text())
        self.assertIn('examples/python-ingress/.env', manifest['excluded'])
        self.assertIn('examples/python-ingress/tls.key', manifest['excluded'])
        with tarfile.open(self.base / 'candidate/source.tar.gz') as archive:
            self.assertIn('appguard/protocol/request-v0.md', archive.getnames())
            self.assertIn('appguard/examples/python-ingress/server.py', archive.getnames())

    def test_git_replace_objects_cannot_change_candidate_head_contents(self):
        original = self.git('rev-parse', 'HEAD:README.md').decode().strip()
        replacement = subprocess.check_output(['git', '-C', str(self.repo), 'hash-object', '-w', '--stdin'],
                                               input=b'replaced object content\n').decode().strip()
        self.git('replace', original, replacement)
        self.assertEqual(self.git('status', '--porcelain'), b'')
        result = self.run_candidate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.base / 'candidate/source/README.md').read_text(), 'candidate\n')

    def test_private_apple_p8_key_is_excluded(self):
        self.write('sdk/apple/AuthKey_TESTONLY.p8', 'synthetic-private-key')
        self.commit()
        result = self.run_candidate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.base / 'candidate/source/sdk/apple/AuthKey_TESTONLY.p8').exists())
        self.assertIn('sdk/apple/AuthKey_TESTONLY.p8', json.loads((self.base / 'candidate/manifest.json').read_text())['excluded'])

    def test_dirty_tracked_and_untracked_sources_rejected(self):
        self.write('README.md', 'dirty')
        self.assertNotEqual(self.run_candidate().returncode, 0)
        self.git('checkout', '--', 'README.md')
        self.write('new.txt', 'untracked')
        self.assertNotEqual(self.run_candidate().returncode, 0)
        self.assertFalse((self.base / 'candidate').exists())

    def test_symlink_rejected(self):
        (self.repo / 'sdk/link').symlink_to('/etc/passwd')
        self.commit()
        self.assertNotEqual(self.run_candidate().returncode, 0)
        self.assertFalse((self.base / 'candidate').exists())

    def test_excludes_tracked_toolchains_and_private_outputs(self):
        for path in ['sdk/node/node_modules/secret.js', 'sdk/android/debug.keystore', '.env', 'sdk/.tools/tool', 'docs/private/key.txt', 'sdk/.evidence/private.log']:
            self.write(path, 'private')
        self.commit()
        result = self.run_candidate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(list((self.base / 'candidate/source').rglob('secret.js')), [])
        excluded = json.loads((self.base / 'candidate/manifest.json').read_text())['excluded']
        self.assertIn('.env', excluded)
        self.assertIn('sdk/android/debug.keystore', excluded)
        self.assertIn('sdk/.evidence/private.log', excluded)

    def test_existing_output_is_preserved(self):
        out = self.base / 'candidate'
        out.mkdir()
        (out / 'sentinel').write_text('preserve')
        self.assertNotEqual(self.run_candidate().returncode, 0)
        self.assertEqual((out / 'sentinel').read_text(), 'preserve')

    def test_output_inside_repository_rejected(self):
        self.assertNotEqual(self.run_candidate('repo/output').returncode, 0)
        self.assertFalse((self.repo / 'output').exists())

    def test_symlink_output_parent_rejected(self):
        (self.base / 'alias').symlink_to(self.base, target_is_directory=True)
        self.assertNotEqual(self.run_candidate('alias/output').returncode, 0)

    def module(self):
        spec = importlib.util.spec_from_file_location('candidate', SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_traversal_path_rejected(self):
        m = self.module()
        for name in ['../secret', '/etc/passwd', 'sdk/../../secret', 'sdk/./a', 'sdk//a', 'sdk\\evil']:
            with self.subTest(name=name), self.assertRaises(ValueError):
                m.validate_path(name)

    def test_input_mutation_aborts_transaction(self):
        m = self.module()
        original = m.git
        calls = 0
        def mutate(repo, *args):
            nonlocal calls
            result = original(repo, *args)
            if args[0] == 'cat-file':
                calls += 1
                if calls == 1:
                    self.write('README.md', 'mutated during snapshot')
            return result
        with patch.object(m, 'git', side_effect=mutate), self.assertRaises(RuntimeError):
            m.create_candidate(self.repo, self.base / 'candidate')
        self.assertFalse((self.base / 'candidate').exists())
        self.assertEqual(list(self.base.glob('.candidate-*')), [])

    def test_partial_failure_cleans_staging(self):
        m = self.module()
        with patch.object(m, 'write_archive', side_effect=OSError('full disk')), self.assertRaises(OSError):
            m.create_candidate(self.repo, self.base / 'candidate')
        self.assertFalse((self.base / 'candidate').exists())
        self.assertEqual(list(self.base.glob('.candidate-*')), [])


if __name__ == '__main__':
    unittest.main()
