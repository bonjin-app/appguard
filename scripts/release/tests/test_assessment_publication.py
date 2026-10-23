"""Retained verifier decisions are exact bytes, never imported approval evidence."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import assess
import verify_container
import verify_hosted
import test_assess as assessment_fixture

COMMIT, MARKER = assessment_fixture.COMMIT, assessment_fixture.MARKER


class AssessmentPublicationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.candidate, self.scans = assessment_fixture.AssessmentTests().fixture(self.base)
        self.artifact = self.base / 'artifact.zip'
        self.artifact.write_bytes(b'owned untrusted artifact fixture')
        self.output = self.base / 'assessment'
        self.decisions, self.paths = {}, {}

    def verifier(self, kind, *, passed=True, malformed=None):
        def verify(*args):
            output = args[-1]
            output.mkdir()
            value = {'technical_gate_verified': passed, 'candidate_commit': COMMIT,
                'sha256': {'candidate_manifest': hashlib.sha256((self.candidate / 'manifest.json').read_bytes()).hexdigest(),
                           'source_archive': hashlib.sha256((self.candidate / 'source.tar.gz').read_bytes()).hexdigest()}}
            if kind == 'container':
                value.update(artifact_verified=passed, run_id=456)
                value['sha256']['artifact_zip'] = hashlib.sha256(self.artifact.read_bytes()).hexdigest()
            raw = (' \n' + json.dumps(value, indent=1) + '\n\n').encode()
            path = output / (kind + '.json')
            self.decisions[kind], self.paths[kind] = raw, path
            if malformed == 'missing':
                return value
            if malformed == 'fifo':
                os.mkfifo(path)
            elif malformed == 'symlink':
                target = self.base / 'untrusted-report'
                target.write_bytes(raw)
                path.symlink_to(target)
            elif malformed == 'oversized':
                with path.open('wb') as stream:
                    stream.truncate(assess.MAX_JSON_BYTES + 1)
            else:
                if malformed == 'contradictory':
                    raw = json.dumps(dict(value, technical_gate_verified=not passed)).encode()
                elif malformed == 'duplicate':
                    raw = b'{"technical_gate_verified":false,' + json.dumps(value).encode()[1:]
                elif malformed == 'nonfinite':
                    raw = b'{"number":1e999,' + json.dumps(value).encode()[1:]
                path.write_bytes(raw)
            return value
        return verify

    def run_assessment(self, *, passed=True, malformed=None, container=True):
        with patch.object(verify_hosted, 'verify_hosted', side_effect=self.verifier('hosted', passed=passed, malformed=malformed)), \
                patch.object(verify_container, 'verify_container', side_effect=self.verifier('container', passed=passed)):
            return assess.assess(self.candidate, self.scans, self.output, COMMIT, hosted_run_id=123,
                **({'container_run_id': 456, 'container_artifact': self.artifact} if container else {}))

    def test_exact_positive_and_negative_decisions_survive_private_workspace_cleanup(self):
        for passed in (True, False):
            with self.subTest(passed=passed):
                self.output = self.base / ('positive' if passed else 'negative')
                report = self.run_assessment(passed=passed)
                self.assertEqual({p.name for p in self.output.iterdir()}, {'assessment.json', 'hosted.json', 'container.json'})
                for kind in ('hosted', 'container'):
                    retained = self.output / (kind + '.json')
                    self.assertEqual(retained.read_bytes(), self.decisions[kind])
                    self.assertEqual(hashlib.sha256(retained.read_bytes()).hexdigest(), report['sha256'][kind + '_verification'])
                    self.assertEqual(stat.S_IMODE(retained.stat().st_mode), 0o600)
                    self.assertFalse(self.paths[kind].exists())
                self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o700)
                self.assertFalse(report['release_ready'])
                self.assertEqual(list(self.base.glob('.assessment-*')), [])
                self.assertNotIn(MARKER, ''.join(p.read_text() for p in self.output.iterdir()))

    def test_unvalidated_decision_has_no_hash_or_companion(self):
        for malformed in ('missing', 'contradictory', 'duplicate', 'nonfinite', 'oversized', 'symlink', 'fifo'):
            with self.subTest(malformed=malformed):
                self.output = self.base / malformed
                report = self.run_assessment(malformed=malformed, container=False)
                self.assertEqual({p.name for p in self.output.iterdir()}, {'assessment.json'})
                self.assertNotIn('hosted_verification', report['sha256'])
                self.assertEqual(assessment_fixture.AssessmentTests.gate(report, 'hosted_ci')['state'], 'blocked')

    def test_late_source_snapshot_or_hash_change_cannot_publish_a_marker(self):
        original = assess._publish
        for mode in ('source', 'snapshot', 'source-swap', 'snapshot-swap', 'hash'):
            with self.subTest(mode=mode):
                self.output = self.base / ('changed-' + mode)
                def change(output, report, workspace, *args, **kwargs):
                    if mode == 'hash':
                        report['sha256']['hosted_verification'] = '0' * 64
                    else:
                        path = self.paths['hosted'] if mode.startswith('source') else workspace / 'decisions/hosted.json'
                        path.parent.mkdir(exist_ok=True)
                        if mode.endswith('-swap'):
                            replacement = path.with_suffix('.replacement')
                            replacement.write_bytes(path.read_bytes())
                            replacement.replace(path)
                        else:
                            path.write_bytes(path.read_bytes() + b' ' if path.exists() else b'{}')
                    return original(output, report, workspace, *args, **kwargs)
                with patch.object(assess, '_publish', side_effect=change), self.assertRaises(assess.AssessmentError):
                    self.run_assessment()
                self.assertFalse((self.output / 'assessment.json').exists())

    def test_input_change_retains_decision_bytes_but_blocks_outer_gates(self):
        def change(source, commit, run, artifact, output):
            result = self.verifier('container')(source, commit, run, artifact, output)
            (self.candidate / 'source/docs/input.txt').write_bytes(b'changed after verification')
            return result
        with patch.object(verify_hosted, 'verify_hosted', side_effect=self.verifier('hosted')), \
                patch.object(verify_container, 'verify_container', side_effect=change):
            report = assess.assess(self.candidate, self.scans, self.output, COMMIT,
                hosted_run_id=123, container_run_id=456, container_artifact=self.artifact)
        self.assertEqual(assessment_fixture.AssessmentTests.gate(report, 'source_and_runtime_scans')['reason'], 'inputs_changed')
        for kind, gate in (('hosted', 'hosted_ci'), ('container', 'owned_container_ci')):
            self.assertEqual(assessment_fixture.AssessmentTests.gate(report, gate)['state'], 'blocked')
            self.assertTrue((self.output / (kind + '.json')).is_file())
            self.assertEqual((self.output / (kind + '.json')).read_bytes(), self.decisions[kind])
        self.assertFalse(report['release_ready'])

    def test_interrupted_links_leave_no_completed_assessment_or_owned_files(self):
        original = assess.os.link
        for mode in ('failure', 'cancel'):
            with self.subTest(mode=mode):
                self.output = self.base / ('link-' + mode)
                def link(source, name, **kwargs):
                    if mode == 'failure' and name == 'container.json':
                        raise OSError(MARKER)
                    original(source, name, **kwargs)
                    if mode == 'cancel' and name == 'assessment.json':
                        raise KeyboardInterrupt
                with patch.object(assess.os, 'link', side_effect=link), \
                        self.assertRaises(assess.AssessmentError if mode == 'failure' else KeyboardInterrupt):
                    self.run_assessment()
                self.assertFalse(self.output.exists())

    def test_cancellation_before_directory_identity_retains_only_empty_reservation(self):
        original = assess.os.mkdir
        def mkdir(path, *args, **kwargs):
            original(path, *args, **kwargs)
            if Path(path).name == 'assessment' and 'dir_fd' in kwargs:
                raise KeyboardInterrupt
        with patch.object(assess.os, 'mkdir', side_effect=mkdir), self.assertRaises(KeyboardInterrupt):
            self.run_assessment()
        # The syscall may have created this directory, but no recorded inode
        # authorizes removing its name after an interrupted return.
        self.assertTrue(self.output.is_dir())
        self.assertEqual(list(self.output.iterdir()), [])
        self.assertEqual(list(self.base.glob('.assessment-*')), [])

    def test_report_change_during_link_rolls_back_the_completed_bundle(self):
        original = assess.os.link
        def link(source, name, **kwargs):
            original(source, name, **kwargs)
            if name == 'assessment.json':
                (self.output / 'hosted.json').write_bytes(b'{}')
        with patch.object(assess.os, 'link', side_effect=link), self.assertRaises(assess.AssessmentError):
            self.run_assessment()
        self.assertFalse(self.output.exists())

    def test_link_time_permission_change_cannot_publish_a_private_bundle(self):
        original = assess.os.link
        for changed in ('hosted.json', 'assessment.json'):
            with self.subTest(changed=changed):
                self.output = self.base / ('mode-' + changed)
                def link(source, name, **kwargs):
                    original(source, name, **kwargs)
                    if name == changed:
                        os.chmod(source, 0o644)
                with patch.object(assess.os, 'link', side_effect=link), self.assertRaises(assess.AssessmentError):
                    self.run_assessment()
                self.assertFalse(self.output.exists())

    def test_destination_replacement_is_preserved_while_owned_entries_are_removed(self):
        original = assess.os.link
        def link(source, name, **kwargs):
            original(source, name, **kwargs)
            if name == 'assessment.json':
                target = self.output / 'hosted.json'
                target.unlink(missing_ok=True)
                target.write_text(MARKER)
        with patch.object(assess.os, 'link', side_effect=link), self.assertRaises(assess.AssessmentError):
            self.run_assessment()
        self.assertEqual((self.output / 'hosted.json').read_text(), MARKER)
        self.assertEqual({p.name for p in self.output.iterdir()}, {'hosted.json'})

    def test_parent_swap_cannot_redirect_publication_into_an_existing_directory(self):
        parent = self.base / 'parent'; parent.mkdir()
        other = self.base / 'existing'; other.mkdir()
        (other / 'keep').write_text(MARKER)
        self.output = parent / 'assessment'
        original = assess.os.mkdir
        swapped = False
        def mkdir(path, *args, **kwargs):
            nonlocal swapped
            if Path(path).name == 'assessment' and not swapped:
                swapped = True
                parent.rename(self.base / 'moved-parent')
                parent.symlink_to(other, target_is_directory=True)
            return original(path, *args, **kwargs)
        with patch.object(assess.os, 'mkdir', side_effect=mkdir), self.assertRaises(assess.AssessmentError):
            self.run_assessment()
        self.assertEqual((other / 'keep').read_text(), MARKER)
        self.assertEqual({p.name for p in other.iterdir()}, {'keep'})
        self.assertFalse((self.base / 'moved-parent/assessment').exists())


if __name__ == '__main__':
    unittest.main()
