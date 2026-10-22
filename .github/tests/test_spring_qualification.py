"""Guard the local qualifier's ownership, wire format and evidence boundaries."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('spring_qualification',ROOT/'scripts/qualification/spring_ingress.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


class QualificationTests(unittest.TestCase):
    def test_new_output_rejects_source_existing_and_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp).resolve()
            with self.assertRaises(ValueError):module.new_output(base)
            with self.assertRaises(ValueError):module.new_output(ROOT/'not-created')
            (base/'link').symlink_to(base,target_is_directory=True)
            with self.assertRaises(ValueError):module.new_output(base/'link/new')
            output=module.new_output(base/'fresh')
            self.assertEqual(output.stat().st_mode&0o777,0o700)

    def test_wire_preserves_raw_target_and_binary_body(self):
        target='/v1/items?x=%2f&x=%2F'
        value=module.wire(target,[('Signature','appguard=:EXAMPLE:')],b'\x00\xff')
        self.assertTrue(value.startswith(('POST '+target+' HTTP/1.1\r\n').encode()))
        self.assertTrue(value.endswith(b'\r\n\r\n\x00\xff'))
        self.assertIn(b'Content-Length: 2\r\n',value)
        self.assertNotIn(b'Transfer-Encoding:',value)

    def test_chunked_encoding_terminates_empty_and_nonempty(self):
        self.assertTrue(module.wire('/v1/items?',[],b'',True).endswith(b'\r\n\r\n0\r\n\r\n'))
        value=module.wire('/v1/items',[],b'abc',True)
        self.assertIn(b'Transfer-Encoding: chunked\r\n',value)
        self.assertNotIn(b'Content-Length:',value)
        self.assertTrue(value.endswith(b'3\r\nabc\r\n0\r\n\r\n'))

    def test_cleanup_only_signals_supplied_owned_child(self):
        child=Mock();child.poll.side_effect=[None,0]
        self.assertTrue(module.stop(child));child.terminate.assert_called_once();child.wait.assert_called_once_with(timeout=8)
        child.kill.assert_not_called()

    def test_cleanup_escalates_only_if_owned_child_does_not_settle(self):
        child=Mock();child.poll.side_effect=[None,-9]
        child.wait.side_effect=[subprocess.TimeoutExpired('owned',8),-9]
        self.assertTrue(module.stop(child));child.kill.assert_called_once()

    def test_cleanup_failure_does_not_skip_other_owned_children(self):
        first,second=object(),object()
        with patch.object(module,'stop',side_effect=[OSError('fixed test failure'),True]) as stop:
            self.assertFalse(module.cleanup([first,second]))
        self.assertEqual([call.args[0] for call in stop.call_args_list],[second,first])

    def test_counter_snapshot_rejects_unexpected_fields_or_boolean_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'counts.json'
            sample={key:0 for key in ('dispatch','auth','key','replay','resource')}
            path.write_text(json.dumps(sample));self.assertEqual(module.counters(path),sample)
            sample['dispatch']=True;path.write_text(json.dumps(sample))
            with self.assertRaises(AssertionError):module.counters(path)

    def test_export_hashes_metadata_and_rejects_unrecorded_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp)
            for name in ('example.jar','_remote.repositories','maven-metadata-local.xml'):
                (directory/name).write_bytes(name.encode())
            hashes=module.file_hashes(directory)
            self.assertEqual(set(hashes),{'example.jar','_remote.repositories','maven-metadata-local.xml'})
            module.verify_pins({},directory,hashes)
            (directory/'unrecorded').write_bytes(b'new')
            with self.assertRaises(AssertionError):module.verify_pins({},directory,hashes)

    def test_provenance_rejects_changed_source_and_exported_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);tree=base/'runtime';tree.mkdir()
            source=base/'source.py';source.write_bytes(b'original')
            metadata=tree/'_remote.repositories';metadata.write_bytes(b'original')
            pins={source:module.digest(source)};hashes=module.file_hashes(tree)
            source.write_bytes(b'changed')
            with self.assertRaises(AssertionError):module.verify_pins(pins,tree,hashes)
            source.write_bytes(b'original');metadata.write_bytes(b'changed')
            with self.assertRaises(AssertionError):module.verify_pins(pins,tree,hashes)

    def test_export_rejects_symlink_files_and_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);tree=base/'runtime';tree.mkdir();file=base/'outside';file.write_bytes(b'value')
            (tree/'link').symlink_to(file)
            with self.assertRaises(AssertionError):module.file_hashes(tree)
            (tree/'link').unlink();(tree/'link').symlink_to(base,target_is_directory=True)
            with self.assertRaises(AssertionError):module.file_hashes(tree)


if __name__=='__main__':unittest.main()
