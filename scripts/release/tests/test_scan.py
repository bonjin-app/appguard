import hashlib
import importlib.util
import io
import json
import os
from collections import ChainMap
from pathlib import Path
import tarfile
import tempfile
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('scan', Path(__file__).resolve().parents[1] / 'scan.py')


class ScanTests(unittest.TestCase):
    def test_maven_child_disables_launcher_rc_without_mutating_caller_environment(self):
        m = self.module()
        identity = {key: os.environ[key] for key in ('HOME', 'CODEX_HOME') if key in os.environ}
        for flag_present in (False, True):
            with self.subTest(flag_present=flag_present), tempfile.TemporaryDirectory() as tmp:
                base = Path(tmp).resolve()
                source = base / 'source'
                (source / 'sdk/spring-boot').mkdir(parents=True)
                (source / 'sdk/spring-boot/pom.xml').write_text('<project/>')
                (base / 'state').mkdir(); (base / 'reports').mkdir()
                fake = base / 'mvn'
                fake.write_text('owned executable placeholder; subprocess intercepted')
                caller = {'PATH': '', **identity}
                if flag_present: caller['MAVEN_SKIP_RC'] = '0'
                before = dict(caller)
                observations = []
                def invoke(command, *, env, **kwargs):
                    observations.append((env.get('MAVEN_SKIP_RC') == '1', env is not caller,
                        all((key in env) == (key in identity) and
                            (key not in identity or env[key] == identity[key]) for key in ('HOME', 'CODEX_HOME'))))
                    return m.subprocess.CompletedProcess(command, 7)
                with patch.object(m, 'os', SimpleNamespace(environ=ChainMap(
                        {'APPGUARD_MAVEN_CMD': str(fake), 'APPGUARD_MAVEN_REPOSITORY': str(base/'cache')}, os.environ))), \
                        patch.object(m.shutil, 'which', return_value=str(fake)), \
                        patch.object(m.subprocess, 'run', side_effect=invoke):
                    result = m.export_maven(source, base/'state', base/'reports', caller)
                self.assertEqual(result['returncode'], 7)
                self.assertTrue(caller == before, 'caller environment must remain unchanged')
                self.assertEqual(len(observations), 1)
                self.assertTrue(observations[0][0], 'Maven launcher rc loading must be disabled')
                self.assertTrue(observations[0][1], 'Maven must receive a child-only environment copy')
                self.assertTrue(observations[0][2], 'tool identity environment must be preserved')
        self.assertTrue(all((key in os.environ) == (key in identity) and
            (key not in identity or os.environ[key] == identity[key]) for key in ('HOME', 'CODEX_HOME')),
            'actual process identity environment must remain unchanged')

    def test_tool_environment_preserves_actual_home_and_isolates_settings(self):
        m = self.module()
        identity = {key: os.environ[key] for key in ('HOME', 'CODEX_HOME') if key in os.environ}
        observations = []
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            source = base / 'candidate/source'
            (source / 'sdk/spring-boot').mkdir(parents=True)
            (source / 'sdk/spring-boot/pom.xml').write_text('<project/>')
            (source.parent / 'manifest.json').write_text(json.dumps({'sha256': {
                'source/sdk/spring-boot/pom.xml': hashlib.sha256(b'<project/>').hexdigest()}}))
            fake = base / 'mvn'
            fake.write_text('owned executable placeholder; subprocess intercepted')
            inherited = ChainMap({'APPGUARD_MAVEN_CMD': str(fake),
                'APPGUARD_MAVEN_REPOSITORY': str(base / 'owned-maven-cache'),
                'PRIVATE_ACCOUNT_TOKEN': 'must-not-be-inherited',
                'SYFT_CONFIG': 'must-not-be-read', 'TRIVY_CONFIG': 'must-not-be-read',
                'MAVEN_OPTS': 'must-not-be-inherited'}, os.environ)

            def invoke(command, *, env, cwd, stdout, stderr, timeout):
                kind = 'maven' if command[0] == str(fake) else Path(command[0]).name
                state = Path(cwd).parent if kind == 'maven' else Path(cwd)
                preserved = all((key in env) == (key in identity) and
                    (key not in identity or env[key] == identity[key]) for key in ('HOME', 'CODEX_HOME'))
                isolated = all(Path(env[key]).is_relative_to(state) for key in
                    ('XDG_CACHE_HOME', 'XDG_CONFIG_HOME', 'TRIVY_CACHE_DIR'))
                filtered = not any(key in env for key in
                    ('PRIVATE_ACCOUNT_TOKEN', 'SYFT_CONFIG', 'TRIVY_CONFIG', 'MAVEN_OPTS'))
                if kind == 'maven':
                    explicit = ('-Duser.home=' + str(state / 'home') in command and
                        '-Dmaven.repo.local=' + str(base / 'owned-maven-cache') in command)
                else:
                    config = Path(command[command.index('--config') + 1])
                    explicit = config.is_relative_to(state) and config.is_file()
                    if kind == 'trivy':
                        ignore = Path(command[command.index('--ignorefile') + 1])
                        explicit = explicit and config.read_text() == '{}\n' and ignore.read_text() == ''
                observations.append((kind, preserved, isolated, filtered, explicit))
                return m.subprocess.CompletedProcess(command, 7)

            with patch.object(m, 'os', SimpleNamespace(environ=inherited)), patch.object(
                    m.shutil, 'which', return_value=str(fake)), patch.object(
                    m, 'install_tool', side_effect=lambda name, state: state / name), patch.object(
                    m.subprocess, 'run', side_effect=invoke):
                self.assertEqual(m.run_scans(source.parent, base / 'reports'), 1)
        self.assertTrue(all((key in os.environ) == (key in identity) and
            (key not in identity or os.environ[key] == identity[key]) for key in ('HOME', 'CODEX_HOME')),
            'actual process identity environment must remain unchanged')
        self.assertEqual([row[0] for row in observations], ['maven', 'syft', 'trivy', 'trivy', 'trivy'])
        self.assertTrue(all(row[1] for row in observations), 'tool identity environment must be preserved')
        self.assertTrue(all(row[2] for row in observations), 'tool caches and config roots must be private')
        self.assertTrue(all(row[3] for row in observations), 'unrelated tool settings and credentials must be filtered')
        self.assertTrue(all(row[4] for row in observations), 'tools must receive explicit private settings')

    def test_raw_finding_directory_remains_owner_only_after_publication(self):
        m = self.module()
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            (base / 'candidate/source').mkdir(parents=True)
            (base / 'candidate/manifest.json').write_text(json.dumps({'sha256': {}}))
            fake = base / 'scanner'
            fake.write_text('#!/bin/sh\necho PRIVATE_FINDING\nexit 7\n')
            fake.chmod(0o700)
            previous = os.umask(0o022)
            try:
                with patch.object(m, 'install_tool', return_value=fake), patch.object(
                        m, 'export_maven', return_value={'name': 'maven-runtime', 'returncode': 127}):
                    self.assertEqual(m.run_scans(base / 'candidate', base / 'reports'), 1)
            finally:
                os.umask(previous)
            self.assertIn('PRIVATE_FINDING', (base / 'reports/syft.log').read_text())
            self.assertEqual((base / 'reports').stat().st_mode & 0o077, 0)

    def test_public_summary_reports_counts_without_private_errors_or_metadata(self):
        m = self.module()
        result = m.public_check_summary({'automated_checks_passed': False, 'error': 'PRIVATE_ERROR',
            'commands': [{'name': 'trivy-sbom', 'returncode': 1, 'path': 'PRIVATE_PATH',
                          'finding_counts': {'Vulnerabilities': 2, 'Secrets': 0, 'Licenses': 0},
                          'finding': 'PRIVATE_FINDING'},
                         {'name': 'trivy-secrets', 'returncode': 0,
                          'finding_counts': {'Secrets': 'PRIVATE_COUNT'}},
                         {'name': 'PRIVATE_CHECK', 'returncode': 1}]})
        self.assertFalse(result['automated_checks_passed'])
        self.assertFalse(result['release_ready'])
        self.assertEqual(result['checks'][0]['vulnerabilities'], 2)
        self.assertEqual(result['checks'][0]['returncode'], 1)
        self.assertNotIn('secrets', result['checks'][1])
        self.assertNotIn('PRIVATE', json.dumps(result))

    def module(self):
        module = importlib.util.module_from_spec(SPEC)
        with patch.object(sys, "path", [str(Path(__file__).resolve().parents[1]), *sys.path]):
            SPEC.loader.exec_module(module)
        return module

    def test_download_checksum_mismatch_fails_before_extraction(self):
        m = self.module()
        with tempfile.TemporaryDirectory() as tmp, patch.object(m.urllib.request, 'urlopen', return_value=io.BytesIO(b'wrong')):
            with self.assertRaisesRegex(ValueError, 'checksum'):
                m.install_tool('syft', Path(tmp), ('Linux', 'x86_64'))
            self.assertFalse((Path(tmp) / 'syft').exists())

    def test_only_expected_regular_binary_extracted(self):
        m = self.module()
        for name, symlink in [('../syft', False), ('syft', True)]:
            with self.subTest(name=name, symlink=symlink), tempfile.TemporaryDirectory() as tmp:
                archive = io.BytesIO()
                with tarfile.open(fileobj=archive, mode='w:gz') as tar:
                    item = tarfile.TarInfo(name)
                    item.size = 3
                    if symlink:
                        item.type = tarfile.SYMTYPE
                        item.linkname = '/etc/passwd'
                    tar.addfile(item, io.BytesIO(b'bad'))
                data = archive.getvalue()
                import hashlib
                entry = {'url':'https://example.invalid/test', 'sha256':hashlib.sha256(data).hexdigest(), 'version':'test'}
                with patch.dict(m.TOOLS, {'syft': {('Linux', 'x86_64'): entry}}), patch.object(m.urllib.request, 'urlopen', return_value=io.BytesIO(data)):
                    with self.assertRaises(ValueError):
                        m.install_tool('syft', Path(tmp), ('Linux', 'x86_64'))

    def test_scanner_failure_propagates_and_retains_reports(self):
        m = self.module()
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            source = base / 'candidate/source'
            source.mkdir(parents=True)
            (source.parent / 'manifest.json').write_text(json.dumps({'sha256': {}}))
            fake = base / 'scanner'
            fake.write_text('#!/bin/sh\necho scanner-failure >&2\nexit 7\n')
            fake.chmod(0o755)
            with patch.object(m, 'install_tool', return_value=fake):
                self.assertEqual(m.run_scans(source.parent, base / 'reports'), 1)
            statuses = json.loads((base / 'reports/status.json').read_text())
            self.assertEqual(len(statuses['commands']), 5)
            self.assertTrue(all(x['returncode'] == 7 for x in statuses['commands'] if x['name'] != 'maven-runtime'))
            self.assertEqual((base / 'reports/syft.log').read_text().strip(), 'scanner-failure')
            self.assertEqual(list(base.glob('.scan-*')), [])

    def test_success_without_report_is_not_a_pass(self):
        m = self.module()
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            (base / 'candidate/source').mkdir(parents=True)
            (base / 'candidate/manifest.json').write_text(json.dumps({'sha256': {}}))
            fake = base / 'scanner'
            fake.write_text('#!/bin/sh\nexit 0\n')
            fake.chmod(0o755)
            with patch.object(m, 'install_tool', return_value=fake):
                self.assertEqual(m.run_scans(base / 'candidate', base / 'reports'), 1)
            self.assertFalse(json.loads((base / 'reports/status.json').read_text())['automated_checks_passed'])

    def test_successful_scanner_cannot_omit_server_lock_entries(self):
        m = self.module()
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            source = base / 'candidate/source'
            source.mkdir(parents=True)
            raw = ('version=1\nrevision=5\n[[package]]\nname="cryptography"\n'
                   'version="50.0.2"\nsource={registry="https://pypi.org/simple"}\n')
            (source / 'uv.lock').write_text(raw)
            import hashlib
            (base / 'candidate/manifest.json').write_text(json.dumps({'sha256': {
                'source/uv.lock': hashlib.sha256(raw.encode()).hexdigest()}}))
            fake = base / 'scanner'
            fake.write_text('#!' + sys.executable + '\n'
                'import json,pathlib,sys\nargs=sys.argv\n'
                'if "-o" in args:\n'
                ' path=pathlib.Path(args[args.index("-o")+1].split("=",1)[1]); report={"bomFormat":"CycloneDX","components":[]}\n'
                'else:\n'
                ' path=pathlib.Path(args[args.index("--output")+1]); report={"SchemaVersion":2,"Results":[]}\n'
                'path.write_text(json.dumps(report))\n')
            fake.chmod(0o755)
            with patch.object(m, 'install_tool', return_value=fake), patch.object(m, 'export_maven', return_value={'name':'maven-runtime','returncode':0}):
                self.assertEqual(m.run_scans(base / 'candidate', base / 'reports'), 1)
            status = json.loads((base / 'reports/status.json').read_text())
            syft = next(v for v in status['commands'] if v['name'] == 'syft')
            self.assertEqual(syft['returncode'], 65)
            self.assertFalse(syft['recorded_source_lock_coverage_passed'])
            coverage = json.loads((base / 'reports/source-lock-coverage.json').read_text())
            self.assertFalse(coverage['all_recorded_packages_cataloged'])

    def test_missing_maven_is_explicit_and_does_not_mutate_candidate(self):
        m = self.module()
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            source = base / 'candidate/source'
            (source / 'sdk/spring-boot').mkdir(parents=True)
            (source / 'sdk/spring-boot/pom.xml').write_text('<project/>')
            (base / 'state').mkdir()
            (base / 'reports').mkdir()
            before = (source / 'sdk/spring-boot/pom.xml').read_bytes()
            with patch.object(m, 'os', SimpleNamespace(environ=ChainMap(
                    {'APPGUARD_MAVEN_CMD': '/missing/mvn'}, os.environ))):
                result = m.export_maven(source, base / 'state', base / 'reports', {'PATH': ''})
            self.assertEqual(result['returncode'], 127)
            self.assertEqual((source / 'sdk/spring-boot/pom.xml').read_bytes(), before)

    def test_maven_exports_are_hashed_and_missing_exports_fail(self):
        m = self.module()
        for produce in (True, False):
            with self.subTest(produce=produce), tempfile.TemporaryDirectory() as tmp:
                base = Path(tmp).resolve()
                source = base / 'candidate/source'
                (source / 'sdk/spring-boot').mkdir(parents=True)
                (source / 'sdk/spring-boot/pom.xml').write_text('<project/>')
                (base / 'state').mkdir()
                (base / 'reports').mkdir()
                fake = base / 'mvn'
                fake.write_text('#!' + sys.executable + '\nimport sys,pathlib\n' +
                    ('args=dict(a[2:].split("=",1) for a in sys.argv if a.startswith("-D") and "=" in a)\n'
                     'pathlib.Path(args["outputDirectory"]).joinpath("library.jar").write_bytes(b"jar")\n'
                     'pathlib.Path(args["outputFile"]).write_text("example:library:jar:1:runtime")\n' if produce else ''))
                fake.chmod(0o755)
                with patch.object(m, 'os', SimpleNamespace(environ=ChainMap(
                        {'APPGUARD_MAVEN_CMD': str(fake)}, os.environ))):
                    env = {'PATH': '', **{key: os.environ[key] for key in ('HOME', 'CODEX_HOME') if key in os.environ}}
                    result = m.export_maven(source, base / 'state', base / 'reports', env)
                self.assertEqual(result['returncode'], 0 if produce else 65)
                manifest = json.loads((base / 'reports/maven-runtime-manifest.json').read_text())
                self.assertEqual(len(manifest['sha256']), 1 if produce else 0)
                self.assertEqual((source / 'sdk/spring-boot/pom.xml').read_text(), '<project/>')

    def test_malformed_trivy_report_is_not_a_successful_empty_scan(self):
        m = self.module()
        for report in ({'SchemaVersion': True, 'Results': []}, {'SchemaVersion': 2},
                       {'SchemaVersion': 2, 'Results': [None]},
                       {'SchemaVersion': 2, 'Results': [{'Vulnerabilities': 'not findings'}]},
                       {'SchemaVersion': 2, 'Results': [{'Secrets': ['not a finding']}]}):
            with self.subTest(report=report), self.assertRaises(ValueError):
                m.evaluate_report({'returncode': 0}, report)

    def test_security_findings_fail_even_when_tool_exits_zero(self):
        m = self.module()
        for key, finding in [('Vulnerabilities', {'VulnerabilityID': 'CVE-test', 'Severity': 'HIGH'}),
                             ('Vulnerabilities', {'VulnerabilityID': 'CVE-test', 'Severity': 'CRITICAL'}),
                             ('Secrets', {'RuleID': 'private-key', 'Severity': 'HIGH'})]:
            with self.subTest(key=key, finding=finding):
                item = {'name': 'trivy-test', 'returncode': 0}
                m.evaluate_report(item, {'SchemaVersion': 2, 'Results': [{key: [finding]}]})
                self.assertEqual(item['returncode'], 1)
                self.assertEqual(item['finding_counts'][key], 1)

    def test_license_findings_stay_visible_without_security_failure(self):
        m = self.module()
        with tempfile.TemporaryDirectory() as tmp:
            reports = Path(tmp)
            for category in ['notice', 'unknown']:
                finding = {'PkgName': 'library', 'Name': 'Apache-2.0' if category == 'notice' else 'UNKNOWN',
                           'Category': category, 'Severity': 'LOW'}
                item = {'name': 'trivy-licenses', 'returncode': 0}
                report = {'SchemaVersion': 2, 'Results': [{'Target': 'Java', 'Licenses': [finding]}]}
                m.evaluate_report(item, report)
                self.assertEqual(item['returncode'], 0)
                self.assertEqual(item['finding_counts']['Licenses'], 1)
                (reports / 'trivy-licenses.json').write_text(json.dumps(report))
                review = m.write_license_review(reports)
                self.assertFalse(review['review_completed'])
                self.assertFalse(review['third_party_notices_complete'])
                self.assertEqual(review['entries'][0]['finding'], finding)
                self.assertEqual(review['entries'][0]['obligation'],
                                 'notice_obligation_review' if category == 'notice' else 'terms_review_required')

    def test_technical_pass_keeps_release_and_unknown_license_review_pending(self):
        m = self.module()
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            (base / 'candidate/source').mkdir(parents=True)
            source = base / 'candidate/source'
            digest = 'a' * 64
            (source / 'pyproject.toml').write_text('[tool.uv]\nrequire-build-hashes=true\n'
                'build-constraint-dependencies=[{requirement="builder==3.2",hashes=["sha256:' + digest + '"]}]\n')
            (source / 'uv.lock').write_text('version=1\nrevision=5\npackage=[]\n[manifest]\n'
                'build-constraints=[{name="builder",specifier="==3.2",hashes=["sha256:' + digest + '"]}]\n')
            (base / 'candidate/manifest.json').write_text(json.dumps({'sha256': {
                'source/' + p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in source.iterdir()}}))
            fake = base / 'scanner'
            fake.write_text('#!' + sys.executable + '\n' +
                'import json,pathlib,sys,hashlib\n'
                'args=sys.argv\n'
                'if "-o" in args:\n'
                ' path=pathlib.Path(args[args.index("-o")+1].split("=",1)[1]); report={"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}\n'
                ' if "maven-runtime" in path.name:\n'
                '  root=pathlib.Path(args[2][4:]); jar=root/"org/example/library/1/library-1.jar"\n'
                '  report["components"]=[{"type":"library","name":"library","version":"1","purl":"pkg:maven/org.example/library@1","properties":[{"name":"syft:location:0:path","value":"/org/example/library/1/library-1.jar"}]},{"type":"file","name":str(jar),"hashes":[{"alg":"SHA-256","content":hashlib.sha256(jar.read_bytes()).hexdigest()}]}]\n'
                'else:\n'
                ' path=pathlib.Path(args[args.index("--output")+1]); report={"SchemaVersion":2,"Results":[]}\n'
                ' if "sbom" in args: report["ObservedPurls"]=[c.get("purl") for c in json.loads(pathlib.Path(args[-1]).read_text())["components"]]\n'
                ' if "license" in args: report["Results"]=[{"Licenses":[{"PkgName":"library","Name":"UNKNOWN","Category":"unknown"}]}]\n'
                'if "--output" in args: report.update(ArtifactName=args[-1],ArtifactType="filesystem" if "fs" in args else "cyclonedx")\n'
                'path.write_text(json.dumps(report))\n')
            fake.chmod(0o755)
            def export_fixture(source, state, reports, env):
                relative = 'org/example/library/1/library-1.jar'
                jar = reports / 'maven-runtime' / relative
                jar.parent.mkdir(parents=True)
                jar.write_bytes(b'owned scan fixture')
                digest = hashlib.sha256(jar.read_bytes()).hexdigest()
                (reports / 'maven-runtime-manifest.json').write_text(json.dumps({
                    'returncode': 0, 'jar_sha256': {relative: digest}, 'sha256': {relative: digest}}))
                (reports / 'maven-runtime-dependencies.txt').write_text('org.example:library:jar:1:runtime\n')
                return {'name': 'maven-runtime', 'returncode': 0}
            with patch.object(m, 'install_tool', return_value=fake), patch.object(m, 'export_maven', side_effect=export_fixture):
                self.assertEqual(m.run_scans(base / 'candidate', base / 'reports'), 0)
            status = json.loads((base / 'reports/status.json').read_text())
            self.assertTrue(status['automated_checks_passed'])
            self.assertEqual(len(status['commands']), 8)
            for name in ('trivy-sbom.json', 'trivy-licenses.json'):
                self.assertIn('pkg:pypi/builder@3.2', json.loads((base / 'reports' / name).read_text())['ObservedPurls'])
            raw = json.loads((base / 'reports/sbom-source.raw.cdx.json').read_text())
            self.assertEqual(raw['components'], [])
            coverage = json.loads((base / 'reports/source-lock-coverage.json').read_text())
            self.assertEqual(len(coverage['python_build_constraints']), 1)
            self.assertFalse(status['release_ready'])
            self.assertGreater(len(status['remaining_release_gates']), 0)
            inventory = json.loads((base / 'reports/license-review.json').read_text())
            self.assertGreater(len(inventory['entries']), 0)
            self.assertFalse(inventory['review_completed'])
            self.assertTrue((base / 'reports/THIRD_PARTY_NOTICES.review.md').exists())

    def test_scanner_cannot_adopt_rewritten_manifest_and_source(self):
        m = self.module()
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            (base / 'candidate/source').mkdir(parents=True)
            (base / 'candidate/source/README.md').write_text('original')
            import hashlib
            manifest = {'commit': 'a'*40, 'sha256': {'source/README.md': hashlib.sha256(b'original').hexdigest()}}
            (base / 'candidate/manifest.json').write_text(json.dumps(manifest))
            fake = base / 'scanner'
            fake.write_text('#!' + sys.executable + '\n' +
                'import json,pathlib,sys\n'
                'args=sys.argv\n'
                'if "-o" in args:\n'
                ' path=pathlib.Path(args[args.index("-o")+1].split("=",1)[1]); report={"bomFormat":"CycloneDX","components":[]}\n'
                'else:\n'
                ' path=pathlib.Path(args[args.index("--output")+1]); report={"SchemaVersion":2,"Results":[]}\n'
                'path.write_text(json.dumps(report))\n')
            fake.chmod(0o755)
            original_review = m.write_license_review
            def rewrite_after_scanning(reports):
                result = original_review(reports)
                (base / 'candidate/source/README.md').write_text('scanner replacement')
                manifest['sha256']['source/README.md'] = hashlib.sha256(b'scanner replacement').hexdigest()
                manifest['commit'] = 'b'*40
                (base / 'candidate/manifest.json').write_text(json.dumps(manifest))
                return result
            with patch.object(m, 'install_tool', return_value=fake), patch.object(m, 'export_maven', return_value={'name':'maven-runtime','returncode':0}), patch.object(m, 'write_license_review', side_effect=rewrite_after_scanning):
                self.assertEqual(m.run_scans(base / 'candidate', base / 'reports'), 1)
            status = json.loads((base / 'reports/status.json').read_text())
            self.assertFalse(status['automated_checks_passed'])
            self.assertIn('manifest', status['error'].lower())

    def test_tampered_or_extra_source_rejected(self):
        m = self.module()
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            (base / 'source').mkdir()
            (base / 'source/unexpected').write_text('private')
            (base / 'manifest.json').write_text(json.dumps({'sha256': {}}))
            with self.assertRaises(ValueError):
                m.verify_candidate(base)


if __name__ == '__main__':
    unittest.main()
