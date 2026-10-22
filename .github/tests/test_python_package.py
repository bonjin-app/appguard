"""Python package contract and opt-in, real uv isolated-build regressions.

Default tests do not download or install anything. Editable SDK/reference
installation and the isolated wheel consumer are exercised only in real-tool mode. Pass --verify-packaging with
explicit uv/Python executables for real builds and one clean consumer install.
An optional --build-wheelhouse supplies reviewed wheels instead of downloading them. Raw tool logs stay private.
"""
import argparse
import base64
import csv
from contextlib import contextmanager
import email
import hashlib
import io
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import tomllib
import unittest
from unittest.mock import patch
import urllib.parse
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[2]
SDK = ROOT / 'sdk/python'
REFERENCE = ROOT / 'reference/python'
OPTIONS = None
EXPECTED_BUILD_VERSIONS = {
    'hatchling': '1.27.0', 'packaging': '25.0', 'pathspec': '0.12.1',
    'pluggy': '1.6.0', 'trove-classifiers': '2025.5.9.12', 'editables': '0.6',
}


def project_data(path=SDK):
    return tomllib.loads((path / 'pyproject.toml').read_text())


def build_pins(data):
    entries = data['tool']['uv']['build-constraint-dependencies']
    pins = {}
    for entry in entries:
        match = re.fullmatch(r'([a-z][a-z0-9-]*)==([0-9][A-Za-z0-9.]*)', entry['requirement'])
        if not match or match[1] in pins or len(entry['hashes']) != 1:
            raise ValueError('invalid_build_pin')
        digest = entry['hashes'][0]
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', digest):
            raise ValueError('invalid_build_pin')
        pins[match[1]] = (match[2], digest[7:])
    return pins


class PackageContractTests(unittest.TestCase):
    def test_normal_build_requires_hashed_build_dependencies(self):
        for project in (SDK, REFERENCE):
            with self.subTest(project=project.name):
                self.assertIs(project_data(project)['tool']['uv'].get('require-build-hashes'), True)

    def test_exact_build_closure_is_recorded_in_lock_manifest(self):
        for project in (SDK, REFERENCE):
            with self.subTest(project=str(project.relative_to(ROOT))):
                pins = build_pins(project_data(project))
                self.assertEqual({name: version for name, (version, _) in pins.items()}, EXPECTED_BUILD_VERSIONS)
                self.assertEqual(pins, build_pins(project_data()))
                lock = tomllib.loads((project / 'uv.lock').read_text())
                actual = {item['name']: (item['specifier'][2:], item['hashes'][0][7:])
                          for item in lock.get('manifest', {}).get('build-constraints', [])}
                self.assertEqual(actual, pins)

    def test_build_tools_are_not_runtime_requirements(self):
        data = project_data()
        runtime = data['project']['dependencies'] + [requirement
            for group in data['project']['optional-dependencies'].values() for requirement in group]
        self.assertFalse(any(re.match(r'(?i)(hatchling|packaging|pathspec|pluggy|trove-classifiers|editables)\b', r)
                             for r in runtime))

    def test_supported_build_command_uses_project_directory_and_isolation(self):
        script = (ROOT / 'scripts/test-server-sdks.sh').read_text()
        self.assertIn('"$uv_cmd" --directory sdk/python build --require-build-hashes --no-cache', script)
        self.assertNotIn('--no-build-isolation', script)


class ProcessLifetimeTests(unittest.TestCase):
    def test_download_absolute_deadline_includes_dns_and_response_headers(self):
        def delayed_dns(*args, **kwargs):
            time.sleep(.3)
            raise OSError('synthetic stalled DNS; no network')
        class DelayedHeaders:
            def open(self, *args, **kwargs):
                time.sleep(.3)
                raise OSError('synthetic stalled headers; no network')
        for target, replacement in [('socket.getaddrinfo', delayed_dns),
                                    ('urllib.request.build_opener', lambda *a, **k: DelayedHeaders())]:
            with self.subTest(target=target), patch(target, replacement):
                started = time.monotonic()
                with self.assertRaises((OSError, ValueError)):
                    official_download('https://pypi.org/probe-no-network', 8, started + .05)
                self.assertLess(time.monotonic() - started, .25)

    def test_download_output_limit_is_enforced_without_network(self):
        class BytesOpener:
            def open(self, *args, **kwargs):
                return io.BytesIO(b'x' * 9)
        with patch('urllib.request.build_opener', return_value=BytesOpener()):
            with self.assertRaises(ValueError):
                official_download('https://pypi.org/probe-no-network', 8, time.monotonic() + 2)

    def test_sigterm_unwinds_driver_and_reaps_owned_tool(self):
        with tempfile.TemporaryDirectory(prefix='appguard-process-regression-') as directory:
            state = Path(directory).resolve()
            pidfile = state / 'tool.pid'
            child_source = 'import os,pathlib,sys,time; pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(30)'
            harness = ('import importlib.util,pathlib,sys; '
                'spec=importlib.util.spec_from_file_location("package_probe",sys.argv[1]); '
                'm=importlib.util.module_from_spec(spec); spec.loader.exec_module(m); '
                'c=m.IsolatedPackageTests; c.state=pathlib.Path(sys.argv[2]); c.evidence=c.state; c.env={"PATH":"/usr/bin:/bin"}; '
                'c.run_tool("owned-process",[sys.executable,"-c",' + repr(child_source) + ',sys.argv[3]])')
            driver = subprocess.Popen([sys.executable, '-c', harness, str(Path(__file__).resolve()), str(state), str(pidfile)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
            identifier = None
            try:
                deadline = time.monotonic() + 5
                while not pidfile.exists() and time.monotonic() < deadline:
                    if driver.poll() is not None:
                        break
                    time.sleep(.01)
                self.assertTrue(pidfile.exists(), 'driver did not start the owned process')
                identifier = int(pidfile.read_text())
                driver.send_signal(signal.SIGTERM)
                driver.wait(timeout=5)
                # Orphans can briefly be zombies; a reaped directly-owned child
                # must disappear, not remain running after driver termination.
                with self.assertRaises(ProcessLookupError):
                    os.kill(identifier, 0)
            finally:
                if identifier is not None:
                    try:
                        os.killpg(identifier, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                if driver.poll() is None:
                    os.killpg(driver.pid, signal.SIGKILL)
                    driver.wait(timeout=5)


def private_write(path, data):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb') as stream:
        stream.write(data)


def _download_transport(url, limit, deadline):
    def permitted(value):
        parsed = urllib.parse.urlparse(value)
        return parsed.scheme == 'https' and parsed.hostname in {'pypi.org', 'files.pythonhosted.org'} and not parsed.username
    class OfficialRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, response, code, message, headers, newurl):
            if not permitted(newurl):
                raise ValueError('unapproved_package_source')
            return super().redirect_request(request, response, code, message, headers, newurl)
    if not permitted(url):
        raise ValueError('unapproved_package_source')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), OfficialRedirect())
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ValueError('package_download_bound')
    chunks, size = [], 0
    with opener.open(url, timeout=min(15, remaining)) as response:
        while True:
            if time.monotonic() >= deadline:
                raise ValueError('package_download_bound')
            chunk = response.read(min(65536, limit - size + 1))
            if not chunk:
                break
            size += len(chunk)
            if size > limit:
                raise ValueError('package_download_bound')
            chunks.append(chunk)
    return b''.join(chunks)


@contextmanager
def cooperative_termination():
    """Convert SIGTERM into unwinding so owned child groups are cleaned up."""
    def cancel(signum, frame):
        raise KeyboardInterrupt()
    previous = signal.signal(signal.SIGTERM, cancel)
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)


def official_download(url, limit, deadline):
    """Bound DNS, headers and body with an owned child and parent wall clock.

    fork is intentional: the parent remains outside potentially blocking DNS or
    urllib operations. This verification runner supports the POSIX CI/macOS
    environments used by the package tests, not Windows process semantics.
    """
    if type(limit) is not int or not 0 < limit <= 2 * 1024 * 1024 or deadline <= time.monotonic():
        raise ValueError('package_download_bound')
    with cooperative_termination():
        read_fd, write_fd = os.pipe()
        identifier = None
        reaped = False
        try:
            identifier = os.fork()
            if identifier == 0:
                os.close(read_fd)
                status = 1
                try:
                    os.setsid()
                    raw = _download_transport(url, limit, deadline)
                    for start in range(0, len(raw), 65536):
                        part = memoryview(raw)[start:start + 65536]
                        while part:
                            part = part[os.write(write_fd, part):]
                    status = 0
                except BaseException:
                    pass
                finally:
                    os.close(write_fd)
                os._exit(status)
            os.close(write_fd)
            write_fd = None
            chunks, size, eof = [], 0, False
            with selectors.DefaultSelector() as selector:
                selector.register(read_fd, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ValueError('package_download_bound')
                    for event, _ in selector.select(min(remaining, .05)):
                        part = os.read(event.fd, min(65536, limit - size + 1))
                        if not part:
                            selector.unregister(event.fd)
                            eof = True
                        else:
                            size += len(part)
                            if size > limit:
                                raise ValueError('package_download_bound')
                            chunks.append(part)
                    if eof:
                        finished, status = os.waitpid(identifier, os.WNOHANG)
                        if finished:
                            reaped = True
                            if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
                                raise ValueError('package_download_unverified')
                            return b''.join(chunks)
        finally:
            os.close(read_fd)
            if write_fd is not None:
                os.close(write_fd)
            if identifier:
                # Clean descendants even after a successful/reaped leader. The
                # direct-PID fallback covers cancellation before child setsid.
                for action in (signal.SIGTERM, signal.SIGKILL):
                    try:
                        os.killpg(identifier, action)
                    except ProcessLookupError:
                        if not reaped:
                            try:
                                os.kill(identifier, action)
                            except ProcessLookupError:
                                pass
                if not reaped:
                    os.waitpid(identifier, 0)


class IsolatedPackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='appguard-package-test-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.state = Path(cls.temporary.name).resolve()
        cls.state.chmod(0o700)
        cls.evidence = OPTIONS.evidence
        cls.observations = {}
        cls.uv = Path(shutil.which(OPTIONS.uv) or OPTIONS.uv).resolve(strict=True)
        cls.python = Path(shutil.which(OPTIONS.python) or OPTIONS.python).resolve(strict=True)
        cls.env = {'PATH': os.defpath, 'HOME': str(cls.state / 'home'),
            'XDG_CONFIG_HOME': str(cls.state / 'home'), 'XDG_CACHE_HOME': str(cls.state / 'cache'),
            'UV_PYTHON_DOWNLOADS': 'never', 'UV_KEYRING_PROVIDER': 'disabled', 'UV_NO_PROGRESS': 'true',
            'UV_HTTP_TIMEOUT': '15', 'UV_HTTP_RETRIES': '1', 'SOURCE_DATE_EPOCH': '1700000000'}
        (cls.state / 'home').mkdir(mode=0o700)
        code, raw = cls.run_tool('uv-version', [cls.uv, '--version'])
        if code or not raw.startswith(b'uv 0.13.4 '):
            raise ValueError('reviewed_uv_0_13_4_required')
        cls.pins = build_pins(project_data())
        if {name: version for name, (version, _) in cls.pins.items()} != EXPECTED_BUILD_VERSIONS:
            raise ValueError('reviewed_build_versions_required')
        download_deadline = time.monotonic() + 90
        cls.wheelhouse = cls.state / 'build-wheelhouse'
        cls.wheelhouse.mkdir(mode=0o700)
        for name, (version, expected) in cls.pins.items():
            if OPTIONS.build_wheelhouse:
                if OPTIONS.build_wheelhouse.absolute() != OPTIONS.build_wheelhouse.resolve():
                    raise ValueError('invalid_build_wheelhouse')
                if len(list(OPTIONS.build_wheelhouse.iterdir())) != len(cls.pins):
                    raise ValueError('invalid_build_wheelhouse')
                files = []
                for file in OPTIONS.build_wheelhouse.iterdir():
                    if file.is_symlink() or not file.is_file() or file.stat().st_size > 2 * 1024 * 1024:
                        raise ValueError('invalid_build_wheelhouse')
                    if hashlib.sha256(file.read_bytes()).hexdigest() == expected:
                        files.append((file.name, file.read_bytes()))
                if len(files) != 1:
                    raise ValueError('reviewed_build_wheel_missing')
                filename, raw = files[0]
            else:
                metadata = official_download(f'https://pypi.org/pypi/{name}/{version}/json', 2 * 1024 * 1024, download_deadline)
                def unique(pairs):
                    result = {}
                    for key, value in pairs:
                        if key in result:
                            raise ValueError('duplicate_package_metadata')
                        result[key] = value
                    return result
                document = json.loads(metadata, object_pairs_hook=unique)
                if document['info']['name'].lower().replace('_', '-') != name or document['info']['version'] != version:
                    raise ValueError('unexpected_package_version')
                choices = [item for item in document['urls'] if item['digests']['sha256'] == expected
                           and item['filename'].endswith('-py3-none-any.whl') and not item['yanked']]
                if len(choices) != 1:
                    raise ValueError('reviewed_build_wheel_missing')
                filename = choices[0]['filename']
                raw = official_download(choices[0]['url'], 2 * 1024 * 1024, download_deadline)
                private_write(cls.evidence / (name + '-pypi.json'), metadata)
            if Path(filename).name != filename or not filename.endswith('.whl') or hashlib.sha256(raw).hexdigest() != expected:
                raise ValueError('build_wheel_checksum_mismatch')
            private_write(cls.wheelhouse / filename, raw)
        cls.source_pins = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
            for project in (SDK, REFERENCE) for p in cls.source_files(project)}
        cls.addClassCleanup(cls.verify_original_source)

    @staticmethod
    def source_files(project=SDK):
        files = [project / name for name in ('pyproject.toml', 'uv.lock', 'README.md', 'LICENSE')
                 if (project / name).is_file()]
        for path in (project / 'src').rglob('*'):
            if '__pycache__' in path.parts:
                continue
            if path.is_symlink():
                raise ValueError('unsafe_source')
            if path.is_file():
                files.append(path)
        return files

    @classmethod
    def verify_original_source(cls):
        if any(hashlib.sha256((ROOT / p).read_bytes()).hexdigest() != digest for p, digest in cls.source_pins.items()):
            raise ValueError('candidate_source_changed')

    @classmethod
    def run_tool(cls, name, command, timeout=90):
        with cooperative_termination():
            env = dict(cls.env, UV_CACHE_DIR=str(cls.state / (name + '-cache')))
            path = cls.evidence / (name + '.log')
            with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as log:
                child = subprocess.Popen([str(arg) for arg in command], cwd=cls.state, env=env,
                    stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
                try:
                    code = child.wait(timeout=timeout)
                finally:
                    for action in (signal.SIGTERM, signal.SIGKILL):
                        try:
                            os.killpg(child.pid, action)
                        except ProcessLookupError:
                            pass
                    child.wait(timeout=5)
            if path.stat().st_size > 8 * 1024 * 1024:
                raise ValueError('tool_output_bound')
            return code, path.read_bytes()

    def copy_source(self, name, project=SDK):
        source = self.state / name
        source.mkdir(parents=True, mode=0o700)
        for path in self.source_files(project):
            target = source / path.relative_to(project)
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            private_write(target, path.read_bytes())
        return source

    def build(self, name, source, explicit=False):
        output = self.state / (name + '-dist')
        command = [self.uv, '--directory', source, 'build', '--wheel', '--python', self.python,
            '--no-python-downloads', '--no-cache', '--offline', '--no-index', '--find-links', self.wheelhouse,
            '--out-dir', output]
        if explicit:
            command.append('--require-build-hashes')
        code, raw = self.run_tool(name, command)
        return code, raw, list(output.glob('*.whl')) if output.exists() else []

    def validate_runtime_wheelhouse(self):
        if OPTIONS.runtime_wheelhouse:
            house = OPTIONS.runtime_wheelhouse
            self.assertEqual(house.absolute(), house.resolve())
            approved = {(Path(item['url']).name, item['hash'].removeprefix('sha256:'))
                for project in (SDK, REFERENCE)
                for package in tomllib.loads((project / 'uv.lock').read_text())['package']
                for item in package.get('wheels', [])}
            files = list(house.iterdir())
            self.assertLessEqual(len(files), 128)
            total = 0
            for path in files:
                self.assertFalse(path.is_symlink())
                self.assertTrue(path.is_file())
                self.assertLessEqual(path.stat().st_size, 64 * 1024 * 1024)
                total += path.stat().st_size
                self.assertIn((path.name, hashlib.sha256(path.read_bytes()).hexdigest()), approved)
            self.assertLessEqual(total, 256 * 1024 * 1024)

    def test_locked_editable_sync_for_sdk_and_reference(self):
        self.validate_runtime_wheelhouse()
        sdk = self.copy_source('editable-tree/sdk/python')
        reference = self.copy_source('editable-tree/reference/python', REFERENCE)
        self.assertEqual((reference / '../../sdk/python').resolve(), sdk)
        smoke = self.state / 'editable-smoke.py'
        private_write(smoke, b'import importlib.metadata, json, pathlib, sys, tomllib\nproject=pathlib.Path(sys.argv[1]).resolve(); sdk=pathlib.Path(sys.argv[2]).resolve(); role=sys.argv[3]\nimport appguard\nassert pathlib.Path(appguard.__file__).resolve()==sdk/"src/appguard/__init__.py"\nmodules=[("appguard-server",sdk)]\nif role=="reference":\n import appguard_reference\n from appguard_reference.verify import verify_request as reference_verify\n from appguard import verify_request\n assert reference_verify is verify_request\n assert pathlib.Path(appguard_reference.__file__).resolve()==project/"src/appguard_reference/__init__.py"\n modules.append(("appguard-reference",project))\nfor name,origin in modules:\n dist=importlib.metadata.distribution(name)\n direct=json.loads(dist.read_text("direct_url.json"))\n assert direct.get("dir_info",{}).get("editable") is True\n assert pathlib.Path(__import__("urllib.parse",fromlist=["urlparse"]).urlparse(direct["url"]).path).resolve()==origin\nlocked={p["name"]:p["version"]for p in tomllib.loads((project/"uv.lock").read_text())["package"]}\nfor d in importlib.metadata.distributions():\n name=d.metadata["Name"].lower().replace("_","-")\n assert locked.get(name)==d.version\nprint(json.dumps({"editable_origins_verified":True,"editable_distributions":len(modules),"installed_versions_match_lock":True}))\n')
        for role, project in (('sdk', sdk), ('reference', reference)):
            with self.subTest(project=role):
                lock = (project / 'uv.lock').read_bytes()
                network = (['--offline', '--no-index', '--find-links', OPTIONS.runtime_wheelhouse]
                    if OPTIONS.runtime_wheelhouse else ['--default-index', 'https://pypi.org/simple',
                        '--index-strategy', 'first-index', '--keyring-provider', 'disabled'])
                code, _ = self.run_tool('editable-' + role + '-sync', [self.uv, '--directory', project,
                    'sync', '--locked', '--no-cache', '--python', self.python, '--no-python-downloads',
                    '--find-links', self.wheelhouse, *network])
                self.assertEqual(code, 0, 'locked editable install failed; inspect private tool log')
                self.assertEqual((project / 'uv.lock').read_bytes(), lock)
                python = project / '.venv/bin/python'
                code, _ = self.run_tool('editable-' + role + '-dependency-check', [self.uv, 'pip', 'check', '--python', python])
                self.assertEqual(code, 0)
                code, raw = self.run_tool('editable-' + role + '-origins', [python, '-I', smoke, project, sdk, role])
                self.assertEqual(code, 0, 'editable origin check failed; inspect private tool log')
                result = json.loads(raw)
                self.assertEqual(result, {'editable_origins_verified': True, 'editable_distributions': 1 if role == 'sdk' else 2,
                    'installed_versions_match_lock': True})
                self.__class__.observations['locked_editable_' + role + '_sync_and_origins_passed'] = True

    def test_missing_or_wrong_transitive_hash_fails_without_wheel(self):
        for name in ('missing', 'wrong', 'missing-entry'):
            with self.subTest(name=name):
                source = self.copy_source('negative-' + name)
                text = (source / 'pyproject.toml').read_text()
                version, digest = self.pins['packaging']
                line = next(line for line in text.splitlines() if 'requirement = "packaging==' in line)
                replacement = (f'    "packaging=={version}",' if name == 'missing' else ''
                    if name == 'missing-entry' else line.replace(digest, '0' * 64))
                (source / 'pyproject.toml').write_text(text.replace(line, replacement))
                code, raw, wheels = self.build('hash-' + name, source)
                self.assertNotEqual(code, 0)
                self.assertEqual(wheels, [])
                self.assertIn(b'hash', raw.lower())
                self.__class__.observations['hash_' + name.replace('-', '_') + '_rejected_without_wheel'] = True

    def test_real_isolated_build_and_clean_consumer(self):
        source = self.copy_source('positive')
        code, _, wheels = self.build('ordinary-settings', source)
        self.assertEqual(code, 0, 'real build failed; inspect private tool log')
        self.assertEqual(len(wheels), 1)
        self.__class__.observations['ordinary_isolated_build_passed'] = True
        code, _, repeated = self.build('explicit-hash-command', source, explicit=True)
        self.assertEqual(code, 0)
        self.assertEqual(len(repeated), 1)
        self.assertEqual(hashlib.sha256(wheels[0].read_bytes()).digest(), hashlib.sha256(repeated[0].read_bytes()).digest())
        self.__class__.observations['wheel_sha256'] = hashlib.sha256(wheels[0].read_bytes()).hexdigest()
        self.__class__.observations['controlled_builds_byte_identical'] = True
        expected_payload = {str(p.relative_to(source / 'src')): p.read_bytes()
            for p in (source / 'src').rglob('*') if p.is_file()}
        with zipfile.ZipFile(wheels[0]) as archive:
            names = archive.namelist()
            self.assertEqual(len(names), len(set(names)))
            metadata_names = [n for n in names if n.endswith('.dist-info/METADATA')]
            self.assertEqual(len(metadata_names), 1)
            prefix = metadata_names[0].split('/')[0]
            self.assertEqual(set(names), set(expected_payload) | {prefix + '/' + n
                for n in ('METADATA', 'WHEEL', 'RECORD', 'licenses/LICENSE')})
            for name, raw in expected_payload.items():
                self.assertEqual(archive.read(name), raw)
            self.assertEqual(archive.read(prefix + '/licenses/LICENSE'), (source / 'LICENSE').read_bytes())
            metadata = email.message_from_bytes(archive.read(metadata_names[0]))
            self.assertEqual(metadata['Name'], 'appguard-server')
            self.assertEqual(metadata['Version'], project_data(source)['project']['version'])
            self.assertEqual(metadata['License-Expression'], 'Apache-2.0')
            requirements = metadata.get_all('Requires-Dist', [])
            self.assertFalse(any(re.match(r'(?i)(hatchling|packaging|pathspec|pluggy|trove-classifiers|editables)\b', r) for r in requirements))
            def normalized(requirement, extra=None):
                dependency, _, marker = requirement.partition(';')
                if marker:
                    match = re.fullmatch(r"\s*extra == ['\"]([a-z]+)['\"]\s*", marker)
                    self.assertIsNotNone(match)
                    extra = match[1]
                match = re.fullmatch(r'([A-Za-z0-9_.-]+)(.*)', dependency.strip())
                self.assertIsNotNone(match)
                return (match[1].lower().replace('_', '-'), tuple(sorted(match[2].replace(' ', '').split(','))), extra)
            project = project_data(source)['project']
            expected_requirements = {normalized(r) for r in project['dependencies']}
            expected_requirements.update(normalized(r, extra) for extra, group in project['optional-dependencies'].items() for r in group)
            self.assertEqual({normalized(r) for r in requirements}, expected_requirements)
            for name, digest, size in csv.reader(io.StringIO(archive.read(prefix + '/RECORD').decode())):
                if name.endswith('/RECORD'):
                    self.assertEqual((digest, size), ('', ''))
                else:
                    raw = archive.read(name)
                    self.assertEqual(digest, 'sha256=' + base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).decode().rstrip('='))
                    self.assertEqual(int(size), len(raw))
        self.__class__.observations['wheel_payload_license_record_and_requires_dist_passed'] = True
        runtime = self.state / 'runtime.txt'
        code, _ = self.run_tool('runtime-export', [self.uv, '--directory', source, 'export', '--frozen', '--all-extras', '--no-dev',
            '--no-default-groups', '--no-editable', '--no-emit-project', '--no-annotate', '--output-file', runtime])
        self.assertEqual(code, 0)
        private_write(self.evidence / 'runtime-requirements.txt', runtime.read_bytes())
        self.__class__.observations['runtime_requirements_sha256'] = hashlib.sha256(runtime.read_bytes()).hexdigest()
        consumer = self.state / 'consumer'
        code, _ = self.run_tool('consumer-venv', [self.uv, 'venv', '--python', self.python, '--no-python-downloads', consumer])
        self.assertEqual(code, 0)
        python = consumer / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
        self.validate_runtime_wheelhouse()
        network = ['--offline', '--no-index', '--find-links', OPTIONS.runtime_wheelhouse] if OPTIONS.runtime_wheelhouse else [
            '--default-index', 'https://pypi.org/simple', '--keyring-provider', 'disabled']
        wheel_requirement = self.state / 'wheel.txt'
        private_write(wheel_requirement, (str(wheels[0]) + ' --hash=sha256:' + hashlib.sha256(wheels[0].read_bytes()).hexdigest() + '\n').encode())
        code, _ = self.run_tool('consumer-install', [self.uv, 'pip', 'install', '--python', python, '--require-hashes',
            '--only-binary', ':all:', '--no-deps', '-r', runtime, '-r', wheel_requirement, *network])
        self.assertEqual(code, 0)
        self.__class__.observations['hash_locked_all_binary_consumer_install_passed'] = True
        code, _ = self.run_tool('consumer-pip-check', [self.uv, 'pip', 'check', '--python', python])
        self.assertEqual(code, 0)
        self.__class__.observations['consumer_dependency_check_passed'] = True
        smoke = '''import base64, importlib, importlib.metadata, json, pathlib, pkgutil, sys, tomllib
import appguard
from appguard import KeyRecord, RequestInput, SignatureParameters, VerificationError, verify_request
from appguard.replay import InMemoryReplayStore
from appguard.wire import parse_signatures
from appguard.policy import PolicyContext, evaluate_policy
package=pathlib.Path(appguard.__file__).resolve()
assert package.is_relative_to(pathlib.Path(sys.prefix).resolve()) and "site-packages" in package.parts
sdk_modules=[m.name for m in pkgutil.walk_packages(appguard.__path__,"appguard.")]
for name in sdk_modules: importlib.import_module(name)
frameworks=("fastapi","django","flask","asgiref","redis","uvicorn","h11","asn1crypto")
for name in frameworks:
 m=importlib.import_module(name)
 assert pathlib.Path(m.__file__).resolve().is_relative_to(pathlib.Path(sys.prefix).resolve()) and "site-packages" in pathlib.Path(m.__file__).parts
assert all(pathlib.Path(m.__file__).resolve().is_relative_to(package.parent) for n,m in sys.modules.items() if n.startswith("appguard.") and getattr(m,"__file__",None))
assert not any(importlib.metadata.packages_distributions().get(n) for n in ("hatchling","packaging","pathspec","pluggy","trove_classifiers","editables"))
v=json.loads(pathlib.Path(sys.argv[1]).read_text())[0]
r=v["request"]; request=RequestInput(r["method"],r["target"],tuple(tuple(p)for p in r["headers"]),base64.b64decode(r["body_b64"]))
k=KeyRecord(**{**v["key"],"public_key_pem":v["key"]["public_key_pem"].encode()}); p=SignatureParameters(**v["parameters"]); replay=InMemoryReplayStore()
assert verify_request(request,p,base64.b64decode(v["signature_b64"]),key=k,replay=replay,**v["context"]).code=="VERIFIED"
try: verify_request(request,p,base64.b64decode(v["signature_b64"]),key=k,replay=replay,**v["context"])
except VerificationError as e: assert e.code=="REPLAY_DETECTED"
else: raise AssertionError("replay accepted")
headers=tuple(tuple(p)for p in r["headers"])+(("Signature-Input","appguard="+v["expected_signature_base"].split('"@signature-params": ',1)[1]),("Signature","appguard=:"+v["signature_b64"]+":"))
assert parse_signatures(headers).parameters==p
assert evaluate_policy("basic",PolicyContext(authentication="authenticated",verification="verified"),now=v["context"]["now"]).action in ("allow","observe")
from appguard.asgi import AppGuardMiddleware, Identity
from appguard.django import protect_django
from appguard.flask import protect_flask
from flask import Flask
from appguard.uvicorn import IngressConfig
async def endpoint(scope,receive,send): pass
options={"app_id":v["context"]["app_id"],"origin":v["context"]["origin"],"identity_resolver":lambda scope,kid:Identity(v["context"]["subject"],k),"replay":InMemoryReplayStore()}
assert callable(protect_flask(Flask("installed-package-consumer"),**options))
assert isinstance(protect_django(endpoint,**options),AppGuardMiddleware)
config=IngressConfig(endpoint,authority="api.example.test",ssl_certfile="unloaded-test-cert.pem",ssl_keyfile="unloaded-test-key.pem")
assert config.workers==1 and config.proxy_headers is False
locked={p["name"]:p["version"]for p in tomllib.loads(pathlib.Path(sys.argv[2]).read_text())["package"]}
installed={d.metadata["Name"].lower().replace("_","-"):d.version for d in importlib.metadata.distributions()}
assert all(locked[name]==version for name,version in installed.items())
print(json.dumps({"installed_sdk_modules":len(sdk_modules)+1,"optional_framework_imports":len(frameworks),"installed_runtime_dependencies":len(installed)-1,"signature_parser_replay_policy_passed":True,"adapter_wrappers_instantiated":2,"ingress_config_instantiated_without_loading_tls_or_opening_listener":True}))
'''
        script = self.state / 'smoke.py'
        private_write(script, smoke.encode())
        vectors = self.state / 'requests.json'
        private_write(vectors, (ROOT / 'conformance/v0/requests.json').read_bytes())
        code, raw = self.run_tool('consumer-smoke', [python, '-I', script, vectors, source / 'uv.lock'])
        self.assertEqual(code, 0, 'consumer API smoke failed; inspect private log')
        result = json.loads(raw)
        expected = {'installed_sdk_modules', 'optional_framework_imports', 'installed_runtime_dependencies',
            'signature_parser_replay_policy_passed', 'adapter_wrappers_instantiated',
            'ingress_config_instantiated_without_loading_tls_or_opening_listener'}
        self.assertEqual(set(result), expected)
        self.assertTrue(all(type(value) is bool or type(value) is int and 0 <= value <= 4096 for value in result.values()))
        self.__class__.observations.update(result, consumer_import_origins_verified=True)


def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite([loader.loadTestsFromTestCase(PackageContractTests),
        loader.loadTestsFromTestCase(ProcessLifetimeTests)])
    if OPTIONS is not None:
        suite.addTests(loader.loadTestsFromTestCase(IsolatedPackageTests))
    return suite


def main():
    global OPTIONS
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify-packaging', action='store_true')
    parser.add_argument('--uv')
    parser.add_argument('--python')
    parser.add_argument('--build-wheelhouse', type=Path)
    parser.add_argument('--runtime-wheelhouse', type=Path)
    parser.add_argument('--evidence', type=Path)
    args, remaining = parser.parse_known_args()
    if args.verify_packaging:
        if not args.uv or not args.python or not args.evidence:
            parser.error('packaging verification requires uv, python and new evidence directory')
        args.evidence = args.evidence.absolute()
        if args.evidence != args.evidence.resolve() or args.evidence.exists() or not args.evidence.parent.is_dir():
            parser.error('evidence must be a new canonical directory')
        args.evidence.mkdir(mode=0o700)
        OPTIONS = args
    result = unittest.main(argv=[sys.argv[0], *remaining], exit=False).result
    if OPTIONS is not None:
        observed = getattr(IsolatedPackageTests, 'observations', {})
        summary = {'schema': 1, 'evidence_class': 'python_wheel_package_verification', 'release_ready': False,
            'automated_checks_passed': result.wasSuccessful(), 'tests_run': result.testsRun,
            'failures': len(result.failures), 'errors': len(result.errors), 'skipped': len(result.skipped),
            'pyproject_sha256': hashlib.sha256((SDK / 'pyproject.toml').read_bytes()).hexdigest(),
            'uv_lock_sha256': hashlib.sha256((SDK / 'uv.lock').read_bytes()).hexdigest(),
            'reference_pyproject_sha256': hashlib.sha256((REFERENCE / 'pyproject.toml').read_bytes()).hexdigest(),
            'reference_uv_lock_sha256': hashlib.sha256((REFERENCE / 'uv.lock').read_bytes()).hexdigest(),
            'test_script_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'source_unchanged': getattr(IsolatedPackageTests, 'source_pins', None) is not None and all(
                hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest
                for name, digest in IsolatedPackageTests.source_pins.items()),
            'observations': observed, 'scope': 'locked_sdk_reference_editables_isolated_uv_producer_and_all_extras_wheel_consumer',
            'cross_platform_reproducibility_proven': False, 'dependency_security_approved': False,
            'license_approved': False, 'pip_source_build_hash_enforcement': False}
        private_write(OPTIONS.evidence / 'receipt.json', (json.dumps(summary, sort_keys=True, indent=2) + '\n').encode())
        print(json.dumps(summary, sort_keys=True))
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    with cooperative_termination():
        raise SystemExit(main())
