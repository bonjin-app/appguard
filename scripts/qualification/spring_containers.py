#!/usr/bin/env python3
"""Qualify newly owned Docker containers on an explicitly selected local daemon.

No remote daemons, registry pushes, pruning, global changes or operator services.
Private keys/logs/inspect output expire with a private temporary directory. Only
fixed checks, counts, identifiers and hashes enter the retained receipt.
"""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
from decimal import Decimal
import errno
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform as host_platform
import re
import secrets
import selectors
import shutil
import signal
import ssl
import stat
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
DEPLOY = ROOT / 'deploy/spring-ingress'
SCOPE = 'spring-ingress-v1'
ID = re.compile(r'[0-9a-f]{64}\Z')
IMAGE_ID = re.compile(r'sha256:[0-9a-f]{64}\Z')
CHECKS = ('resource_and_isolation_inspection', 'effective_process_restrictions',
          'signed_fidelity', 'replay_rejected', 'backend_bypass_zero_dispatch',
          'absolute_upload_deadline_zero_dispatch', 'malformed_zero_dispatch',
          'redis_outage_denied', 'redis_recovery', 'redis_restart_replay_retained',
          'owned_container_cleanup', 'provenance_unchanged')
STARTUP_PHASES = frozenset(('startup_compose_up', 'startup_runtime_inspection', 'startup_volume_inspection',
    'startup_readiness', 'startup_effective_restrictions'))
CAUSE_SNIPPETS = (
    ('permission_denied', (b'permission denied',)),
    ('read_only_filesystem', (b'read-only file system',)),
    ('disk_full', (b'no space left on device',)),
    ('port_unavailable', (b'port is already allocated', b'address already in use')),
    ('dependency_unhealthy', (b'dependency failed to start', b'is unhealthy')),
    ('file_missing', (b'no such file or directory', b'executable file not found')),
    ('invalid_executable', (b'exec format error', b'invalid executable')),
    ('operation_not_permitted', (b'operation not permitted',)),
    ('cgroup_failure', (b'cgroup',)),
    ('sysctl_failure', (b'sysctl',)),
    ('mount_failure', (b'error mounting', b'failed to mount', b'mount callback failed')),
    ('namespace_failure', (b'failed to create namespace', b'failed to setns', b'failed to unshare')),
    ('security_profile_failure', (b'seccomp', b'apparmor')),
    ('logging_configuration_invalid', (b'compression cannot be enabled when max file count is 1',)),
    ('container_runtime_failure', (b'oci runtime create failed', b'failed to create task')),
    ('memory_allocation_failed', (b'could not reserve enough space', b'cannot allocate memory')),
    ('native_thread_unavailable', (b'unable to create native thread',)),
    ('gateway_start_failed', (b'spring_ingress_host_failed',)),
    ('backend_start_failed', (b'appguard_backend_start_failed',)),
)


def safe_causes(value):
    data = value.encode('utf-8') if type(value) is str else bytes(value)
    data = data.lower()
    return [name for name, snippets in CAUSE_SNIPPETS if any(snippet in data for snippet in snippets)]


class CommandFailure(RuntimeError):
    def __init__(self, category, exit_code, output):
        super().__init__('owned command failed')
        self.category = category
        self.exit_code = exit_code if type(exit_code) is int and -128 <= exit_code <= 255 else None
        self.causes = safe_causes(output)


def failure_summary(error):
    if isinstance(error, CommandFailure):
        return {'category': error.category, 'exit_code': error.exit_code, 'causes': error.causes}
    if isinstance(error, KeyboardInterrupt):
        category = 'cancelled'
    elif isinstance(error, (KeyError, TypeError)):
        category = 'metadata_invalid'
    elif isinstance(error, ValueError):
        category = 'invariant_failed'
    elif isinstance(error, OSError):
        category = 'io_failed'
    else:
        category = 'unclassified'
    return {'category': category, 'exit_code': None, 'causes': []}


def require(condition):
    if not condition:
        raise ValueError('container qualification invariant failed')


@contextmanager
def cancellation_scope():
    def cancel(signum, frame):
        raise KeyboardInterrupt
    previous = signal.signal(signal.SIGTERM, cancel)
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)


def wait_for_group_absence(child):
    """A permission error is benign only after the reaped child's group is gone."""
    if child.poll() is None:
        return False
    deadline = time.monotonic() + .25
    while True:
        try:
            os.killpg(child.pid, 0)
        except ProcessLookupError:
            return True
        except PermissionError as error:
            if error.errno != errno.EPERM:
                raise
            # Darwin can report EPERM for a zombie-only group after TERM.
            # It is not proof of exit: require a subsequent ESRCH instead.
            # Apple xnu/bsd/kern/kern_sig.c, killpg1(), skips SZOMB members:
            # https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_sig.c
            pass
        if time.monotonic() >= deadline:
            return False
        time.sleep(.01)


def bounded_command(command, *, timeout=30, limit=2097152, env=None, cwd=None,
                    observer=None, observer_interval=5):
    """Bound output, elapsed time and retained memory for every CLI command."""
    require(0 < timeout <= (3615 if observer is not None else 1200) and 0 < limit <= 8388608)
    require(observer is None or callable(observer))
    require(type(observer_interval) in (int, float) and 0 < observer_interval <= 5)
    child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, env=env, cwd=cwd, start_new_session=True)
    output = bytearray()
    deadline = time.monotonic() + timeout
    next_observation = time.monotonic() + observer_interval
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            while child.poll() is None or selector.get_map():
                if time.monotonic() >= deadline:
                    raise CommandFailure('timeout', child.poll(), output)
                if observer is not None and time.monotonic() >= next_observation:
                    observer()
                    next_observation = time.monotonic() + observer_interval
                    if time.monotonic() >= deadline:
                        raise CommandFailure('timeout', child.poll(), output)
                for event, _ in selector.select(min(.05, max(0, deadline - time.monotonic()))):
                    part = os.read(event.fd, min(65536, limit - len(output) + 1))
                    if not part:
                        selector.unregister(event.fileobj)
                    else:
                        output.extend(part)
                        if len(output) > limit:
                            raise CommandFailure('output_limit', child.poll(), output)
            if child.returncode != 0:
                raise CommandFailure('nonzero_exit', child.returncode, output)
        return output.decode('utf-8', errors='strict')
    finally:
        # Docker's CLI plugins also belong to this newly created process group.
        # The daemon is never a child and is never signalled.
        try:
            for action in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.killpg(child.pid, action)
                except ProcessLookupError:
                    pass
                except PermissionError as error:
                    if error.errno != errno.EPERM or not wait_for_group_absence(child):
                        raise
                try:
                    child.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass
            child.wait(timeout=2)
        finally:
            child.stdout.close()


def valid_commit(value):
    return type(value) is str and re.fullmatch(r'(?:[0-9a-f]{40}|[0-9a-f]{64})', value) is not None


class ReceiptDirectory:
    """Hold the original output directory through qualification and publication."""
    def __init__(self, path):
        self.path = Path(path)
        require(self.path.is_absolute() and self.path == self.path.resolve(strict=True))
        self.identities = {part: self.identity(part) for part in (self.path, *self.path.parents)}
        self.descriptor = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            self.check()
        except BaseException:
            os.close(self.descriptor)
            raise

    @staticmethod
    def identity(path):
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode))
        return info.st_dev, info.st_ino

    def check(self):
        info = os.fstat(self.descriptor)
        require((info.st_dev, info.st_ino) == self.identities[self.path])
        for path, identity in self.identities.items():
            require(self.identity(path) == identity)

    def publish(self, value):
        payload = value.encode('utf-8')
        require(0 < len(payload) <= 2097152)
        self.check()
        descriptor = os.open('receipt.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=self.descriptor)
        info = os.fstat(descriptor)
        created = info.st_dev, info.st_ino
        try:
            remaining = memoryview(payload)
            while remaining:
                written = os.write(descriptor, remaining)
                require(written > 0)
                remaining = remaining[written:]
            os.fsync(descriptor)
            current = os.stat('receipt.json', dir_fd=self.descriptor, follow_symlinks=False)
            require((current.st_dev, current.st_ino) == created and stat.S_ISREG(current.st_mode)
                    and current.st_size == len(payload) and current.st_mode & 0o777 == 0o600)
            self.check()
        except BaseException:
            try:
                current = os.stat('receipt.json', dir_fd=self.descriptor, follow_symlinks=False)
                if (current.st_dev, current.st_ino) == created:
                    os.unlink('receipt.json', dir_fd=self.descriptor)
            except FileNotFoundError:
                pass
            raise
        finally:
            os.close(descriptor)

    def __enter__(self):
        return self

    def __exit__(self, kind, value, traceback):
        os.close(self.descriptor)


def validate_local_context(record):
    try:
        host = record['Endpoints']['docker']['Host']
        require(type(host) is str and host.startswith('unix:///') and len(host) <= 4096)
        path = Path(host[len('unix://'):])
        require(path.is_absolute() and str(path) == host[len('unix://'):]
                and '..' not in path.parts and '\x00' not in host and '\n' not in host)
    except (KeyError, TypeError):
        raise ValueError('explicit local Unix Docker endpoint required') from None


def validate_builder(text, context):
    """Only the chosen daemon's built-in Docker driver may receive source bytes."""
    drivers = re.findall(r'^Driver:\s*(\S+)\s*$', text, re.MULTILINE)
    endpoints = re.findall(r'^Endpoint:\s*(\S+)\s*$', text, re.MULTILINE)
    require(drivers == ['docker'] and endpoints == [context])


class Docker:
    def __init__(self, executable, context, environment):
        require(re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', context) is not None)
        self.executable, self.context = str(executable), context
        self.environment = {key: value for key, value in os.environ.items()
                            if not key.startswith(('APPGUARD_', 'COMPOSE_'))
                            and key not in {'DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH',
                                'BUILDKIT_HOST', 'BUILDX_BUILDER', 'DOCKER_BUILDKIT'}}
        self.environment.update(environment)
        record = json.loads(self.call(['context', 'inspect', context]))
        require(type(record) is list and len(record) == 1)
        validate_local_context(record[0])
        server = json.loads(self.call(['version', '--format', '{{json .Server}}']))
        require(server['Os'] == 'linux')
        self.version = server['Version']
        validate_builder(self.call(['buildx', 'inspect', context]), context)

    def call(self, args, *, timeout=30, limit=2097152):
        return bounded_command([self.executable, '--context', self.context, *args],
                               timeout=timeout, limit=limit, env=self.environment, cwd=ROOT)


def inspect_owned(record, project, owner, service=None):
    require(type(record) is dict and ID.fullmatch(record.get('Id', '')) is not None)
    labels = record.get('Config', {}).get('Labels') or record.get('Labels') or {}
    require(labels.get('com.docker.compose.project') == project
            and labels.get('io.appguard.owner') == owner
            and labels.get('io.appguard.scope') == SCOPE)
    if service is not None:
        require(labels.get('com.docker.compose.service') == service)
    return record['Id']


def inspect_volume(docker, name, project, owner):
    require(name == project + '_redis-data')
    rows = json.loads(docker.call(['volume', 'inspect', name]))
    require(type(rows) is list and len(rows) == 1)
    record = rows[0]
    labels = record.get('Labels') or {}
    require(record['Name'] == name and record['Driver'] == 'local' and not record.get('Options')
            and labels.get('com.docker.compose.project') == project
            and labels.get('io.appguard.owner') == owner and labels.get('io.appguard.scope') == SCOPE)
    return record


def inspect_container(docker, identifier, project, owner, service=None):
    require(ID.fullmatch(identifier) is not None)
    rows = json.loads(docker.call(['container', 'inspect', identifier]))
    require(type(rows) is list and len(rows) == 1 and rows[0].get('Id') == identifier)
    inspect_owned(rows[0], project, owner, service)
    return rows[0]


def discovered(docker, project, owner):
    rows = docker.call(['ps', '--all', '--quiet', '--no-trunc',
        '--filter', 'label=com.docker.compose.project=' + project,
        '--filter', 'label=io.appguard.owner=' + owner,
        '--filter', 'label=io.appguard.scope=' + SCOPE]).splitlines()
    require(len(rows) <= 8 and len(rows) == len(set(rows)))
    require(all(ID.fullmatch(row) is not None for row in rows))
    return rows


def cleanup_owned(docker, project, owner):
    """Reinspect labels and full IDs before each mutation; never compose-down/prune."""
    settled = True
    try:
        identifiers = discovered(docker, project, owner)
    except (ValueError, RuntimeError, KeyError, TypeError, OSError, subprocess.SubprocessError):
        return False
    # Dependents stop before their network-namespace anchor.
    ordered = []
    for identifier in identifiers:
        try:
            record = inspect_container(docker, identifier, project, owner)
            service = record['Config']['Labels']['com.docker.compose.service']
            require(service in {'gateway', 'backend', 'redis', 'probe'})
            ordered.append((service == 'gateway', identifier))
        except (ValueError, RuntimeError, KeyError, TypeError, OSError, subprocess.SubprocessError):
            settled = False
    for _, identifier in sorted(ordered):
        try:
            inspect_container(docker, identifier, project, owner)
            docker.call(['container', 'stop', '--time', '8', identifier], timeout=15)
            inspect_container(docker, identifier, project, owner)
            docker.call(['container', 'rm', '--volumes', identifier], timeout=15)
        except (ValueError, RuntimeError, KeyError, TypeError, OSError, subprocess.SubprocessError):
            settled = False
    try:
        networks = docker.call(['network', 'ls', '--quiet', '--no-trunc',
            '--filter', 'label=com.docker.compose.project=' + project,
            '--filter', 'label=io.appguard.owner=' + owner]).splitlines()
        require(len(networks) <= 1)
        for identifier in networks:
            require(ID.fullmatch(identifier) is not None)
            rows = json.loads(docker.call(['network', 'inspect', identifier]))
            require(type(rows) is list and len(rows) == 1 and rows[0].get('Id') == identifier)
            inspect_owned(rows[0], project, owner)
            require(not rows[0].get('Containers'))
            docker.call(['network', 'rm', identifier], timeout=15)
    except (ValueError, RuntimeError, KeyError, TypeError, OSError, subprocess.SubprocessError):
        settled = False
    try:
        volumes = docker.call(['volume', 'ls', '--quiet',
            '--filter', 'label=com.docker.compose.project=' + project,
            '--filter', 'label=io.appguard.owner=' + owner]).splitlines()
        require(len(volumes) <= 1)
        for name in volumes:
            inspect_volume(docker, name, project, owner)
            require(not docker.call(['ps', '--all', '--quiet', '--no-trunc', '--filter', 'volume=' + name]).strip())
            inspect_volume(docker, name, project, owner)
            docker.call(['volume', 'rm', name], timeout=15)
    except (ValueError, RuntimeError, KeyError, TypeError, OSError, subprocess.SubprocessError):
        settled = False
    try:
        require(not discovered(docker, project, owner))
        for kind in ('network', 'volume'):
            require(not docker.call([kind, 'ls', '--quiet',
                '--filter', 'label=com.docker.compose.project=' + project,
                '--filter', 'label=io.appguard.owner=' + owner]).strip())
    except (ValueError, RuntimeError, KeyError, TypeError, OSError, subprocess.SubprocessError):
        settled = False
    return settled


def validate_runtime(records, project, owner):
    require(set(records) == {'gateway', 'backend', 'redis'})
    gateway = inspect_owned(records['gateway'], project, owner, 'gateway')
    result = {'container_ids': {}, 'image_ids': {}, 'logging': {}}
    for name, record in records.items():
        identifier = inspect_owned(record, project, owner, name)
        require(record['State']['Running'] is True and IMAGE_ID.fullmatch(record['Image']) is not None)
        host, config = record['HostConfig'], record['Config']
        require(log_policy_bounded(host))
        require(re.fullmatch(r'[1-9][0-9]{0,8}:[1-9][0-9]{0,8}', config['User']) is not None)
        require(host.get('Privileged') is False and host.get('ReadonlyRootfs') is True
                and set(host.get('CapDrop') or []) == {'ALL'} and not host.get('CapAdd')
                and 'no-new-privileges:true' in (host.get('SecurityOpt') or [])
                and host.get('PidMode') != 'host' and host.get('IpcMode') != 'host'
                and not host.get('Devices') and not host.get('DeviceRequests'))
        require(type(host['Memory']) is int and 67108864 <= host['Memory'] <= 1073741824
                and host['MemorySwap'] == host['Memory']
                and type(host['PidsLimit']) is int and 1 <= host['PidsLimit'] <= 256
                and type(host['NanoCpus']) is int and 0 < host['NanoCpus'] <= 2000000000)
        tmpfs = host.get('Tmpfs') or {}
        require('/tmp' in tmpfs and set(tmpfs) <= {'/tmp', '/data'})
        for options in tmpfs.values():
            parts = set(options.split(','))
            sizes = [part[5:] for part in parts if part.startswith('size=')]
            require({'noexec', 'nosuid', 'nodev'} <= parts and len(sizes) == 1
                    and sizes[0].isdigit() and 0 < int(sizes[0]) <= 16777216)
        allowed = {'gateway': {'frontend.pem', 'frontend.key', 'server-ca.pem', 'ingress-client.pem', 'ingress-client.key'},
                   'backend': {'backend.p12', 'trust.p12', 'backend-password', 'enrolled.pem'}, 'redis': set()}[name]
        mounted = set()
        for mount in record.get('Mounts', []):
            if mount['Type'] == 'tmpfs':
                require(mount['Destination'] in tmpfs)
            elif mount['Destination'] == '/run/appguard/counters.json' and name == 'backend':
                require(mount['Type'] == 'bind' and mount['RW'] is True)
            elif mount['Type'] == 'volume' and name == 'redis':
                require(mount['Destination'] == '/data' and mount['Name'] == project + '_redis-data'
                        and mount['Driver'] == 'local' and mount['RW'] is True)
                mounted.add('/data')
            else:
                require(mount['Type'] == 'bind' and mount['RW'] is False
                        and mount['Destination'].startswith('/run/secrets/')
                        and mount['Destination'][len('/run/secrets/'):] in allowed)
                mounted.add(mount['Destination'][len('/run/secrets/'):])
        require(mounted == ({'/data'} if name == 'redis' else allowed))
        bindings = host.get('PortBindings') or {}
        published = record['NetworkSettings'].get('Ports') or {}
        if name == 'gateway':
            require(not host['NetworkMode'].startswith(('container:', 'host', 'none')))
            require(set(bindings) == {'8443/tcp'} and len(bindings['8443/tcp']) == 1)
            configured = bindings['8443/tcp'][0]
            require(set(published) == {'8443/tcp'} and len(published['8443/tcp']) == 1)
            port = published['8443/tcp'][0]
            require(configured['HostIp'] == '127.0.0.1' and port['HostIp'] == '127.0.0.1'
                    and port['HostPort'].isdigit() and 1 <= int(port['HostPort']) <= 65535
                    and configured['HostPort'] in {'', '0', port['HostPort']})
            result['gateway_port'] = int(port['HostPort'])
        else:
            require(host['NetworkMode'] == 'container:' + gateway and not bindings
                    and not any(published.values()))
        result['container_ids'][name], result['image_ids'][name] = identifier, record['Image']
        result['logging'][name] = {'driver':'local','max_size_bytes':1048576,'max_files':1,'compress':False}
    return result


def log_policy_bounded(host):
    config = host.get('LogConfig') or {}
    options = config.get('Config') or {}
    return (config.get('Type') == 'local' and options.get('max-size') == '1m'
            and options.get('max-file') == '1' and options.get('compress') == 'false')


def source_hashes():
    paths = [ROOT / value for value in ('scripts/qualification/spring_containers.py',
        'scripts/qualification/spring_ingress.py', 'sdk/python/pyproject.toml', 'sdk/python/uv.lock',
        'sdk/python/README.md', 'sdk/python/LICENSE', 'LICENSE', 'sdk/spring-boot/pom.xml', 'examples/spring-ingress/backend/pom.xml')]
    for directory in ('deploy/spring-ingress', 'sdk/python/src', 'sdk/spring-boot/src/main', 'examples/spring-ingress'):
        base = ROOT / directory
        require(base.is_dir() and not base.is_symlink())
        for path in base.rglob('*'):
            if any(part in {'__pycache__', 'target', '.venv'} for part in path.relative_to(base).parts):
                continue
            require(not path.is_symlink())
            if path.is_file():
                paths.append(path)
    require(len(paths) <= 2048)
    result = {}
    for path in paths:
        require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 16777216)
        result[str(path.relative_to(ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def helpers():
    spec = importlib.util.spec_from_file_location('appguard_spring_local', ROOT / 'scripts/qualification/spring_ingress.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_private(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'wb') as handle:
        handle.write(value if isinstance(value, bytes) else value.encode())


def generate_certificates(private, java_home):
    # Run the existing helper in a bounded child group so a stuck keytool also
    # expires. Its only captured output is the random PKCS12 password.
    program = ('import importlib.util,sys; from pathlib import Path; '
        's=importlib.util.spec_from_file_location("appguard_certs",sys.argv[1]); '
        'm=importlib.util.module_from_spec(s); s.loader.exec_module(m); '
        'print(m.certificates(Path(sys.argv[2]),Path(sys.argv[3])))')
    value = bounded_command([sys.executable, '-c', program, str(ROOT / 'scripts/qualification/spring_ingress.py'),
        str(private), str(java_home)], timeout=30, limit=4096).strip()
    require(re.fullmatch(r'[A-Za-z0-9_-]{32,128}', value) is not None)
    return value


def compose_args(project, override):
    return ['compose', '--env-file', os.devnull, '--project-name', project,
            '--file', str(DEPLOY / 'compose.json'), '--file', str(override)]


def records_for(docker, project, owner):
    records = {}
    for identifier in discovered(docker, project, owner):
        record = inspect_container(docker, identifier, project, owner)
        name = record['Config']['Labels']['com.docker.compose.service']
        require(name in {'gateway', 'backend', 'redis', 'probe'} and name not in records)
        records[name] = record
    return records


def wait_ready(docker, gateway, backend, project, owner, timeout=90):
    require(0 < timeout <= 90)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        inspect_container(docker, gateway, project, owner, 'gateway')
        current = inspect_container(docker, backend, project, owner, 'backend')
        require(current['State']['Running'] is True)
        try:
            docker.call(['exec', gateway, '/opt/appguard/.venv/bin/python', '/opt/appguard/probe.py', 'ready'], timeout=5)
            return
        except RuntimeError:
            time.sleep(.25)
    raise ValueError('owned backend readiness bound exceeded')


def effective_restrictions(docker, records, project, owner):
    namespaces = set()
    for name, record in records.items():
        identifier = inspect_container(docker, record['Id'], project, owner, name)['Id']
        status = docker.call(['exec', identifier, 'cat', '/proc/1/status'], limit=32768)
        fields = dict(line.split(':', 1) for line in status.splitlines() if ':' in line)
        expected_uid = int(record['Config']['User'].split(':')[0])
        require([int(value) for value in fields['Uid'].split()] == [expected_uid] * 4
                and int(fields['CapEff'].strip(), 16) == 0 and fields['NoNewPrivs'].strip() == '1')
        namespace = docker.call(['exec', identifier, 'readlink', '/proc/self/ns/net'], limit=1024).strip()
        require(re.fullmatch(r'net:\[[0-9]+\]', namespace) is not None)
        namespaces.add(namespace)
    require(len(namespaces) == 1)
    return runtime_version_readback(docker,records,project,owner)


GLOBAL_PYTHON_READBACK = (
    'import importlib.util,json,sys; '
    'print(json.dumps({"version":".".join(map(str,sys.version_info[:3])), '
    '"installers_absent":{name:importlib.util.find_spec(name) is None '
    'for name in ("pip","setuptools","wheel","ensurepip")}}))')
VENV_INVENTORY_READBACK = (
    'import importlib.metadata as m,json,sys; from pathlib import Path; '
    'pairs=[(d.metadata["Name"].lower().replace("_","-"),d.version) for d in m.distributions()]; '
    'actual=dict(pairs); '
    'print(json.dumps({"matches_build_inventory":len(actual)==len(pairs) and '
    'actual==json.loads(Path(sys.argv[1]).read_text()), '
    '"required":{name:m.version(name) for name in ("cryptography","h11","uvicorn","redis")}}))')


def runtime_version_readback(docker, records, project, owner):
    """Read actual binaries and retained package metadata; never emit CLI text."""
    required = {'cryptography':'50.0.2','h11':'0.16.0','uvicorn':'0.54.0','redis':'8.1.0'}
    gateway = inspect_container(docker,records['gateway']['Id'],project,owner,'gateway')['Id']
    global_python = json.loads(docker.call(['exec',gateway,'/usr/local/bin/python','-I','-c',GLOBAL_PYTHON_READBACK],
        timeout=5,limit=4096))
    require(type(global_python) is dict and set(global_python)=={'version','installers_absent'}
        and global_python['version']=='3.11.17'
        and type(global_python['installers_absent']) is dict
        and set(global_python['installers_absent'])=={'pip','setuptools','wheel','ensurepip'}
        and all(value is True for value in global_python['installers_absent'].values()))
    inspect_container(docker,gateway,project,owner,'gateway')
    inventory = json.loads(docker.call(['exec',gateway,'/opt/appguard/.venv/bin/python','-I','-c',VENV_INVENTORY_READBACK,
        '/opt/appguard/runtime-inventory.json'],timeout=5,limit=4096))
    require(type(inventory) is dict and set(inventory)=={'matches_build_inventory','required'}
        and inventory['matches_build_inventory'] is True and inventory['required']==required)
    backend = inspect_container(docker,records['backend']['Id'],project,owner,'backend')['Id']
    java = docker.call(['exec',backend,'java','-version'],timeout=5,limit=4096)
    match = re.search(r'(?m)^(?:openjdk|java) version "([0-9.]+)"',java)
    require(match is not None and match.group(1)=='17.0.20.1')
    redis = inspect_container(docker,records['redis']['Id'],project,owner,'redis')['Id']
    redis_version = docker.call(['exec',redis,'redis-server','--version'],timeout=5,limit=4096)
    match = re.match(r'Redis server v=([0-9]+\.[0-9]+\.[0-9]+)(?:\s|$)',redis_version)
    require(match is not None and match.group(1)=='7.2.16')
    return {'python':'3.11.17','installers_absent':{name:True for name in ('pip','setuptools','wheel','ensurepip')},
        'python_inventory_matches_build':True,'python_required_packages':required,'java':'17.0.20.1','redis':'7.2.16'}


def platform_environment(docker, target):
    require(target in ('linux/amd64','linux/arm64') and host_platform.system() == 'Linux')
    arch = target.split('/')[1]; machine = 'x86_64' if arch == 'amd64' else 'aarch64'
    require(host_platform.machine() == machine)
    daemon = json.loads(docker.call(['info','--format','{{json .}}'],timeout=5,limit=4096))
    actual = {'x86_64':'amd64','amd64':'amd64','aarch64':'arm64','arm64':'arm64'}.get(daemon.get('Architecture'))
    require(daemon.get('OSType') == 'linux' and actual == arch)
    return dict(schema=1,platform=target,host_machine=machine,daemon_architecture=actual,images={},verified=False)


def observe_runtime_platform(docker, records, project, owner, target):
    value = platform_environment(docker,target)
    require(set(records) == {'gateway','backend','redis'})
    arch = target.split('/')[1]; expected_machine = 62 if arch == 'amd64' else 183
    for role, original in records.items():
        current = inspect_container(docker,original['Id'],project,owner,role)
        require(current['Image'] == original['Image'])
        rows = json.loads(docker.call(['image','inspect',current['Image']],timeout=5,limit=8192))
        require(type(rows) is list and len(rows) == 1 and type(rows[0]) is dict)
        image = rows[0]
        require(image.get('Id') == current['Image'] and image.get('Os') == 'linux' and image.get('Architecture') == arch)
        raw = docker.call(['exec',current['Id'],'od','-An','-N20','-tx1','/proc/1/exe'],timeout=5,limit=256)
        header = ''.join(raw.split())
        require(re.fullmatch('[0-9a-fA-F]{40}',header) is not None)
        header = bytes.fromhex(header)
        require(header[:6] == b'\x7fELF\x02\x01' and int.from_bytes(header[16:18],'little') in (2,3)
            and int.from_bytes(header[18:20],'little') == expected_machine)
        inspect_container(docker,current['Id'],project,owner,role)
        value['images'][role] = dict(image_id=current['Image'],os='linux',architecture=arch,pid1_elf_machine=expected_machine)
    value['verified'] = True
    return value


def run_startup(docker, compose, receipt, project, owner):
    """Keep the existing startup sequence, with a phase at every boundary."""
    receipt['phase'] = 'startup_compose_up'
    docker.call([*compose, 'up', '--detach', '--no-build', 'gateway', 'redis', 'backend'], timeout=90)
    receipt['phase'] = 'startup_runtime_inspection'
    records = records_for(docker, project, owner)
    inspected = validate_runtime(records, project, owner)
    receipt['phase'] = 'startup_volume_inspection'
    inspect_volume(docker, project + '_redis-data', project, owner)
    receipt['checks']['resource_and_isolation_inspection'] = True
    receipt['containers'] = inspected
    receipt['docker_server_version'] = docker.version
    receipt['phase'] = 'startup_readiness'
    wait_ready(docker, records['gateway']['Id'], records['backend']['Id'], project, owner)
    receipt['phase'] = 'startup_effective_restrictions'
    receipt['runtime_versions'] = effective_restrictions(docker, records, project, owner)
    receipt['checks']['effective_process_restrictions'] = True
    return records, inspected


def diagnostic_number(value, minimum=-1, maximum=9223372036854775807):
    return value if type(value) is int and minimum <= value <= maximum else None


def diagnostic_constraints(record, name, project, gateway):
    """Independent observations, not a replacement for runtime validation."""
    config = record.get('Config') or {}
    host = record.get('HostConfig') or {}
    published = (record.get('NetworkSettings') or {}).get('Ports') or {}
    bindings = host.get('PortBindings') or {}
    memory, swap, pids, cpus = (diagnostic_number(host.get(key)) for key in ('Memory','MemorySwap','PidsLimit','NanoCpus'))
    user = config.get('User')
    constraints = {
        'image_id_valid': type(record.get('Image')) is str and IMAGE_ID.fullmatch(record['Image']) is not None,
        'nonroot_user': type(user) is str and re.fullmatch(r'[1-9][0-9]{0,8}:[1-9][0-9]{0,8}',user) is not None,
        'root_readonly': host.get('ReadonlyRootfs') is True,
        'not_privileged': host.get('Privileged') is False,
        'all_capabilities_dropped': host.get('CapDrop') == ['ALL'],
        'no_added_capabilities': not host.get('CapAdd'),
        'no_new_privileges': 'no-new-privileges:true' in (host.get('SecurityOpt') or []),
        'private_pid_ipc': host.get('PidMode') != 'host' and host.get('IpcMode') != 'host',
        'no_device_passthrough': not host.get('Devices') and not host.get('DeviceRequests'),
        'memory_bounded': memory is not None and 67108864 <= memory <= 1073741824,
        'swap_bounded': memory is not None and swap == memory,
        'pids_bounded': pids is not None and 1 <= pids <= 256,
        'cpu_bounded': cpus is not None and 0 < cpus <= 2000000000,
        'logging_bounded': log_policy_bounded(host),
        'tmpfs_bounded': False, 'expected_mounts': False,
        'network_namespace_expected': False, 'publication_expected': False,
    }
    try:
        tmpfs = host.get('Tmpfs') or {}
        tmpfs_ok = '/tmp' in tmpfs and set(tmpfs) <= {'/tmp','/data'}
        for options in tmpfs.values():
            parts = set(options.split(','))
            sizes = [part[5:] for part in parts if part.startswith('size=')]
            tmpfs_ok = tmpfs_ok and {'noexec','nosuid','nodev'} <= parts and len(sizes) == 1
            tmpfs_ok = tmpfs_ok and sizes[0].isdigit() and 0 < int(sizes[0]) <= 16777216
        constraints['tmpfs_bounded'] = bool(tmpfs_ok)
        allowed = {'gateway': {'frontend.pem','frontend.key','server-ca.pem','ingress-client.pem','ingress-client.key'},
            'backend': {'backend.p12','trust.p12','backend-password','enrolled.pem'}, 'redis': {'/data'}}[name]
        observed, mounts_ok = set(), True
        for mount in record.get('Mounts') or []:
            target = mount.get('Destination','')
            if mount.get('Type') == 'tmpfs':
                mounts_ok = mounts_ok and target in tmpfs
            elif name == 'backend' and target == '/run/appguard/counters.json':
                mounts_ok = mounts_ok and mount.get('Type') == 'bind' and mount.get('RW') is True
            elif name == 'redis' and mount.get('Type') == 'volume':
                mounts_ok = mounts_ok and target == '/data' and mount.get('Name') == project + '_redis-data'
                mounts_ok = mounts_ok and mount.get('Driver') == 'local' and mount.get('RW') is True
                observed.add('/data')
            else:
                mounts_ok = mounts_ok and mount.get('Type') == 'bind' and mount.get('RW') is False
                mounts_ok = mounts_ok and target.startswith('/run/secrets/') and target[len('/run/secrets/'):] in allowed
                observed.add(target[len('/run/secrets/'):])
        constraints['expected_mounts'] = bool(mounts_ok and observed == allowed)
        mode = host.get('NetworkMode','')
        if name == 'gateway':
            constraints['network_namespace_expected'] = type(mode) is str and not mode.startswith(('container:','host','none'))
            if set(bindings) == {'8443/tcp'} and set(published) == {'8443/tcp'} and len(bindings['8443/tcp']) == len(published['8443/tcp']) == 1:
                configured, actual = bindings['8443/tcp'][0], published['8443/tcp'][0]
                port = actual.get('HostPort','')
                constraints['publication_expected'] = (configured.get('HostIp') == actual.get('HostIp') == '127.0.0.1'
                    and port.isdigit() and 1 <= int(port) <= 65535 and configured.get('HostPort') in {'','0',port})
        else:
            constraints['network_namespace_expected'] = gateway is not None and mode == 'container:' + gateway
            constraints['publication_expected'] = not bindings and not any(published.values())
    except (AttributeError, TypeError, KeyError, ValueError, IndexError):
        pass
    return constraints, {'memory_bytes':memory,'swap_bytes':swap,'pids':pids,'nano_cpus':cpus}


def empty_startup_diagnostics(error):
    constraint_names = ('image_id_valid','nonroot_user','root_readonly','not_privileged','all_capabilities_dropped',
        'no_added_capabilities','no_new_privileges','private_pid_ipc','no_device_passthrough','memory_bounded',
        'swap_bounded','pids_bounded','cpu_bounded','logging_bounded','tmpfs_bounded','expected_mounts',
        'network_namespace_expected','publication_expected')
    return {'schema':1,'complete':False,'budget_exhausted':False,'discovered_containers':0,
        'ownership_rejections':0,'metadata_errors':0,'failure':failure_summary(error),
        'services':{name:{'present':False,'running':None,'exit_code':None,'oom_killed':None,
            'state_error_present':None,'state_error_causes':[],'health':None,'health_failures':None,'restart_count':None,
            'constraints':{key:None for key in constraint_names},
            'limits':{key:None for key in ('memory_bytes','swap_bytes','pids','nano_cpus')},'log_causes':[]}
            for name in ('gateway','backend','redis')},'volume_owned_valid':None}


def startup_diagnostics(docker, project, owner, error):
    """Twelve-second read budget plus bounded CLI cleanup; fixed schema only."""
    result = empty_startup_diagnostics(error)
    deadline = time.monotonic() + 12
    def read(args, limit=262144):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            result['budget_exhausted'] = True
            raise RuntimeError('diagnostic bound exhausted')
        return docker.call(args, timeout=min(2,remaining), limit=limit)
    records = {}
    try:
        identifiers = read(['ps','--all','--quiet','--no-trunc','--filter','label=com.docker.compose.project='+project,
            '--filter','label=io.appguard.owner='+owner,'--filter','label=io.appguard.scope='+SCOPE],8192).splitlines()
        require(len(identifiers) <= 8 and len(identifiers) == len(set(identifiers))
                and all(ID.fullmatch(value) is not None for value in identifiers))
        result['discovered_containers'] = len(identifiers)
        for identifier in identifiers:
            try:
                rows = json.loads(read(['container','inspect',identifier]))
                require(type(rows) is list and len(rows) == 1 and rows[0].get('Id') == identifier)
                record = rows[0]
                try:
                    inspect_owned(record,project,owner)
                except (ValueError,KeyError,TypeError):
                    result['ownership_rejections'] += 1
                    continue
                name = record['Config']['Labels'].get('com.docker.compose.service')
                require(name in result['services'] and name not in records)
                records[name] = record
            except (OSError,RuntimeError,ValueError,KeyError,TypeError):
                result['metadata_errors'] += 1
    except (OSError,RuntimeError,ValueError,KeyError,TypeError):
        result['metadata_errors'] += 1
    gateway = records.get('gateway',{}).get('Id')
    for name,record in records.items():
        try:
            state = record.get('State') or {}
            health = state.get('Health') or {}
            health_status = health.get('Status','none')
            constraints,limits = diagnostic_constraints(record,name,project,gateway)
            summary = {'present':True,'running':state.get('Running') if type(state.get('Running')) is bool else None,
                'exit_code':diagnostic_number(state.get('ExitCode'),0,255),
                'oom_killed':state.get('OOMKilled') if type(state.get('OOMKilled')) is bool else None,
                'state_error_present':bool(state.get('Error')),
                'state_error_causes':safe_causes(state['Error']) if type(state.get('Error')) is str else [],
                'health':health_status if health_status in {'none','starting','healthy','unhealthy'} else 'unknown',
                'health_failures':diagnostic_number(health.get('FailingStreak'),0,1000000),
                'restart_count':diagnostic_number(record.get('RestartCount'),0,1000000),
                'constraints':constraints,'limits':limits,'log_causes':[]}
            result['services'][name] = summary
            try:
                summary['log_causes'] = safe_causes(read(['logs','--tail','80',record['Id']],65536))
            except (OSError,RuntimeError,ValueError):
                result['metadata_errors'] += 1
        except (OSError,RuntimeError,ValueError,KeyError,TypeError,AttributeError):
            result['metadata_errors'] += 1
    try:
        name = project + '_redis-data'
        rows = json.loads(read(['volume','inspect',name],32768))
        require(type(rows) is list and len(rows) == 1)
        record = rows[0]
        require(type(record) is dict)
        labels = record.get('Labels') or {}
        result['volume_owned_valid'] = (record.get('Name') == name and record.get('Driver') == 'local'
            and not record.get('Options') and labels.get('com.docker.compose.project') == project
            and labels.get('io.appguard.owner') == owner and labels.get('io.appguard.scope') == SCOPE)
    except (OSError,RuntimeError,ValueError,KeyError,TypeError,AttributeError):
        result['metadata_errors'] += 1
    result['complete'] = not (result['budget_exhausted'] or result['metadata_errors'] or result['ownership_rejections'])
    return result


def redis_values(docker, identifier, section):
    text = docker.call(['exec', identifier, 'redis-cli', '-h', '127.0.0.1', '-p', '6379', '--raw', 'INFO', section], limit=32768)
    values = {}
    for line in text.splitlines():
        if line and not line.startswith('#'):
            key, value = line.split(':', 1)
            require(key not in values)
            values[key] = value
    return values


def redis_configuration(docker, identifier):
    value = json.loads(docker.call(['exec', identifier, 'redis-cli', '-h', '127.0.0.1', '-p', '6379', '--json',
        'CONFIG', 'GET', 'appendonly', 'appendfsync', 'maxmemory', 'maxmemory-policy', 'bind', 'port', 'dir', 'save'], limit=32768))
    if type(value) is list:
        require(len(value) == 16 and all(type(entry) is str for entry in value))
        value = dict(zip(value[::2], value[1::2]))
    require(value == {'appendonly': 'yes', 'appendfsync': 'always', 'maxmemory': '67108864',
        'maxmemory-policy': 'noeviction', 'bind': '127.0.0.1', 'port': '6379', 'dir': '/data', 'save': ''})


def restart_redis(docker, identifier, project, owner, port, tls, signer, original, local, counter_file=None):
    """Own stop/start only. Exercise synchronous AOF retention, not power-loss durability."""
    inspect_container(docker, identifier, project, owner, 'redis')
    inspect_volume(docker, project + '_redis-data', project, owner)
    redis_configuration(docker, identifier)
    before = redis_values(docker, identifier, 'server')['run_id']
    require(re.fullmatch(r'[0-9a-f]{40}', before) is not None and counter_file is not None)
    baseline = local.counters(counter_file)
    inspect_container(docker, identifier, project, owner, 'redis')
    docker.call(['container', 'stop', '--time', '8', identifier], timeout=15)
    inspect_container(docker, identifier, project, owner, 'redis')
    target, body = '/v1/items', b'redis-unavailable'
    request = local.wire(target, signer.headers(target, body), body)
    started = time.monotonic()
    status, response = local.exchange(port, tls, request)
    denied = time.monotonic() - started
    require(status == 503 and json.loads(response) == {'code': 'REPLAY_STORE_UNAVAILABLE'} and denied < 3.5)
    require(local.counters(counter_file)['resource'] == baseline['resource'])
    inspect_container(docker, identifier, project, owner, 'redis')
    docker.call(['container', 'start', identifier], timeout=15)
    started = time.monotonic()
    recovered, attempts = False, 0
    while time.monotonic() - started < 15:
        current = inspect_container(docker, identifier, project, owner, 'redis')
        require(current['State']['Running'] is True)
        attempts += 1
        # A new signature/nonce for every trial; never replay an ambiguous write.
        body = secrets.token_bytes(32)
        request = local.wire(target, signer.headers(target, body), body)
        status, response = local.exchange(port, tls, request)
        if (status, response) == (200, body):
            recovered = True
            break
        require(status == 503 and json.loads(response) == {'code': 'REPLAY_STORE_UNAVAILABLE'})
        time.sleep(.25)
    require(recovered)
    recovered_seconds = time.monotonic() - started
    require(recovered_seconds <= 15)
    after = redis_values(docker, identifier, 'server')['run_id']
    require(re.fullmatch(r'[0-9a-f]{40}', after) is not None and after != before)
    redis_configuration(docker, identifier)
    persistence = redis_values(docker, identifier, 'persistence')
    require(persistence['aof_enabled'] == '1' and persistence['aof_last_write_status'] == 'ok'
            and int(persistence['aof_current_size']) > 0 and persistence['loading'] == '0')
    baseline = local.counters(counter_file)
    rejected = local.exchange(port, tls, original)
    require(rejected[0] == 403 and json.loads(rejected[1]) == {'code': 'REPLAY_DETECTED'})
    require(local.counters(counter_file)['resource'] == baseline['resource'])
    return {'outage_status': 503, 'outage_seconds': denied, 'recovery_seconds': recovered_seconds,
        'recovery_attempts': attempts, 'run_identity_changed': True,
        'aof_enabled': True, 'appendfsync': 'always', 'original_replay_status': 403,
        'scope': 'routine owned Redis container stop/start; no power-loss or disk-failure claim'}


def qualification_override(private, uid, gid, project, owner, target_platform=None):
    def mount(name, target, readonly=True):
        return {'type': 'bind', 'source': str(private / name), 'target': target,
                'read_only': readonly, 'bind': {'create_host_path': False}}
    # A separate client shares only the network namespace. It receives no trusted
    # client key or backend server key; its wrong client belongs to a different CA.
    probe = {'image': 'appguard-spring-gateway:' + owner, 'profiles': ['qualification'],
        'network_mode': 'service:gateway', 'user': f'{uid}:{gid}', 'read_only': True,
        'cap_drop': ['ALL'], 'security_opt': ['no-new-privileges:true'], 'ipc': 'private',
        'mem_limit': '128m', 'memswap_limit': '128m', 'pids_limit': 32, 'cpus': .5,
        'tmpfs': ['/tmp:rw,noexec,nosuid,nodev,size=16777216,mode=1777'],
        'labels': {'io.appguard.scope': SCOPE, 'io.appguard.owner': owner},
        'entrypoint': ['/opt/appguard/.venv/bin/python', '/opt/appguard/probe.py', 'bypass'],
        'environment': {'APPGUARD_BACKEND_HOSTNAME': 'backend.example.test'},
        'volumes': [mount('server-ca.pem', '/run/secrets/server-ca.pem'),
            mount('wrong-client.pem', '/run/secrets/wrong-client.pem'),
            mount('wrong-client.key', '/run/secrets/wrong-client.key'), mount('request.bin', '/run/probe/request.bin')],
        'logging': {'driver': 'local', 'options': {'max-size': '1m', 'max-file': '1', 'compress':'false'}}}
    result = {'services': {'backend': {'environment': {'APPGUARD_BACKEND_COUNTER_FILE': '/run/appguard/counters.json'},
        'volumes': [mount('counters.json', '/run/appguard/counters.json', False)]}, 'probe': probe}}
    if target_platform is not None:
        require(target_platform in ('linux/amd64','linux/arm64'))
        for role in ('gateway','backend','redis'):
            result['services'].setdefault(role,{})['platform'] = target_platform
            result['services'][role]['build'] = {'platforms':[target_platform]}
        probe['platform'] = target_platform
    return result


def validate_soak_options(seconds, concurrency):
    require(type(seconds) is int and 0 <= seconds <= 3600
            and type(concurrency) is int and 1 <= concurrency <= 32)


def integer(value):
    require(type(value) is str and re.fullmatch(r'[0-9]{1,20}', value) is not None)
    result = int(value)
    require(result <= 2 ** 63 - 1)
    return result


def byte_quantity(value):
    match = re.fullmatch(r'([0-9]{1,12}(?:\.[0-9]{1,6})?)\s*(B|kB|MB|GB|TB|KiB|MiB|GiB|TiB)', value)
    require(match is not None)
    units = {'B': 1, 'kB': 1000, 'MB': 1000 ** 2, 'GB': 1000 ** 3, 'TB': 1000 ** 4,
             'KiB': 1024, 'MiB': 1024 ** 2, 'GiB': 1024 ** 3, 'TiB': 1024 ** 4}
    result = int(Decimal(match[1]) * units[match[2]])
    require(result <= 2 ** 63 - 1)
    return result


def normalize_stats(text, identifiers, diagnostic=None):
    """CLI memory excludes inactive file cache on Linux; quantities are rounded."""
    def mark(code, field=None):
        if diagnostic is not None: diagnostic.update(code=code, field=field)
    mark('stats_schema')
    require(type(text) is str and len(text) <= 32768 and set(identifiers) == {'gateway', 'backend', 'redis'})
    roles = {identifier: role for role, identifier in identifiers.items()}
    require(len(roles) == 3 and all(ID.fullmatch(value) is not None for value in roles))
    result = {}
    for line in text.splitlines():
        mark('stats_json')
        row = json.loads(line)
        mark('stats_identity', 'ID')
        if diagnostic is not None: diagnostic['role'] = None
        require(type(row) is dict and row.get('ID') in roles and roles[row['ID']] not in result)
        if diagnostic is not None: diagnostic['role'] = roles[row['ID']]
        mark('stats_cpu', 'CPUPerc')
        cpu = row.get('CPUPerc')
        require(type(cpu) is str and re.fullmatch(r'[0-9]{1,6}(?:\.[0-9]{1,6})?%', cpu) is not None)
        cpu = float(cpu[:-1]); require(cpu <= 100000)
        mark('stats_memory', 'MemUsage')
        memory = row['MemUsage'].split(' / '); require(len(memory) == 2)
        used, limit = map(byte_quantity, memory)
        require(0 < limit and used <= limit)
        mark('stats_pids', 'PIDs')
        result[roles[row['ID']]] = {'cpu_percent': cpu, 'memory_bytes': used,
            'memory_limit_bytes': limit, 'pids': integer(row['PIDs'])}
    mark('stats_roles')
    require(set(result) == set(identifiers))
    mark(None)
    return result


CGROUP_FILES = ('memory.current', 'memory.max', 'memory.swap.max', 'memory.swap.current',
                'memory.events', 'cpu.stat', 'cpu.max', 'pids.current', 'pids.max')
CGROUP_READBACK = ('test -f /sys/fs/cgroup/cgroup.controllers || exit 1; '
    'for name in ' + ' '.join(CGROUP_FILES) + '; do '
    'printf "[%s]\\n" "$name"; cat "/sys/fs/cgroup/$name" || exit 1; done')


def normalize_cgroup(text, host, diagnostic=None):
    def mark(code, field=None):
        if diagnostic is not None: diagnostic.update(code=code, field=field)
    mark('cgroup_schema')
    require(type(text) is str and len(text) <= 8192)
    sections = {}; current = None
    for line in text.splitlines():
        if line.startswith('[') and line.endswith(']'):
            mark('cgroup_sections')
            current = line[1:-1]
            require(current in CGROUP_FILES and current not in sections)
            sections[current] = []
        else:
            require(current is not None and line != '')
            sections[current].append(line)
    require(set(sections) == set(CGROUP_FILES))
    def single(name):
        mark('cgroup_scalar', name)
        require(len(sections[name]) == 1)
        return integer(sections[name][0])
    def fields(name, required):
        result = {}
        for line in sections[name]:
            parts = line.split()
            mark('cgroup_metric_key', name)
            # cpu.stat may contain core_sched.force_idle_usec. Kernel fields
            # are extensible; unknown numeric fields are validated then dropped.
            require(len(parts) == 2 and len(parts[0]) <= 64
                and re.fullmatch(r'[a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)*', parts[0]) is not None
                and parts[0] not in result)
            mark('cgroup_metric_value', parts[0] if parts[0] in required else 'additional_metric')
            result[parts[0]] = integer(parts[1])
        mark('cgroup_required_fields', name)
        require(required <= result.keys())
        return result
    mark('cgroup_cpu_quota', 'cpu.max')
    require(len(sections['cpu.max']) == 1)
    quota = sections['cpu.max'][0].split(); require(len(quota) == 2)
    quota, period = map(integer, quota)
    limit, pids = single('memory.max'), single('pids.max')
    if diagnostic is not None:
        diagnostic['numbers'] = {'memory_limit_bytes': limit, 'expected_memory_limit_bytes': host['Memory'],
            'pids_limit': pids, 'expected_pids_limit': host['PidsLimit'], 'cpu_quota_usec': quota,
            'cpu_period_usec': period, 'expected_nano_cpus': host['NanoCpus']}
        diagnostic['checks'] = {'memory_limit_matches': limit == host['Memory'],
            'pids_limit_matches': pids == host['PidsLimit'],
            'cpu_limit_matches': period > 0 and quota * 1000000000 == host['NanoCpus'] * period}
    mark('cgroup_limits')
    require(limit == host['Memory'] and pids == host['PidsLimit'] and period > 0
            and quota * 1000000000 == host['NanoCpus'] * period)
    events = fields('memory.events', {'oom', 'oom_kill', 'max'})
    cpu = fields('cpu.stat', {'usage_usec', 'throttled_usec', 'nr_throttled', 'nr_periods'})
    if diagnostic is not None:
        diagnostic['checks']['core_scheduling_metric_present'] = 'core_sched.force_idle_usec' in cpu
    result = {'version': 2, 'memory_bytes': single('memory.current'), 'memory_limit_bytes': limit,
        'swap_limit_bytes': single('memory.swap.max'), 'swap_bytes': single('memory.swap.current'),
        'memory_oom_events': events['oom'], 'memory_oom_kills': events['oom_kill'],
        'memory_max_events': events['max'], 'cpu_usage_usec': cpu['usage_usec'],
        'cpu_throttled_usec': cpu['throttled_usec'], 'cpu_throttled_periods': cpu['nr_throttled'],
        'cpu_periods': cpu['nr_periods'], 'cpu_quota_usec': quota, 'cpu_period_usec': period,
        'pids': single('pids.current'), 'pids_limit': pids}
    if diagnostic is not None:
        diagnostic['numbers'].update({key: result[key] for key in ('memory_bytes', 'pids', 'swap_limit_bytes', 'swap_bytes')})
        diagnostic['checks'].update(memory_usage_bounded=result['memory_bytes'] <= limit,
            pids_usage_bounded=result['pids'] <= pids, swap_disabled=result['swap_limit_bytes'] == result['swap_bytes'] == 0)
    mark('cgroup_usage_and_swap')
    require(result['memory_bytes'] <= limit and result['pids'] <= pids
            and result['swap_limit_bytes'] == result['swap_bytes'] == 0)
    mark(None)
    return result


def canonical_mounts(mounts):
    """Only the outer inspect array is unordered; retain all fields and duplicates.

    Docker 28.0.4 container/container_unix.go GetMountPoints ranges over a map.
    Nested lists retain their order, as do Config and HostConfig lists elsewhere.
    """
    require(type(mounts) is list and len(mounts) <= 64 and all(type(row) is dict for row in mounts))
    return sorted(json.dumps(row, sort_keys=True, separators=(',', ':'), allow_nan=False) for row in mounts)


def mount_observations(before, after):
    same = canonical_mounts(before) == canonical_mounts(after)
    result = {'mounts_unchanged': same, 'mount_order_only_changed': same and before != after,
        'mount_count_unchanged': len(before) == len(after)}
    fields = ('Type', 'Name', 'Source', 'Destination', 'Driver', 'Mode', 'RW', 'Propagation')
    for field in fields:
        def projection(rows):
            return canonical_mounts([{key: row[key] for key in ('Destination', field) if key in row} for row in rows])
        result['mount_' + field.lower() + '_unchanged'] = projection(before) == projection(after)
    def other_fields(rows):
        return canonical_mounts([{key: value for key, value in row.items() if key == 'Destination' or key not in fields}
            for row in rows])
    result['mount_other_fields_unchanged'] = other_fields(before) == other_fields(after)
    return result


def restriction_fingerprint(record):
    values = {name: record[name] for name in ('Id', 'Image', 'Config', 'HostConfig')}
    values['Mounts'] = canonical_mounts(record['Mounts'])
    values['ports'] = record['NetworkSettings'].get('Ports')
    return hashlib.sha256(json.dumps(values, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def container_state(record):
    state = record['State']
    require(type(state['Running']) is bool and type(state['OOMKilled']) is bool)
    require(type(record['RestartCount']) is int and 0 <= record['RestartCount'] <= 1000000)
    require(type(state['ExitCode']) is int and -128 <= state['ExitCode'] <= 255)
    started = state['StartedAt']
    require(type(started) is str and re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z', started) is not None)
    return {'running': state['Running'], 'oom_killed': state['OOMKilled'], 'exit_code': state['ExitCode'],
        'restart_count': record['RestartCount'], 'started_at': started}


def sample_container_resources(docker, original, project, owner, diagnostic=None):
    """Twelve-second budget; exact owned IDs only, no host process/env/log reads."""
    deadline = time.monotonic() + 12
    class Reader:
        def call(self, args, *, timeout=2, limit=262144):
            remaining = deadline - time.monotonic()
            require(remaining > 0)
            return docker.call(args, timeout=min(timeout, remaining), limit=limit)
    reader = Reader()
    def stage(name, role=None):
        if diagnostic is not None:
            diagnostic.clear()
            diagnostic.update(stage=name, role=role, code=None, field=None, numbers={}, checks={})
    require(set(original) == {'gateway', 'backend', 'redis'})
    current = {}
    for name, record in original.items():
        stage('ownership_inspection', name)
        current[name] = inspect_container(reader, record['Id'], project, owner, name)
    stage('runtime_validation')
    if diagnostic is not None:
        diagnostic['constraints'] = {name: diagnostic_constraints(record, name, project, original['gateway']['Id'])[0]
            for name, record in current.items()}
    validate_runtime(current, project, owner)
    for name in original:
        stage('restriction_comparison', name)
        if diagnostic is not None:
            diagnostic['code'] = 'restriction_changed'
            diagnostic['checks'] = {key: current[name][field] == original[name][field]
                for field, key in (('Id', 'container_id_unchanged'), ('Image', 'image_unchanged'),
                    ('Config', 'config_unchanged'), ('HostConfig', 'host_config_unchanged'))}
            diagnostic['checks'].update(mount_observations(original[name]['Mounts'], current[name]['Mounts']))
            diagnostic['checks']['ports_unchanged'] = current[name]['NetworkSettings'].get('Ports') == original[name]['NetworkSettings'].get('Ports')
        require(restriction_fingerprint(current[name]) == restriction_fingerprint(original[name]))
    identifiers = {name: current[name]['Id'] for name in current}
    stage('stats_readback')
    text = reader.call(['stats', '--no-stream', '--no-trunc', '--format', '{{json .}}',
        *identifiers.values()], timeout=5, limit=32768)
    stage('stats_normalization')
    stats = normalize_stats(text, identifiers, diagnostic)
    result = {}
    for name, record in current.items():
        stage('cgroup_readback', name)
        text = reader.call(['exec', record['Id'], '/bin/sh', '-c', CGROUP_READBACK], limit=8192)
        stage('cgroup_normalization', name)
        group = normalize_cgroup(text, record['HostConfig'], diagnostic)
        # Docker's rounded display is descriptive; exact limits come from cgroup v2.
        if diagnostic is not None:
            diagnostic.update(stage='stats_cgroup_comparison', code='stats_cgroup_limits', field=None)
            diagnostic['numbers'].update(docker_memory_limit_bytes=stats[name]['memory_limit_bytes'], docker_pids=stats[name]['pids'])
        require(abs(stats[name]['memory_limit_bytes'] - group['memory_limit_bytes']) <= 1048576
                and stats[name]['pids'] <= group['pids_limit'])
        if diagnostic is not None: diagnostic.update(stage='state_normalization', code='container_state')
        result[name] = {'state': container_state(record), 'docker': stats[name], 'cgroup': group,
            'restriction_sha256': restriction_fingerprint(record)}
    if diagnostic is not None: diagnostic.update(stage='completed', code=None, field=None)
    return result


def require_resource_continuity(before, after):
    require(set(before) == set(after) == {'gateway', 'backend', 'redis'})
    for name, previous in before.items():
        current = after[name]
        require(previous['restriction_sha256'] == current['restriction_sha256']
            and current['state']['running'] is True and current['state']['oom_killed'] is False
            and current['state']['started_at'] == previous['state']['started_at']
            and current['state']['restart_count'] == previous['state']['restart_count'])
        for key in ('memory_oom_events', 'memory_oom_kills'):
            require(current['cgroup'][key] == previous['cgroup'][key] == 0)
        for key in ('cpu_usage_usec', 'cpu_throttled_usec', 'cpu_throttled_periods', 'cpu_periods', 'memory_max_events'):
            require(current['cgroup'][key] >= previous['cgroup'][key])


def read_private_control(path):
    path = Path(path)
    require(path.is_absolute() and path == path.resolve(strict=True))
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_mode & 0o777 == 0o600
            and before.st_uid == os.getuid() and before.st_nlink == 1 and 0 < before.st_size <= 16384)
        payload = os.read(descriptor, 16385)
        after, named = os.fstat(descriptor), path.lstat()
        require(len(payload) == before.st_size and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            and (after.st_dev, after.st_ino) == (named.st_dev, named.st_ino))
        result = json.loads(payload); require(type(result) is dict)
        return result
    finally:
        os.close(descriptor)


def normalize_soak_result(value, seconds, concurrency, local):
    """Reject arbitrary child output before retaining any traffic metrics."""
    counters = ('signed_requests', 'replay_requests', 'fidelity_failures', 'replay_failures', 'transport_errors')
    numbers = ('requested_seconds', 'concurrency', 'elapsed_seconds', 'requests_per_second', 'error_rate')
    require(type(value) is dict and set(value) == set(counters + numbers + ('latency', 'outcomes')))
    def count(number):
        require(type(number) is int and 0 <= number <= 2 ** 40)
    def finite(number):
        require(type(number) in (int, float) and math.isfinite(number) and 0 <= number <= 2 ** 40)
    for key in counters: count(value[key])
    for key in numbers: finite(value[key])
    require(value['requested_seconds'] == seconds and value['concurrency'] == concurrency
        and seconds <= value['elapsed_seconds'] <= seconds + 10 and value['error_rate'] <= 1)
    latency = value['latency']
    require(type(latency) is dict and set(latency) == {'samples', 'min_ms', 'max_ms', 'mean_ms',
        'p50_upper_bound_ms', 'p95_upper_bound_ms', 'p99_upper_bound_ms', 'histogram_upper_bounds_ms', 'histogram_counts'})
    bounds = list(local.LatencyMetrics.bounds)
    require(latency['histogram_upper_bounds_ms'] == bounds and type(latency['histogram_counts']) is list
        and len(latency['histogram_counts']) == len(bounds) + 1)
    for number in latency['histogram_counts']: count(number)
    count(latency['samples'])
    for key in ('min_ms', 'max_ms', 'mean_ms', 'p50_upper_bound_ms', 'p95_upper_bound_ms', 'p99_upper_bound_ms'):
        finite(latency[key])
    requests = value['signed_requests'] + value['replay_requests']
    require(sum(latency['histogram_counts']) == latency['samples'] == requests)
    outcomes = value['outcomes']; require(type(outcomes) is dict and set(outcomes) == {'schema', 'normal', 'replay'} and outcomes['schema'] == 1)
    for role, expected in (('normal', value['signed_requests']), ('replay', value['replay_requests'])):
        row = outcomes[role]
        require(type(row) is dict and set(row) == {'missing_status', 'invalid_status', 'unrecognized_error_body', 'transport_errors', 'statuses', 'error_codes'})
        for key in ('missing_status', 'invalid_status', 'unrecognized_error_body', 'transport_errors'): count(row[key])
        require(type(row['statuses']) is list and len(row['statuses']) <= 500)
        seen = set()
        for status in row['statuses']:
            require(type(status) is dict and set(status) == {'status', 'count'} and type(status['status']) is int
                and 100 <= status['status'] <= 599 and status['status'] not in seen)
            seen.add(status['status']); count(status['count'])
        require(sum(status['count'] for status in row['statuses']) + row['missing_status'] + row['invalid_status'] + row['transport_errors'] == expected)
        require(type(row['error_codes']) is dict and set(row['error_codes']) == set(local.OutcomeMetrics.codes))
        for number in row['error_codes'].values(): count(number)
    return value


def require_sustained_success(result, local):
    local.require_soak_success(result)
    for role, status, count in (('normal', 200, result['signed_requests']), ('replay', 403, result['replay_requests'])):
        row = result['outcomes'][role]
        require(row['statuses'] == [{'status': status, 'count': count}]
            and all(row[key] == 0 for key in ('missing_status', 'invalid_status', 'unrecognized_error_body', 'transport_errors')))
        require(row['error_codes'] == {code: count if role == 'replay' and code == 'REPLAY_DETECTED' else 0
            for code in local.OutcomeMetrics.codes})


def traffic_control(path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    payload = read_private_control(path)
    require(set(payload) == {'seconds', 'concurrency', 'port', 'ca_file', 'private_key', 'token'})
    validate_soak_options(payload['seconds'], payload['concurrency']); require(payload['seconds'] > 0)
    require(type(payload['port']) is int and 1 <= payload['port'] <= 65535)
    require(type(payload['token']) is str and re.fullmatch(r'[A-Za-z0-9_-]{32,128}', payload['token']) is not None)
    require(type(payload['private_key']) is str and len(payload['private_key']) <= 4096)
    ca = Path(payload['ca_file']); require(ca == Path(path).parent / 'server-ca.pem' and ca == ca.resolve(strict=True))
    local = helpers(); signer = local.Signer.__new__(local.Signer)
    signer.key = serialization.load_pem_private_key(payload['private_key'].encode(), password=None)
    require(isinstance(signer.key, ec.EllipticCurvePrivateKey) and signer.key.curve.name == 'secp256r1')
    signer.token = payload['token']
    context = ssl.create_default_context(cafile=str(ca))
    result = local.run_soak(payload['seconds'], payload['concurrency'], payload['port'], context, signer)
    return normalize_soak_result(result, payload['seconds'], payload['concurrency'], local)


def new_operational(seconds, concurrency):
    return {'schema': 1, 'scope': 'owned resource-constrained Linux containers; synthetic signed/replay HTTP traffic',
        'requested_seconds': seconds, 'concurrency': concurrency, 'phase': 'pending', 'passed': False, 'release_ready': False,
        'checks': {name: False for name in ('sustained_traffic', 'counter_fidelity', 'runtime_unchanged',
            'no_oom_or_restart', 'backend_restart_replay_retained', 'owned_container_cleanup', 'provenance_unchanged')},
        'limitations': ['sampled resource points are not leak or long-term capacity proof',
            'cgroup v2 is required for effective resource evidence', 'Docker CLI memory excludes inactive file cache and is rounded',
            'no external security, provider, production or physical-device approval']}


def restart_backend(docker, records, project, owner, port, tls, signer, local, counter_file):
    backend = records['backend']['Id']
    redis = records['redis']['Id']
    inspect_container(docker, redis, project, owner, 'redis')
    before_run = redis_values(docker, redis, 'server')['run_id']
    require(re.fullmatch(r'[0-9a-f]{40}', before_run) is not None)
    target, body = '/v1/items', secrets.token_bytes(32)
    original = local.wire(target, signer.headers(target, body), body)
    require(local.exchange(port, tls, original) == (200, body))
    started = time.monotonic()
    inspect_container(docker, backend, project, owner, 'backend')
    docker.call(['container', 'stop', '--time', '8', backend], timeout=15)
    require(inspect_container(docker, backend, project, owner, 'backend')['State']['Running'] is False)
    descriptor = os.open(counter_file, os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and info.st_mode & 0o777 == 0o600 and info.st_uid == os.getuid()
            and info.st_nlink == 1 and (info.st_dev, info.st_ino) == (counter_file.lstat().st_dev, counter_file.lstat().st_ino))
        os.ftruncate(descriptor, 0)
    finally:
        os.close(descriptor)
    inspect_container(docker, backend, project, owner, 'backend')
    docker.call(['container', 'start', backend], timeout=15)
    wait_ready(docker, records['gateway']['Id'], backend, project, owner, timeout=30)
    body = secrets.token_bytes(32)
    require(local.exchange(port, tls, local.wire(target, signer.headers(target, body), body)) == (200, body))
    require(local.replay_denied(local.exchange(port, tls, original)))
    elapsed = time.monotonic() - started
    inspect_container(docker, redis, project, owner, 'redis')
    require(elapsed < 45 and redis_values(docker, redis, 'server')['run_id'] == before_run)
    current = {name: inspect_container(docker, row['Id'], project, owner, name) for name, row in records.items()}
    require(validate_runtime(current, project, owner) == validate_runtime(records, project, owner)
        and all(restriction_fingerprint(current[name]) == restriction_fingerprint(records[name]) for name in records))
    require(current['backend']['State']['OOMKilled'] is False)
    return {'recovered': True, 'recovery_seconds': elapsed, 'original_replay_status': 403,
        'redis_run_unchanged': True, 'counter_reset_expected': True,
        'scope': 'owned backend container stop/start; existing Redis volume and network namespace retained'}


def run_operational(report, seconds, concurrency, docker, records, project, owner, port, tls, signer, local, private):
    from cryptography.hazmat.primitives import serialization
    resources = {'samples': 0, 'interval_seconds': 5, 'peak': {name: {'docker_memory_bytes': 0,
        'cgroup_memory_bytes': 0, 'pids': 0, 'cpu_percent': 0.} for name in records}}
    resources['scope'] = 'sampled Docker CLI and exact cgroup-v2 readbacks; observer exec processes contribute to usage; no leak proof'
    report['resources'] = resources
    def sample():
        diagnostic = resources.setdefault('sampling_diagnostic', {})
        value = sample_container_resources(docker, records, project, owner, diagnostic)
        resources['samples'] += 1
        if 'before' not in resources: resources['before'] = value
        resources['after'] = value
        require_resource_continuity(resources['before'], value)
        for name, row in value.items():
            for key, number in (('docker_memory_bytes', row['docker']['memory_bytes']),
                    ('cgroup_memory_bytes', row['cgroup']['memory_bytes']), ('pids', row['cgroup']['pids']),
                    ('cpu_percent', row['docker']['cpu_percent'])):
                resources['peak'][name][key] = max(resources['peak'][name][key], number)
        return value
    try:
        report['phase'] = 'resources_before'
        sample()
        before = local.counters(private / 'counters.json')
        control = private / 'traffic-control.json'
        write_private(control, json.dumps({'seconds': seconds, 'concurrency': concurrency, 'port': port,
            'ca_file': str(private / 'server-ca.pem'), 'token': signer.token,
            'private_key': signer.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()).decode()}))
        command = [sys.executable, str(Path(__file__).resolve()), '--traffic-control', str(control)]
        environment = {'PATH': os.environ.get('PATH', ''), 'PYTHONPATH': str(ROOT / 'sdk/python/src'), 'PYTHONDONTWRITEBYTECODE': '1'}
        report['phase'] = 'traffic'
        result = json.loads(bounded_command(command, timeout=seconds + 15, limit=131072, observer=sample, env=environment, cwd=ROOT))
        report['soak'] = normalize_soak_result(result, seconds, concurrency, local)
        after = local.counters(private / 'counters.json')
        report['phase'] = 'resources_after'
        sample()
        report['counters'] = {'before': before, 'after': after}
        require_sustained_success(report['soak'], local)
        report['checks']['sustained_traffic'] = True
        report['counters']['delta'] = local.verify_soak_counters(before, after, report['soak'])
        report['checks']['counter_fidelity'] = True
        report['checks']['runtime_unchanged'] = report['checks']['no_oom_or_restart'] = True
        report['phase'] = 'backend_restart'
        report['backend_restart'] = restart_backend(docker, records, project, owner, port, tls, signer, local, private / 'counters.json')
        report['checks']['backend_restart_replay_retained'] = True
        report['phase'] = 'completed'
    except BaseException as error:
        report['failure'] = failure_summary(error)
        if not isinstance(error, KeyboardInterrupt):
            try:
                deadline = time.monotonic() + 6
                class Reader:
                    def call(self, args, **kwargs):
                        remaining = deadline - time.monotonic(); require(remaining > 0)
                        return docker.call(args, timeout=min(2, remaining), limit=262144)
                report['last_states'] = {name: container_state(inspect_container(Reader(), record['Id'], project, owner, name))
                    for name, record in records.items()}
            except (Exception, KeyboardInterrupt):
                report['state_readback_incomplete'] = True
        raise


def qualify(output, executable, context, java_home, soak_seconds=0, soak_concurrency=8, target_platform=None):
    validate_soak_options(soak_seconds, soak_concurrency)
    require(target_platform is None or target_platform in ('linux/amd64','linux/arm64'))
    with ReceiptDirectory(output) as receipt_directory:
        return _qualify(receipt_directory, executable, context, java_home, soak_seconds, soak_concurrency,target_platform)


def _qualify(output, executable, context, java_home, soak_seconds=0, soak_concurrency=8, target_platform=None):
    local = helpers()
    started = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    pins = source_hashes()
    commit = bounded_command(['git', 'rev-parse', 'HEAD'], cwd=ROOT).strip()
    require(valid_commit(commit))
    clean = not bool(bounded_command(['git', 'status', '--porcelain', '--untracked-files=normal'], cwd=ROOT))
    receipt = {'schema': 1, 'evidence_class': 'owned_container_deployment',
        'profile': 'spring-loopback-mtls-containers-v1', 'observed_at': started,
        'candidate_commit': commit, 'source_matches_commit': clean, 'source_sha256': pins,
        'checks': {name: False for name in CHECKS}, 'release_ready': False,
        'external_approval': False, 'technical_verification': False, 'phase': 'certificates',
        'limitations': ['owned local Linux Docker daemon only', 'no external security or license approval',
            'no provider account or physical device evidence', 'image vulnerabilities require a separate current scan']}
    docker = None
    if target_platform is not None:
        receipt['runtime_platform'] = dict(schema=1,platform=target_platform,host_machine=None,
            daemon_architecture=None,images={},verified=False)
    if soak_seconds:
        receipt['operational'] = new_operational(soak_seconds, soak_concurrency)
    completed = False
    project = 'appguard-spring-' + secrets.token_hex(12)
    owner = secrets.token_hex(12)
    with tempfile.TemporaryDirectory(prefix='appguard-spring-containers-') as directory:
        private = Path(directory).resolve()
        private.chmod(0o700)
        try:
            uid, gid = os.getuid(), os.getgid()
            require(uid > 0 and gid > 0)
            password = generate_certificates(private, java_home)
            signer = local.Signer(private)
            write_private(private / 'backend-password', password)
            write_private(private / 'counters.json', '')
            write_private(private / 'request.bin', b'')
            values = {'APPGUARD_OWNER': owner, 'APPGUARD_IMAGE_TAG': owner,
                'APPGUARD_UID': str(uid), 'APPGUARD_GID': str(gid), 'APPGUARD_PUBLISHED_PORT': '0',
                'APPGUARD_ORIGIN': 'https://api.example.test', 'APPGUARD_BACKEND_HOSTNAME': 'backend.example.test',
                'APPGUARD_BODY_TIMEOUT': '.8', 'APPGUARD_BACKEND_TIMEOUT': '2', 'APPGUARD_TOTAL_TIMEOUT': '5',
                'APPGUARD_APP_ID': 'qualification-app', 'APPGUARD_SUBJECT': 'qualification-user',
                'APPGUARD_KEY_ID': 'qualification-key', 'APPGUARD_BEARER_SHA256': hashlib.sha256(signer.token.encode()).hexdigest()}
            for name, file in {'FRONTEND_CERT': 'api.example.test.pem', 'FRONTEND_KEY': 'api.example.test.key',
                'SERVER_CA': 'server-ca.pem', 'INGRESS_CERT': 'ingress-client.pem', 'INGRESS_KEY': 'ingress-client.key',
                'BACKEND_KEYSTORE': 'backend.p12', 'BACKEND_TRUSTSTORE': 'trust.p12',
                'BACKEND_PASSWORD': 'backend-password', 'ENROLLED_KEY': 'enrolled.pem'}.items():
                values['APPGUARD_' + name + '_FILE'] = str(private / file)
            receipt['phase'] = 'daemon_and_builder'
            docker = Docker(executable, context, values)
            if target_platform is not None:
                receipt['runtime_platform'] = platform_environment(docker,target_platform)
            require(not discovered(docker, project, owner))
            override = private / 'qualification.json'
            write_private(override, json.dumps(qualification_override(private, uid, gid, project, owner,target_platform)))
            compose = compose_args(project, override)
            resolved = docker.call([*compose, '--profile', 'qualification', 'config', '--format', 'json'])
            # Never retain configuration/environment values, even synthetic ones.
            receipt['resolved_compose_sha256'] = hashlib.sha256(resolved.encode()).hexdigest()
            receipt['phase'] = 'image_build'
            docker.call([*compose, 'build', '--builder', context, '--pull', 'gateway', 'redis', 'backend'], timeout=1200, limit=8388608)
            require(source_hashes() == pins)
            records, inspected = run_startup(docker, compose, receipt, project, owner)
            if target_platform is not None:
                platform_before = observe_runtime_platform(docker,records,project,owner,target_platform)
                receipt['runtime_platform'] = dict(platform_before,verified=False)
            port = inspected['gateway_port']
            tls = ssl.create_default_context(cafile=str(private / 'server-ca.pem'))
            receipt['phase'] = 'signed_requests'
            for target, body, chunked in [('/v1/items', b'\x00\xff\r\n', False),
                    ('/v1/items?', b'', False), ('/v1/items?x=%2f&x=%2F', '한글日本語'.encode(), True)]:
                require(local.exchange(port, tls, local.wire(target, signer.headers(target, body), body, chunked)) == (200, body))
            receipt['checks']['signed_fidelity'] = True
            target, body = '/v1/items', b'container-replay'
            request = local.wire(target, signer.headers(target, body), body)
            require(local.exchange(port, tls, request) == (200, body))
            rejected = local.exchange(port, tls, request)
            require(rejected[0] == 403 and json.loads(rejected[1]) == {'code': 'REPLAY_DETECTED'})
            receipt['checks']['replay_rejected'] = True
            receipt['phase'] = 'redis_restart'
            receipt['redis_restart'] = restart_redis(docker, records['redis']['Id'], project, owner,
                port, tls, signer, request, local, private / 'counters.json')
            for name in ('redis_outage_denied', 'redis_recovery', 'redis_restart_replay_retained'):
                receipt['checks'][name] = True
            baseline = local.counters(private / 'counters.json')
            receipt['phase'] = 'backend_bypass'
            # Building images can exceed the signature's one-minute lifetime.
            # Sign this private fixture immediately before its probe container.
            probe_body = b'backend-bypass'
            (private / 'request.bin').write_bytes(local.wire('/v1/items', signer.headers('/v1/items', probe_body), probe_body))
            docker.call([*compose, '--profile', 'qualification', 'up', '--detach', '--no-build', '--no-deps', 'probe'], timeout=30)
            probe = records_for(docker, project, owner)['probe']
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                probe = inspect_container(docker, probe['Id'], project, owner, 'probe')
                if not probe['State']['Running']:
                    break
                time.sleep(.1)
            require(not probe['State']['Running'] and probe['State']['ExitCode'] == 0)
            result = json.loads(docker.call(['logs', probe['Id']], limit=4096))
            require(result == {'plaintext': True, 'no_client': True, 'wrong_client': True})
            require(local.counters(private / 'counters.json') == baseline)
            receipt['checks']['backend_bypass_zero_dispatch'] = True
            receipt['phase'] = 'upload_deadline'
            target, body = '/v1/items', b'12345678'
            request = local.wire(target, signer.headers(target, body), body)
            begin = time.monotonic()
            require(local.exchange(port, tls, request, drip=.2)[0] in {408, 504})
            require(time.monotonic() - begin < 3.5 and local.counters(private / 'counters.json') == baseline)
            head = request.split(b'\r\n\r\n', 1)[0] + b'\r\n\r\n'
            require(local.exchange(port, tls, head)[0] in {408, 504})
            require(local.counters(private / 'counters.json') == baseline)
            receipt['checks']['absolute_upload_deadline_zero_dispatch'] = True
            receipt['phase'] = 'malformed_framing'
            for attack in [request.replace(b'Content-Length: 8', b'Content-Length: 8\r\nTransfer-Encoding: chunked'),
                request.replace(b'Content-Length: 8', b'Content-Length: 8\r\nContent-Length: 8'),
                request.replace(b'Host: api.example.test', b'Host: api.example.test\r\nForwarded: for=127.0.0.1'),
                request.replace(b'\r\n', b'\n')]:
                try:
                    require(local.exchange(port, tls, attack)[0] in {None, 400, 408, 413, 431, 504})
                except (OSError, ssl.SSLError):
                    pass
            require(local.counters(private / 'counters.json') == baseline)
            receipt['checks']['malformed_zero_dispatch'] = True
            receipt['backend_counters'] = baseline
            receipt['resource_limits'] = {name: {key: records[name]['HostConfig'][key]
                for key in ('Memory', 'MemorySwap', 'PidsLimit', 'NanoCpus')} for name in records}
            # Reinspect surviving services after the probes, not just at startup.
            current = records_for(docker, project, owner)
            require(validate_runtime({name: current[name] for name in records}, project, owner) == inspected)
            if soak_seconds:
                receipt['phase'] = 'sustained_containers'
                run_operational(receipt['operational'], soak_seconds, soak_concurrency, docker, records,
                    project, owner, port, tls, signer, local, private)
            if target_platform is not None:
                require(observe_runtime_platform(docker,records,project,owner,target_platform) == platform_before)
                receipt['runtime_platform'] = platform_before
            completed = True
            receipt['phase'] = 'completed'
        except BaseException as error:
            if docker is not None and receipt['phase'] in STARTUP_PHASES:
                receipt['startup_diagnostics'] = empty_startup_diagnostics(error)
                if not isinstance(error, KeyboardInterrupt):
                    try:
                        receipt['startup_diagnostics'] = startup_diagnostics(docker,project,owner,error)
                    except Exception:
                        receipt['startup_diagnostics']['metadata_errors'] = 1
            raise
        finally:
            if docker is not None:
                receipt['checks']['owned_container_cleanup'] = cleanup_owned(docker, project, owner)
            receipt['cleanup'] = receipt['checks']['owned_container_cleanup']
            if soak_seconds:
                receipt['operational']['checks']['owned_container_cleanup'] = receipt['cleanup']
            try:
                require(source_hashes() == pins
                    and bounded_command(['git', 'rev-parse', 'HEAD'], cwd=ROOT).strip() == commit)
                receipt['source_matches_commit'] = clean and not bool(bounded_command(
                    ['git', 'status', '--porcelain', '--untracked-files=normal'], cwd=ROOT))
                receipt['checks']['provenance_unchanged'] = True
            except (ValueError, RuntimeError, OSError):
                receipt['checks']['provenance_unchanged'] = False
            if soak_seconds:
                operating = receipt['operational']
                operating['checks']['provenance_unchanged'] = receipt['checks']['provenance_unchanged']
                operating['passed'] = completed and all(operating['checks'].values())
            receipt['technical_verification'] = completed and all(receipt['checks'].values())
            if soak_seconds:
                receipt['technical_verification'] = receipt['technical_verification'] and receipt['operational']['passed']
            output.publish(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
    require(receipt['technical_verification'])
    return receipt


def main():
    if len(sys.argv) == 3 and sys.argv[1] == '--traffic-control':
        try:
            print(json.dumps(traffic_control(Path(sys.argv[2])), separators=(',', ':')))
            return 0
        except (Exception, KeyboardInterrupt):
            print('SPRING_CONTAINER_TRAFFIC_FAILED', file=sys.stderr)
            return 1
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True)
    parser.add_argument('--docker-context', required=True)
    parser.add_argument('--docker', default='docker')
    parser.add_argument('--java-home', default=os.environ.get('JAVA_HOME'))
    parser.add_argument('--soak-seconds', type=int, default=0, help='0 disables sustained qualification; otherwise 1..3600 seconds')
    parser.add_argument('--soak-concurrency', type=int, default=8, help='1..32 concurrent synthetic request workers')
    parser.add_argument('--platform',choices=('linux/amd64','linux/arm64'),default=None)
    args = parser.parse_args()
    try:
        validate_soak_options(args.soak_seconds, args.soak_concurrency)
        require(args.java_home is not None)
        java = Path(args.java_home).resolve(strict=True)
        require((java / 'bin/keytool').is_file())
        executable = Path(shutil.which(args.docker) or args.docker).resolve(strict=True)
        output = helpers().new_output(args.output)
        with cancellation_scope():
            qualify(output, executable, args.docker_context, java, args.soak_seconds, args.soak_concurrency,args.platform)
    except (Exception, KeyboardInterrupt):
        print('SPRING_CONTAINER_QUALIFICATION_FAILED', file=sys.stderr)
        return 1
    print('SPRING_CONTAINER_QUALIFICATION_PASSED')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
