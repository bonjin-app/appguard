#!/usr/bin/env python3
"""Qualify newly owned Docker containers on an explicitly selected local daemon.

No remote daemons, registry pushes, pruning, global changes or operator services.
Private keys/logs/inspect output expire with a private temporary directory. Only
fixed checks, counts, identifiers and hashes enter the retained receipt.
"""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
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


def bounded_command(command, *, timeout=30, limit=2097152, env=None, cwd=None):
    """Bound output, elapsed time and retained memory for every CLI command."""
    require(0 < timeout <= 1200 and 0 < limit <= 8388608)
    child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, env=env, cwd=cwd, start_new_session=True)
    output = bytearray()
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            while child.poll() is None or selector.get_map():
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


def wait_ready(docker, gateway, backend, project, owner):
    deadline = time.monotonic() + 90
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
    effective_restrictions(docker, records, project, owner)
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


def qualification_override(private, uid, gid, project, owner):
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
    return {'services': {'backend': {'environment': {'APPGUARD_BACKEND_COUNTER_FILE': '/run/appguard/counters.json'},
        'volumes': [mount('counters.json', '/run/appguard/counters.json', False)]}, 'probe': probe}}


def qualify(output, executable, context, java_home):
    with ReceiptDirectory(output) as receipt_directory:
        return _qualify(receipt_directory, executable, context, java_home)


def _qualify(output, executable, context, java_home):
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
            require(not discovered(docker, project, owner))
            override = private / 'qualification.json'
            write_private(override, json.dumps(qualification_override(private, uid, gid, project, owner)))
            compose = compose_args(project, override)
            resolved = docker.call([*compose, '--profile', 'qualification', 'config', '--format', 'json'])
            # Never retain configuration/environment values, even synthetic ones.
            receipt['resolved_compose_sha256'] = hashlib.sha256(resolved.encode()).hexdigest()
            receipt['phase'] = 'image_build'
            docker.call([*compose, 'build', '--builder', context, '--pull', 'gateway', 'redis', 'backend'], timeout=1200, limit=8388608)
            require(source_hashes() == pins)
            records, inspected = run_startup(docker, compose, receipt, project, owner)
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
            try:
                require(source_hashes() == pins
                    and bounded_command(['git', 'rev-parse', 'HEAD'], cwd=ROOT).strip() == commit)
                receipt['source_matches_commit'] = clean and not bool(bounded_command(
                    ['git', 'status', '--porcelain', '--untracked-files=normal'], cwd=ROOT))
                receipt['checks']['provenance_unchanged'] = True
            except (ValueError, RuntimeError, OSError):
                receipt['checks']['provenance_unchanged'] = False
            receipt['technical_verification'] = completed and all(receipt['checks'].values())
            output.publish(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
    require(receipt['technical_verification'])
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True)
    parser.add_argument('--docker-context', required=True)
    parser.add_argument('--docker', default='docker')
    parser.add_argument('--java-home', default=os.environ.get('JAVA_HOME'))
    args = parser.parse_args()
    try:
        require(args.java_home is not None)
        java = Path(args.java_home).resolve(strict=True)
        require((java / 'bin/keytool').is_file())
        executable = Path(shutil.which(args.docker) or args.docker).resolve(strict=True)
        output = helpers().new_output(args.output)
        with cancellation_scope():
            qualify(output, executable, args.docker_context, java)
    except (Exception, KeyboardInterrupt):
        print('SPRING_CONTAINER_QUALIFICATION_FAILED', file=sys.stderr)
        return 1
    print('SPRING_CONTAINER_QUALIFICATION_PASSED')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
