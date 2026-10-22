#!/usr/bin/env python3
"""Qualify replay behavior against a Redis process created and owned here.

No external Redis URL is accepted. This is process-crash/configuration evidence,
not a claim about disk loss, replication, a cloud service or production capacity.
"""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import json
import math
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid


def require(condition):
    if not condition:
        raise AssertionError("qualification invariant failed")


class OwnedRedis:
    def __init__(self, binary):
        self.binary = Path(binary).resolve(strict=True)
        if not self.binary.is_file() or not os.access(self.binary, os.X_OK):
            raise ValueError('runtime')
        self._temp = tempfile.TemporaryDirectory(prefix='appguard-replay-qualification-')
        self.directory = Path(self._temp.name).resolve()
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            self.port = listener.getsockname()[1]
        self.process = None
        self.client = None
        self.run_id = None

    def _client(self, port=None):
        import redis
        from redis.backoff import NoBackoff
        from redis.retry import Retry
        return redis.Redis(host='127.0.0.1', port=port or self.port, db=0,
                           socket_connect_timeout=0.25, socket_timeout=0.25,
                           retry=Retry(NoBackoff(), 0), decode_responses=False)

    def start(self):
        self.process = subprocess.Popen([str(self.binary), '--bind', '127.0.0.1', '--port', str(self.port),
            '--daemonize', 'no', '--save', '', '--appendonly', 'yes', '--appendfsync', 'always',
            '--maxmemory-policy', 'noeviction', '--dir', str(self.directory),
            '--logfile', str(self.directory / 'server.log')],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.client = self._client()
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError('owned process exited')
            try:
                info = self.client.info('server')
            except Exception:
                time.sleep(0.025)
                continue
            if info.get('process_id') != self.process.pid:
                raise RuntimeError('port belongs to a different process')
            self.run_id = info['run_id']
            self.assert_owner()
            return
        raise RuntimeError('owned process did not become ready')

    def assert_owner(self):
        if self.process is None or self.process.poll() is not None:
            raise RuntimeError('not an active owned process')
        info = self.client.info('server')
        if info.get('process_id') != self.process.pid or info.get('run_id') != self.run_id:
            raise RuntimeError('ownership changed')
        directory = self.client.config_get('dir').get('dir')
        if type(directory) is not str or Path(directory).resolve() != self.directory:
            raise RuntimeError('state directory changed')

    def crash(self):
        self.assert_owner()
        self.process.kill()
        self.process.wait(timeout=5)
        self.client.close()
        self.client = None

    def close(self):
        if self.client is not None:
            self.client.close()
            self.client = None
        if self.process is not None and self.process.poll() is None:
            # Signal only the child process, never a server discovered at a URL.
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self._temp.cleanup()


def scope(prefix):
    return (prefix, 'qualification-key', base64.urlsafe_b64encode(uuid.uuid4().bytes).decode().rstrip('='))


def expect_unavailable(operation):
    from appguard.replay import ReplayStoreUnavailable
    try:
        operation()
    except ReplayStoreUnavailable as error:
        if error.__cause__ is not None or error.__context__ is not None:
            raise AssertionError('backend exception retained')
        return
    raise AssertionError('backend failure did not fail closed')


def percentile(samples, fraction):
    return sorted(samples)[max(0, math.ceil(len(samples) * fraction) - 1)]


def qualify(binary, iterations, concurrency):
    if type(iterations) is not int or not 1 <= iterations <= 100000 or type(concurrency) is not int or not 1 <= concurrency <= 64:
        raise ValueError('bounded load configuration')
    from appguard.redis import RedisReplayStore, redis_replay_key
    owned = OwnedRedis(binary)
    directory = owned.directory
    clients = []
    scenarios = {}
    try:
        owned.start()
        prefix = 'qualification-' + uuid.uuid4().hex
        now = int(time.time())
        persistent_scope = scope(prefix)
        require(RedisReplayStore(owned.client).claim(persistent_scope, expires=now + 120, now=now) is True)
        # fsync=always means this process acknowledged the claim before SIGKILL.
        owned.crash()
        unavailable = owned._client()
        clients.append(unavailable)
        expect_unavailable(lambda: RedisReplayStore(unavailable).claim(scope(prefix), expires=now + 120, now=now))
        scenarios['outage_fail_closed'] = True
        owned.start()
        require(RedisReplayStore(owned.client).claim(persistent_scope, expires=now + 120, now=int(time.time())) is False)
        require(90 <= owned.client.ttl(redis_replay_key(persistent_scope)) <= 120)
        scenarios['process_crash_replay_preserved'] = True
        owned.assert_owner()
        # The following configuration mutation is allowed only after proving PID,
        # Redis run ID and exclusive temporary directory ownership.
        used = owned.client.info('memory')['used_memory']
        owned.client.config_set('maxmemory', used)
        expect_unavailable(lambda: RedisReplayStore(owned.client).claim(scope(prefix), expires=now + 120, now=int(time.time())))
        scenarios['noeviction_capacity_fail_closed'] = True
        owned.assert_owner()
        owned.client.config_set('maxmemory', 0)

        local = threading.local()
        lock = threading.Lock()
        def store():
            if not hasattr(local, 'client'):
                local.client = owned._client()
                with lock:
                    clients.append(local.client)
            return RedisReplayStore(local.client)
        shared_scope = scope(prefix)
        def single_winner(_):
            return store().claim(shared_scope, expires=now + 120, now=int(time.time()))
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            winners = list(pool.map(single_winner, range(max(32, concurrency))))
        require(winners.count(True) == 1 and winners.count(False) == len(winners) - 1)
        scenarios['atomic_single_winner'] = True

        all_scopes = [scope(prefix) for _ in range(iterations)]
        latencies = []
        def timed_claim(item):
            started = time.perf_counter()
            result = store().claim(item, expires=now + 120, now=int(time.time()))
            elapsed = (time.perf_counter() - started) * 1000
            return result, elapsed
        started = time.perf_counter()
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            new = list(pool.map(timed_claim, all_scopes))
            repeated = list(pool.map(timed_claim, all_scopes))
        seconds = time.perf_counter() - started
        require(all(result is True for result, _ in new) and all(result is False for result, _ in repeated))
        latencies = [elapsed for _, elapsed in new + repeated]
        load = {'unique_claims': len(new), 'replays_rejected': len(repeated), 'failures': 0,
                'concurrency': concurrency, 'elapsed_seconds': seconds,
                'operations_per_second': (len(new) + len(repeated)) / seconds,
                'p50_ms': percentile(latencies, .5), 'p95_ms': percentile(latencies, .95),
                'p99_ms': percentile(latencies, .99), 'max_ms': max(latencies),
                'latency_scope': 'configured client claim, including first connection per worker; no production SLO asserted'}
        # A test-owned listening socket deliberately never speaks Redis. Client
        # socket timeout must bound the operation; no connection to outside hosts.
        with socket.socket() as stalled:
            stalled.bind(('127.0.0.1', 0))
            stalled.listen(4)
            silent = owned._client(stalled.getsockname()[1])
            clients.append(silent)
            started = time.monotonic()
            expect_unavailable(lambda: RedisReplayStore(silent).claim(scope(prefix), expires=now + 120, now=int(time.time())))
            require(time.monotonic() - started < 3)
        scenarios['socket_timeout_fail_closed'] = True
        version = owned.client.info('server')['redis_version']
    finally:
        for client in clients:
            client.close()
        owned.close()
    scenarios['temporary_state_removed'] = not directory.exists()
    if not scenarios['temporary_state_removed']:
        raise RuntimeError('temporary state retained')
    return {'status': 'passed', 'redis_version': version, 'scenarios': scenarios, 'load': load,
            'durability_scope': 'owned process crash with appendonly=yes, appendfsync=always, noeviction; not host/disk/replica failure'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--redis-server', required=True)
    parser.add_argument('--iterations', type=int, default=200)
    parser.add_argument('--concurrency', type=int, default=8)
    args = parser.parse_args()
    try:
        report = qualify(args.redis_server, args.iterations, args.concurrency)
    except Exception:
        print(json.dumps({'status': 'failed', 'code': 'QUALIFICATION_FAILED'}, separators=(',', ':')), file=sys.stderr)
        return 1
    print(json.dumps(report, separators=(',', ':'), sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
