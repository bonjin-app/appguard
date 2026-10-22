#!/usr/bin/env python3
"""Explicit ext-redis live probe. Pass PHP binary/options; URL stays in environment."""
import base64
import os
from pathlib import Path
import secrets
import selectors
import subprocess
import sys
import time
from urllib.parse import urlsplit


def require(condition):
    if not condition:
        raise RuntimeError("REDIS_LIVE_FAILED")


if not os.environ.get('APPGUARD_TEST_REDIS_URL') or len(sys.argv) < 2:
    sys.exit('Require owned disposable APPGUARD_TEST_REDIS_URL and PHP command/options')
try:
    parsed = urlsplit(os.environ['APPGUARD_TEST_REDIS_URL'])
    require(parsed.scheme == 'redis' and parsed.hostname == '127.0.0.1'
            and parsed.port is not None and parsed.username is None and parsed.password is None
            and not parsed.query and not parsed.fragment and parsed.path.startswith('/')
            and parsed.path[1:].isdigit() and 0 <= int(parsed.path[1:]) <= 15)
except (ValueError, RuntimeError):
    sys.exit('Require owned disposable redis://127.0.0.1:PORT/DB without credentials')
command = sys.argv[1:] + [str(Path(__file__).with_name('redis_live.php'))]
key = 'probe-' + secrets.token_hex(16)
nonce = base64.urlsafe_b64encode(secrets.token_bytes(16)).decode().rstrip('=')
expiry_nonce = base64.urlsafe_b64encode(secrets.token_bytes(16)).decode().rstrip('=')
literal_nonce = base64.urlsafe_b64encode(secrets.token_bytes(16)).decode().rstrip('=')
queued_nonce = base64.urlsafe_b64encode(secrets.token_bytes(16)).decode().rstrip('=')

def run(action, chosen_nonce=nonce, ttl=30):
    result = subprocess.run(command + [action, key, chosen_nonce, str(ttl)], capture_output=True, text=True, timeout=10)
    if result.returncode:
        raise RuntimeError('REDIS_LIVE_FAILED')
    return result.stdout.strip()

children = []
try:
    require(run('literal-required', literal_nonce) == 'DENIED')
    require(run('raw-mode', queued_nonce) == 'DENIED')
    require(run('mode') == 'DENIED')
    env = dict(os.environ, APPGUARD_REDIS_BARRIER='1')
    for _ in range(8):
        children.append(subprocess.Popen(command + ['claim', key, nonce, '30'], stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env))
    ready = selectors.DefaultSelector()
    for child in children:
        ready.register(child.stdout, selectors.EVENT_READ)
    deadline = time.monotonic() + 10
    while ready.get_map():
        events = ready.select(max(0, deadline-time.monotonic()))
        if not events:
            raise RuntimeError('REDIS_LIVE_FAILED')
        for event, _ in events:
            require(event.fileobj.readline().strip() == 'READY')
            ready.unregister(event.fileobj)
    ready.close()
    for child in children:
        child.stdin.write('1')
        child.stdin.flush()
    results = []
    for child in children:
        stdout, _ = child.communicate(timeout=10)
        require(child.returncode == 0)
        results.append(stdout.strip())
    require(results.count('WON') == 1 and results.count('CONFLICT') == 7)
    require(run('claim') == 'CONFLICT')
    require(run('inspect') == 'STORED')
    require(run('claim-literal', expiry_nonce, 1) == 'WON')
    require(run('inspect', expiry_nonce) == 'STORED')
    time.sleep(1.2)
    require(run('claim', expiry_nonce, 1) == 'WON')
    require(run('unavailable') == 'DENIED')
    require(run('backend-error') == 'DENIED')
    print('PASS: ext-redis live independent clients, 8-process atomic race, canonical key/value/TTL, expiry, required literal replies/prefix bypass, raw-MULTI/QUEUED/pipeline/backend-error/unconnected-client denial')
except Exception:
    sys.exit('REDIS_LIVE_FAILED (requires loaded ext-redis and reachable owned disposable URL)')
finally:
    for child in children:
        if child.poll() is None:
            child.kill()
            child.communicate()
    for chosen in (nonce, expiry_nonce, literal_nonce, queued_nonce):
        try:
            run('delete', chosen)
        except Exception:
            pass  # Only random keys created here; both expire within 30 seconds.
