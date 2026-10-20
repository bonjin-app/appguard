"""Test-only probe against an explicitly disposable loopback Redis instance."""

import base64
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import subprocess
import sys
import time
from urllib.parse import urlsplit
import uuid

import redis

from appguard.redis import RedisReplayStore, redis_replay_key

ROOT = Path(__file__).resolve().parents[1]


def test_url():
    value = os.environ.get("APPGUARD_TEST_REDIS_URL", "")
    parsed = urlsplit(value)
    if (parsed.scheme != "redis" or parsed.hostname != "127.0.0.1"
            or parsed.username is not None or parsed.password is not None
            or parsed.port is None or parsed.query or parsed.fragment
            or not parsed.path.removeprefix("/").isdigit()):
        raise SystemExit("Supply an explicitly disposable redis://127.0.0.1:PORT/DB test instance")
    return value


def check(url):
    client = redis.Redis.from_url(url, socket_connect_timeout=2, socket_timeout=2)
    classpath_file = ROOT / "sdk/spring-boot/target/test-classpath.txt"
    classpath = os.pathsep.join((str(ROOT / "sdk/spring-boot/target/test-classes"),
                               str(ROOT / "sdk/spring-boot/target/classes"),
                               classpath_file.read_text().strip()))

    def claim(language, scope, now):
        if language == "Python":
            return RedisReplayStore(client).claim(scope, expires=now + 120, now=now)
        args = (["node", str(ROOT / "sdk/node/test/redis-claim.js"), *scope, str(now), str(now + 120)]
                if language == "Node" else
                ["java", "-cp", classpath, "io.appguard.RedisClaimCli", url, *scope, str(now + 120), str(now)])
        result = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, timeout=30, check=True)
        lines = [line for line in result.stdout.splitlines() if line in {"CLAIMED", "REPLAY", "REPLAY_DETECTED"}]
        if len(lines) != 1:
            raise AssertionError(f"{language} returned no unambiguous claim result")
        return lines[0] == "CLAIMED"

    try:
        client.ping()
        languages = ("Python", "Node", "Java")
        for first in languages:
            scope = ("cross-sdk-" + uuid.uuid4().hex, "test-key",
                     base64.urlsafe_b64encode(uuid.uuid4().bytes).decode().rstrip("="))
            key, now = redis_replay_key(scope), int(time.time())
            try:
                order = (first,) + tuple(language for language in languages if language != first)
                results = [claim(language, scope, now) for language in order]
                assert results == [True, False, False], f"cross-language replay failed with {first} first"
                assert 90 <= client.ttl(key) <= 120, "claim retention is too short"
                print(f"{first} first: one claim; both other SDKs reject replay", flush=True)
            finally:
                client.delete(key)

        scope = ("cross-sdk-" + uuid.uuid4().hex, "test-key",
                 base64.urlsafe_b64encode(uuid.uuid4().bytes).decode().rstrip("="))
        key, now = redis_replay_key(scope), int(time.time())
        try:
            with ThreadPoolExecutor(max_workers=3) as pool:
                results = list(pool.map(lambda language: claim(language, scope, now), languages))
            assert results.count(True) == 1, "concurrent SDK processes accepted duplicate claims"
            print("Concurrent Python/Node/Java processes: exactly one claim", flush=True)
        finally:
            client.delete(key)
    finally:
        client.close()


if __name__ == "__main__":
    url = test_url()
    if "--validate-url" not in sys.argv:
        check(url)
