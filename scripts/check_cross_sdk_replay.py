"""Test-only probe against an explicitly disposable loopback Redis instance."""

import base64
import argparse
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
            or not parsed.path.removeprefix("/").isdigit()
            or not 0 <= int(parsed.path[1:]) <= 15):
        raise SystemExit("Supply an explicitly disposable redis://127.0.0.1:PORT/DB test instance")
    return value


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def check(url, *, extended=False, extended_only=False):
    client = redis.Redis.from_url(url, socket_connect_timeout=2, socket_timeout=2)
    languages = (("Python", "Go", ".NET", "PHP") if extended_only else
                 ("Python", "Node", "Java", "Go", ".NET", "PHP") if extended else
                 ("Python", "Node", "Java"))
    classpath = ""
    if "Java" in languages:
        classpath_file = ROOT / "sdk/spring-boot/target/test-classpath.txt"
        classpath = os.pathsep.join((str(ROOT / "sdk/spring-boot/target/test-classes"),
                                   str(ROOT / "sdk/spring-boot/target/classes"),
                                   classpath_file.read_text().strip()))
    env = dict(os.environ, APPGUARD_TEST_REDIS_URL=url,
               DOTNET_GENERATE_ASPNET_CERTIFICATE="false", DOTNET_CLI_TELEMETRY_OPTOUT="1",
               DOTNET_SKIP_FIRST_TIME_EXPERIENCE="1", GOTOOLCHAIN="local", GOWORK="off",
               GOFLAGS="-mod=readonly")
    env["DOTNET_CLI_HOME"] = os.environ.get("APPGUARD_DOTNET_CLI_HOME", str(ROOT / "sdk/dotnet/.tools/cli-home"))
    env["GOPATH"] = os.environ.get("APPGUARD_GO_PATH", str(ROOT / "sdk/go/.tools/gopath"))
    env["GOCACHE"] = os.environ.get("APPGUARD_GO_CACHE", str(ROOT / "sdk/go/.tools/cache"))

    def claim(language, scope, now):
        if language == "Python":
            return RedisReplayStore(client).claim(scope, expires=now + 120, now=now)
        cwd = ROOT
        if language == "Node":
            args = ["node", str(ROOT / "sdk/node/test/redis-claim.js"), *scope, str(now), str(now + 120)]
        elif language == "Java":
            args = ["java", "-cp", classpath, "io.appguard.RedisClaimCli", url, *scope, str(now + 120), str(now)]
        elif language == "Go":
            cwd = ROOT / "sdk/go"
            args = [os.environ.get("APPGUARD_GO_CMD", "go"), "run", "./tools/claim-redis", url,
                    *scope, str(now), str(now + 120)]
        elif language == ".NET":
            cwd = ROOT / "sdk/dotnet"
            args = [os.environ.get("APPGUARD_DOTNET", "dotnet"),
                    str(cwd / "tools/RedisProbe/bin/Release/net10.0/RedisProbe.dll"), url,
                    *scope, str(now), str(now + 120)]
        else:
            # Optional extension override is exactly one readable absolute file,
            # never php.ini, a shell expression, or an argument string.
            args = [os.environ.get("APPGUARD_PHP_CMD", "php"), "-n"]
            extension = os.environ.get("APPGUARD_PHP_REDIS_EXTENSION")
            if extension:
                extension_path = Path(extension)
                require(extension_path.is_absolute() and extension_path.is_file(), "Invalid Redis extension path")
                args.extend(["-d", "extension=" + str(extension_path)])
            args.extend([str(ROOT / "sdk/php/tests/redis_live.php"), "cross", *scope, str(now), str(now + 120)])
        result = subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True, timeout=45, check=True)
        lines = [line for line in result.stdout.splitlines() if line in {"CLAIMED", "REPLAY", "REPLAY_DETECTED"}]
        if len(lines) != 1:
            raise AssertionError(f"{language} returned no unambiguous claim result")
        return lines[0] == "CLAIMED"

    try:
        client.ping()
        for first in languages:
            scope = ("cross-sdk-" + uuid.uuid4().hex, "test-key",
                     base64.urlsafe_b64encode(uuid.uuid4().bytes).decode().rstrip("="))
            key, now = redis_replay_key(scope), int(time.time())
            try:
                order = (first,) + tuple(language for language in languages if language != first)
                results = [claim(language, scope, now) for language in order]
                require(results == [True] + [False] * (len(languages) - 1), f"cross-language replay failed with {first} first")
                require(60 <= client.ttl(key) <= 120, "claim retention is too short")
                print(f"{first} first: one claim; all other SDKs reject replay", flush=True)
            finally:
                client.delete(key)

        scope = ("cross-sdk-" + uuid.uuid4().hex, "test-key",
                 base64.urlsafe_b64encode(uuid.uuid4().bytes).decode().rstrip("="))
        key, now = redis_replay_key(scope), int(time.time())
        try:
            with ThreadPoolExecutor(max_workers=len(languages)) as pool:
                results = list(pool.map(lambda language: claim(language, scope, now), languages))
            require(results.count(True) == 1, "concurrent SDK processes accepted duplicate claims")
            print("Concurrent " + "/".join(languages) + " processes: exactly one claim", flush=True)
        finally:
            client.delete(key)
    finally:
        client.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validate-url", action="store_true")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--extended", action="store_true", help="All six server SDKs; build both SDK runners first")
    mode.add_argument("--extended-only", action="store_true", help="Python/Go/.NET/PHP; build extended runner first")
    args = parser.parse_args()
    url = test_url()
    if not args.validate_url:
        check(url, extended=args.extended, extended_only=args.extended_only)
