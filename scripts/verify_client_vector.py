"""Test-only JSON transport for independently generated native client requests."""

import base64
import json
import os
from pathlib import Path
import subprocess
import sys

from appguard import KeyRecord, RequestInput, SignatureParameters, VerificationError, verify_request
from appguard.replay import InMemoryReplayStore
from appguard.wire import parse_signatures


ROOT = Path(__file__).resolve().parents[1]


def java_consumer():
    sdk = ROOT / "sdk/spring-boot"
    classes = ROOT / ".superpowers/mobile-tools/client-verifier"
    classes.mkdir(parents=True, exist_ok=True)
    classpath = os.pathsep.join((str(classes), str(sdk / "target/appguard-spring-boot-starter-0.1.0-SNAPSHOT.jar"),
                                (sdk / "target/test-classpath.txt").read_text().strip()))
    subprocess.run(["javac", "-cp", classpath, "-d", str(classes), str(ROOT / "scripts/VerifyClientVector.java")], check=True, timeout=30)
    return classpath


def check(value, classpath):
    raw = json.dumps(value).encode("utf-8")
    r, c = value["request"], value["context"]
    request = RequestInput(r["method"], r["target"], tuple(tuple(pair) for pair in r["headers"]), base64.b64decode(r["body_b64"], validate=True))
    parameters = SignatureParameters(**value["parameters"])
    signature = base64.b64decode(value["signature_b64"], validate=True)
    parsed = parse_signatures(request.headers)
    assert parsed.parameters == parameters and parsed.signature == signature
    key = KeyRecord(**{**value["key"], "public_key_pem": value["key"]["public_key_pem"].encode("ascii")})
    context = {**c, "key": key, "replay": InMemoryReplayStore()}
    assert verify_request(request, parameters, signature, **context).code == "VERIFIED"
    try:
        verify_request(request, parameters, signature, **context)
    except VerificationError as error:
        assert error.code == "REPLAY_DETECTED"
    else:
        raise AssertionError("native request replay accepted")
    variants = [RequestInput(request.method, request.target, request.headers, request.body + b"!"),
                RequestInput(request.method, "/different-target", request.headers, request.body),
                RequestInput(request.method, request.target, tuple((k, "Bearer OTHER_TOKEN" if k.lower() == "authorization" else v)
                             for k, v in request.headers), request.body)]
    for changed in variants:
        try:
            verify_request(changed, parameters, signature, **{**context, "replay": InMemoryReplayStore()})
        except VerificationError:
            pass
        else:
            raise AssertionError("mutated native request accepted")
    print("PYTHON_NATIVE_CLIENT_VERIFIED_REPLAY_AND_MUTATIONS_REJECTED", flush=True)
    subprocess.run(["node", str(ROOT / "scripts/verify_client_vector.mjs")], input=raw, cwd=ROOT, check=True, timeout=15)
    subprocess.run(["java", "-cp", classpath, "VerifyClientVector"], input=raw, cwd=ROOT, check=True, timeout=15)


if __name__ == "__main__":
    classpath = java_consumer()
    for path in sys.argv[1:]:
        raw = Path(path).read_bytes()
        if len(raw) > 2 * 1024 * 1024:
            raise ValueError("test vectors too large")
        values = json.loads(raw)
        if type(values) is not list:
            values = [values]
        if not 1 <= len(values) <= 100:
            raise ValueError("invalid test vector count")
        for value in values:
            check(value, classpath)
        print(f"{Path(path).name}: {len(values)} vectors accepted by all three server verifiers", flush=True)
