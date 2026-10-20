"""Pin the portable contract and detect corrupted/ambiguous fixture envelopes."""

import copy
import base64
import json
import shutil
import subprocess

import pytest
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from conftest import ROOT
from vector_runner import FixtureFormatError, load_vectors, run_vector, validate_coverage

CORPUS = ROOT / "conformance/v0/requests.json"


@pytest.fixture
def raw_vectors():
    return json.loads(CORPUS.read_text())


@pytest.mark.parametrize("record", load_vectors(CORPUS), ids=lambda record: record["id"])
def test_portable_conformance_corpus(record):
    assert run_vector(record) == record["expected_codes"], record["id"]


def test_review_focus_corpus_coverage():
    validate_coverage(load_vectors(CORPUS))


@pytest.mark.skipif(shutil.which("openssl") is None, reason="OpenSSL CLI not installed")
def test_fixed_signatures_independently_verify_with_openssl(tmp_path):
    checked = set()
    for record in load_vectors(CORPUS):
        if "VERIFIED" not in record["expected_codes"]:
            continue
        ident = (record["expected_signature_base"], record["signature_b64"], record["key"]["public_key_pem"])
        if ident in checked:
            continue
        signature = base64.b64decode(record["signature_b64"], validate=True)
        der = encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
        (tmp_path / "signature.der").write_bytes(der)
        (tmp_path / "base.bin").write_bytes(record["expected_signature_base"].encode("ascii"))
        (tmp_path / "key.pem").write_text(record["key"]["public_key_pem"], encoding="ascii")
        result = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(tmp_path / "key.pem"),
                                 "-signature", str(tmp_path / "signature.der"), str(tmp_path / "base.bin")],
                                capture_output=True, timeout=10)
        assert result.returncode == 0, f'{record["id"]}: independent signature check failed'
        checked.add(ident)
    assert len(checked) >= 4


def test_missing_review_focus_scenario_fails(raw_vectors):
    incomplete = [r for r in raw_vectors if r["id"] != "query-reordered"]
    with pytest.raises(FixtureFormatError):
        validate_coverage(incomplete)


@pytest.mark.parametrize("now", [True, 999999999999999])
def test_full_store_does_not_bypass_invalid_time_validation(raw_vectors, now):
    record = copy.deepcopy(raw_vectors[0])
    record["replay_store"] = "full"
    record["context"]["now"] = now
    record["expected_codes"] = ["INVALID_TIME"]
    assert run_vector(record) == ["INVALID_TIME"]


@pytest.mark.parametrize("mutation", ["duplicate-id", "unknown-root", "missing-field", "bad-base64",
                                      "base64-pad-bits", "unknown-request", "unknown-parameters",
                                      "unknown-key", "unknown-context", "invalid-store", "invalid-code",
                                      "empty-codes", "bad-headers", "bad-key-transport"])
def test_corrupted_fixture_envelope(tmp_path, raw_vectors, mutation):
    records = copy.deepcopy(raw_vectors)
    record = records[0]
    if mutation == "duplicate-id":
        records.append(copy.deepcopy(record))
    elif mutation == "unknown-root":
        record["extra"] = 1
    elif mutation == "missing-field":
        del record["request"]["target"]
    elif mutation == "bad-base64":
        record["signature_b64"] = "not-base64!"
    elif mutation == "base64-pad-bits":
        record["request"]["body_b64"] = "e31="  # decodes to {}, but canonical form is e30=
    elif mutation.startswith("unknown-"):
        record[mutation.removeprefix("unknown-")]["extra"] = 1
    elif mutation == "invalid-store":
        record["replay_store"] = "allow-all"
    elif mutation == "invalid-code":
        record["expected_codes"] = ["AUTHORIZED"]
    elif mutation == "empty-codes":
        record["expected_codes"] = []
    elif mutation == "bad-headers":
        record["request"]["headers"] = {"Authorization": "Bearer FAKE"}
    elif mutation == "bad-key-transport":
        record["key"]["public_key_pem"] = 1
    path = tmp_path / "corrupted.json"
    path.write_text(json.dumps(records))
    with pytest.raises(FixtureFormatError):
        load_vectors(path)


@pytest.mark.parametrize("text", ['[{"id":"a","id":"b"}]', '{"a":1,"a":2}', '[NaN]', '{}', 'null', '[]'])
def test_ambiguous_or_invalid_json_rejected(tmp_path, text):
    path = tmp_path / "bad.json"
    path.write_text(text)
    with pytest.raises(FixtureFormatError):
        load_vectors(path)


@pytest.mark.parametrize("change", ["expected-bytes", "expected-reason", "missing-expected-base"])
def test_runner_detects_contract_mismatch(raw_vectors, change):
    record = copy.deepcopy(raw_vectors[0])
    if change == "expected-bytes":
        record["expected_signature_base"] += "\n"
    elif change == "expected-reason":
        record["expected_codes"] = ["KEY_REJECTED"]
    else:
        record["expected_signature_base"] = None
    with pytest.raises(AssertionError):
        run_vector(record)
