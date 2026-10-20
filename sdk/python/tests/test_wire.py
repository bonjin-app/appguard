"""Catch metadata/coverage loss at the real HTTP envelope boundary."""

import base64
import json
from dataclasses import asdict
from pathlib import Path

import pytest

from appguard.types import VerificationError
from appguard.wire import parse_signatures

ROOT = Path(__file__).resolve().parents[3]
CASES = json.loads((ROOT / "conformance/v0/http.json").read_text())


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
def test_shared_http_corpus(case):
    headers = tuple(tuple(pair) for pair in case["headers"])
    if case["expected_code"] != "PARSED":
        with pytest.raises(VerificationError, match=f'^{case["expected_code"]}$'):
            parse_signatures(headers)
    else:
        result = parse_signatures(headers)
        assert asdict(result.parameters) == case["expected"]["parameters"]
        assert base64.b64encode(result.signature).decode() == case["expected"]["signature_b64"]
