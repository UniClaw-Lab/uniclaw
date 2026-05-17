"""Cross-language conformance test. Loads
``crates/boardproof-receipt/tests/vectors/canonical-v2.json`` — the
SAME fixture Rust and ``packages/verifier-ts`` load — and asserts
that every vector's canonical bytes and BLAKE3 hash match.

If this passes in all three implementations, they agree byte-for-byte.
If it fails, whichever language drifted gets caught here first.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from boardproof_client._canonical import canonicalize_jcs
from boardproof_client.verify import compute_content_id_hex

REPO_ROOT = Path(__file__).resolve().parents[3]
FIXTURE = (
    REPO_ROOT
    / "crates"
    / "boardproof-receipt"
    / "tests"
    / "vectors"
    / "canonical-v2.json"
)


def _load_fixture() -> dict[str, Any]:
    data: Any = json.loads(FIXTURE.read_text())
    if not isinstance(data, dict):
        pytest.fail(f"fixture {FIXTURE} did not deserialize to a dict")
    assert data.get("format") == "boardproof-canonical-v2", (
        f"unexpected fixture format: {data.get('format')!r}"
    )
    return data


def test_fixture_loads() -> None:
    fixture = _load_fixture()
    assert len(fixture["vectors"]) >= 5


@pytest.mark.parametrize("vector", _load_fixture()["vectors"], ids=lambda v: str(v["name"]))
def test_canonical_bytes_match(vector: dict[str, Any]) -> None:
    canonical_str = canonicalize_jcs(vector["body"])
    canonical_hex = canonical_str.encode("utf-8").hex()
    assert canonical_hex == vector["canonical_hex"], (
        f"canonical-bytes drift on vector {vector['name']!r}"
    )


@pytest.mark.parametrize("vector", _load_fixture()["vectors"], ids=lambda v: str(v["name"]))
def test_blake3_content_id_matches(vector: dict[str, Any]) -> None:
    content_id_hex = compute_content_id_hex(vector["body"])
    assert content_id_hex == vector["blake3_hex"], (
        f"BLAKE3 content_id drift on vector {vector['name']!r}"
    )
