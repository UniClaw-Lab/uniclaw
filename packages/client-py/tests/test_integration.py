"""Integration test for ``boardproof_client``. Spawns a real
``boardproof-host`` subprocess in proposal-API mode, drives the client
through every decision flow, and asserts that the minted receipts
verify cold.

**Off by default.** Without ``BOARDPROOF_INTEGRATION=1``, the suite
skips. This keeps ``pytest`` working in environments where the Rust
toolchain isn't available.

The release binary must already exist at
``target/release/boardproof-host``. We don't run ``cargo build`` from
here — that's the developer's job, and CI does it explicitly.
"""

from __future__ import annotations

import os
import re
import subprocess
import time
from pathlib import Path
from typing import Iterator

import pytest

from boardproof_client import (
    Action,
    Redaction,
    RuleMatch,
    BoardProofClient,
    BoardProofError,
    BoardProofVerifyError,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
HOST_BIN = REPO_ROOT / "target" / "release" / "boardproof-host"
FIXTURE = Path(__file__).parent / "fixtures" / "test-constitution.toml"
SEED_HEX = "2a" * 32

INTEGRATION = os.environ.get("BOARDPROOF_INTEGRATION") == "1"

pytestmark = pytest.mark.skipif(
    not INTEGRATION,
    reason="set BOARDPROOF_INTEGRATION=1 and build the release binary to run integration tests",
)


@pytest.fixture(scope="module")
def host_url() -> Iterator[str]:
    if not HOST_BIN.exists():
        pytest.skip(
            f"release binary missing at {HOST_BIN}; "
            f"run `cargo build --release --bin boardproof-host -p boardproof-host`",
        )
    # Step 25: binary refuses proposal mode without explicit
    # auth choice. These tests don't exercise auth themselves
    # — see ``test_integration_auth.py`` for that — so we pass
    # --insecure-no-auth to stay on the prior code path.
    proc = subprocess.Popen(
        [
            str(HOST_BIN),
            "--constitution",
            str(FIXTURE),
            "--signer-seed-hex",
            SEED_HEX,
            "--insecure-no-auth",
            "--bind",
            "127.0.0.1:0",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    buf = ""
    url: str | None = None
    deadline = time.monotonic() + 10.0
    assert proc.stderr is not None
    try:
        while time.monotonic() < deadline:
            line = proc.stderr.readline()
            if not line:
                if proc.poll() is not None:
                    pytest.fail(
                        f"boardproof-host exited early with code {proc.returncode}: {buf}",
                    )
                time.sleep(0.05)
                continue
            buf += line
            m = re.search(r"listening on (http://127\.0\.0\.1:\d+)", line)
            if m:
                url = m.group(1)
                break
        if url is None:
            pytest.fail(f"boardproof-host did not bind within 10s; stderr so far: {buf}")
        yield url
    finally:
        proc.send_signal(2)  # SIGINT
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()


def test_evaluate_allowed_verifies_cold(host_url: str) -> None:
    c = BoardProofClient(base_url=host_url)
    d = c.evaluate(Action(kind="http.fetch", target="https://example.com/data", input_hash="00" * 32))
    assert d.kind == "allowed"
    assert d.receipt_url.startswith(host_url)
    assert len(d.content_id) == 64
    assert d.sequence == 0
    assert d.schema_version == 2


def test_evaluate_denied(host_url: str) -> None:
    c = BoardProofClient(base_url=host_url)
    d = c.evaluate(Action(kind="shell.exec", target="rm -rf /", input_hash="00" * 32))
    assert d.kind == "denied"


def test_pending_to_approved_chain_links(host_url: str) -> None:
    c = BoardProofClient(base_url=host_url)
    pending = c.evaluate(Action(
        kind="http.fetch",
        target="https://example.com/admin/secrets",
        input_hash="00" * 32,
    ))
    assert pending.kind == "pending"

    pending_full = c.get_receipt(pending.content_id)
    pending_leaf = pending_full["body"]["merkle_leaf"]["leaf_hash"]

    approved = c.resolve_approval(
        pending.content_id,
        principal="operator@example.com",
        outcome="approved",
    )
    assert approved.kind == "approved"

    approved_full = c.get_receipt(approved.content_id)
    assert approved_full["body"]["merkle_leaf"]["prev_hash"] == pending_leaf


def test_pending_to_denied(host_url: str) -> None:
    c = BoardProofClient(base_url=host_url)
    pending = c.evaluate(Action(
        kind="http.fetch",
        target="https://example.com/admin/other",
        input_hash="01" * 32,
    ))
    assert pending.kind == "pending"
    denied = c.resolve_approval(pending.content_id, principal="ops", outcome="denied")
    assert denied.kind == "denied"


def test_record_tool_execution_full_chain(host_url: str) -> None:
    c = BoardProofClient(base_url=host_url)
    allowed = c.evaluate(Action(
        kind="tool.http_fetch",
        target="https://api.example.com/data",
        input_hash="aa" * 32,
    ))
    assert allowed.kind == "allowed"

    allowed_full = c.get_receipt(allowed.content_id)
    allowed_leaf = allowed_full["body"]["merkle_leaf"]["leaf_hash"]

    execution = c.record_tool_execution(
        allowed_receipt_id=allowed.content_id,
        output_hash="bb" * 32,
        secrets_used=["github.token"],
        redaction=Redaction(
            redacted_output_hash="cc" * 32,
            stack_hash="dd" * 32,
            matches=(RuleMatch(rule_id="github_pat", count=1),),
        ),
    )
    assert execution.kind == "allowed"
    assert execution.sequence > allowed.sequence

    exec_full = c.get_receipt(execution.content_id)
    assert exec_full["body"]["merkle_leaf"]["prev_hash"] == allowed_leaf
    assert exec_full["body"]["action"]["kind"] == "$kernel/tool/executed"
    assert exec_full["body"]["redactor_stack_hash"] == "dd" * 32

    kinds = [edge["kind"] for edge in exec_full["body"]["provenance"]]
    assert "tool_execution" in kinds
    assert "secret_used" in kinds
    assert "redaction_applied" in kinds
    assert "tool_output" in kinds
    output_edge = next(e for e in exec_full["body"]["provenance"] if e["kind"] == "tool_output")
    assert output_edge["to"].endswith("cc" * 32)


def test_record_tool_execution_failure_path(host_url: str) -> None:
    c = BoardProofClient(base_url=host_url)
    allowed = c.evaluate(Action(
        kind="tool.http_fetch",
        target="https://api.example.com/fail",
        input_hash="33" * 32,
    ))
    assert allowed.kind == "allowed"
    exec_d = c.record_tool_execution(
        allowed_receipt_id=allowed.content_id,
        error="tool host reported failure",
    )
    assert exec_d.kind == "allowed"
    exec_full = c.get_receipt(exec_d.content_id)
    assert "status=failed" in exec_full["body"]["action"]["target"]
    kinds = [edge["kind"] for edge in exec_full["body"]["provenance"]]
    assert "tool_execution_failure" in kinds


def test_record_tool_execution_409_on_non_tool_action(host_url: str) -> None:
    c = BoardProofClient(base_url=host_url, verify_by_default=False)
    allowed = c.evaluate(Action(
        kind="http.fetch",  # not tool.*
        target="https://example.com/conflict",
        input_hash="11" * 32,
    ))
    assert allowed.kind == "allowed"
    with pytest.raises(BoardProofError) as exc:
        c.record_tool_execution(
            allowed_receipt_id=allowed.content_id,
            output_hash="22" * 32,
        )
    assert exc.value.status == 409


def test_verify_by_default_catches_tampered_receipt(host_url: str) -> None:
    """Mint a real receipt, then construct a client whose GET path
    returns a tampered receipt. verify-by-default should reject."""
    import io
    import json
    import urllib.request
    from unittest.mock import patch

    c = BoardProofClient(base_url=host_url, verify_by_default=False)
    real = c.evaluate(Action(
        kind="http.fetch",
        target="https://example.com/tamper",
        input_hash="ff" * 32,
    ))
    assert real.kind == "allowed"

    original_urlopen = urllib.request.urlopen

    def tampering_urlopen(req: object, **kwargs: object) -> object:
        result = original_urlopen(req, **kwargs)
        # Only tamper with /receipts/<hash> GETs.
        full_url = getattr(req, "full_url", "")
        if "/receipts/" in str(full_url):
            text = result.read().decode("utf-8")
            obj = json.loads(text)
            obj["body"]["decision"] = "denied"  # tamper

            class _FakeResp:
                def __init__(self, payload: bytes) -> None:
                    self.status = 200
                    self._payload = payload

                def read(self) -> bytes:
                    return self._payload

                def __enter__(self) -> "_FakeResp":
                    return self

                def __exit__(self, *_exc: object) -> None:
                    pass

            return _FakeResp(json.dumps(obj).encode("utf-8"))
        return result

    with patch("urllib.request.urlopen", side_effect=tampering_urlopen):
        evil = BoardProofClient(base_url=host_url, verify_by_default=True)
        with pytest.raises(BoardProofVerifyError):
            evil.evaluate(Action(
                kind="http.fetch",
                target="https://example.com/tamper-trip",
                input_hash="ee" * 32,
            ))


def test_400_error_surfaces(host_url: str) -> None:
    c = BoardProofClient(base_url=host_url, verify_by_default=False)
    with pytest.raises(BoardProofError) as exc:
        c.evaluate(Action(kind="http.fetch", target="x", input_hash="not-hex"))
    assert exc.value.status == 400
    assert exc.value.code == "bad_request"


def test_404_on_unknown_approval(host_url: str) -> None:
    c = BoardProofClient(base_url=host_url, verify_by_default=False)
    with pytest.raises(BoardProofError) as exc:
        c.resolve_approval("ab" * 32, principal="ops", outcome="approved")
    assert exc.value.status == 404
    assert exc.value.code == "not_found"
