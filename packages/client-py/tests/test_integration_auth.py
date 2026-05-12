"""Integration test for step 25 (bearer-token auth). Spawns
``uniclaw-host`` with ``--bearer-token-hex <token>`` and verifies:

- Without ``bearer_token`` on the client, /v1 calls return 401.
- With the WRONG ``bearer_token``, /v1 calls return 401.
- With the CORRECT ``bearer_token``, /v1 calls succeed.
- Read-only routes (``GET /receipts/<hash>`` / ``verify_receipt_url``)
  stay public.

Opt-in via ``UNICLAW_INTEGRATION=1``. The release binary at
``target/release/uniclaw-host`` must exist.
"""

from __future__ import annotations

import os
import re
import subprocess
import time
from pathlib import Path
from typing import Iterator

import pytest

from uniclaw_client import Action, UniclawClient, UniclawError

REPO_ROOT = Path(__file__).resolve().parents[3]
HOST_BIN = REPO_ROOT / "target" / "release" / "uniclaw-host"
FIXTURE = Path(__file__).parent / "fixtures" / "test-constitution.toml"
SEED_HEX = "2a" * 32
# Distinct token for this suite so it doesn't collide with the TS
# auth fixture's token.
TOKEN_HEX = "c3" * 32

INTEGRATION = os.environ.get("UNICLAW_INTEGRATION") == "1"

pytestmark = pytest.mark.skipif(
    not INTEGRATION,
    reason="set UNICLAW_INTEGRATION=1 and build the release binary to run integration tests",
)


@pytest.fixture(scope="module")
def authed_host_url() -> Iterator[str]:
    if not HOST_BIN.exists():
        pytest.skip(
            f"release binary missing at {HOST_BIN}; "
            f"run `cargo build --release --bin uniclaw-host -p uniclaw-host`",
        )
    proc = subprocess.Popen(
        [
            str(HOST_BIN),
            "--constitution",
            str(FIXTURE),
            "--signer-seed-hex",
            SEED_HEX,
            "--bearer-token-hex",
            TOKEN_HEX,
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
                        f"uniclaw-host exited early with code {proc.returncode}: {buf}",
                    )
                time.sleep(0.05)
                continue
            buf += line
            m = re.search(r"listening on (http://127\.0\.0\.1:\d+)", line)
            if m:
                url = m.group(1)
                break
        if url is None:
            pytest.fail(f"uniclaw-host did not bind within 10s; stderr so far: {buf}")
        yield url
    finally:
        proc.send_signal(2)
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()


def test_evaluate_without_token_returns_401(authed_host_url: str) -> None:
    client = UniclawClient(base_url=authed_host_url, verify_by_default=False)
    with pytest.raises(UniclawError) as exc:
        client.evaluate(Action(
            kind="http.fetch",
            target="https://example.com/no-auth",
            input_hash="00" * 32,
        ))
    assert exc.value.status == 401
    assert exc.value.code == "unauthorized"


def test_evaluate_with_wrong_token_returns_401(authed_host_url: str) -> None:
    client = UniclawClient(
        base_url=authed_host_url,
        verify_by_default=False,
        bearer_token="b6" * 32,  # right length, wrong bytes
    )
    with pytest.raises(UniclawError) as exc:
        client.evaluate(Action(
            kind="http.fetch",
            target="https://example.com/wrong-token",
            input_hash="00" * 32,
        ))
    assert exc.value.status == 401


def test_evaluate_with_correct_token_succeeds_and_verifies_cold(authed_host_url: str) -> None:
    client = UniclawClient(base_url=authed_host_url, bearer_token=TOKEN_HEX)
    d = client.evaluate(Action(
        kind="http.fetch",
        target="https://example.com/with-token",
        input_hash="00" * 32,
    ))
    assert d.kind == "allowed"


def test_read_only_routes_stay_public(authed_host_url: str) -> None:
    # Mint a receipt with auth, then fetch it without.
    authed = UniclawClient(base_url=authed_host_url, bearer_token=TOKEN_HEX)
    minted = authed.evaluate(Action(
        kind="http.fetch",
        target="https://example.com/public-fetch",
        input_hash="01" * 32,
    ))
    # No token configured on this client.
    reader = UniclawClient(base_url=authed_host_url, verify_by_default=False)
    receipt = reader.get_receipt(minted.content_id)
    assert receipt is not None
    result = reader.verify_receipt_url(minted.receipt_url)
    assert result.ok is True


def test_full_chain_works_with_auth(authed_host_url: str) -> None:
    client = UniclawClient(base_url=authed_host_url, bearer_token=TOKEN_HEX)
    allowed = client.evaluate(Action(
        kind="tool.http_fetch",
        target="https://api.example.com/auth-chain",
        input_hash="aa" * 32,
    ))
    assert allowed.kind == "allowed"
    exec_d = client.record_tool_execution(
        allowed_receipt_id=allowed.content_id,
        output_hash="bb" * 32,
    )
    assert exec_d.kind == "allowed"
    assert exec_d.sequence > allowed.sequence
