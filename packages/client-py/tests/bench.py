"""Bench harness for ``boardproof_client``. Spawns ``boardproof-host`` and
measures end-to-end ``BoardProofClient.evaluate()`` /
``record_tool_execution()`` latency under three modes:

  (a) verify=True   — submit + verify by re-fetching + recheck
  (b) verify=False  — submit only (faster)
  (c) raw HTTP POST (urllib, no client, no verify) — keepalive
      baseline

Plus the same comparison for tool-execution and a full
propose+record chain.

Run::

    cargo build --release --bin boardproof-host -p boardproof-host
    python tests/bench.py

Output goes to stdout; redirect to ``bench-results/24-python-client.txt``.
"""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from boardproof_client import Action, BoardProofClient

REPO_ROOT = Path(__file__).resolve().parents[3]
HOST_BIN = REPO_ROOT / "target" / "release" / "boardproof-host"
FIXTURE = Path(__file__).parent / "fixtures" / "test-constitution.toml"
SEED_HEX = "2a" * 32
# Bench-only token. Set via env BENCH_TOKEN_HEX="..." to use a
# specific token; defaults to a fixed pattern. Either way the
# bench measures the auth-enabled path so the numbers reflect
# production-style deployments.
BENCH_TOKEN_HEX = os.environ.get("BENCH_TOKEN_HEX") or ("c3" * 32)


def start_host() -> tuple[subprocess.Popen[str], str]:
    if not HOST_BIN.exists():
        print(f"missing {HOST_BIN} — run cargo build --release first", file=sys.stderr)
        sys.exit(2)
    proc = subprocess.Popen(
        [
            str(HOST_BIN),
            "--constitution", str(FIXTURE),
            "--signer-seed-hex", SEED_HEX,
            "--bearer-token-hex", BENCH_TOKEN_HEX,
            "--bind", "127.0.0.1:0",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    buf = ""
    deadline = time.monotonic() + 10.0
    assert proc.stderr is not None
    while time.monotonic() < deadline:
        line = proc.stderr.readline()
        if not line:
            time.sleep(0.05)
            continue
        buf += line
        m = re.search(r"listening on (http://127\.0\.0\.1:\d+)", line)
        if m:
            return proc, m.group(1)
    raise SystemExit("boardproof-host did not bind within 10s")


def time_run(label: str, fn, n: int) -> dict[str, float | str | int]:
    # Warm-up.
    for _ in range(5):
        fn()
    t0 = time.monotonic()
    for _ in range(n):
        fn()
    dt = time.monotonic() - t0
    return {
        "label": label,
        "n": n,
        "total_ms": dt * 1000,
        "per_req_ms": dt * 1000 / n,
    }


def fmt(r: dict[str, float | str | int]) -> str:
    return f"  {str(r['label']).ljust(40)} N={r['n']}  total={r['total_ms']:.1f}ms  per-req={r['per_req_ms']:.3f}ms"


def main() -> None:
    proc, base_url = start_host()
    try:
        n = 200
        action = Action(kind="http.fetch", target="https://example.com/bench", input_hash="00" * 32)
        tool_action = Action(kind="tool.http_fetch", target="https://example.com/bench-tool", input_hash="11" * 32)

        c_verify = BoardProofClient(base_url=base_url, bearer_token=BENCH_TOKEN_HEX)
        c_no_verify = BoardProofClient(
            base_url=base_url,
            verify_by_default=False,
            bearer_token=BENCH_TOKEN_HEX,
        )

        # (a) evaluate verify=True
        r1 = time_run(
            "client.evaluate verify=True",
            lambda: c_verify.evaluate(action),
            n,
        )

        # (b) evaluate verify=False
        r2 = time_run(
            "client.evaluate verify=False",
            lambda: c_no_verify.evaluate(action),
            n,
        )

        # (c) raw HTTP POST baseline
        proposal_payload = json.dumps({
            "action": {
                "kind": action.kind,
                "target": action.target,
                "input_hash": action.input_hash,
            }
        }).encode("utf-8")

        def raw_post() -> None:
            # Bench host runs with --bearer-token-hex; raw baseline
            # must include the Authorization header too so it's an
            # apples-to-apples comparison with the client paths.
            req = urllib.request.Request(
                f"{base_url}/v1/proposals",
                method="POST",
                data=proposal_payload,
                headers={
                    "content-type": "application/json",
                    "authorization": f"Bearer {BENCH_TOKEN_HEX}",
                },
            )
            with urllib.request.urlopen(req, timeout=5) as r:
                r.read()

        r3 = time_run("raw urllib POST /v1/proposals", raw_post, n)

        # (d) Pre-mint pool of Allowed tool receipts and measure
        # record_tool_execution alone.
        pool_n = n + 5
        allowed_ids: list[str] = []
        for _ in range(pool_n):
            d = c_no_verify.evaluate(tool_action)
            if d.kind != "allowed":
                raise RuntimeError(f"unexpected: {d.kind}")
            allowed_ids.append(d.content_id)
        cursor = [0]

        def record_one() -> None:
            i = cursor[0]
            cursor[0] += 1
            c_no_verify.record_tool_execution(
                allowed_receipt_id=allowed_ids[i],
                output_hash="22" * 32,
            )

        r4 = time_run(
            "client.record_tool_execution verify=False",
            record_one,
            n,
        )

        # (e) Full chain: evaluate + record, both verify=True.
        def chain() -> None:
            allowed = c_verify.evaluate(tool_action)
            if allowed.kind != "allowed":
                raise RuntimeError(f"unexpected: {allowed.kind}")
            c_verify.record_tool_execution(
                allowed_receipt_id=allowed.content_id,
                output_hash="22" * 32,
            )

        r5 = time_run("propose+record chain (both verify=True)", chain, n // 2)

        print("=== boardproof-client (Python) end-to-end latency bench ===")
        print(f"baseUrl={base_url}")
        print(f"python={sys.version.split()[0]}")
        print(f"host bin={HOST_BIN}")
        print()
        for r in (r1, r2, r3, r4, r5):
            print(fmt(r))
        print()
        print("verify-overhead = (verify=True) - (verify=False)")
        print(f"  = {r1['per_req_ms'] - r2['per_req_ms']:.3f} ms/req")
        print("client-overhead = (verify=False) - (raw urllib)")
        print(f"  = {r2['per_req_ms'] - r3['per_req_ms']:.3f} ms/req")
        print(f"record_tool_execution verify=False: {r4['per_req_ms']:.3f} ms/req")

    finally:
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    main()
