# Phase 3.5 Step 26 — Persistence in proposal mode

> **Phase:** 3.5 — Receipt-format hardening + adoption-foundations
> **PR:** _this PR_
> **Crates touched:** `boardproof-host` (api + bin)
> **No new crate, no schema change, no client change.**

## What is this step?

Before this PR, `boardproof-host --constitution <path>` (proposal mode) and `boardproof-host --db <path>` (persistent mode) were **mutually exclusive**. Proposal mode used `InMemoryReceiptLog` only; restart the host and every minted receipt's URL went 404.

That was the single largest deployment blocker for everything we've shipped since step 21:

- Step 21 ships an HTTP proposal API → restart = lost API history.
- Step 22 + 24 ship TS + Python clients → callers can't trust the URLs they got back across the operator's next deploy.
- Step 25 ships authentication → you can safely expose the sidecar, but only for a single process lifetime.
- Step 19a ships `key_id` → you can name keys, but a key only outlives one process if its receipts do.

Step 26 unblocks all of it. `boardproof-host --constitution <path> --db <path>` now works together: the kernel mints over HTTP, every minted receipt is persisted to a `SqliteReceiptLog`, and on restart the kernel **resumes its state from the log's head** so the chain continues seamlessly at the next sequence number.

```
$ boardproof-host \
    --constitution constitutions/solo-dev.toml \
    --signer-seed-hex $SIGNER_SEED \
    --bearer-token-hex $TOKEN \
    --key-id "prod-2026" \
    --db /var/lib/boardproof/receipts.db \
    --bind 0.0.0.0:8787

# (mint some receipts via /v1/proposals)
# kill -INT, redeploy, restart with the same flags

# Every prior /receipts/<hash> URL still resolves.
# New receipts mint at sequence = (last + 1), prev_hash = (last leaf).
```

This is the **first production-deployable** state for BoardProof — restart-safe, auth-gated, key-identified, persistent.

## Where does this fit in the whole BoardProof?

Step 26 is the final foundation layer before threshold 3 (adoption) gets a real test. After this:

- A real claw can integrate (`@boardproof/client` / `boardproof-client`) against a sidecar that survives ops events.
- A hosted `demo.boardproof.dev` instance becomes operationally credible.
- Compliance use cases (SOC 2 evidence chains) can rely on the chain across business days.
- Key rotation (Phase 6) lands on a chain that doesn't reset between rotations.

```
Boot 1                         |  Restart  |  Boot 2
─────────────────────────────────────────────────────────────────
fresh Kernel::new (sequence=0) |           |  Kernel::resume from log
mint A → sequence=0            |           |    state.sequence = 3
mint B → sequence=1            |  SIGINT   |    state.prev_hash  = C.leaf_hash
mint C → sequence=2            |  SQLite   |
                               |  intact   |  mint D → sequence=3 ✓
                               |           |    prev_hash links to C ✓
                               |           |
GET /receipts/<C.hash> 200 OK ─────────────|  GET /receipts/<C.hash> 200 OK
                                              GET /receipts/<A.hash> 200 OK
```

## What problem does it solve technically?

### 1. "Why was proposal mode in-memory only?"

Step 21 deliberately punted persistence because the cleanest first cut of the HTTP API needed `ApiState` to hold a concrete log type for axum's state extractor. Generic over `L: ReceiptLog` propagates through every handler signature; the simplest pre-26 path was `ApiState` concrete on `InMemoryReceiptLog`.

Step 26 pays that complexity tax: `ApiState<L>` becomes generic; every handler signature gains `<L: ReceiptLog + Send + Sync + 'static>`. The pattern matches the read-only `router<L>(log)` that's existed since step 9, so the cost is bounded.

### 2. "Why does Kernel::new not work after restart?"

The kernel carries `KernelState { sequence, prev_hash }` (see `crates/boardproof-kernel/src/state.rs`). `Kernel::new` calls `KernelState::genesis()` — `sequence = 0`, `prev_hash = [0u8; 32]`. After a restart against a populated `SqliteReceiptLog`, the kernel would mint at sequence 0 again and the log would reject with `AppendError::OutOfOrder { expected: 3, got: 0 }`.

Fix: a small helper `api::build_kernel_from_log(&log, signer, constitution)`:

```rust
match log.last() {
    Some(last) => {
        let state = KernelState {
            sequence: last.body.merkle_leaf.sequence + 1,
            prev_hash: last.body.merkle_leaf.leaf_hash,
        };
        Kernel::resume(state, signer, SystemClock, constitution)
    }
    None => Kernel::new(signer, SystemClock, constitution),
}
```

The binary calls this once at startup. Empty log → genesis state (byte-identical to pre-step-26 hosts). Non-empty log → resume.

### 3. "How does SQLite-mode handle issuer mismatch?"

The DB pins one issuer in its meta table at first open. Re-opening with a DIFFERENT pubkey is a chain-integrity failure: either the operator rotated keys without using `--key-id`-style aliasing, or they're pointing the wrong key at the wrong DB.

The binary checks `SqliteReceiptLog::peek_issuer(db_path)` BEFORE calling `open` so it can produce a helpful error:

```
$ boardproof-host --constitution ... --signer-seed-hex <NEW> --db /var/lib/boardproof/receipts.db
Error: kernel signing key (issuer 197f6b23…) does not match the pinned issuer
       of the SQLite log at /var/lib/boardproof/receipts.db (issuer ab12cd34…).
       Refusing to fork the chain. Use the original signing seed, or start a new
       DB at a different path.
```

If the operator gets past `peek_issuer` somehow, `SqliteReceiptLog::open` itself also rejects mismatched issuers — belt-and-suspenders.

### 4. "What about the wire format?"

**Unchanged.** Receipts on the wire are identical whether the backing log is in-memory or SQLite. The clients (`@boardproof/client`, `boardproof-client`) need no changes; their tests pass against the new release binary without modification.

## How does it work in plain words?

Three changes, all in `crates/boardproof-host`:

1. **`api::ApiState` becomes generic over `L`.** Every `/v1` handler signature gains `<L: ReceiptLog + Send + Sync + 'static>`. Existing tests (in-memory) compile unchanged because Rust's type inference picks up `InMemoryReceiptLog` from the test fixture.
2. **New helper `api::build_kernel_from_log`.** Threads through `log.last()` to decide between `Kernel::new` (empty log) and `Kernel::resume` (non-empty). Used by the binary AND by the new SQLite tests.
3. **Binary `bin/boardproof-host.rs` allows `--constitution` + `--db` together.** The path was previously a hard `bail!`; now it dispatches to `serve_proposal_mode<L>` with either `InMemoryReceiptLog` (existing default) or `SqliteReceiptLog` (`--db` supplied). The SQLite path runs an issuer-pin pre-check via `peek_issuer` for a clean error message.

## What you can do with this step today

Deploy proposal mode against a persistent SQLite log:

```bash
# Generate auth token + signing seed once.
TOKEN=$(head -c 32 /dev/urandom | xxd -p -c 64)
SEED=$(head -c 32 /dev/urandom | xxd -p -c 64)

# First boot.
boardproof-host \
    --constitution constitutions/solo-dev.toml \
    --signer-seed-hex $SEED \
    --bearer-token-hex $TOKEN \
    --key-id "prod-2026" \
    --db /var/lib/boardproof/receipts.db \
    --bind 0.0.0.0:8787
```

Mint some receipts via `POST /v1/proposals`. Operator restarts the host (deploy, kernel patch, oom-killer, whatever):

```bash
# Same flags. The chain continues at the next sequence number.
boardproof-host \
    --constitution constitutions/solo-dev.toml \
    --signer-seed-hex $SEED \
    --bearer-token-hex $TOKEN \
    --key-id "prod-2026" \
    --db /var/lib/boardproof/receipts.db \
    --bind 0.0.0.0:8787
```

Every previously-published `/receipts/<hash>` URL still 200s. Auditors can still cold-verify them.

## Verified during this PR

- **4 new Rust integration tests in `tests/api.rs`** (Rust test count: 423 → 427):
  - `sqlite_backed_proposal_mints_and_persists_across_drop`: mint → drop the app/log → reopen the same DB → fetch the receipt → 200 OK + signature verifies.
  - `sqlite_backed_proposal_chain_continues_across_reopen`: 3 mints (sequence 0, 1, 2) → drop → reopen → mint another (sequence 3) → `prev_hash` of the new receipt equals `leaf_hash` of receipt 2.
  - `sqlite_backed_proposal_with_tool_execution_persists`: full propose → record-tool-execution flow → drop → reopen → execution receipt fetchable + `secret_used` provenance edge intact.
  - `sqlite_reopen_with_wrong_issuer_is_caught_by_peek_issuer`: original DB pinned to issuer A → `peek_issuer` reveals A → `open` with wrong pubkey fails (belt-and-suspenders).
- **Existing tests unchanged.** All 36 prior `tests/api.rs` tests continue to pass without type annotations — Rust's type inference picks up `InMemoryReceiptLog` from the fixture helper.
- **All four CI-flag Rust gates clean** (every exit code explicitly checked, never piped before the check — the lesson from CI #29 + CI #33):
  - `cargo fmt --all -- --check` → exit 0
  - `cargo build --workspace --all-targets` → exit 0
  - `cargo test --workspace` → 427/427, exit 0
  - `cargo clippy --workspace --all-targets -- -D warnings` → exit 0
- **Cross-language smoke against the fresh release binary**: TS 52/52 + Python 84/84 with integration enabled (`BOARDPROOF_INTEGRATION=1`). The clients run unchanged — wire format is identical.
- **Bench** (`bench-results/26-proposal-mode-persistence.txt`):
  - In-memory mode: 13.3 ms/req (HTTP keepalive, 200 sequential POST `/v1/proposals`).
  - SQLite mode: **7.1 ms/req** (faster on this run — cross-process system noise dominates the difference; both well below any meaningful latency budget).
  - Restart-survival demonstrated end-to-end: pre-restart mint at sequence 0 → SIGINT → respawn with same `--db` → `GET /receipts/<hash>` returns 200 → next mint at sequence 1 with `prev_hash` linking to the persisted leaf.

## Adopt-don't-copy

- No source borrowed.
- The `Kernel::resume(state, ...)` API was already in `boardproof-kernel` (since the kernel state-machine sketch in step 1) — this PR is the first real consumer.
- `SqliteReceiptLog`'s WAL-mode locking + `peek_issuer` helper already shipped in step 10.

## What this step does **not** ship

- **Restart-resumption of pending approvals across processes.** A `Pending` receipt minted before a restart is still retrievable via `GET /receipts/<hash>` after the restart, but the caller-side state — the `(pending_receipt, original_proposal)` pair needed for `POST /v1/approvals/{id}/resolve` — is whatever the caller stored. The kernel doesn't materialize approval state from the log; that's caller orchestration. (Most operator UIs already persist this; the protocol just demands the pair on the wire.)
- **Multi-host federation.** `SqliteReceiptLog` is single-writer. Concurrent host instances against the same DB would race. Multi-host is Phase 4 work.
- **Online backup / replication.** Operators back up the `.db` file with normal SQLite tooling (`.backup`, `litestream`, filesystem snapshots).
- **Schema migrations.** The SQLite schema is rev 1 (set in step 10). When a future change adds a column, we'll ship a migration step.
- **Hot reload of the constitution.** Operators restart with the new TOML; the chain continues.

## Performance / size

Same numbers as the bench above. No new dependencies (everything was already in the workspace since step 10). Binary size for `boardproof-host` stripped: ~6.5 MB (unchanged — `rusqlite` was already linked).

## In summary

Step 26 closes the last remaining production-readiness gap. The HTTP API can be exposed (step 25), the signing key can be named (step 19a), every step of an agent action is anchored (step 23), three languages can integrate (steps 20a/22/24), and **now the chain survives restart**.

Threshold status:

- ✅ Threshold 1 (portability) — closed by 20a + 24, exercised by 19a.
- ✅ Threshold 2 (visibility) — closed by 20.
- 🟢 Threshold 3 (adoption) — adapter in 2 languages + auth-ready API + named keys + **persistent chain**. The sidecar is now genuinely deployable.

Next: any of `npm publish` / `pip publish` (operations; makes T1 literal), key directory service (companion to 19a), step 19b (witness signatures + chain checkpoints), a worked cross-claw demo, or — finally — the first real cross-claw integration (NemoClaw is the obvious target). All of them are easier once the sidecar can be deployed for real.
