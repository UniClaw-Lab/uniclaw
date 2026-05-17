# Phase 3.5 Step 19a — `key_id` field on receipts

> **Phase:** 3.5 — Receipt-format hardening + adoption-foundations
> **PR:** _this PR_
> **Spec change:** RFC-0001 rev **2.1** (wire `schema_version` stays `2`; additive optional field)
> **Crates / packages touched:** `boardproof-receipt`, `boardproof-kernel`, `boardproof-host` (api + bin + signer), `packages/verifier-ts`, `packages/client-ts`, `packages/client-py`. **Conformance fixture (`canonical-v2.json`) gains 2 new vectors.**

## What is this step?

Today a BoardProof receipt embeds an `issuer` — 32 bytes of Ed25519 public key. That's enough to verify the signature, but it has no name. Production deployments rotate keys; without a name for the key, every rotation either:
- forks the chain (new issuer = new pinned issuer = new log), or
- silently swaps the key bytes underneath the same log (auditors have no idea something changed).

Step 19a fixes that. Receipts can now carry an optional `key_id` — an opaque, operator-chosen string identifying which key signed each receipt. A receipt issued by `"prod-2026"` and the same logical action issued by `"hsm-3"` produce **different content_ids** because the field is part of the signed body. An external key directory (out of scope for this step) maps `key_id → (public_key, valid_from, valid_until, revocation_status)`, and auditors correlate receipts via the `key_id`.

The change is fully additive:

- Receipts minted by signers **without** a `key_id` (the v0.x default) are byte-identical to pre-19a output. No old receipts re-canonicalize differently. No verifier needs an upgrade to keep validating pre-19a chains.
- Receipts minted by signers **with** a `key_id` include the field in canonical bytes (JCS sorts it between `"issued_at"` and `"merkle_leaf"`). Any pre-19a verifier built with a permissive JSON parser will still verify them — the new field is in the canonical bytes the signature covers.

## Where does this fit in the whole BoardProof?

Step 19a is the first **post-multi-language schema-additive change**. The two reasons that's important:

1. **It validates the conformance machinery against a real change.** Three implementations (Rust kernel, TS verifier, Python verifier) all load the same `canonical-v2.json` fixture. We added 2 new vectors with `key_id` set; all three implementations re-canonicalize them to byte-identical output and re-compute the same BLAKE3 hashes. **If the architecture works here, it works for every future additive change** (`witness_signatures`, `chain_checkpoint`, federated-memory provenance, etc.).
2. **It's the foundation for Phase 6 governance.** Key rotation procedures, revocation, expiry — all build on `key_id`. Without a name for the key, governance is impossible.

```
                ┌────────────────────────────────┐
                │  Operator's key directory      │
                │  (out of scope for step 19a)   │
                │                                │
                │  prod-2026 → 0x197f6b... valid │
                │  prod-2027 → 0x... valid       │
                │  hsm-3     → 0x... REVOKED     │
                └────────────────┬───────────────┘
                                 │ correlate via key_id
                                 ▼
              ┌──────────────────────────────────┐
              │  Receipt                         │
              │    body.issuer  = "0x197f6b..."  │  ← trust anchor (bytes)
              │    body.key_id  = "prod-2026"    │  ← audit-only label (string)
              │    body.signature = ...          │
              └──────────────────────────────────┘
```

## What problem does it solve technically?

### 1. "Which of my keys signed this receipt?"

Before: read the receipt's `issuer` (32 bytes), compare against your set of historical keys, deduce which deployment minted it. Tedious; ambiguous if two keys were live at different times.

After: read `body.key_id`. Done.

### 2. "How do I rotate the kernel's signing key without breaking the chain?"

Before: you can't, really. New key = new pubkey = the existing chain's pinned issuer doesn't match anymore. Old receipts still verify under their own embedded pubkey, but the storage layer (`InMemoryReceiptLog` / `SqliteReceiptLog`) pins ONE issuer and rejects any receipt whose `issuer` field differs.

After: rotation is still a chain boundary (the storage layer's pin is unchanged in this PR), but with `key_id` the AUDIT path makes the rotation visible — receipts under `"prod-2026"` correlate to one entry in the key directory; under `"prod-2027"` to the next. A follow-up step can teach the storage layer to accept multiple pinned issuers when each carries a `key_id` matching the directory.

### 3. "Why is `key_id` in the body and not the wrapper?"

The wrapper (`Receipt { version, body, issuer, signature }`) is unsigned. Anything outside `body` can be mutated by anyone with the receipt — including by the operator after the fact. `key_id` is meaningful only when it's *signed* — when the kernel commits to it as part of the canonical bytes.

That's why `key_id` lives on `ReceiptBody`. Tampering with it after signing breaks verification, just like tampering with `decision` or `output_hash` does.

### 4. "How does `key_id` ride through JCS canonicalization?"

JCS sorts object keys lexicographically (UTF-16 code-unit order). `"key_id"` sorts between `"issued_at"` and `"merkle_leaf"`. Adding the field to a receipt only changes the canonical bytes if the field is *present* (Rust `#[serde(skip_serializing_if = "Option::is_none")]`; TS/Python JCS omit the key when absent in the parsed object). The schema_version stays at 2 because the wire shape is backward-compatible.

The conformance fixture has 7 vectors now (was 5):

- `[0]` minimal-allowed
- `[1]` denied-with-rule
- `[2]` with-provenance-edges
- `[3]` with-redactor-stack-hash
- `[4]` pending-approval
- `[5]` **with-key-id-prod-2026** *(new)* — Allowed receipt; `body.key_id = "prod-2026"`
- `[6]` **tool-execution-with-key-id-hsm-3** *(new)* — `$kernel/tool/executed` receipt with `body.key_id = "hsm-3"` and a `tool_execution` provenance edge

All three implementations (Rust + TS + Python) produce byte-identical canonical bytes AND byte-identical BLAKE3 content_ids for every vector. **The architecture survived its first multi-language additive change.**

## How does it work in plain words?

**Rust crate `boardproof-receipt`:**
- `ReceiptBody` gains `pub key_id: Option<String>` with `#[serde(default, skip_serializing_if = "Option::is_none")]`. Old receipts (no field) deserialize to `None`; new receipts with the field deserialize to `Some(...)`. Serialization omits `None`. JCS handles the rest.

**Rust crate `boardproof-kernel`:**
- The `Signer` trait gains `fn key_id(&self) -> Option<&str> { None }` (default impl returns None, so existing Signer impls are unaffected).
- `Kernel::mint()` reads `self.signer.key_id()` and threads it into the minted body.

**Rust crate `boardproof-host` (signer + binary):**
- `Ed25519Signer` is reshaped: `struct Ed25519Signer { key: SigningKey, key_id: Option<String> }`. Builder methods `with_key_id(impl Into<String>)` and `without_key_id()`. The existing `new(key)` and `from_seed(seed)` constructors continue to return signers with `key_id: None` (backward compat).
- `bin/boardproof-host.rs` gains `--key-id <string>`. When provided, the signer is configured with that key_id; every minted receipt gets it.

**Server response shape (`boardproof-host::api::ReceiptResponse`):**
- Optional `key_id: Option<String>` with `skip_serializing_if`. When the minted receipt has a key_id, the HTTP response includes it; otherwise the field is omitted (pre-19a wire-shape compat).

**TS package `@boardproof/verifier`:**
- `ReceiptBody` gains `key_id?: string` (optional).
- `VerifyResult` gains `keyId?: string`. The verifier reads `body.key_id` when present and surfaces it.

**TS package `@boardproof/client`:**
- `DecisionBase` gains `keyId?: string`. The client reads the server's optional `key_id` in the wire response and threads it through into every `Decision` variant (`allowed`, `denied`, `approved`, `pending`).

**Python package `boardproof-client`:**
- `_DecisionBase.key_id: str | None = None` field; same in `VerifyResult`. `verify_receipt` reads `body["key_id"]` when present; `_build_decision` threads it from the wire response.

## What you can do with this step today

Start the host with a key identifier:

```bash
boardproof-host \
    --constitution constitutions/solo-dev.toml \
    --signer-seed-hex $SIGNER_SEED \
    --bearer-token-hex $TOKEN \
    --key-id "prod-2026" \
    --bind 0.0.0.0:8787
```

Every receipt minted will carry `body.key_id = "prod-2026"`. The TS / Python clients surface it:

```ts
const decision = await client.evaluate(action);
console.log(decision.keyId);  // "prod-2026"
```

```python
decision = client.evaluate(Action(...))
print(decision.key_id)  # "prod-2026"
```

Tampering with `key_id` after signing breaks the signature — verified by tests in all three languages.

## Verified during this PR

- **23 new tests across three suites** (559 total in the workspace):
  - **Rust (5 new in `tests/api.rs`, plus 2 new fixture vectors):** signer-without-key-id mints receipts without the field (byte-identical to pre-19a output); signer-with-key-id surfaces it in `body.key_id`; different key_ids on otherwise-identical receipts produce different `content_id`s; key_id persists across a chain of mints; `Ed25519Signer::with_key_id` / `.without_key_id()` builder methods work.
  - **TS verifier (4 new in `verify.test.ts`):** surfaces `body.key_id` in `VerifyResult.keyId`; absent when not in body; different key_ids → different content_ids; tampering with key_id breaks signature. **Plus 4 new conformance assertions** auto-picked from the 2 new fixture vectors.
  - **TS client (4 new in `client.test.ts`):** keyId surfaces on `Decision` when server returns it; undefined otherwise; threaded through resolveApproval and recordToolExecution responses.
  - **Python verifier + client (8 new in `test_client.py`, plus 4 new auto-conformance assertions):** mirror of the TS surface — keyId present / absent / threaded through resolve_approval / threaded through record_tool_execution.
- **All CI-flag Rust gates clean:** fmt, build (`--profile ci -D warnings`), test 423/423, clippy.
- **TS gates:** typecheck + 52/52 tests with integration.
- **Python gates:** mypy strict + 84/84 tests with integration.
- **RFC-0001 updated** with the new optional field and the rev 2.1 note.

## Adopt-don't-copy

- The `key_id` concept is generic (cryptography textbooks use it; JWT has `kid`; X.509 has `subjectKeyIdentifier`). The BoardProof choice — opaque operator-chosen string, embedded in the signed body, audit-only — is the simplest possible shape.
- No source borrowed. The implementation is ~15 LOC per language.

## What this step does **not** ship

- **A key directory service** (mapping `key_id → pubkey + valid_from + valid_until + revocation_status`). That's the next-step companion; this PR ships the *receipt-side support* so future verifiers can correlate against a directory when one exists.
- **A revocation API.** Future-step.
- **Multi-issuer chains.** The `InMemoryReceiptLog` / `SqliteReceiptLog` still pin a single issuer. A follow-up step can teach the store to accept rotation under matching key_id directory entries.
- **`schema_version` bump.** Additive optional field, no bump needed. The RFC spec text bumps to "rev 2.1" for documentation purposes; the wire field stays `2`.
- **Signature aggregation or multi-key signing.** Different concern; future-phase work.
- **Hot-reload of key_id.** Operators rotate by restarting the host with `--key-id <new>`.

## Performance / size

The change is one optional field per receipt:

- When `key_id` is `None`: zero bytes added (skip_serializing_if). Verified by the snapshot test: all 5 pre-19a vectors still produce identical canonical bytes + BLAKE3.
- When `key_id` is set: ~20-30 bytes per receipt (field name + value + JSON quoting + JCS separators). Below the receipt's noise floor.

No bench file for this step — it's a metadata change, not a perf-sensitive path. Re-running the existing step-25 bench against an auth-enabled host with `--key-id prod-2026` should show no measurable difference; future PRs that exercise large key-id values can re-measure if needed.

## In summary

Step 19a closes the deep-strategy memory's risk #3 ("Key-management gap") at the receipt-format layer. Every receipt can now name its signing key. The wire format stays backward-compatible. The architecture survived its first multi-language additive change with zero conformance drift across three implementations.

Threshold status (unchanged but better-foundationed):

- ✅ Threshold 1 (portability) — closed by 20a + 24, *now exercised against a real schema-additive change*.
- ✅ Threshold 2 (visibility) — closed by 20.
- 🟢 Threshold 3 (adoption) — adapter in two languages + auth-ready HTTP API + named keys.

Next: a key-directory service, an actual cross-claw integration (NemoClaw with the Python client is the obvious target), or `npm publish` + `pip publish` for the literal install story.
