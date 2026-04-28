# Phase 1 Step 7 — The Receipt Store

> **Phase:** 1 — Shippable Core
> **PR:** #6
> **Crate introduced:** `uniclaw-store`

## What is this step?

This step adds **storage** for receipts: a chain-validated, issuer-pinned log that refuses any tampered or out-of-order entry.

The kernel produces receipts. The receipt store keeps them. But it does not just keep them — it **validates** every append. A receipt that breaks the chain, comes from the wrong issuer, or fails its signature check is **refused**, and the log's state is unchanged.

## Where does this fit in the whole Uniclaw?

```
Kernel  --emits-->  Receipt  --append-->  ReceiptLog
                                              |
                                              +-- get_by_sequence
                                              +-- get_by_id
                                              +-- verify_chain (whole-log integrity walk)
```

The store is **downstream** of the kernel. The kernel produces signed receipts; the store keeps them honest. The store is also the substrate that public-URL hosting (Phase 2) and Deep Sleep (later) will build on.

## What problem does it solve technically?

Four problems:

### 1. "How do we make sure the chain actually links?"

When you append a receipt, the store checks five things in cheap-to-expensive order:

1. **Format version** — does this build understand this receipt format?
2. **Issuer pin** — does this receipt's issuer match the log's pinned issuer? (A log is locked to one signing key at construction.)
3. **Sequence** — is `sequence` exactly equal to `len()`? (The next expected slot.)
4. **Chain link** — does `prev_hash` match the previous receipt's `leaf_hash`?
5. **Signature** — does Ed25519 verify against the issuer's public key?

If any of these fail, the append is **rejected** and the log is **not modified**. The caller gets back a typed `AppendError` saying which check failed.

This ordering matters: cheap checks first. A receipt with the wrong issuer should be rejected without spending ~52 µs on Ed25519 verify.

### 2. "How do we detect tampering after the fact?"

`verify_chain()` walks the entire log left-to-right and re-checks every invariant: sequence monotonicity, prev_hash chaining, signature on the body. It returns the **first** invariant violation found, or `Ok(())` if every receipt is honest.

This is what **Deep Sleep** (master plan §16.3.3) calls periodically. Even if storage was tampered with after the receipts were appended (e.g., someone edited the database file directly), `verify_chain` catches it.

### 3. "How do we look up a receipt without scanning the log?"

Two indexes:

- **By sequence number** — direct array access. O(1).
- **By content ID** (the BLAKE3 hash of the receipt) — `BTreeMap<[u8;32], usize>`. O(log n).

Lookups by content ID matter because that's how receipts get *referenced* in the world: `uniclaw://receipt/<hex_hash>` is the canonical address. The receipt store must be able to find a receipt by its public address.

### 4. "How do we make this trait-shaped so SQLite can plug in later?"

The `ReceiptLog` trait is the contract:

```rust
pub trait ReceiptLog {
    fn issuer(&self) -> PublicKey;
    fn append(&mut self, receipt: Receipt) -> Result<(), AppendError>;
    fn len(&self) -> usize;
    fn last(&self) -> Option<&Receipt>;
    fn get_by_sequence(&self, seq: u64) -> Option<&Receipt>;
    fn get_by_id(&self, id: &Digest) -> Option<&Receipt>;
    fn verify_chain(&self) -> Result<(), VerifyChainError>;
}
```

Today only `InMemoryReceiptLog` implements it (a `Vec<Receipt>` plus a `BTreeMap<[u8;32], usize>` for the content-id index). A future `SqliteReceiptLog` will plug in without changing the trait.

## How does it work in plain words?

```rust
let mut log = InMemoryReceiptLog::new(my_pubkey);

// Append a fresh receipt straight from the kernel.
log.append(receipt)?;

// Look up by sequence (e.g., for chronological listing).
let r = log.get_by_sequence(0).unwrap();

// Look up by content hash (e.g., for /receipts/<hash> lookup).
let r = log.get_by_id(&Digest([0xab; 32]));

// Periodic integrity walk (called by Deep Sleep).
log.verify_chain()?;
```

The log can also be iterated:

```rust
for receipt in &log {  // IntoIterator on &InMemoryReceiptLog
    println!("seq {}: {:?}", receipt.body.merkle_leaf.sequence, receipt.body.action);
}
```

## Why this design choice and not another?

- **Why `&mut self` on `append`?** Because appending mutates `Vec` and `BTreeMap` state. Concurrent appends are not supported by `InMemoryReceiptLog`; callers wrap in `Arc<Mutex>` if they need it.
- **Why pin the issuer at construction?** Because mixing receipts from different kernels in one log is a bug, not a feature. A log should be one kernel's history.
- **Why does `verify_chain` return the first error?** Because once the chain breaks, downstream errors are noise. Show the first break; the operator fixes it; re-run.
- **Why an in-memory-only impl in Phase 1?** Because Phase 1 is about shaping the trusted core. Phase 2 needs persistence (for the public-URL server) and that's when SQLite lands. We did not want the trait surface to be premature for SQLite.

## What you can do with this step today

- Construct an `InMemoryReceiptLog` pinned to a kernel's public key.
- Append every kernel-produced receipt. Get rejected if the chain breaks (which means the kernel is buggy or the receipt has been tampered).
- Look up receipts by sequence or by content ID.
- Periodically call `verify_chain()` to detect post-facto tampering of the storage layer.

## Performance baseline

On x86_64 Linux:

- `append` (full validation including Ed25519 verify and BTreeMap insert): **64.6 µs/call**
- `verify_chain` on a 1000-entry log: **56.9 µs per receipt** (~57 ms for the whole walk)
- `get_by_id`: **0.131 µs per lookup**

These numbers tell us the store can sustain ~15,000 appends/sec on commodity hardware, and a `verify_chain` over a million-receipt log would take about a minute. Both are comfortable for the use cases we have.

## In summary

Step 7 gives the kernel a memory. A picky one. The store refuses tampered or out-of-order receipts at append time, and re-verifies the whole chain on demand. The trait is generic enough that SQLite, a content-addressed file store, or a future distributed log can all slot in without changing callers.
