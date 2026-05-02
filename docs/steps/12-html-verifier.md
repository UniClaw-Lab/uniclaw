# Phase 2 Step 4 — HTML Verifier UI

> **Phase:** 2 — Public Service
> **PR:** _this PR_
> **Crate updated:** `uniclaw-host` (new `GET /verify` route + embedded HTML page)

## What is this step?

This step closes the verifiability wedge to **non-engineers**. Until now, "anyone can verify a receipt" still required running a Rust binary from a terminal — which excludes exactly the audiences the project is built for: auditors, regulators, journalists, lawyers, compliance officers.

After this step, those people can paste a receipt JSON into a browser at `https://your-host/verify`, click **Verify**, and see ✓ or ✗ within milliseconds. **No backend call, no account, no install.** The page itself does the Ed25519 check using the browser's built-in `crypto.subtle` API.

## Where does this fit in the whole Uniclaw?

Phase 2 is "Public Service" — the goal is making receipts publicly verifiable through a URL. Three steps shipped before this:

```
Step 9  /receipts/<hash>  — serve receipts as JSON                ✓
Step 10 SqliteReceiptLog  — receipts that survive process restart ✓
Step 11 Deep Sleep        — scheduled integrity walk receipts     ✓
Step 12 /verify           — in-browser verifier  ← THIS STEP
```

Together, they mean: an auditor opens `https://your-host/receipts/abc...` in the browser → sees JSON → copies it → goes to `https://your-host/verify` → pastes → sees ✓. The entire experience needs **no Uniclaw knowledge** beyond "paste this here, see if it's valid."

## What problem does it solve technically?

Three problems.

### 1. "How does a non-engineer verify a receipt?"

By visiting a web page. The page contains the verifier — there is no separate tool to install. Open the URL, paste the JSON, see the result. The audience constraint (regulators, lawyers) is non-negotiable; the UX has to match.

### 2. "How do we keep the trust model honest?"

By doing the verification **in the browser**, never on the server. If the server claimed `"verified": true`, downstream tooling could trust the claim instead of the signature — that would dilute the entire point of cold verification.

The page is delivered as a **static HTML file** with no external dependencies (no script tags pointing elsewhere, no CDN-loaded libraries, no fonts). An auditor can save the page (`Ctrl+S`) and run it offline against any receipt forever. The page IS the verifier.

### 3. "How do we verify Ed25519 in the browser without shipping a JS crypto library?"

`crypto.subtle.verify` has had native Ed25519 support since:
- Chrome 113 (May 2023)
- Firefox 130 (September 2024)
- Safari 17 (September 2023, with various intermediate flag-gated versions)
- Node 20+ (so we can also smoke-test the same logic headlessly)

That covers ≥ 95% of the auditor-class audience as of this writing. We detect feature absence at page load and show a clear warning telling the user to upgrade or use the CLI verifier instead — graceful degradation, not silent failure.

No JS crypto library means: ~8.5 KB total page, no supply-chain risk, no version drift.

## How does it work in plain words?

The verification pipeline in the page (mirroring [`uniclaw-receipt::crypto::verify`](../../crates/uniclaw-receipt/src/lib.rs)):

1. **Parse** the pasted JSON.
2. **Reconstruct the canonical body bytes** the kernel signed:
   ```js
   const bodyBytes = new TextEncoder().encode(JSON.stringify(receipt.body));
   ```
   This is the most subtle part — see "Why this works" below.
3. **Decode** the issuer's Ed25519 public key (32 bytes) from hex.
4. **Decode** the signature (64 bytes) from hex.
5. **Import** the public key into `crypto.subtle`:
   ```js
   const key = await crypto.subtle.importKey(
     "raw", issuerBytes, { name: "Ed25519" }, false, ["verify"]
   );
   ```
6. **Verify**:
   ```js
   const ok = await crypto.subtle.verify("Ed25519", key, sigBytes, bodyBytes);
   ```
7. **Render** ✓ or ✗ along with the receipt's decision, action, sequence, issued-at, and an issuer fingerprint (first 4 bytes hex).

### Why the canonical-body reconstruction works

The kernel's `crypto::sign` does:

```rust
let body_bytes = serde_json::to_vec(&body).expect("canonical body must encode");
```

`serde_json::to_vec` emits keys in **struct field declaration order** with no whitespace. The receipt JSON returned by `/receipts/<hash>` contains the body in exactly that order.

In the browser:

- `JSON.parse(text)` creates a JS object with property order matching **the order keys appeared in the source string** (ES2015+ preserves insertion order for string-keyed properties).
- `JSON.stringify(receipt.body)` writes properties in property order, with no whitespace.

Therefore: `JSON.parse → JSON.stringify(body)` of the receipt fetched from the host produces the **exact same byte sequence** the kernel signed.

This isn't theoretical. The PR's smoke test runs the page's JS through Node 22 (same `crypto.subtle.verify("Ed25519", ...)` API as browsers) against a Rust-signed receipt. Verification passes.

If the user pastes a pretty-printed copy, parse-then-stringify-without-indent produces the compact form anyway — same bytes, same signature.

## Why this design choice and not another?

- **Why one static HTML file, not a SPA framework?** Because the page must be self-contained for the trust model. A React/Vue build would pull dozens of dependencies and a build step; a static page is auditable end-to-end at a glance.
- **Why `include_str!` at compile time, not a `static/` directory at runtime?** Because the binary has to be deployable as a single file. No filesystem reads at runtime. No "where do I put the static files?" deploy step.
- **Why `Cache-Control: no-store` on `/verify`?** Receipts are content-addressed (immutable); the verifier page is not — we need the freedom to ship updates to the JS logic without CDN caching getting in the way. The receipts themselves still ship `Cache-Control: public, max-age=31536000, immutable` (unchanged from step 9).
- **Why no server-side verify endpoint?** Same reason as step 9: server-side verification would dilute the trust model. The user must verify on their own machine, in their own JS engine, against the receipt's embedded public key. Anything else is hand-waving.
- **Why detect Ed25519 support at page load instead of falling back to a JS Ed25519 library?** Because shipping a JS crypto library is the supply-chain risk we're trying to avoid. A clear message ("upgrade your browser, or use `uniclaw-verify`") is honest. A polyfill we've never audited is dishonest.
- **Why no CSP header set?** v0 keeps the route handler small. A future hardening step can add `Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'` (the `'unsafe-inline'` is needed because the page inlines its own script and style — the page is the same kind of artifact a user can save locally; an audited inline script is preferable to an external one for this use case).

## What you can do with this step today

- Open `http://127.0.0.1:8787/verify` against a running `uniclaw-host`.
- Paste a receipt fetched from `/receipts/<hash>`.
- Get a ✓ or ✗ in milliseconds.
- Save the page locally (`Ctrl+S`) and verify receipts offline forever — no Uniclaw install.
- Hand the URL to an auditor.

## Performance baseline (release, in-process via tower::oneshot)

| Endpoint | Per request |
|---|---|
| `GET /verify` (8576-byte HTML page) | **4.98 µs** |
| `GET /` (small index for comparison) | 5.47 µs |

Handler cost is invisible behind any network round-trip. Browser-side Ed25519 verify of a single receipt is ≤ 1 ms on commodity hardware.

## What this step does **not** ship

- **Drag-and-drop file upload.** Paste-only for v0. Adding file upload is a small follow-up if needed.
- **Bulk verification.** The page verifies one receipt at a time. Auditors with thousands of receipts should script the CLI verifier.
- **Public-key allowlist.** The page verifies against the receipt's embedded issuer key, not against a list of known-good keys. An auditor who wants stricter trust must externally check the issuer fingerprint matches the one they expect (the page shows the fingerprint prominently).
- **CSP / Subresource Integrity / TLS.** Run behind a TLS-terminating reverse proxy. CSP can be added later without touching the page itself.

## In summary

Step 12 makes Uniclaw's verifiability promise reach an auditor's hands. The page is small (~8.5 KB), self-contained, browser-native, and designed to be saved and run offline. No server-side trust extension. No JS crypto dependencies. The smoke test proves the canonical-body reconstruction matches the kernel's signed bytes byte-for-byte. With this step, the wedge is **complete for non-engineers** — Phase 2's stated goal is materially met.
