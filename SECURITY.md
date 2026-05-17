# Security Policy

BoardProof's whole product thesis is *the kernel proves what it did*. Security
issues against the kernel, the receipt format, the Constitution engine, the
capability budget algebra, the secret broker, the sandbox, or the verifier
binary are taken extremely seriously.

## Reporting a vulnerability

**Do not file a public GitHub issue for security vulnerabilities.**

Instead, report via one of:

- GitHub Security Advisories: open a private advisory on the repository.
- Email: `security@boardproof.dev` (PGP key fingerprint will be published with
  the first signed release).

Please include:

1. A clear description of the issue.
2. Reproduction steps or a proof-of-concept.
3. Affected versions / commits.
4. Your assessment of impact and severity.
5. Whether you intend to publicly disclose, and on what timeline.

## Response targets

- **Acknowledgement** within 72 hours.
- **Initial assessment** within 7 days.
- **Patch** within 30 days for high-severity issues, or a written explanation
  if more time is required.
- **Coordinated disclosure** is the default; we will work with you on a
  timeline.

## Scope

In scope:

- Kernel (`boardproof-kernel`).
- Receipt format and verifier (`boardproof-receipt`, `boardproof-verify`).
- Policy DSL, Constitution engine, capability leases, audit chain, provenance
  graph (when these crates exist).
- Secret broker, sandbox, redaction pipeline.
- Adapters that ship in tree.

Out of scope:

- Issues that depend on a malicious operator who already has admin privileges
  on the host running BoardProof.
- Denial-of-service via legitimate but expensive operations
  (rate-limit your agents).
- Findings against third-party WASM tools or skills that are not bundled with
  BoardProof.
- Issues in the upstream `wasmtime`, `automerge-rs`, or other dependencies
  that we do not maintain (please report to the upstream project, then notify
  us so we can coordinate updates).

## Bug bounty (Phase 3+)

A public bug bounty with a $50k pool launches in Phase 3 of the roadmap. Until
then, security findings are gratefully acknowledged in the changelog and on the
public Receipt Gallery.

## Preferred Languages

We prefer reports in English.
