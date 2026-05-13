# Phase 3.5 Step 27 — Publish-ready packaging for the three client libraries

> **Phase:** 3.5 — Receipt-format hardening + adoption-foundations
> **PR:** _this PR_
> **Touches:** root `package.json` (new), `packages/verifier-ts/package.json`, `packages/client-ts/package.json`, both packages' `LICENSE-*` files, `packages/client-py/LICENSE-*`, `packages/client-ts/tests/bench.mjs` (side-fix for step-25 auth)
> **No runtime code changed.** Zero Rust changes. Zero Python source changes. Zero TS library source changes.

## What is this step?

Three packages have existed in `packages/` since steps 20a, 22, and 24:

- `@uniclaw/verifier` (step 20a) — TS verifier.
- `@uniclaw/client` (step 22) — TS HTTP client + verify-by-default.
- `uniclaw-client` (step 24) — Python verifier + HTTP client.

They were *built* but not *published*. `npm install @uniclaw/client` did not work — the package wasn't on the registry. `pip install uniclaw-client` did not work either. Threshold 1 ("a TypeScript developer can `npm install` a verifier and validate a Uniclaw receipt minted on a Rust kernel") was conceptually closed since step 24 but **literally** still needed the registry push.

Step 27 is the **operations bridge**: small, focused engineering changes that make all three packages publish-ready, plus the runbook for the operator (the user) to actually push them.

### What was blocking publish

| Blocker | Where | Fix |
|---|---|---|
| `@uniclaw/client` depended on `"file:../verifier-ts"` | `packages/client-ts/package.json` | Changed to `"^0.1.0"`; root npm workspaces resolves it locally for dev. |
| Scoped npm packages default to private | both TS `package.json` | Added `publishConfig.access = "public"`. |
| `dist/` could be stale on publish | both TS `package.json` | Added `prepublishOnly: "npm run build && npm test"`. |
| LICENSE text not in tarballs (only SPDX expression in `license` field) | all three packages | Added real LICENSE-MIT + LICENSE-APACHE files; declared in `files`. |
| Bench broken since step 25 | `packages/client-ts/tests/bench.mjs` | Side-fix: added `--bearer-token-hex` + `Authorization: Bearer` header. |

## Where does this fit in the whole Uniclaw?

Step 27 closes the **last operational step** of threshold 1. After this PR is merged AND the user pushes to npm + PyPI:

- `npm install @uniclaw/client` — works.
- `npm install @uniclaw/verifier` — works.
- `pip install uniclaw-client` — works.

That's the literal version of the threshold-1 test from `project_deep_strategy.md`.

```
threshold 1 (portability)
  step 20a: TS verifier built     ✓
  step 22:  TS client built       ✓
  step 24:  Python verifier+client built ✓
  step 27:  npm publish + pip publish — ← THIS step makes the bytes flow
                                         from this repo to anyone's machine
                                         via the public registries.
```

## What problem did it solve technically?

The TS monorepo had a *development-time* convenience that was a *publish-time* blocker: `@uniclaw/client` used `"@uniclaw/verifier": "file:../verifier-ts"` so `npm install` from inside `packages/client-ts` worked during development. But `npm publish` records that string literally — anyone installing `@uniclaw/client@0.1.0` from npm would get a manifest pointing at a directory that doesn't exist on their machine.

The clean fix is the **npm workspaces** pattern: add a top-level `package.json` with

```json
{
  "private": true,
  "workspaces": ["packages/verifier-ts", "packages/client-ts"]
}
```

and change the client's dependency to `"@uniclaw/verifier": "^0.1.0"`. Now:

- **Local dev** (`npm install` from repo root) — npm sees both workspaces, symlinks `node_modules/@uniclaw/verifier → packages/verifier-ts`, and `@uniclaw/client` resolves its dep to the *local* source. Tests work against the live verifier.
- **Publish** (`npm publish -w @uniclaw/client`) — npm packs the client with the literal `^0.1.0` dependency. Anyone installing it pulls `@uniclaw/verifier@0.1.0` from the npm registry.

Same `dist/` artifacts, same tests, two different resolution paths. The workspace declaration is the only structural change.

For Python it was simpler — `uniclaw-client` had no inter-package dependency to manage. The remaining gap was just LICENSE files in the sdist + wheel, fixed by copying both LICENSE-MIT and LICENSE-APACHE into `packages/client-py/`. Setuptools 68+ auto-discovers `LICENSE*` at the package root.

## How it works in plain words

For each TS package, on `npm publish`:

1. `prepublishOnly` script fires: runs `tsc -p tsconfig.build.json` (regenerates `dist/`), runs `vitest run` (regenerates confidence).
2. npm builds the tarball using the `files` array: `dist/`, `bin/` (verifier only), `README.md`, `LICENSE-MIT`, `LICENSE-APACHE`.
3. `publishConfig.access = "public"` makes the scoped package public-by-default — no `--access public` flag needed.

For the Python package, on `python -m build`:

1. setuptools reads `pyproject.toml`, builds a wheel (`uniclaw_client-0.1.0-py3-none-any.whl`) and an sdist (`uniclaw_client-0.1.0.tar.gz`).
2. setuptools auto-discovers LICENSE-MIT + LICENSE-APACHE; includes them in the wheel's `dist-info/licenses/` and the sdist's root.
3. `twine check dist/*` validates both for PyPI metadata correctness.
4. `twine upload dist/*` ships them.

## What you can do with it today

After this PR merges, the operator (only the user has the npm + PyPI credentials) follows the runbook below to push to the registries.

### Operator runbook — npm publish

Pre-flight:

- Confirm `@uniclaw` npm org exists and the operator has publish rights.
- Confirm 2FA-on-publish is enabled (recommended; npm prompts during publish).
- Confirm the operator is logged in: `npm whoami` should show the publisher account.

Publish in **this exact order** (verifier first; client depends on it):

```bash
# From the repo root
cd packages/verifier-ts
npm publish
# Triggers prepublishOnly: build + test. Then publishes
# @uniclaw/verifier@0.1.0 to https://www.npmjs.com/package/@uniclaw/verifier

cd ../client-ts
npm publish
# Same flow. After this, npm install @uniclaw/client resolves
# @uniclaw/verifier from the registry (not the local workspace).
```

Verification after publish:

```bash
cd /tmp && mkdir t && cd t && npm init -y >/dev/null
npm install @uniclaw/client@0.1.0
node -e "
  const { UniclawClient } = require('@uniclaw/client');
  console.log('installed; UniclawClient =', typeof UniclawClient);
"
```

### Operator runbook — PyPI publish

Pre-flight:

- Confirm `uniclaw-client` is reserved on PyPI by the operator's account (https://pypi.org/manage/account/projects/).
- Use an API token (Settings → API tokens → Create token, scope: this project) rather than username/password.
- Configure `~/.pypirc`:
  ```ini
  [pypi]
    username = __token__
    password = pypi-AgEI...   ; the API token
  ```

Build + upload:

```bash
cd packages/client-py
rm -rf dist/ build/ *.egg-info
python -m build
python -m twine check dist/*    # validates metadata
python -m twine upload dist/*   # ships
```

Verification after publish:

```bash
python -m venv /tmp/verify-pypi && source /tmp/verify-pypi/bin/activate
pip install uniclaw-client==0.1.0
python -c "from uniclaw_client import UniclawClient; print('ok')"
```

### Operator runbook — version bumps

The version is set in two places per package:

- TS: `packages/<name>/package.json` → `"version": "0.1.0"`.
- Python: `packages/client-py/pyproject.toml` → `version = "0.1.0"`.

Each subsequent publish needs a unique version. Use semver:

- Patch (`0.1.0 → 0.1.1`) — bug fix, no API change.
- Minor (`0.1.0 → 0.2.0`) — additive API (new method, new field).
- Major (`0.x → 1.0.0`) — breaking change.

For the TS client, the `@uniclaw/verifier` dependency uses `^0.1.0` — that resolves to any `0.1.x`. If the verifier ever publishes a `0.2.0` (additive but pre-1.0 semver still treats minor bumps as breaking), the client manifest needs a manual bump to `"^0.2.0"`.

## What it deliberately doesn't ship

- **No npm CI workflow.** Adding `npm publish` to GitHub Actions on tag-push is the next operational step but is **not** in this PR (the user holds the registry credentials; automation can come later when manual publishes are stable).
- **No version bumps.** All three packages stay at `0.1.0`. This PR is the *first* publish; subsequent bumps will land in their own PRs.
- **No PyPI CI workflow.** Same reason — credentialed automation is operator-driven.
- **No CHANGELOG entries inside each package.** The repo-level `CHANGELOG.md` covers per-step changes; per-package changelogs can come later if usage warrants them.
- **No runtime code changes** of any kind. The library behaviors are unchanged. The library *source* is unchanged. Only the packaging metadata and the LICENSE files are new.

## Verification

```
Rust:        427 passed (cargo test --workspace)
TS verifier:  42 passed (npm test --workspace @uniclaw/verifier)
TS client:    52 passed (UNICLAW_INTEGRATION=1 npm test --workspace @uniclaw/client)
Python:       84 passed (UNICLAW_INTEGRATION=1 pytest in packages/client-py)
total:       605 — same as pre-PR baseline (zero regression).
```

`npm pack --dry-run` confirms both TS tarballs include LICENSE-MIT, LICENSE-APACHE, README.md, and the `dist/` build artifacts:

```
@uniclaw/verifier  →  14.9 kB packed, 47.3 kB unpacked, 29 files.
@uniclaw/client    →  15.1 kB packed, 48.9 kB unpacked, 20 files.
```

`python -m build` produces both sdist + wheel; `twine check dist/*` passes for both. LICENSE files appear in `dist-info/licenses/` and at the sdist root.

## Side-fix bundled in this PR

`packages/client-ts/tests/bench.mjs` had been broken since step 25 (PR #33): the bench spawns the host without `--bearer-token-hex` and without `--insecure-no-auth`, so step 25's safe-default check (proposal mode refuses to start without an explicit auth choice) made the bench error out at startup. The Python bench was updated in step 25 but the TS bench wasn't. Fixed in this PR by adding `--bearer-token-hex`, `bearerToken` to both `UniclawClient` instances, and an `Authorization: Bearer` header on the raw-fetch baseline. This is a one-file dev-tools fix; no library behavior changes.
