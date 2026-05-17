// Bench harness for @boardproof/client. Spawns boardproof-host and
// measures end-to-end client.evaluate() latency under three modes:
//
//   (a) verify=true   — submit + verify by re-fetching + recheck
//   (b) verify=false  — submit only (faster)
//   (c) raw HTTP fetch (no client, no verify) — keepalive baseline
//
// Run:
//   cargo build --release --bin boardproof-host -p boardproof-host
//   node tests/bench.mjs
//
// Output goes to stdout; redirect to bench-results/22-typescript-client.txt.

import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { performance } from "node:perf_hooks";

import { BoardProofClient } from "../dist/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(here, "../../..");
const HOST_BIN = resolve(REPO_ROOT, "target/release/boardproof-host");
const FIXTURE = resolve(here, "fixtures/test-constitution.toml");
const SEED_HEX = "2a".repeat(32);
const BENCH_TOKEN_HEX = "ab".repeat(32);

if (!existsSync(HOST_BIN)) {
  console.error(`missing ${HOST_BIN} — run cargo build --release first`);
  process.exit(2);
}

const proc = spawn(
  HOST_BIN,
  [
    "--constitution", FIXTURE,
    "--signer-seed-hex", SEED_HEX,
    "--bearer-token-hex", BENCH_TOKEN_HEX,
    "--bind", "127.0.0.1:0",
  ],
  { stdio: ["ignore", "pipe", "pipe"] },
);

const baseUrl = await new Promise((res, rej) => {
  const t = setTimeout(() => rej(new Error("bind timeout")), 10_000);
  let buf = "";
  proc.stderr.on("data", (c) => {
    buf += String(c);
    const m = /listening on (http:\/\/127\.0\.0\.1:\d+)/.exec(buf);
    if (m) { clearTimeout(t); res(m[1]); }
  });
});

const ACTION = {
  kind: "http.fetch",
  target: "https://example.com/bench",
  inputHash: "00".repeat(32),
};

const TOOL_ACTION = {
  kind: "tool.http_fetch",
  target: "https://example.com/bench-tool",
  inputHash: "11".repeat(32),
};

async function timeRun(label, fn, n) {
  // Warm-up.
  for (let i = 0; i < 5; i++) await fn(i);
  const t0 = performance.now();
  for (let i = 0; i < n; i++) await fn(i);
  const dt = performance.now() - t0;
  return { label, n, totalMs: dt, perReqMs: dt / n };
}

function fmt(r) {
  return `  ${r.label.padEnd(30)} N=${r.n}  total=${r.totalMs.toFixed(1)}ms  per-req=${r.perReqMs.toFixed(3)}ms`;
}

const N = 200;

// (a) verify=true (default)
const clientVerify = new BoardProofClient({ baseUrl, bearerToken: BENCH_TOKEN_HEX });
const r1 = await timeRun(
  "client.evaluate verify=true",
  () => clientVerify.evaluate(ACTION),
  N,
);

// (b) verify=false
const clientNoVerify = new BoardProofClient({
  baseUrl,
  verifyByDefault: false,
  bearerToken: BENCH_TOKEN_HEX,
});
const r2 = await timeRun(
  "client.evaluate verify=false",
  () => clientNoVerify.evaluate(ACTION),
  N,
);

// (c) raw fetch baseline (keepalive). Auth header included so
// this is apples-to-apples with the client paths (which also
// send it on every /v1 POST since step 25).
const r3 = await timeRun(
  "raw fetch POST /v1/proposals",
  async () => {
    const r = await fetch(`${baseUrl}/v1/proposals`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${BENCH_TOKEN_HEX}`,
      },
      body: JSON.stringify({
        action: {
          kind: ACTION.kind,
          target: ACTION.target,
          input_hash: ACTION.inputHash,
        },
      }),
    });
    await r.json();
  },
  N,
);

// --- Step 23: tool-execution bench ---
//
// recordToolExecution requires an Allowed `tool.*` proposal
// receipt. We mint a fresh one per iteration (so the bench
// measures the actual sidecar-style flow: propose, then record
// the result). We measure the recordToolExecution call alone,
// AND the full propose+record chain.

async function mintTool() {
  const d = await clientNoVerify.evaluate(TOOL_ACTION);
  if (d.kind !== "allowed") throw new Error(`expected allowed, got ${d.kind}`);
  return d.contentId;
}

// Pre-mint pool to isolate recordToolExecution from evaluate cost.
const POOL_N = 200 + 5;
const allowedIds = [];
for (let i = 0; i < POOL_N; i++) {
  allowedIds.push(await mintTool());
}
let poolCursor = 0;

const r4 = await timeRun(
  "client.recordToolExecution verify=false",
  () =>
    clientNoVerify.recordToolExecution({
      allowedReceiptId: allowedIds[poolCursor++],
      outputHash: "22".repeat(32),
    }),
  N,
);

// And the full chain: propose + record + verify both.
const r5 = await timeRun(
  "propose+record chain (both verify=true)",
  async () => {
    const allowed = await clientVerify.evaluate(TOOL_ACTION);
    if (allowed.kind !== "allowed") throw new Error("expected allowed");
    await clientVerify.recordToolExecution({
      allowedReceiptId: allowed.contentId,
      outputHash: "22".repeat(32),
    });
  },
  Math.floor(N / 2),
);

console.log("=== @boardproof/client end-to-end latency bench ===");
console.log(`baseUrl=${baseUrl}`);
console.log(`node=${process.version}`);
console.log(`host bin=${HOST_BIN}`);
console.log("");
console.log(fmt(r1));
console.log(fmt(r2));
console.log(fmt(r3));
console.log(fmt(r4));
console.log(fmt(r5));
console.log("");
console.log("verify-overhead = (verify=true) - (verify=false)");
console.log(`  = ${(r1.perReqMs - r2.perReqMs).toFixed(3)} ms/req`);
console.log("client-overhead = (verify=false) - (raw fetch)");
console.log(`  = ${(r2.perReqMs - r3.perReqMs).toFixed(3)} ms/req`);
console.log("recordToolExecution (verify=false) is in the same band as evaluate (verify=false)");
console.log(`  evaluate:            ${r2.perReqMs.toFixed(3)} ms/req`);
console.log(`  recordToolExecution: ${r4.perReqMs.toFixed(3)} ms/req`);

proc.kill("SIGINT");
await new Promise((res) => proc.once("exit", res));
