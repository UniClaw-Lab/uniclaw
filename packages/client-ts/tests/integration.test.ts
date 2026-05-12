// Integration test for `@uniclaw/client`. Spawns a real
// `uniclaw-host` subprocess in proposal-API mode, drives the
// client through every decision flow, and asserts that the
// minted receipts verify under `@uniclaw/verifier`.
//
// **Off by default.** Without `UNICLAW_INTEGRATION=1`, the suite
// skips itself with a console hint. This keeps `npm test` working
// in environments where the Rust toolchain isn't available
// (e.g. consumer CI that just wants to typecheck the npm package).
//
// The release binary must already exist at
// `target/release/uniclaw-host`. We don't run `cargo build` from
// here — that's the developer's job, and CI does it explicitly.
//
// Lifecycle:
//   1. `beforeAll`: spawn `uniclaw-host --constitution ... --bind 127.0.0.1:0`.
//      Read stderr until we see `listening on http://127.0.0.1:<port>`.
//      Stash the port.
//   2. Per-test: drive `UniclawClient` against `http://127.0.0.1:<port>`.
//   3. `afterAll`: SIGINT the subprocess for graceful shutdown.

import { ChildProcess, spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { UniclawClient } from "../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(here, "../../..");
const HOST_BIN = resolve(REPO_ROOT, "target/release/uniclaw-host");
const FIXTURE = resolve(here, "fixtures/test-constitution.toml");
const SEED_HEX = "2a".repeat(32);

const INTEGRATION = process.env["UNICLAW_INTEGRATION"] === "1";

let child: ChildProcess | undefined;
let baseUrl = "";

async function startHost(): Promise<string> {
  if (!existsSync(HOST_BIN)) {
    throw new Error(
      `release binary missing: ${HOST_BIN}\n` +
        `Run \`cargo build --release --bin uniclaw-host -p uniclaw-host\` first.`,
    );
  }
  // Step 25: the binary refuses to start in proposal mode without
  // explicitly choosing an auth posture. These tests don't exercise
  // auth themselves — see `tests/integration_auth.test.ts` for that
  // — so we pass --insecure-no-auth to stay on the prior code path.
  const proc = spawn(
    HOST_BIN,
    [
      "--constitution",
      FIXTURE,
      "--signer-seed-hex",
      SEED_HEX,
      "--insecure-no-auth",
      "--bind",
      "127.0.0.1:0",
    ],
    { stdio: ["ignore", "pipe", "pipe"] },
  );
  child = proc;

  // Wait for the "listening on http://127.0.0.1:<port>" line on
  // stderr. The binary prints that synchronously after `bind`.
  const url = await new Promise<string>((resolveLine, reject) => {
    const timer = setTimeout(
      () => reject(new Error("uniclaw-host did not bind within 10 s")),
      10_000,
    );
    let buf = "";
    proc.stderr?.on("data", (chunk) => {
      buf += String(chunk);
      const match = /listening on (http:\/\/127\.0\.0\.1:\d+)/.exec(buf);
      if (match) {
        clearTimeout(timer);
        const found = match[1];
        if (found) resolveLine(found);
      }
    });
    proc.once("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
    proc.once("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`uniclaw-host exited early with code ${code}: ${buf}`));
    });
  });

  return url;
}

async function stopHost(): Promise<void> {
  if (!child) return;
  child.kill("SIGINT");
  await new Promise<void>((res) => {
    if (!child) return res();
    child.once("exit", () => res());
    setTimeout(() => res(), 3_000);
  });
  child = undefined;
}

// Top-level `describe.skipIf(...)` — the whole suite skips if the
// integration flag isn't set.
describe.skipIf(!INTEGRATION)("client ↔ uniclaw-host integration", () => {
  beforeAll(async () => {
    baseUrl = await startHost();
  }, 15_000);

  afterAll(async () => {
    await stopHost();
  });

  it("evaluate({allowed action}) verifies cold", async () => {
    const client = new UniclawClient({ baseUrl });
    const decision = await client.evaluate({
      kind: "http.fetch",
      target: "https://example.com/data",
      inputHash: "00".repeat(32),
    });
    expect(decision.kind).toBe("allowed");
    if (decision.kind !== "allowed") throw new Error("narrowing");
    expect(decision.receiptUrl.startsWith(baseUrl)).toBe(true);
    expect(decision.contentId).toHaveLength(64);
    expect(decision.sequence).toBe(0);
    expect(decision.schemaVersion).toBe(2);
  });

  it("evaluate({denied action}) returns a Denied", async () => {
    const client = new UniclawClient({ baseUrl });
    const decision = await client.evaluate({
      kind: "shell.exec",
      target: "rm -rf /",
      inputHash: "00".repeat(32),
    });
    expect(decision.kind).toBe("denied");
  });

  it("pending → approve flow returns Approved + links via prev_hash", async () => {
    const client = new UniclawClient({ baseUrl });
    const pending = await client.evaluate({
      kind: "http.fetch",
      target: "https://example.com/admin/secrets",
      inputHash: "00".repeat(32),
    });
    expect(pending.kind).toBe("pending");
    if (pending.kind !== "pending") throw new Error("narrowing");

    const pendingFull = (await client.getReceipt(pending.contentId)) as {
      body: { merkle_leaf: { leaf_hash: string } };
    };
    const pendingLeaf = pendingFull.body.merkle_leaf.leaf_hash;

    const approved = await pending.approve("operator@example.com");
    expect(approved.kind).toBe("approved");

    const approvedFull = (await client.getReceipt(approved.contentId)) as {
      body: { merkle_leaf: { prev_hash: string } };
    };
    expect(approvedFull.body.merkle_leaf.prev_hash).toBe(pendingLeaf);
  });

  it("pending → deny flow returns Denied with narrowed type", async () => {
    const client = new UniclawClient({ baseUrl });
    const pending = await client.evaluate({
      kind: "http.fetch",
      target: "https://example.com/admin/other",
      inputHash: "01".repeat(32),
    });
    if (pending.kind !== "pending") throw new Error("narrowing");
    const denied = await pending.deny("operator@example.com");
    expect(denied.kind).toBe("denied");
  });

  it("verify-by-default catches a tampered receipt", async () => {
    // Mint a real allowed receipt, then intercept the verify GET
    // with a tampered body. The client should reject.
    const realClient = new UniclawClient({ baseUrl, verifyByDefault: false });
    const real = await realClient.evaluate({
      kind: "http.fetch",
      target: "https://example.com/tamper",
      inputHash: "ff".repeat(32),
    });
    expect(real.kind).toBe("allowed");

    // Build a client whose fetch returns a tampered version of the
    // receipt when asked.
    const tamperingFetch: typeof fetch = async (input, init) => {
      const url = String(input);
      const resp = await fetch(url, init);
      if (url.includes("/receipts/")) {
        const text = await resp.text();
        const obj = JSON.parse(text) as { body: { decision: string } };
        obj.body.decision = "denied"; // tamper
        return new Response(JSON.stringify(obj), {
          status: resp.status,
          headers: { "content-type": "application/json" },
        });
      }
      return resp;
    };
    const evilClient = new UniclawClient({
      baseUrl,
      fetch: tamperingFetch,
      verifyByDefault: true,
    });
    await expect(
      evilClient.evaluate({
        kind: "http.fetch",
        target: "https://example.com/tamper-trip",
        inputHash: "ee".repeat(32),
      }),
    ).rejects.toThrow(/UniclawVerifyError/);
  });

  it("400 errors surface as UniclawError(bad_request)", async () => {
    const client = new UniclawClient({ baseUrl, verifyByDefault: false });
    let caught: unknown;
    try {
      await client.evaluate({
        kind: "http.fetch",
        target: "x",
        inputHash: "not-hex",
      });
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeDefined();
    const err = caught as { status: number; code: string };
    expect(err.status).toBe(400);
    expect(err.code).toBe("bad_request");
  });

  it("404 on unknown approval id surfaces as UniclawError(not_found)", async () => {
    const client = new UniclawClient({ baseUrl, verifyByDefault: false });
    let caught: unknown;
    try {
      await client.resolveApproval("ab".repeat(32), {
        principal: "operator@example.com",
        outcome: "approved",
      });
    } catch (e) {
      caught = e;
    }
    const err = caught as { status: number; code: string };
    expect(err.status).toBe(404);
    expect(err.code).toBe("not_found");
  });

  it("end-to-end tool-execution chain: propose → record → verify chain link", async () => {
    const client = new UniclawClient({ baseUrl });
    // 1. Mint an Allowed `tool.*` receipt.
    const allowed = await client.evaluate({
      kind: "tool.http_fetch",
      target: "https://api.example.com/integration",
      inputHash: "aa".repeat(32),
    });
    expect(allowed.kind).toBe("allowed");
    if (allowed.kind !== "allowed") throw new Error("narrowing");

    const allowedFull = (await client.getReceipt(allowed.contentId)) as {
      body: { merkle_leaf: { leaf_hash: string } };
    };
    const allowedLeaf = allowedFull.body.merkle_leaf.leaf_hash;

    // 2. Record an execution with secrets + redaction (full payload).
    const execution = await client.recordToolExecution({
      allowedReceiptId: allowed.contentId,
      outputHash: "bb".repeat(32),
      secretsUsed: ["github.token"],
      redaction: {
        redactedOutputHash: "cc".repeat(32),
        stackHash: "dd".repeat(32),
        matches: [{ ruleId: "github_pat", count: 1 }],
      },
    });
    expect(execution.kind).toBe("allowed");
    expect(execution.sequence).toBeGreaterThan(allowed.sequence);

    // 3. Fetch the execution receipt and assert chain linkage +
    //    presence of the expected provenance edges.
    const execFull = (await client.getReceipt(execution.contentId)) as {
      body: {
        action: { kind: string; target: string };
        merkle_leaf: { prev_hash: string };
        redactor_stack_hash: string | null;
        provenance: { from: string; to: string; kind: string }[];
      };
    };
    expect(execFull.body.merkle_leaf.prev_hash).toBe(allowedLeaf);
    expect(execFull.body.action.kind).toBe("$kernel/tool/executed");
    expect(execFull.body.action.target).toContain("tool=http_fetch");
    expect(execFull.body.redactor_stack_hash).toBe("dd".repeat(32));

    const kinds = execFull.body.provenance.map((e) => e.kind);
    expect(kinds).toContain("tool_execution");
    expect(kinds).toContain("secret_used");
    expect(kinds).toContain("redaction_applied");
    expect(kinds).toContain("tool_output");
    const outputEdge = execFull.body.provenance.find(
      (e) => e.kind === "tool_output",
    );
    expect(outputEdge?.to.endsWith("cc".repeat(32))).toBe(true);
  });

  it("recordToolExecution against http.fetch (non-tool action) returns 409", async () => {
    const client = new UniclawClient({ baseUrl, verifyByDefault: false });
    const allowed = await client.evaluate({
      kind: "http.fetch", // not "tool.*"
      target: "https://example.com/conflict",
      inputHash: "11".repeat(32),
    });
    if (allowed.kind !== "allowed") throw new Error("expected allowed");
    let caught: unknown;
    try {
      await client.recordToolExecution({
        allowedReceiptId: allowed.contentId,
        outputHash: "22".repeat(32),
      });
    } catch (e) {
      caught = e;
    }
    const err = caught as { status: number; code: string };
    expect(err.status).toBe(409);
    expect(err.code).toBe("conflict");
  });

  it("recordToolExecution failure case (error field) verifies cold", async () => {
    const client = new UniclawClient({ baseUrl });
    const allowed = await client.evaluate({
      kind: "tool.http_fetch",
      target: "https://api.example.com/fail",
      inputHash: "33".repeat(32),
    });
    if (allowed.kind !== "allowed") throw new Error("expected allowed");
    const execution = await client.recordToolExecution({
      allowedReceiptId: allowed.contentId,
      error: "tool host reported failure",
    });
    expect(execution.kind).toBe("allowed");
    const execFull = (await client.getReceipt(execution.contentId)) as {
      body: { action: { target: string }; provenance: { kind: string }[] };
    };
    expect(execFull.body.action.target).toContain("status=failed");
    const failureKinds = execFull.body.provenance.map((e) => e.kind);
    expect(failureKinds).toContain("tool_execution_failure");
  });
});

if (!INTEGRATION) {
  // eslint-disable-next-line no-console
  console.log(
    "[skip] @uniclaw/client integration tests — set UNICLAW_INTEGRATION=1 and build the release binary to run them.",
  );
}
