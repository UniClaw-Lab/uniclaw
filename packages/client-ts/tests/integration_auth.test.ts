// Integration test for step 25 (bearer-token auth). Spawns
// boardproof-host with `--bearer-token-hex <token>` and verifies:
//
// - Without `bearerToken` on the client, /v1 calls 401.
// - With the WRONG `bearerToken`, /v1 calls 401.
// - With the CORRECT `bearerToken`, /v1 calls succeed.
// - Read-only routes (GET /receipts/<hash>, /verify) stay public.
//
// Opt-in via `BOARDPROOF_INTEGRATION=1`. The release binary at
// `target/release/boardproof-host` must exist.

import { ChildProcess, spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { BoardProofClient, BoardProofError } from "../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(here, "../../..");
const HOST_BIN = resolve(REPO_ROOT, "target/release/boardproof-host");
const FIXTURE = resolve(here, "fixtures/test-constitution.toml");
const SEED_HEX = "2a".repeat(32);
// Distinct token for this suite so it doesn't collide with other
// fixtures.
const TOKEN_HEX = "c3".repeat(32);

const INTEGRATION = process.env["BOARDPROOF_INTEGRATION"] === "1";

let child: ChildProcess | undefined;
let baseUrl = "";

async function startAuthedHost(): Promise<string> {
  if (!existsSync(HOST_BIN)) {
    throw new Error(
      `release binary missing: ${HOST_BIN}\n` +
        `Run \`cargo build --release --bin boardproof-host -p boardproof-host\` first.`,
    );
  }
  const proc = spawn(
    HOST_BIN,
    [
      "--constitution",
      FIXTURE,
      "--signer-seed-hex",
      SEED_HEX,
      "--bearer-token-hex",
      TOKEN_HEX,
      "--bind",
      "127.0.0.1:0",
    ],
    { stdio: ["ignore", "pipe", "pipe"] },
  );
  child = proc;
  const url = await new Promise<string>((resolveLine, reject) => {
    const timer = setTimeout(
      () => reject(new Error("boardproof-host did not bind within 10 s")),
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
      reject(new Error(`boardproof-host exited early with code ${code}: ${buf}`));
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

describe.skipIf(!INTEGRATION)("auth: bearer-token on live boardproof-host", () => {
  beforeAll(async () => {
    baseUrl = await startAuthedHost();
  }, 15_000);

  afterAll(async () => {
    await stopHost();
  });

  it("rejects evaluate without bearer token (401)", async () => {
    const client = new BoardProofClient({
      baseUrl,
      verifyByDefault: false,
      // intentionally no bearerToken
    });
    let caught: unknown;
    try {
      await client.evaluate({
        kind: "http.fetch",
        target: "https://example.com/no-auth",
        inputHash: "00".repeat(32),
      });
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(BoardProofError);
    const err = caught as BoardProofError;
    expect(err.status).toBe(401);
    expect(err.code).toBe("unauthorized");
  });

  it("rejects evaluate with WRONG token (401)", async () => {
    const client = new BoardProofClient({
      baseUrl,
      verifyByDefault: false,
      bearerToken: "b6".repeat(32), // wrong (right length, wrong bytes)
    });
    let caught: unknown;
    try {
      await client.evaluate({
        kind: "http.fetch",
        target: "https://example.com/wrong-token",
        inputHash: "00".repeat(32),
      });
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(BoardProofError);
    expect((caught as BoardProofError).status).toBe(401);
  });

  it("accepts evaluate with CORRECT token (200 + verifies cold)", async () => {
    const client = new BoardProofClient({ baseUrl, bearerToken: TOKEN_HEX });
    const decision = await client.evaluate({
      kind: "http.fetch",
      target: "https://example.com/with-token",
      inputHash: "00".repeat(32),
    });
    expect(decision.kind).toBe("allowed");
  });

  it("read-only routes stay public (no token needed)", async () => {
    // Mint a receipt with auth, then fetch it without.
    const authed = new BoardProofClient({ baseUrl, bearerToken: TOKEN_HEX });
    const minted = await authed.evaluate({
      kind: "http.fetch",
      target: "https://example.com/public-fetch",
      inputHash: "01".repeat(32),
    });

    // No token configured on this client — GET /receipts/<hash>
    // must still succeed.
    const reader = new BoardProofClient({ baseUrl, verifyByDefault: false });
    const receipt = await reader.getReceipt(minted.contentId);
    expect(receipt).toBeDefined();
    // verifyReceiptUrl also doesn't send auth and must work.
    const result = await reader.verifyReceiptUrl(minted.receiptUrl);
    expect(result.ok).toBe(true);
  });

  it("full chain works with auth: propose + record_tool_execution", async () => {
    const client = new BoardProofClient({ baseUrl, bearerToken: TOKEN_HEX });
    const allowed = await client.evaluate({
      kind: "tool.http_fetch",
      target: "https://api.example.com/auth-chain",
      inputHash: "aa".repeat(32),
    });
    expect(allowed.kind).toBe("allowed");
    const exec = await client.recordToolExecution({
      allowedReceiptId: allowed.contentId,
      outputHash: "bb".repeat(32),
    });
    expect(exec.kind).toBe("allowed");
    expect(exec.sequence).toBeGreaterThan(allowed.sequence);
  });
});
