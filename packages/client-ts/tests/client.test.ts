// Unit tests for `BoardProofClient` with a mocked fetch. Cover the
// request shape (snake_case wire / camelCase API), the response
// parsing, the discriminated union, the pending callback flow, and
// the error mapping.
//
// The integration test (`tests/integration.test.ts`) covers the
// live-binary end-to-end flow.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { BoardProofClient, BoardProofError } from "../src/index.js";

// A fake `fetch` we can program per-test. Vitest's `vi.fn()` makes
// the call log inspectable.
type FetchFn = typeof fetch;

interface Calls {
  url: string;
  method: string;
  body?: unknown;
  /// Lowercased header map captured per call. Tests assert on
  /// auth headers + content-type.
  headers: Record<string, string>;
}

function makeFetchMock(handlers: Record<
  string, // "METHOD URL"
  () => { status?: number; body: unknown }
>): { fetch: FetchFn; calls: Calls[] } {
  const calls: Calls[] = [];
  const fn = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.toString();
    const method = init?.method ?? "GET";
    const body = init?.body
      ? JSON.parse(init.body as string)
      : undefined;
    // Normalize whatever headers shape `init.headers` is in into a
    // plain { lowercased: string } map. RequestInit.headers can be
    // a Headers, a [key, value][], or a Record — the client passes
    // a plain Record so the simple branch covers it, but we handle
    // the others too in case test code does something different.
    const headers: Record<string, string> = {};
    const raw = init?.headers;
    if (raw instanceof Headers) {
      raw.forEach((v, k) => {
        headers[k.toLowerCase()] = v;
      });
    } else if (Array.isArray(raw)) {
      for (const [k, v] of raw) {
        headers[k.toLowerCase()] = v;
      }
    } else if (raw && typeof raw === "object") {
      for (const [k, v] of Object.entries(raw)) {
        headers[k.toLowerCase()] = String(v);
      }
    }
    calls.push({ url, method, body, headers });
    const key = `${method} ${url}`;
    const handler = handlers[key];
    if (!handler) {
      throw new Error(`unhandled mock: ${key}`);
    }
    const r = handler();
    const status = r.status ?? 200;
    const text = JSON.stringify(r.body);
    return new Response(text, {
      status,
      headers: { "content-type": "application/json" },
    });
  });
  return { fetch: fn as unknown as FetchFn, calls };
}

const BASE = "http://127.0.0.1:9999";

const ALLOWED_RESP = {
  decision: "allowed",
  content_id: "a".repeat(64),
  receipt_url: `/receipts/${"a".repeat(64)}`,
  issuer: "b".repeat(64),
  sequence: 0,
  schema_version: 2,
};

const DENIED_RESP = {
  decision: "denied",
  content_id: "c".repeat(64),
  receipt_url: `/receipts/${"c".repeat(64)}`,
  issuer: "b".repeat(64),
  sequence: 1,
  schema_version: 2,
};

const PENDING_RESP = {
  decision: "pending",
  content_id: "d".repeat(64),
  receipt_url: `/receipts/${"d".repeat(64)}`,
  issuer: "b".repeat(64),
  sequence: 2,
  schema_version: 2,
};

const APPROVED_RESP = {
  decision: "approved",
  content_id: "e".repeat(64),
  receipt_url: `/receipts/${"e".repeat(64)}`,
  issuer: "b".repeat(64),
  sequence: 3,
  schema_version: 2,
};

describe("BoardProofClient.evaluate — wire shape", () => {
  it("posts to /v1/proposals with snake_case body", async () => {
    const { fetch, calls } = makeFetchMock({
      [`POST ${BASE}/v1/proposals`]: () => ({ body: ALLOWED_RESP }),
    });
    const client = new BoardProofClient({
      baseUrl: BASE,
      fetch,
      verifyByDefault: false,
    });
    await client.evaluate({
      kind: "http.fetch",
      target: "https://example.com/",
      inputHash: "00".repeat(32),
    });
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe(`${BASE}/v1/proposals`);
    expect(calls[0]!.method).toBe("POST");
    expect(calls[0]!.body).toEqual({
      action: {
        kind: "http.fetch",
        target: "https://example.com/",
        input_hash: "00".repeat(32),
      },
    });
  });

  it("returns an AllowedDecision with absolute receiptUrl", async () => {
    const { fetch } = makeFetchMock({
      [`POST ${BASE}/v1/proposals`]: () => ({ body: ALLOWED_RESP }),
    });
    const client = new BoardProofClient({ baseUrl: BASE, fetch, verifyByDefault: false });
    const d = await client.evaluate({
      kind: "http.fetch",
      target: "x",
      inputHash: "00".repeat(32),
    });
    expect(d.kind).toBe("allowed");
    if (d.kind !== "allowed") throw new Error("type narrowing");
    expect(d.contentId).toBe("a".repeat(64));
    expect(d.receiptUrl).toBe(`${BASE}/receipts/${"a".repeat(64)}`);
    expect(d.issuer).toBe("b".repeat(64));
    expect(d.sequence).toBe(0);
    expect(d.schemaVersion).toBe(2);
  });

  it("strips trailing slashes from baseUrl", async () => {
    const { fetch, calls } = makeFetchMock({
      [`POST ${BASE}/v1/proposals`]: () => ({ body: ALLOWED_RESP }),
    });
    const client = new BoardProofClient({
      baseUrl: `${BASE}////`,
      fetch,
      verifyByDefault: false,
    });
    await client.evaluate({ kind: "x", target: "y", inputHash: "00".repeat(32) });
    expect(calls[0]!.url).toBe(`${BASE}/v1/proposals`);
  });
});

describe("BoardProofClient.evaluate — decision variants", () => {
  it("maps denied", async () => {
    const { fetch } = makeFetchMock({
      [`POST ${BASE}/v1/proposals`]: () => ({ body: DENIED_RESP }),
    });
    const client = new BoardProofClient({ baseUrl: BASE, fetch, verifyByDefault: false });
    const d = await client.evaluate({ kind: "shell.exec", target: "rm", inputHash: "00".repeat(32) });
    expect(d.kind).toBe("denied");
  });

  it("maps pending and exposes approve/deny callbacks", async () => {
    const { fetch, calls } = makeFetchMock({
      [`POST ${BASE}/v1/proposals`]: () => ({ body: PENDING_RESP }),
      [`POST ${BASE}/v1/approvals/${"d".repeat(64)}/resolve`]: () => ({
        body: APPROVED_RESP,
      }),
    });
    const client = new BoardProofClient({ baseUrl: BASE, fetch, verifyByDefault: false });
    const d = await client.evaluate({
      kind: "http.fetch",
      target: "/admin/x",
      inputHash: "00".repeat(32),
    });
    expect(d.kind).toBe("pending");
    if (d.kind !== "pending") throw new Error("narrowing");
    const final = await d.approve("operator@example.com");
    expect(final.kind).toBe("approved");
    expect(calls).toHaveLength(2);
    expect(calls[1]!.body).toEqual({
      principal: "operator@example.com",
      outcome: "approved",
    });
  });

  it("pending.deny narrows the return type to DeniedDecision", async () => {
    const { fetch, calls } = makeFetchMock({
      [`POST ${BASE}/v1/proposals`]: () => ({ body: PENDING_RESP }),
      [`POST ${BASE}/v1/approvals/${"d".repeat(64)}/resolve`]: () => ({
        body: { ...DENIED_RESP, content_id: "f".repeat(64) },
      }),
    });
    const client = new BoardProofClient({ baseUrl: BASE, fetch, verifyByDefault: false });
    const d = await client.evaluate({ kind: "x", target: "y", inputHash: "00".repeat(32) });
    if (d.kind !== "pending") throw new Error("narrowing");
    const denied = await d.deny("operator@example.com");
    expect(denied.kind).toBe("denied");
    expect(calls[1]!.body).toEqual({
      principal: "operator@example.com",
      outcome: "denied",
    });
  });

  it("throws on unknown decision kind", async () => {
    const { fetch } = makeFetchMock({
      [`POST ${BASE}/v1/proposals`]: () => ({
        body: { ...ALLOWED_RESP, decision: "weird" },
      }),
    });
    const client = new BoardProofClient({ baseUrl: BASE, fetch, verifyByDefault: false });
    await expect(
      client.evaluate({ kind: "x", target: "y", inputHash: "00".repeat(32) }),
    ).rejects.toThrow(/unknown decision/);
  });
});

describe("BoardProofClient — error mapping", () => {
  it("400 → BoardProofError(bad_request)", async () => {
    const { fetch } = makeFetchMock({
      [`POST ${BASE}/v1/proposals`]: () => ({
        status: 400,
        body: { error: "bad_request", detail: "action.input_hash: not hex" },
      }),
    });
    const client = new BoardProofClient({ baseUrl: BASE, fetch, verifyByDefault: false });
    let caught: unknown;
    try {
      await client.evaluate({ kind: "x", target: "y", inputHash: "bogus" });
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(BoardProofError);
    const err = caught as BoardProofError;
    expect(err.status).toBe(400);
    expect(err.code).toBe("bad_request");
    expect(err.detail).toContain("input_hash");
  });

  it("404 → BoardProofError(not_found)", async () => {
    const { fetch } = makeFetchMock({
      [`POST ${BASE}/v1/approvals/${"f".repeat(64)}/resolve`]: () => ({
        status: 404,
        body: { error: "not_found", detail: "no receipt with content_id ..." },
      }),
    });
    const client = new BoardProofClient({ baseUrl: BASE, fetch, verifyByDefault: false });
    await expect(
      client.resolveApproval("f".repeat(64), {
        principal: "x",
        outcome: "approved",
      }),
    ).rejects.toMatchObject({ status: 404, code: "not_found" });
  });

  it("409 → BoardProofError(conflict)", async () => {
    const { fetch } = makeFetchMock({
      [`POST ${BASE}/v1/approvals/${"a".repeat(64)}/resolve`]: () => ({
        status: 409,
        body: { error: "conflict", detail: "not pending" },
      }),
    });
    const client = new BoardProofClient({ baseUrl: BASE, fetch, verifyByDefault: false });
    await expect(
      client.resolveApproval("a".repeat(64), {
        principal: "x",
        outcome: "approved",
      }),
    ).rejects.toMatchObject({ status: 409, code: "conflict" });
  });

  it("500 with non-JSON body → BoardProofError(non_json_response)", async () => {
    const fetch: typeof globalThis.fetch = async () =>
      new Response("oops", {
        status: 500,
        headers: { "content-type": "text/plain" },
      });
    const client = new BoardProofClient({ baseUrl: BASE, fetch, verifyByDefault: false });
    await expect(
      client.evaluate({ kind: "x", target: "y", inputHash: "00".repeat(32) }),
    ).rejects.toMatchObject({ status: 500, code: "non_json_response" });
  });
});

describe("BoardProofClient — verify-by-default", () => {
  // We can't run the real verifier inline here without a real
  // receipt + key. The integration test covers the happy path with
  // a live binary. Here we just confirm the default value applies
  // when no override is given, and that `verify: false` opts out.

  const PASSTHROUGH_BASE = "http://test/";
  let savedBaseUrl: string;
  beforeEach(() => {
    savedBaseUrl = PASSTHROUGH_BASE;
  });
  afterEach(() => {
    void savedBaseUrl; // silence unused warning under noUnusedLocals
  });

  it("verifyByDefault: false bypasses the verify call entirely", async () => {
    let getReceiptCalled = false;
    const fetch: typeof globalThis.fetch = async (input, init) => {
      const url = String(input);
      if (url.endsWith("/v1/proposals")) {
        return new Response(JSON.stringify(ALLOWED_RESP), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (url.includes("/receipts/")) {
        getReceiptCalled = true;
        return new Response("{}", { status: 200 });
      }
      throw new Error(`unexpected url ${url} (init=${JSON.stringify(init)})`);
    };
    const client = new BoardProofClient({
      baseUrl: BASE,
      fetch,
      verifyByDefault: false,
    });
    await client.evaluate({ kind: "x", target: "y", inputHash: "00".repeat(32) });
    expect(getReceiptCalled).toBe(false);
  });

  it("evaluate({verify: false}) overrides verifyByDefault: true", async () => {
    let getReceiptCalled = false;
    const fetch: typeof globalThis.fetch = async (input) => {
      const url = String(input);
      if (url.endsWith("/v1/proposals")) {
        return new Response(JSON.stringify(ALLOWED_RESP), { status: 200 });
      }
      if (url.includes("/receipts/")) {
        getReceiptCalled = true;
        return new Response("{}", { status: 200 });
      }
      throw new Error(`unexpected url ${url}`);
    };
    const client = new BoardProofClient({
      baseUrl: BASE,
      fetch,
      verifyByDefault: true,
    });
    await client.evaluate(
      { kind: "x", target: "y", inputHash: "00".repeat(32) },
      { verify: false },
    );
    expect(getReceiptCalled).toBe(false);
  });
});

describe("BoardProofClient.resolveApproval — direct path", () => {
  it("can be called without a PendingDecision", async () => {
    const { fetch, calls } = makeFetchMock({
      [`POST ${BASE}/v1/approvals/${"d".repeat(64)}/resolve`]: () => ({
        body: APPROVED_RESP,
      }),
    });
    const client = new BoardProofClient({ baseUrl: BASE, fetch, verifyByDefault: false });
    const d = await client.resolveApproval("d".repeat(64), {
      principal: "operator@example.com",
      outcome: "approved",
    });
    expect(d.kind).toBe("approved");
    expect(calls[0]!.url).toBe(
      `${BASE}/v1/approvals/${"d".repeat(64)}/resolve`,
    );
  });

  it("rejects unexpected response kinds (server bug)", async () => {
    const { fetch } = makeFetchMock({
      [`POST ${BASE}/v1/approvals/${"d".repeat(64)}/resolve`]: () => ({
        body: { ...PENDING_RESP, content_id: "d".repeat(64) },
      }),
    });
    const client = new BoardProofClient({ baseUrl: BASE, fetch, verifyByDefault: false });
    await expect(
      client.resolveApproval("d".repeat(64), {
        principal: "x",
        outcome: "approved",
      }),
    ).rejects.toThrow(/unexpected resolve response/);
  });
});

describe("BoardProofClient.recordToolExecution — wire shape", () => {
  const ALLOWED_ID = "f".repeat(64);
  const TE_RESP = {
    decision: "allowed",
    content_id: "9".repeat(64),
    receipt_url: `/receipts/${"9".repeat(64)}`,
    issuer: "b".repeat(64),
    sequence: 4,
    schema_version: 2,
  };

  it("posts to /v1/tool-executions with minimum success shape", async () => {
    const { fetch, calls } = makeFetchMock({
      [`POST ${BASE}/v1/tool-executions`]: () => ({ body: TE_RESP }),
    });
    const client = new BoardProofClient({ baseUrl: BASE, fetch, verifyByDefault: false });
    const r = await client.recordToolExecution({
      allowedReceiptId: ALLOWED_ID,
      outputHash: "11".repeat(32),
    });
    expect(r.kind).toBe("allowed");
    expect(calls).toHaveLength(1);
    expect(calls[0]!.body).toEqual({
      allowed_receipt_id: ALLOWED_ID,
      output_hash: "11".repeat(32),
    });
  });

  it("includes secrets_used only when non-empty", async () => {
    const { fetch, calls } = makeFetchMock({
      [`POST ${BASE}/v1/tool-executions`]: () => ({ body: TE_RESP }),
    });
    const client = new BoardProofClient({ baseUrl: BASE, fetch, verifyByDefault: false });
    await client.recordToolExecution({
      allowedReceiptId: ALLOWED_ID,
      outputHash: "11".repeat(32),
      secretsUsed: ["github.token", "slack.webhook"],
    });
    expect(calls[0]!.body).toEqual({
      allowed_receipt_id: ALLOWED_ID,
      output_hash: "11".repeat(32),
      secrets_used: ["github.token", "slack.webhook"],
    });
  });

  it("omits secrets_used when explicitly empty", async () => {
    const { fetch, calls } = makeFetchMock({
      [`POST ${BASE}/v1/tool-executions`]: () => ({ body: TE_RESP }),
    });
    const client = new BoardProofClient({ baseUrl: BASE, fetch, verifyByDefault: false });
    await client.recordToolExecution({
      allowedReceiptId: ALLOWED_ID,
      outputHash: "11".repeat(32),
      secretsUsed: [],
    });
    // Empty list is omitted (smaller wire body; the server's
    // #[serde(default)] makes either form equivalent).
    expect(calls[0]!.body).toEqual({
      allowed_receipt_id: ALLOWED_ID,
      output_hash: "11".repeat(32),
    });
  });

  it("camelCases the redaction shape on the wire", async () => {
    const { fetch, calls } = makeFetchMock({
      [`POST ${BASE}/v1/tool-executions`]: () => ({ body: TE_RESP }),
    });
    const client = new BoardProofClient({ baseUrl: BASE, fetch, verifyByDefault: false });
    await client.recordToolExecution({
      allowedReceiptId: ALLOWED_ID,
      outputHash: "11".repeat(32),
      redaction: {
        redactedOutputHash: "22".repeat(32),
        stackHash: "33".repeat(32),
        matches: [{ ruleId: "github_pat", count: 1 }],
      },
    });
    expect(calls[0]!.body).toEqual({
      allowed_receipt_id: ALLOWED_ID,
      output_hash: "11".repeat(32),
      redaction: {
        redacted_output_hash: "22".repeat(32),
        stack_hash: "33".repeat(32),
        matches: [{ rule_id: "github_pat", count: 1 }],
      },
    });
  });

  it("sends the failure shape when error is set", async () => {
    const { fetch, calls } = makeFetchMock({
      [`POST ${BASE}/v1/tool-executions`]: () => ({ body: TE_RESP }),
    });
    const client = new BoardProofClient({ baseUrl: BASE, fetch, verifyByDefault: false });
    await client.recordToolExecution({
      allowedReceiptId: ALLOWED_ID,
      error: "connection refused",
    });
    expect(calls[0]!.body).toEqual({
      allowed_receipt_id: ALLOWED_ID,
      error: "connection refused",
    });
  });

  it("surfaces 400 from the server", async () => {
    const { fetch } = makeFetchMock({
      [`POST ${BASE}/v1/tool-executions`]: () => ({
        status: 400,
        body: {
          error: "bad_request",
          detail: "exactly one of output_hash or error must be set",
        },
      }),
    });
    const client = new BoardProofClient({ baseUrl: BASE, fetch, verifyByDefault: false });
    await expect(
      client.recordToolExecution({ allowedReceiptId: ALLOWED_ID }),
    ).rejects.toMatchObject({ status: 400, code: "bad_request" });
  });

  it("surfaces 404 from the server", async () => {
    const { fetch } = makeFetchMock({
      [`POST ${BASE}/v1/tool-executions`]: () => ({
        status: 404,
        body: { error: "not_found", detail: "no receipt with content_id ..." },
      }),
    });
    const client = new BoardProofClient({ baseUrl: BASE, fetch, verifyByDefault: false });
    await expect(
      client.recordToolExecution({
        allowedReceiptId: ALLOWED_ID,
        outputHash: "11".repeat(32),
      }),
    ).rejects.toMatchObject({ status: 404, code: "not_found" });
  });

  it("surfaces 409 from the server", async () => {
    const { fetch } = makeFetchMock({
      [`POST ${BASE}/v1/tool-executions`]: () => ({
        status: 409,
        body: {
          error: "conflict",
          detail: "receipt ... action.kind \"http.fetch\" does not start with \"tool.\"",
        },
      }),
    });
    const client = new BoardProofClient({ baseUrl: BASE, fetch, verifyByDefault: false });
    await expect(
      client.recordToolExecution({
        allowedReceiptId: ALLOWED_ID,
        outputHash: "11".repeat(32),
      }),
    ).rejects.toMatchObject({ status: 409, code: "conflict" });
  });

  it("throws if server returns a non-allowed decision (server bug)", async () => {
    const { fetch } = makeFetchMock({
      [`POST ${BASE}/v1/tool-executions`]: () => ({
        body: { ...TE_RESP, decision: "denied" },
      }),
    });
    const client = new BoardProofClient({ baseUrl: BASE, fetch, verifyByDefault: false });
    await expect(
      client.recordToolExecution({
        allowedReceiptId: ALLOWED_ID,
        outputHash: "11".repeat(32),
      }),
    ).rejects.toThrow(/unexpected tool-execution response/);
  });
});

describe("BoardProofClient.getReceipt", () => {
  it("GETs /receipts/<hash> and returns parsed JSON", async () => {
    const expectedReceipt = { version: 1, body: { foo: "bar" } };
    const { fetch, calls } = makeFetchMock({
      [`GET ${BASE}/receipts/${"a".repeat(64)}`]: () => ({ body: expectedReceipt }),
    });
    const client = new BoardProofClient({ baseUrl: BASE, fetch, verifyByDefault: false });
    const r = await client.getReceipt("a".repeat(64));
    expect(r).toEqual(expectedReceipt);
    expect(calls[0]!.method).toBe("GET");
  });

  it("throws BoardProofError on 404", async () => {
    const { fetch } = makeFetchMock({
      [`GET ${BASE}/receipts/${"a".repeat(64)}`]: () => ({
        status: 404,
        body: { error: "receipt_not_found", hash: "..." },
      }),
    });
    const client = new BoardProofClient({ baseUrl: BASE, fetch, verifyByDefault: false });
    await expect(client.getReceipt("a".repeat(64))).rejects.toMatchObject({
      status: 404,
    });
  });
});

describe("BoardProofClient — bearer-token auth (step 25)", () => {
  const TOKEN = "a5".repeat(32);
  const RECEIPT_BODY = {
    version: 1,
    body: {
      schema_version: 2,
      decision: "allowed",
      merkle_leaf: { sequence: 0, leaf_hash: "00".repeat(32), prev_hash: "00".repeat(32) },
    },
  };

  it("attaches Authorization: Bearer <token> on POST /v1/proposals", async () => {
    const { fetch, calls } = makeFetchMock({
      [`POST ${BASE}/v1/proposals`]: () => ({ body: ALLOWED_RESP }),
    });
    const client = new BoardProofClient({
      baseUrl: BASE,
      fetch,
      verifyByDefault: false,
      bearerToken: TOKEN,
    });
    await client.evaluate({ kind: "x", target: "y", inputHash: "00".repeat(32) });
    expect(calls).toHaveLength(1);
    expect(calls[0]!.headers["authorization"]).toBe(`Bearer ${TOKEN}`);
    expect(calls[0]!.headers["content-type"]).toBe("application/json");
  });

  it("attaches Authorization on POST /v1/approvals/{id}/resolve", async () => {
    const id = "d".repeat(64);
    const { fetch, calls } = makeFetchMock({
      [`POST ${BASE}/v1/approvals/${id}/resolve`]: () => ({ body: APPROVED_RESP }),
    });
    const client = new BoardProofClient({
      baseUrl: BASE,
      fetch,
      verifyByDefault: false,
      bearerToken: TOKEN,
    });
    await client.resolveApproval(id, { principal: "ops", outcome: "approved" });
    expect(calls[0]!.headers["authorization"]).toBe(`Bearer ${TOKEN}`);
  });

  it("attaches Authorization on POST /v1/tool-executions", async () => {
    const teResp = {
      decision: "allowed",
      content_id: "9".repeat(64),
      receipt_url: `/receipts/${"9".repeat(64)}`,
      issuer: "b".repeat(64),
      sequence: 4,
      schema_version: 2,
    };
    const { fetch, calls } = makeFetchMock({
      [`POST ${BASE}/v1/tool-executions`]: () => ({ body: teResp }),
    });
    const client = new BoardProofClient({
      baseUrl: BASE,
      fetch,
      verifyByDefault: false,
      bearerToken: TOKEN,
    });
    await client.recordToolExecution({
      allowedReceiptId: "f".repeat(64),
      outputHash: "11".repeat(32),
    });
    expect(calls[0]!.headers["authorization"]).toBe(`Bearer ${TOKEN}`);
  });

  it("does NOT attach Authorization on GET /receipts/<hash>", async () => {
    const hash = "a".repeat(64);
    const { fetch, calls } = makeFetchMock({
      [`GET ${BASE}/receipts/${hash}`]: () => ({ body: RECEIPT_BODY }),
    });
    const client = new BoardProofClient({
      baseUrl: BASE,
      fetch,
      verifyByDefault: false,
      bearerToken: TOKEN,
    });
    await client.getReceipt(hash);
    expect(calls[0]!.method).toBe("GET");
    expect(calls[0]!.headers["authorization"]).toBeUndefined();
  });

  it("does NOT attach Authorization on verifyReceiptUrl", async () => {
    const hash = "a".repeat(64);
    const url = `${BASE}/receipts/${hash}`;
    const { fetch, calls } = makeFetchMock({
      [`GET ${url}`]: () => ({ body: RECEIPT_BODY }),
    });
    const client = new BoardProofClient({
      baseUrl: BASE,
      fetch,
      verifyByDefault: false,
      bearerToken: TOKEN,
    });
    // The receipt body above is intentionally minimal — verify will
    // return ok=false, but we're testing the auth header, not the
    // verifier correctness.
    await client.verifyReceiptUrl(url);
    expect(calls[0]!.headers["authorization"]).toBeUndefined();
  });

  it("omits Authorization entirely when no token configured", async () => {
    const { fetch, calls } = makeFetchMock({
      [`POST ${BASE}/v1/proposals`]: () => ({ body: ALLOWED_RESP }),
    });
    const client = new BoardProofClient({ baseUrl: BASE, fetch, verifyByDefault: false });
    await client.evaluate({ kind: "x", target: "y", inputHash: "00".repeat(32) });
    expect(calls[0]!.headers["authorization"]).toBeUndefined();
    expect(calls[0]!.headers["content-type"]).toBe("application/json");
  });

  it("surfaces 401 from server as BoardProofError(status=401, code='unauthorized')", async () => {
    const { fetch } = makeFetchMock({
      [`POST ${BASE}/v1/proposals`]: () => ({
        status: 401,
        body: { error: "unauthorized", detail: "missing Authorization header" },
      }),
    });
    const client = new BoardProofClient({ baseUrl: BASE, fetch, verifyByDefault: false });
    await expect(
      client.evaluate({ kind: "x", target: "y", inputHash: "00".repeat(32) }),
    ).rejects.toMatchObject({ status: 401, code: "unauthorized" });
  });
});

describe("BoardProofClient — key_id surface (step 19a)", () => {
  it("surfaces keyId on the Decision when server returns it", async () => {
    const { fetch } = makeFetchMock({
      [`POST ${BASE}/v1/proposals`]: () => ({
        body: { ...ALLOWED_RESP, key_id: "prod-2026" },
      }),
    });
    const client = new BoardProofClient({
      baseUrl: BASE,
      fetch,
      verifyByDefault: false,
    });
    const d = await client.evaluate({
      kind: "http.fetch",
      target: "x",
      inputHash: "00".repeat(32),
    });
    expect(d.kind).toBe("allowed");
    expect(d.keyId).toBe("prod-2026");
  });

  it("omits keyId when server doesn't return it", async () => {
    const { fetch } = makeFetchMock({
      [`POST ${BASE}/v1/proposals`]: () => ({ body: ALLOWED_RESP }),
    });
    const client = new BoardProofClient({
      baseUrl: BASE,
      fetch,
      verifyByDefault: false,
    });
    const d = await client.evaluate({
      kind: "http.fetch",
      target: "x",
      inputHash: "00".repeat(32),
    });
    expect(d.kind).toBe("allowed");
    expect(d.keyId).toBeUndefined();
  });

  it("threads keyId through resolveApproval responses", async () => {
    const cid = "d".repeat(64);
    const { fetch } = makeFetchMock({
      [`POST ${BASE}/v1/approvals/${cid}/resolve`]: () => ({
        body: { ...APPROVED_RESP, key_id: "hsm-3" },
      }),
    });
    const client = new BoardProofClient({
      baseUrl: BASE,
      fetch,
      verifyByDefault: false,
    });
    const d = await client.resolveApproval(cid, {
      principal: "ops",
      outcome: "approved",
    });
    expect(d.kind).toBe("approved");
    expect(d.keyId).toBe("hsm-3");
  });

  it("threads keyId through recordToolExecution responses", async () => {
    const teResp = {
      decision: "allowed",
      content_id: "9".repeat(64),
      receipt_url: `/receipts/${"9".repeat(64)}`,
      issuer: "b".repeat(64),
      sequence: 4,
      schema_version: 2,
      key_id: "prod-2026",
    };
    const { fetch } = makeFetchMock({
      [`POST ${BASE}/v1/tool-executions`]: () => ({ body: teResp }),
    });
    const client = new BoardProofClient({
      baseUrl: BASE,
      fetch,
      verifyByDefault: false,
    });
    const d = await client.recordToolExecution({
      allowedReceiptId: "f".repeat(64),
      outputHash: "11".repeat(32),
    });
    expect(d.kind).toBe("allowed");
    expect(d.keyId).toBe("prod-2026");
  });
});
