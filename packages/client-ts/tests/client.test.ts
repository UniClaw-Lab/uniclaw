// Unit tests for `UniclawClient` with a mocked fetch. Cover the
// request shape (snake_case wire / camelCase API), the response
// parsing, the discriminated union, the pending callback flow, and
// the error mapping.
//
// The integration test (`tests/integration.test.ts`) covers the
// live-binary end-to-end flow.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { UniclawClient, UniclawError } from "../src/index.js";

// A fake `fetch` we can program per-test. Vitest's `vi.fn()` makes
// the call log inspectable.
type FetchFn = typeof fetch;

interface Calls {
  url: string;
  method: string;
  body?: unknown;
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
    calls.push({ url, method, body });
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

describe("UniclawClient.evaluate — wire shape", () => {
  it("posts to /v1/proposals with snake_case body", async () => {
    const { fetch, calls } = makeFetchMock({
      [`POST ${BASE}/v1/proposals`]: () => ({ body: ALLOWED_RESP }),
    });
    const client = new UniclawClient({
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
    const client = new UniclawClient({ baseUrl: BASE, fetch, verifyByDefault: false });
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
    const client = new UniclawClient({
      baseUrl: `${BASE}////`,
      fetch,
      verifyByDefault: false,
    });
    await client.evaluate({ kind: "x", target: "y", inputHash: "00".repeat(32) });
    expect(calls[0]!.url).toBe(`${BASE}/v1/proposals`);
  });
});

describe("UniclawClient.evaluate — decision variants", () => {
  it("maps denied", async () => {
    const { fetch } = makeFetchMock({
      [`POST ${BASE}/v1/proposals`]: () => ({ body: DENIED_RESP }),
    });
    const client = new UniclawClient({ baseUrl: BASE, fetch, verifyByDefault: false });
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
    const client = new UniclawClient({ baseUrl: BASE, fetch, verifyByDefault: false });
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
    const client = new UniclawClient({ baseUrl: BASE, fetch, verifyByDefault: false });
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
    const client = new UniclawClient({ baseUrl: BASE, fetch, verifyByDefault: false });
    await expect(
      client.evaluate({ kind: "x", target: "y", inputHash: "00".repeat(32) }),
    ).rejects.toThrow(/unknown decision/);
  });
});

describe("UniclawClient — error mapping", () => {
  it("400 → UniclawError(bad_request)", async () => {
    const { fetch } = makeFetchMock({
      [`POST ${BASE}/v1/proposals`]: () => ({
        status: 400,
        body: { error: "bad_request", detail: "action.input_hash: not hex" },
      }),
    });
    const client = new UniclawClient({ baseUrl: BASE, fetch, verifyByDefault: false });
    let caught: unknown;
    try {
      await client.evaluate({ kind: "x", target: "y", inputHash: "bogus" });
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(UniclawError);
    const err = caught as UniclawError;
    expect(err.status).toBe(400);
    expect(err.code).toBe("bad_request");
    expect(err.detail).toContain("input_hash");
  });

  it("404 → UniclawError(not_found)", async () => {
    const { fetch } = makeFetchMock({
      [`POST ${BASE}/v1/approvals/${"f".repeat(64)}/resolve`]: () => ({
        status: 404,
        body: { error: "not_found", detail: "no receipt with content_id ..." },
      }),
    });
    const client = new UniclawClient({ baseUrl: BASE, fetch, verifyByDefault: false });
    await expect(
      client.resolveApproval("f".repeat(64), {
        principal: "x",
        outcome: "approved",
      }),
    ).rejects.toMatchObject({ status: 404, code: "not_found" });
  });

  it("409 → UniclawError(conflict)", async () => {
    const { fetch } = makeFetchMock({
      [`POST ${BASE}/v1/approvals/${"a".repeat(64)}/resolve`]: () => ({
        status: 409,
        body: { error: "conflict", detail: "not pending" },
      }),
    });
    const client = new UniclawClient({ baseUrl: BASE, fetch, verifyByDefault: false });
    await expect(
      client.resolveApproval("a".repeat(64), {
        principal: "x",
        outcome: "approved",
      }),
    ).rejects.toMatchObject({ status: 409, code: "conflict" });
  });

  it("500 with non-JSON body → UniclawError(non_json_response)", async () => {
    const fetch: typeof globalThis.fetch = async () =>
      new Response("oops", {
        status: 500,
        headers: { "content-type": "text/plain" },
      });
    const client = new UniclawClient({ baseUrl: BASE, fetch, verifyByDefault: false });
    await expect(
      client.evaluate({ kind: "x", target: "y", inputHash: "00".repeat(32) }),
    ).rejects.toMatchObject({ status: 500, code: "non_json_response" });
  });
});

describe("UniclawClient — verify-by-default", () => {
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
    const client = new UniclawClient({
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
    const client = new UniclawClient({
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

describe("UniclawClient.resolveApproval — direct path", () => {
  it("can be called without a PendingDecision", async () => {
    const { fetch, calls } = makeFetchMock({
      [`POST ${BASE}/v1/approvals/${"d".repeat(64)}/resolve`]: () => ({
        body: APPROVED_RESP,
      }),
    });
    const client = new UniclawClient({ baseUrl: BASE, fetch, verifyByDefault: false });
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
    const client = new UniclawClient({ baseUrl: BASE, fetch, verifyByDefault: false });
    await expect(
      client.resolveApproval("d".repeat(64), {
        principal: "x",
        outcome: "approved",
      }),
    ).rejects.toThrow(/unexpected resolve response/);
  });
});

describe("UniclawClient.getReceipt", () => {
  it("GETs /receipts/<hash> and returns parsed JSON", async () => {
    const expectedReceipt = { version: 1, body: { foo: "bar" } };
    const { fetch, calls } = makeFetchMock({
      [`GET ${BASE}/receipts/${"a".repeat(64)}`]: () => ({ body: expectedReceipt }),
    });
    const client = new UniclawClient({ baseUrl: BASE, fetch, verifyByDefault: false });
    const r = await client.getReceipt("a".repeat(64));
    expect(r).toEqual(expectedReceipt);
    expect(calls[0]!.method).toBe("GET");
  });

  it("throws UniclawError on 404", async () => {
    const { fetch } = makeFetchMock({
      [`GET ${BASE}/receipts/${"a".repeat(64)}`]: () => ({
        status: 404,
        body: { error: "receipt_not_found", hash: "..." },
      }),
    });
    const client = new UniclawClient({ baseUrl: BASE, fetch, verifyByDefault: false });
    await expect(client.getReceipt("a".repeat(64))).rejects.toMatchObject({
      status: 404,
    });
  });
});
