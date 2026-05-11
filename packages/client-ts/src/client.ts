// UniclawClient: the TypeScript adapter for Uniclaw's HTTP
// proposal API (step 21). One class, three operations:
//
//   - `evaluate(action)`  → POST /v1/proposals
//   - `resolveApproval()` → POST /v1/approvals/{id}/resolve
//   - `getReceipt(id)`    → GET  /receipts/{hash}
//
// Plus `verifyReceiptUrl()` which re-exports the verify path from
// `@uniclaw/verifier` (step 20a).
//
// **Verify-by-default.** Every mint goes through the verifier
// before being returned to the caller. If the recomputed
// signature doesn't validate, `UniclawVerifyError` is thrown. The
// caller can opt out per-call with `{ verify: false }` or globally
// with `verifyByDefault: false` — but the safe path is on by
// default. This is the trust property the wedge depends on: the
// client never trusts the server's claim about what was signed.

import { verifyReceiptJson, type VerifyResult } from "@uniclaw/verifier";

import { UniclawError, UniclawVerifyError } from "./error.js";
import type {
  Action,
  AllowedDecision,
  ApprovedDecision,
  Decision,
  DecisionBase,
  DeniedDecision,
  PendingDecision,
  WireErrorBody,
  WireReceiptResponse,
} from "./types.js";

export interface UniclawClientOptions {
  /// Base URL of the running `uniclaw-host` (e.g.
  /// `"http://127.0.0.1:8787"`). Trailing slashes are tolerated.
  baseUrl: string;
  /// Optional `fetch` override — useful in tests, or for callers
  /// that need to inject auth headers / agent options. Defaults to
  /// the global `fetch` (Node 20+ and all browsers).
  fetch?: typeof fetch;
  /// Default `true`. When true, every mint is verified locally
  /// against its embedded issuer key before being returned. Per-
  /// call override via the `verify` option on `evaluate()` /
  /// `resolveApproval()`.
  verifyByDefault?: boolean;
}

export interface EvaluateOptions {
  /// Per-call override for the verify-by-default behavior.
  verify?: boolean;
}

/// Idiomatic TypeScript client for the Uniclaw HTTP proposal API.
/// One instance per `uniclaw-host` you talk to.
export class UniclawClient {
  readonly #baseUrl: string;
  readonly #fetch: typeof fetch;
  readonly #verifyByDefault: boolean;

  constructor(opts: UniclawClientOptions) {
    // Strip any trailing slash so `${baseUrl}/v1/...` doesn't
    // produce a double slash.
    this.#baseUrl = opts.baseUrl.replace(/\/+$/, "");
    this.#fetch = opts.fetch ?? globalThis.fetch.bind(globalThis);
    this.#verifyByDefault = opts.verifyByDefault ?? true;
  }

  /// Submit an action for evaluation. Returns the kernel's
  /// decision as a discriminated union — switch on `kind`:
  ///
  /// ```ts
  /// const d = await client.evaluate({ kind: "http.fetch", ... });
  /// switch (d.kind) {
  ///   case "allowed":  run(d.receiptUrl); break;
  ///   case "denied":   block();           break;
  ///   case "pending":  await d.approve("ops@example.com"); break;
  /// }
  /// ```
  async evaluate(action: Action, opts: EvaluateOptions = {}): Promise<Decision> {
    const resp = await this.#postProposal(action);
    const decision = this.#buildDecision(resp);
    await this.#maybeVerify(decision, opts);
    return decision;
  }

  /// Resolve a pending receipt programmatically. Usually called
  /// indirectly via `pendingDecision.approve(...)` /
  /// `pendingDecision.deny(...)`, but exposed publicly for cases
  /// where the operator response is collected through a separate
  /// flow (e.g. a Slack webhook) and the pending decision object
  /// is no longer in scope.
  async resolveApproval(
    contentId: string,
    body: { principal: string; outcome: "approved" | "denied" },
    opts: EvaluateOptions = {},
  ): Promise<ApprovedDecision | DeniedDecision> {
    const resp = await this.#postResolve(contentId, body);
    const decision = this.#buildDecision(resp);
    if (decision.kind !== "approved" && decision.kind !== "denied") {
      throw new Error(
        `unexpected resolve response: kind=${decision.kind} (server bug?)`,
      );
    }
    await this.#maybeVerify(decision, opts);
    return decision;
  }

  /// Fetch a receipt by content_id and verify it locally. Returns
  /// the full `VerifyResult` from `@uniclaw/verifier`.
  async verifyReceiptUrl(url: string): Promise<VerifyResult> {
    const response = await this.#fetch(url);
    if (!response.ok) {
      throw new UniclawError(
        response.status,
        "fetch_failed",
        `GET ${url} → HTTP ${response.status}`,
      );
    }
    const text = await response.text();
    return verifyReceiptJson(text);
  }

  /// Fetch a receipt as its parsed JSON. Does NOT verify — use
  /// `verifyReceiptUrl()` when you want the signature checked.
  async getReceipt(contentId: string): Promise<unknown> {
    const url = `${this.#baseUrl}/receipts/${contentId}`;
    const response = await this.#fetch(url);
    if (!response.ok) {
      throw new UniclawError(
        response.status,
        "fetch_failed",
        `GET ${url} → HTTP ${response.status}`,
      );
    }
    return response.json();
  }

  // ------------------------------------------------------------
  // Internals
  // ------------------------------------------------------------

  async #postProposal(action: Action): Promise<WireReceiptResponse> {
    const url = `${this.#baseUrl}/v1/proposals`;
    const body = JSON.stringify({
      action: {
        kind: action.kind,
        target: action.target,
        input_hash: action.inputHash,
      },
    });
    const response = await this.#fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
    });
    if (!response.ok) {
      throw await this.#parseError(response);
    }
    return (await response.json()) as WireReceiptResponse;
  }

  async #postResolve(
    contentId: string,
    body: { principal: string; outcome: "approved" | "denied" },
  ): Promise<WireReceiptResponse> {
    const url = `${this.#baseUrl}/v1/approvals/${contentId}/resolve`;
    const response = await this.#fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!response.ok) {
      throw await this.#parseError(response);
    }
    return (await response.json()) as WireReceiptResponse;
  }

  #buildDecision(resp: WireReceiptResponse): Decision {
    const base: DecisionBase = {
      contentId: resp.content_id,
      receiptUrl: joinUrl(this.#baseUrl, resp.receipt_url),
      issuer: resp.issuer,
      sequence: resp.sequence,
      schemaVersion: resp.schema_version,
    };
    switch (resp.decision) {
      case "allowed":
        return { ...base, kind: "allowed" } satisfies AllowedDecision;
      case "denied":
        return { ...base, kind: "denied" } satisfies DeniedDecision;
      case "approved":
        return { ...base, kind: "approved" } satisfies ApprovedDecision;
      case "pending":
        return {
          ...base,
          kind: "pending",
          approve: (principal) =>
            this.resolveApproval(base.contentId, {
              principal,
              outcome: "approved",
            }),
          deny: (principal) =>
            // The wire shape lets us send "denied" and get back a
            // DeniedDecision. We narrow the return type here.
            this.resolveApproval(base.contentId, {
              principal,
              outcome: "denied",
            }).then((d) => {
              if (d.kind !== "denied") {
                throw new Error(
                  `kernel returned ${d.kind} from a deny() call (server bug?)`,
                );
              }
              return d;
            }),
        } satisfies PendingDecision;
      default:
        throw new Error(`unknown decision in response: ${resp.decision}`);
    }
  }

  async #maybeVerify(decision: Decision, opts: EvaluateOptions): Promise<void> {
    const verify = opts.verify ?? this.#verifyByDefault;
    if (!verify) return;

    const result = await this.verifyReceiptUrl(decision.receiptUrl);
    if (!result.ok) {
      throw new UniclawVerifyError(
        decision.contentId,
        result.error ??
          "signature did not verify under the embedded issuer key",
      );
    }
    // Defense in depth: if the server's claimed content_id differs
    // from what we just hashed locally, the server lied about
    // which receipt it returned. The verify result's contentIdHex
    // is recomputed from the bytes the verifier received.
    if (result.contentIdHex !== decision.contentId) {
      throw new UniclawVerifyError(
        decision.contentId,
        `server claimed content_id ${decision.contentId} but the ` +
          `recomputed hash is ${result.contentIdHex}`,
      );
    }
  }

  async #parseError(response: Response): Promise<UniclawError> {
    const status = response.status;
    let body: unknown;
    try {
      body = await response.json();
    } catch {
      return new UniclawError(status, "non_json_response", await safeText(response));
    }
    if (isErrorBody(body)) {
      return new UniclawError(status, body.error, body.detail);
    }
    return new UniclawError(status, "unknown", JSON.stringify(body));
  }
}

function joinUrl(base: string, path: string): string {
  if (/^https?:\/\//i.test(path)) return path;
  if (path.startsWith("/")) return `${base}${path}`;
  return `${base}/${path}`;
}

function isErrorBody(v: unknown): v is WireErrorBody {
  return (
    typeof v === "object" &&
    v !== null &&
    typeof (v as Record<string, unknown>)["error"] === "string" &&
    typeof (v as Record<string, unknown>)["detail"] === "string"
  );
}

async function safeText(response: Response): Promise<string> {
  try {
    return await response.text();
  } catch {
    return "<unreadable response body>";
  }
}
