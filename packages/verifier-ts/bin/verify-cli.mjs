#!/usr/bin/env node
// Tiny CLI around `@boardproof/verifier`. Pairs with the demo binary:
//
//   $ cargo run --release --example end-to-end-demo -p boardproof-host
//   ...prints 6 receipt URLs...
//
//   $ npx boardproof-verify-ts http://127.0.0.1:PORT/receipts/HASH
//   ✓ verified | issuer=2a... seq=0 decision=allowed
//
// Usage:
//   boardproof-verify-ts <url-or-path>
//
// Where the argument is either a `http(s)://` URL, a `boardproof://`-style
// receipt URL the host produced, or a local JSON file path. Exit
// code 0 = verified, 1 = failed verification, 2 = bad input.

import { readFileSync } from "node:fs";
import { verifyReceiptJson, verifyReceiptUrl } from "../dist/index.js";

async function main() {
  const arg = process.argv[2];
  if (!arg) {
    console.error("usage: boardproof-verify-ts <url-or-path>");
    process.exit(2);
  }

  let result;
  if (/^https?:\/\//i.test(arg)) {
    result = await verifyReceiptUrl(arg);
  } else {
    let json;
    try {
      json = readFileSync(arg, "utf8");
    } catch (e) {
      console.error(`could not read file: ${e.message}`);
      process.exit(2);
    }
    result = await verifyReceiptJson(json);
  }

  if (result.ok) {
    console.log(
      `✓ verified | issuer=${result.issuerHex.slice(0, 8)}... ` +
      `decision=${result.decision} ` +
      `schema_v=${result.schemaVersion} ` +
      `content_id=${result.contentIdHex.slice(0, 8)}...`,
    );
    process.exit(0);
  } else {
    console.error(`✗ FAILED | ${result.error ?? "unknown error"}`);
    process.exit(1);
  }
}

main().catch((e) => {
  console.error(`✗ ERROR | ${e.stack ?? e.message ?? String(e)}`);
  process.exit(2);
});
