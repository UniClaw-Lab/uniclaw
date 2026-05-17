//! HTTP-tool Component — `boardproof:tool/tool-with-host` test fixture.
//!
//! Demonstrates 16c's host-import surface end to end. The guest:
//!
//! 1. Reads its input as a small JSON command string. Two
//!    commands are recognised:
//!    - `"fetch <url>"` — call `host::http-fetch(url, None, None)`,
//!      return the response body bytes (or an error).
//!    - `"fetch_auth <url> <secret-ref>"` — same fetch but with
//!      `auth: Some(BearerHeader(secret-ref))`. Tests the credential
//!      injection path.
//!    - `"check <secret-ref>"` — call `host::secret-exists`,
//!      return "yes" or "no".
//!    - `"now"` — call `host::now-millis`, return the value as
//!      ASCII digits.
//!    - `"log"` — emit a single info-level log entry, return "ok".
//!
//! Anything else returns `Err("unknown command: ...")`.
//!
//! Everything goes through the host imports — there's no Rust HTTP
//! client linked in. The point is to verify those host imports are
//! routed correctly through the kernel's capability + secret + SSRF
//! plumbing.
//!
//! Built locally via `cargo component build --release`. CI doesn't
//! rebuild — see BUILD.md.

#[allow(warnings)]
mod bindings;

use bindings::exports::boardproof::tool::tool_api::Guest;
use bindings::boardproof::tool::host;

struct Component;

impl Guest for Component {
    fn call(input: Vec<u8>) -> Result<Vec<u8>, String> {
        let cmd = core::str::from_utf8(&input)
            .map_err(|e| format!("input is not utf-8: {e}"))?
            .trim();

        if let Some(rest) = cmd.strip_prefix("fetch_auth ") {
            // "fetch_auth <url> <secret-ref>"
            let mut parts = rest.splitn(2, ' ');
            let url = parts.next().ok_or("fetch_auth: missing url")?;
            let secret_ref = parts.next().ok_or("fetch_auth: missing secret-ref")?;
            let auth = Some(host::AuthSpec::BearerHeader(secret_ref.to_string()));
            let resp = host::http_fetch(&url.to_string(), auth.as_ref(), None)?;
            return Ok(resp.body);
        }

        if let Some(url) = cmd.strip_prefix("fetch ") {
            let resp = host::http_fetch(&url.to_string(), None, None)?;
            return Ok(resp.body);
        }

        if let Some(name) = cmd.strip_prefix("check ") {
            let yes = host::secret_exists(&name.to_string());
            return Ok(if yes { b"yes".to_vec() } else { b"no".to_vec() });
        }

        if cmd == "now" {
            let t = host::now_millis();
            return Ok(t.to_string().into_bytes());
        }

        if cmd == "log" {
            host::log_message(host::LogLevel::Info, &"hello from guest".to_string());
            return Ok(b"ok".to_vec());
        }

        Err(format!("unknown command: {cmd}"))
    }
}

bindings::export!(Component with_types_in bindings);
