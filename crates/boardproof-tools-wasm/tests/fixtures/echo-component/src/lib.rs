//! Echo Component — `boardproof:tool/tool-api.call` implemented as a
//! pass-through.
//!
//! `Ok(input)` for non-empty input, `Err("empty input")` for empty.
//! Both arms of the Component Model `result<list<u8>, string>`
//! ABI exercised in one fixture so the host bindings are validated
//! end to end.
//!
//! ## A note on imports
//!
//! Rust's standard library, when linked against `wasm32-wasip2`,
//! pulls in WASI imports (`wasi:cli/environment`, etc.) regardless
//! of whether the program touches them. This Component therefore
//! *imports* WASI even though it never *uses* it. The host side
//! satisfies those imports via `wasmtime_wasi::p2::add_to_linker_sync`
//! — strictly to make instantiation succeed, not to grant any real
//! capability. v0 tools never reach a WASI syscall; if they do,
//! it's a bug in our wiring.
//!
//! Going `no_std` would strip the WASI imports but conflicts with
//! `wit-bindgen-rt` 0.41 (which depends on std). A future fixture
//! refactor against a newer wit-bindgen could land that.
//!
//! Built locally via `cargo component build --release`; resulting
//! `target/wasm32-wasip1/release/echo_component.wasm` is copied to
//! `crates/boardproof-tools-wasm/tests/fixtures/echo-component.wasm`
//! and committed. CI doesn't rebuild — see `BUILD.md`.

#[allow(warnings)]
mod bindings;

use bindings::exports::boardproof::tool::tool_api::Guest;

struct Component;

impl Guest for Component {
    fn call(input: Vec<u8>) -> Result<Vec<u8>, String> {
        if input.is_empty() {
            Err("empty input".to_string())
        } else {
            Ok(input)
        }
    }
}

bindings::export!(Component with_types_in bindings);
