//! Auto-generated wasmtime Component Model bindings for the
//! `uniclaw:tool` package's `tool` world.
//!
//! The macro reads `wit/tool.wit` (relative to the crate root) and
//! emits a `Tool` host struct with `instantiate` + a `tool_api()`
//! accessor that exposes the typed `call_call(...)` method bound
//! to the guest's `tool-api.call` export.
//!
//! The bindgen-generated code triggers a few clippy lints that are
//! out of our control (it lives below the `unsafe_code = "forbid"`
//! workspace lint in the macro-expanded form, so the generator
//! emits attribute-allows; we add module-level allows here so the
//! pedantic lints don't fail the build either).

#![allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::restriction,
    clippy::style,
    missing_debug_implementations
)]

wasmtime::component::bindgen!({
    path: "wit/tool.wit",
    world: "tool",
});
