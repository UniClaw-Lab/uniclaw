//! Auto-generated wasmtime Component Model bindings.
//!
//! Two `bindgen!` invocations, one per world:
//!
//! - `tool` — 16b's export-only world. The bindgen output is the
//!   `tool::Tool` host struct used by [`crate::WasmTool::from_component_bytes`].
//! - `tool-with-host` — 16c's world that also imports `host`. The
//!   bindgen output is the `with_host::ToolWithHost` host struct
//!   plus a generated `Host` trait that the host implements (in
//!   `src/host.rs`) to satisfy the imports.
//!
//! Each world lives in its own submodule so type names don't
//! collide. The two outputs share nothing at runtime; a Component
//! is built against one or the other, and `WasmTool` records
//! which one via its `WasmKind` enum.
//!
//! The bindgen-generated code triggers a flock of pedantic
//! lints out of our control. Module-level allows here keep the
//! workspace lints from failing the build.

#![allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::restriction,
    clippy::style,
    missing_debug_implementations
)]

pub mod tool {
    wasmtime::component::bindgen!({
        path: "wit/tool.wit",
        world: "tool",
    });
}

pub mod with_host {
    wasmtime::component::bindgen!({
        path: "wit/tool.wit",
        world: "tool-with-host",
    });
}
