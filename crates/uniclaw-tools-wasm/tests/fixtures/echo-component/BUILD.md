# Building the echo-component fixture

This sub-crate compiles to a WebAssembly Component that the
`uniclaw-tools-wasm` integration tests load via
`WasmTool::from_component_bytes`. It is **not** a workspace member —
the `[workspace]` directive in its `Cargo.toml` keeps it isolated
from the host workspace's deps and lints.

The committed artifact at
`crates/uniclaw-tools-wasm/tests/fixtures/echo-component.wasm` is
the **single source of truth for tests**. CI does not rebuild.

## Prerequisites

```
rustup target add wasm32-wasip2
cargo install cargo-component --locked   # tested with v0.21.1
```

## Building

From this directory:

```
cargo component build --release
```

The output lands at
`target/wasm32-wasip1/release/echo_component.wasm` (cargo-component
0.21 still uses the wasm32-wasip1 target on disk even when wasip2
is requested — that's a tooling quirk, not a behaviour issue;
the produced bytes are a v2 Component).

## Updating the committed artifact

```
cp target/wasm32-wasip1/release/echo_component.wasm \
   ../echo-component.wasm
```

Then commit. The artifact is small (~46 KB) and stable — diffs only
appear when the source actually changes.

## Why is the .wasm committed?

CI runners don't have `wasm32-wasip2` or `cargo-component` installed,
and bringing those in would balloon CI build times. The committed
`.wasm` is reproducible from the source in this directory plus the
versioned tools listed above. Reviewers can verify the bytes by
rebuilding locally.
