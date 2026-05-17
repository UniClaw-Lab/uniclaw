# Building the http-tool-component fixture

This sub-crate compiles to a WebAssembly Component that
exercises 16c's `tool-with-host` world (host imports for
`http-fetch`, `secret-exists`, `log-message`, `now-millis`).

The committed artifact at
`crates/boardproof-tools-wasm/tests/fixtures/http-tool-component.wasm`
is the **single source of truth for tests**. CI does not rebuild.

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

Output lands at
`target/wasm32-wasip1/release/http_tool_component.wasm`. (Tooling
quirk; the artifact is a v2 Component despite the directory name.)

## Updating the committed artifact

```
cp target/wasm32-wasip1/release/http_tool_component.wasm \
   ../http-tool-component.wasm
```

Then commit. The artifact is small and stable — diffs only appear
when the source actually changes.
