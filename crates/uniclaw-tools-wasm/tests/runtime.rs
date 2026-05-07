//! Integration tests for [`uniclaw_tools_wasm::WasmTool`] using
//! WebAssembly Text fixtures inline.
//!
//! Each fixture is a small `.wat` string compiled at test time via
//! `wat::parse_str` (which `WasmTool::from_wat` calls internally).
//! Keeps tests reviewable without checked-in `.wasm` blobs and
//! without requiring `wasm32-*` toolchains on CI.

use std::time::Duration;

use uniclaw_receipt::Digest;
use uniclaw_tools::{
    ApprovalPolicy, Capability, GlobPattern, Tool, ToolCall, ToolError, ToolManifest,
};
use uniclaw_tools_wasm::{BuildError, WasmConfig, WasmTool};

/// Minimal manifest for tests. Capabilities are informational here
/// (no host imports in 16a, so the manifest doesn't gate anything
/// at runtime).
fn test_manifest(name: &str) -> ToolManifest {
    ToolManifest {
        name: name.into(),
        description: "test fixture".into(),
        action_kind: format!("tool.{name}"),
        declared_capabilities: vec![Capability::NetConnect(GlobPattern::new("noop"))],
        default_approval: ApprovalPolicy::Never,
    }
}

fn make_call(input: &[u8]) -> ToolCall {
    ToolCall {
        tool_name: "wasm".into(),
        target: "test".into(),
        input: input.to_vec(),
        input_hash: Digest(*blake3::hash(input).as_bytes()),
    }
}

// =====================================================================
// Fixture: echo — returns input verbatim. Exercises the happy path:
// alloc, write input, call, read output, hash.
// =====================================================================

const ECHO: &str = r#"
(module
  (memory (export "memory") 1)

  ;; Bump allocator: hand out memory starting at offset 1024 (leave
  ;; the first page available for guest scratch). Tests don't free.
  (global $next (mut i32) (i32.const 1024))

  (func (export "alloc") (param $size i32) (result i32)
    (local $ptr i32)
    (local.set $ptr (global.get $next))
    (global.set $next (i32.add (global.get $next) (local.get $size)))
    (local.get $ptr)
  )

  ;; Echo: pack (input_ptr << 32) | input_len and return.
  (func (export "call") (param $ptr i32) (param $len i32) (result i64)
    (i64.or
      (i64.shl (i64.extend_i32_u (local.get $ptr)) (i64.const 32))
      (i64.extend_i32_u (local.get $len)))
  )
)
"#;

#[test]
fn echo_returns_input_verbatim_and_hashes_output() {
    let tool = WasmTool::from_wat(ECHO, test_manifest("echo"), WasmConfig::default()).unwrap();
    let input = b"hello, wasm";
    let out = tool.call(&make_call(input)).expect("ok");
    assert_eq!(out.bytes, input);

    // The output_hash is BLAKE3 over the bytes (same convention
    // every other Tool impl uses).
    let expected = Digest(*blake3::hash(input).as_bytes());
    assert_eq!(out.output_hash, expected);

    // 16a tools never report secrets used.
    assert!(out.metadata.secrets_used.is_empty());
}

#[test]
fn echo_handles_empty_input() {
    let tool = WasmTool::from_wat(ECHO, test_manifest("echo"), WasmConfig::default()).unwrap();
    let out = tool.call(&make_call(b"")).expect("ok");
    assert_eq!(out.bytes, b"");
}

#[test]
fn echo_handles_one_kib_input() {
    let tool = WasmTool::from_wat(ECHO, test_manifest("echo"), WasmConfig::default()).unwrap();
    let input: Vec<u8> = (0..=255).cycle().take(1024).collect();
    let out = tool.call(&make_call(&input)).expect("ok");
    assert_eq!(out.bytes, input);
}

// =====================================================================
// Fixture: burn_fuel — infinite loop that consumes fuel and never
// returns. Verifies fuel exhaustion → ToolError::Failed("fuel...").
// =====================================================================

const BURN_FUEL: &str = r#"
(module
  (memory (export "memory") 1)
  (global $next (mut i32) (i32.const 1024))
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "call") (param i32) (param i32) (result i64)
    ;; Tight loop — each back-edge consumes fuel. Eventually the
    ;; engine traps with OutOfFuel.
    (loop $forever
      (br $forever))
    ;; Unreachable.
    (i64.const 0)
  )
)
"#;

#[test]
fn fuel_exhaustion_traps_and_maps_to_failed() {
    // Tight fuel budget; the alloc step alone consumes some fuel,
    // and the infinite loop in `call` will exhaust it quickly.
    let cfg = WasmConfig {
        fuel: 1_000,
        ..WasmConfig::default()
    };
    let tool = WasmTool::from_wat(BURN_FUEL, test_manifest("burn"), cfg).unwrap();
    let err = tool.call(&make_call(b"x")).expect_err("must trap");
    match err {
        ToolError::Failed(msg) => assert!(
            msg.contains("fuel"),
            "expected fuel-exhaustion message, got: {msg}",
        ),
        other => panic!("expected Failed(fuel), got {other:?}"),
    }
}

// =====================================================================
// Fixture: trap_unreachable — guest code runs `unreachable`. Verifies
// that arbitrary traps map cleanly to ToolError::Failed.
// =====================================================================

const TRAP: &str = r#"
(module
  (memory (export "memory") 1)
  (global $next (mut i32) (i32.const 1024))
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "call") (param i32) (param i32) (result i64)
    unreachable)
)
"#;

#[test]
fn unreachable_trap_in_guest_surfaces_as_failed() {
    let tool = WasmTool::from_wat(TRAP, test_manifest("trap"), WasmConfig::default()).unwrap();
    let err = tool.call(&make_call(b"x")).expect_err("must trap");
    assert!(matches!(err, ToolError::Failed(_)));
}

// =====================================================================
// Fixture: grow_memory — guest tries to grow memory beyond the cap.
// memory.grow returns -1; if guest then unreachables, that's the
// observable failure. Test verifies the cap is enforced.
// =====================================================================

const GROW_MEMORY: &str = r#"
(module
  (memory (export "memory") 1 100)  ;; initial 1 page, max 100 pages = 6.4 MiB
  (global $next (mut i32) (i32.const 1024))
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "call") (param i32) (param i32) (result i64)
    ;; Grow by 50 pages (= 3.2 MiB). If the limiter caps at 1 page,
    ;; this returns -1 and we unreachable. Otherwise we return ok.
    (if (i32.eq (memory.grow (i32.const 50)) (i32.const -1))
      (then unreachable))
    (i64.const 0)
  )
)
"#;

#[test]
fn memory_growth_past_cap_is_refused() {
    // Cap at exactly the initial memory size — any grow refused.
    let cfg = WasmConfig {
        max_memory_bytes: 64 * 1024,
        ..WasmConfig::default()
    };
    let tool = WasmTool::from_wat(GROW_MEMORY, test_manifest("grow"), cfg).unwrap();
    let err = tool
        .call(&make_call(b"x"))
        .expect_err("memory cap must fire");
    assert!(matches!(err, ToolError::Failed(_)));
}

#[test]
fn memory_growth_under_cap_is_allowed() {
    // Generous cap; grow should succeed and the call returns ok.
    let cfg = WasmConfig {
        max_memory_bytes: 8 * 1024 * 1024, // 8 MiB > 1 + 50 pages = 3.26 MiB
        ..WasmConfig::default()
    };
    let tool = WasmTool::from_wat(GROW_MEMORY, test_manifest("grow"), cfg).unwrap();
    let out = tool.call(&make_call(b"x")).expect("grow should succeed");
    // The fixture returns (0, 0) → empty output. Just verify no
    // error path fired.
    assert_eq!(out.bytes.len(), 0);
}

// =====================================================================
// Fixture: long_loop — a loop that runs for many iterations,
// exercising the epoch deadline. Uses a finite count so fuel is
// the OTHER bound; if the count is high enough, both could fire.
// We give it lots of fuel and a very short timeout so the timeout
// fires first.
// =====================================================================

const LONG_LOOP: &str = r#"
(module
  (memory (export "memory") 1)
  (global $next (mut i32) (i32.const 1024))
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "call") (param i32) (param i32) (result i64)
    (local $i i32)
    ;; Loop ~i32::MAX iterations. With u64::MAX fuel this takes
    ;; seconds; the epoch deadline fires far sooner.
    (loop $tight
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br_if $tight (i32.lt_s (local.get $i) (i32.const 0x7FFFFFFF))))
    (i64.const 0)
  )
)
"#;

#[test]
fn epoch_deadline_fires_and_maps_to_timeout() {
    // u64::MAX fuel so fuel never bites; the long loop iterates
    // >2B times, easily outlasting any reasonable timeout.
    //
    // Timing values are picked for CI robustness, NOT for
    // measurement precision:
    //  - timeout 200 ms (long enough that the ticker thread
    //    being starved by other tests for one cycle still gives
    //    multiple wakeups)
    //  - epoch_tick 25 ms (8 tick wakeups before the deadline,
    //    so an unlucky scheduler gap doesn't blow past it)
    //  - slack 5 s (catches any plausible CI scheduler badness;
    //    we just need to confirm it eventually does time out,
    //    not that it does so precisely)
    //
    // The structural property — "wall-clock-exceeded calls
    // surface as ToolError::Timeout, not ToolError::Failed" —
    // is what this test pins down. The slack is just a sanity
    // backstop so a hung test doesn't run forever.
    let cfg = WasmConfig {
        fuel: u64::MAX,
        timeout: Duration::from_millis(200),
        epoch_tick: Duration::from_millis(25),
        ..WasmConfig::default()
    };
    let tool = WasmTool::from_wat(LONG_LOOP, test_manifest("long"), cfg).unwrap();
    let started = std::time::Instant::now();
    let err = tool.call(&make_call(b"")).expect_err("must time out");
    let elapsed = started.elapsed();

    // The mapping must be Timeout (not Failed) — the wall-clock
    // bound is the trait surface's exact match.
    assert!(
        matches!(err, ToolError::Timeout),
        "expected Timeout, got {err:?} after {elapsed:?}",
    );
    // Generous backstop: if the deadline hasn't fired in 5s,
    // something is genuinely wrong with the runtime.
    assert!(
        elapsed < Duration::from_secs(5),
        "epoch deadline took {elapsed:?} — even under heavy CI load \
         this should fire well under 5 s",
    );
}

// =====================================================================
// Construction-time validation: missing required exports.
// =====================================================================

const NO_CALL_EXPORT: &str = r#"
(module
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
)
"#;

#[test]
fn missing_call_export_fails_at_construction() {
    let err = WasmTool::from_wat(
        NO_CALL_EXPORT,
        test_manifest("nocall"),
        WasmConfig::default(),
    )
    .expect_err("must reject");
    match err {
        BuildError::MissingExport { name, .. } => assert_eq!(name, "call"),
        other => panic!("expected MissingExport(call), got {other:?}"),
    }
}

const NO_MEMORY_EXPORT: &str = r#"
(module
  (memory 1)
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "call") (param i32) (param i32) (result i64) (i64.const 0))
)
"#;

#[test]
fn missing_memory_export_fails_at_construction() {
    let err = WasmTool::from_wat(
        NO_MEMORY_EXPORT,
        test_manifest("nomem"),
        WasmConfig::default(),
    )
    .expect_err("must reject");
    match err {
        BuildError::MissingExport { name, .. } => assert_eq!(name, "memory"),
        other => panic!("expected MissingExport(memory), got {other:?}"),
    }
}

#[test]
fn invalid_wat_fails_at_construction() {
    let err = WasmTool::from_wat("not valid wat", test_manifest("bad"), WasmConfig::default())
        .expect_err("must reject");
    assert!(matches!(err, BuildError::InvalidWat(_)));
}

// =====================================================================
// Multiple sequential calls share engine + module without leaking
// state. Verifies the per-call Store is fresh.
// =====================================================================

#[test]
fn multiple_calls_have_independent_state() {
    let tool = WasmTool::from_wat(ECHO, test_manifest("echo"), WasmConfig::default()).unwrap();
    let a = tool.call(&make_call(b"first")).unwrap();
    let b = tool.call(&make_call(b"second")).unwrap();
    let c = tool.call(&make_call(b"third")).unwrap();
    assert_eq!(a.bytes, b"first");
    assert_eq!(b.bytes, b"second");
    assert_eq!(c.bytes, b"third");
}

// =====================================================================
// Approval policy mirrors the manifest's default.
// =====================================================================

#[test]
fn approval_policy_mirrors_manifest_default() {
    let mut m = test_manifest("echo");
    m.default_approval = ApprovalPolicy::Always;
    let tool = WasmTool::from_wat(ECHO, m, WasmConfig::default()).unwrap();
    assert_eq!(
        tool.approval_policy(&make_call(b"x")),
        ApprovalPolicy::Always
    );
}

// =====================================================================
// Tool: Send + Sync — required by the trait surface, important here
// because we hold an Engine + a thread handle.
// =====================================================================

// =====================================================================
// Component Model fixture (16b) — loads the echo-component.wasm
// artifact built from `tests/fixtures/echo-component/`. The fixture's
// `call(input)`:
//   - returns `Ok(input)` when input is non-empty,
//   - returns `Err("empty input")` when input is empty.
// Both arms of `result<list<u8>, string>` are exercised in one fixture.
// =====================================================================

const ECHO_COMPONENT: &[u8] = include_bytes!("fixtures/echo-component.wasm");

#[test]
fn component_echo_returns_input_verbatim_via_canonical_abi() {
    let tool = WasmTool::from_component_bytes(
        ECHO_COMPONENT,
        test_manifest("echo-component"),
        WasmConfig::default(),
    )
    .expect("component compiles");

    let input = b"hello, component model";
    let out = tool.call(&make_call(input)).expect("ok");
    assert_eq!(out.bytes, input);

    // BLAKE3 of the bytes — same convention as core wasm.
    let expected = Digest(*blake3::hash(input).as_bytes());
    assert_eq!(out.output_hash, expected);
    assert!(out.metadata.secrets_used.is_empty());
}

#[test]
fn component_guest_error_arm_surfaces_as_failed() {
    // The fixture returns `Err("empty input")` for empty input.
    // We must surface that as `ToolError::Failed` with the message
    // preserved — the guest error is *logical*, not a sandbox
    // violation, so it's not Timeout and not a fuel/memory bound.
    let tool = WasmTool::from_component_bytes(
        ECHO_COMPONENT,
        test_manifest("echo-component"),
        WasmConfig::default(),
    )
    .unwrap();
    let err = tool.call(&make_call(b"")).expect_err("guest must reject");
    match err {
        ToolError::Failed(msg) => {
            assert!(
                msg.contains("empty input"),
                "expected guest's error message in output, got: {msg}",
            );
            assert!(
                msg.contains("guest:"),
                "expected the 'guest:' prefix that distinguishes \
                 logical errors from sandbox traps, got: {msg}",
            );
        }
        other => panic!("expected Failed, got {other:?}"),
    }
}

#[test]
fn component_call_handles_4kib_input() {
    // Larger input exercises the canonical-ABI memory transfer.
    let tool = WasmTool::from_component_bytes(
        ECHO_COMPONENT,
        test_manifest("echo-component"),
        WasmConfig::default(),
    )
    .unwrap();
    let input: Vec<u8> = (0..=255).cycle().take(4 * 1024).collect();
    let out = tool.call(&make_call(&input)).expect("ok");
    assert_eq!(out.bytes, input);
}

#[test]
fn component_multiple_calls_have_independent_state() {
    let tool = WasmTool::from_component_bytes(
        ECHO_COMPONENT,
        test_manifest("echo-component"),
        WasmConfig::default(),
    )
    .unwrap();
    let a = tool.call(&make_call(b"first")).unwrap();
    let b = tool.call(&make_call(b"second")).unwrap();
    assert_eq!(a.bytes, b"first");
    assert_eq!(b.bytes, b"second");
}

#[test]
fn component_with_zero_fuel_traps_with_failed() {
    // 16a's resource bounds inherit unchanged for Component Model:
    // fuel exhaustion still maps to Failed("fuel exhausted").
    // We use 0 fuel — the very first instruction the canonical ABI
    // executes will trip the bound.
    let cfg = WasmConfig {
        fuel: 0,
        ..WasmConfig::default()
    };
    let tool = WasmTool::from_component_bytes(ECHO_COMPONENT, test_manifest("echo-component"), cfg)
        .unwrap();
    let err = tool.call(&make_call(b"x")).expect_err("must trap");
    match err {
        ToolError::Failed(msg) => assert!(
            msg.contains("fuel"),
            "expected fuel-exhaustion message, got: {msg}",
        ),
        other => panic!("expected Failed(fuel...), got {other:?}"),
    }
}

#[test]
fn component_invalid_bytes_fail_at_construction() {
    let err = WasmTool::from_component_bytes(
        b"not a wasm component",
        test_manifest("bad"),
        WasmConfig::default(),
    )
    .expect_err("must reject");
    assert!(matches!(err, BuildError::InvalidWasm(_)));
}

#[test]
fn core_wasm_bytes_rejected_by_from_component_bytes() {
    // A core wasm module is NOT a Component. wasmtime's
    // `Component::new` rejects it. We verify the error path
    // is BuildError::InvalidWasm rather than a runtime crash.
    let core_bytes = wat::parse_str(ECHO).unwrap();
    let err = WasmTool::from_component_bytes(
        &core_bytes,
        test_manifest("core-as-component"),
        WasmConfig::default(),
    )
    .expect_err("must reject");
    assert!(matches!(err, BuildError::InvalidWasm(_)));
}

// =====================================================================
// Tool: Send + Sync — required by the trait surface, important here
// because we hold an Engine + a thread handle.
// =====================================================================

#[test]
fn wasm_tool_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<WasmTool>();
}
