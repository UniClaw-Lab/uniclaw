//! [`MemoryLimiter`] — refuses guest memory growth past a configured
//! cap.
//!
//! `wasmtime` calls [`ResourceLimiter::memory_growing`] on every
//! `memory.grow` instruction (and during instantiation when the
//! module declares an initial memory). Returning `Ok(false)` makes
//! `memory.grow` return `-1` to the guest, which usually traps soon
//! after when the guest tries to use what it thought was new memory.
//!
//! The single field is the configured cap; we don't track current
//! usage separately because wasmtime supplies the desired new size
//! on every callback.

use wasmtime::ResourceLimiter;

#[derive(Debug)]
pub(crate) struct MemoryLimiter {
    pub(crate) max_memory_bytes: usize,
}

impl ResourceLimiter for MemoryLimiter {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        // `desired` is the new total size in bytes (not the delta).
        // Allow if it fits under our cap; refuse otherwise.
        Ok(desired <= self.max_memory_bytes)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        _desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        // Tables hold function references; v0 doesn't constrain
        // them separately (the module's own type-checking bounds
        // size). Permit any growth wasmtime would otherwise allow.
        Ok(true)
    }
}
