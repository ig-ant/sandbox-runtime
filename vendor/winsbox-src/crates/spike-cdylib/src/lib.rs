//! Phase B0 spike cdylib: validates that we can inject a Rust cdylib
//! into an AppContainer-confined target and have its `DllMain` run +
//! signal back to the broker.
//!
//! Coordination protocol with the broker (`spike_inject.rs`):
//!
//!   1. Broker creates an anonymous file mapping (8+ bytes), maps it
//!      into both broker and target, and creates an auto-reset event.
//!      Both handles are duplicated into the target.
//!   2. Broker writes a small `SpikeBuffer` struct into a
//!      `VirtualAllocEx`'d region in the target containing the
//!      target-side handle/VA values + a magic sentinel.
//!   3. Broker passes the SpikeBuffer's target-VA to the cdylib via
//!      an environment variable (`SPIKE_BUFFER=<hex>`) set on the
//!      target at CreateProcess time. Env vars survive AC token
//!      transitions and are visible inside DllMain.
//!   4. Target loads us via remote `LoadLibraryW`.
//!   5. Our `DllMain(DLL_PROCESS_ATTACH)` reads SPIKE_BUFFER, calls
//!      `probe()`, writes the result + sentinel + PID into the
//!      mapped section, and `SetEvent`s the wake event.
//!   6. Broker waits on the event, reads the section, expects 42.
//!
//! This avoids named-object ACL/namespace issues entirely by using
//! anonymous handles + DuplicateHandle. The named-event variant
//! (`Local\spike-...`) gets rewritten by the kernel under AC and
//! requires extra ACL plumbing — not worth it for the spike.

#![cfg(windows)]

use std::ffi::c_void;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Threading::SetEvent;

const DLL_PROCESS_ATTACH: u32 = 1;

/// The function the broker explicitly wants to validate calling.
/// Phase B will replace this with real hook entry points; for the
/// spike it just returns a recognisable constant.
#[no_mangle]
pub extern "system" fn probe() -> u32 {
    42
}

/// Layout of the broker-allocated scratch buffer in the target.
/// Pointer-sized fields are stored as `u64` so the layout is the
/// same regardless of whether broker and target are 32/64-bit
/// (they're both 64-bit in practice — ARM64 / x64 — but the
/// explicit u64 is documentary).
#[repr(C)]
struct SpikeBuffer {
    /// Target-side HANDLE for the result section. Currently unused
    /// by DllMain (broker pre-mapped the view) but included for
    /// completeness / future variants.
    _section: u64,
    /// Target-side HANDLE for the wake event.
    event: u64,
    /// Target-side VA where the section is mapped (broker did the
    /// map via NtMapViewOfSection so DllMain doesn't have to).
    view: u64,
    /// Sanity sentinel.
    magic: u64,
}

/// Magic value placed in `SpikeBuffer.magic` by the broker.
pub const SPIKE_MAGIC: u64 = 0xB0B0_DEAD_BEEF_CAFEu64;

/// Layout of the result section (broker reads this back).
#[repr(C)]
struct SpikeResult {
    /// `probe()` return value. Broker expects 42.
    probe_result: u32,
    /// Sentinel so the broker can tell "DllMain ran" from
    /// "section was zero-initialised".
    sentinel: u32,
    /// PID we ran in (sanity check the right process attached).
    pid: u32,
    _pad: u32,
}

/// Sentinel placed in `SpikeResult.sentinel` to mark a real reply.
pub const RESULT_SENTINEL: u32 = 0xCAFE_BABE;

fn env_u64(key: &str) -> Option<u64> {
    let v = std::env::var(key).ok()?;
    u64::from_str_radix(v.trim_start_matches("0x"), 16).ok()
}

unsafe fn run_attach() {
    let Some(buf_addr) = env_u64("SPIKE_BUFFER") else { return };
    let buf = &*(buf_addr as *const SpikeBuffer);
    if buf.magic != SPIKE_MAGIC {
        return;
    }
    let view = buf.view as *mut SpikeResult;
    if view.is_null() {
        return;
    }
    let pid = windows::Win32::System::Threading::GetCurrentProcessId();
    let result = SpikeResult {
        probe_result: probe(),
        sentinel: RESULT_SENTINEL,
        pid,
        _pad: 0,
    };
    std::ptr::write_volatile(view, result);
    let _ = SetEvent(HANDLE(buf.event as *mut c_void));
}

#[no_mangle]
pub extern "system" fn DllMain(
    _hinst: *mut c_void,
    reason: u32,
    _reserved: *mut c_void,
) -> i32 {
    if reason == DLL_PROCESS_ATTACH {
        // Catch panics so a bug here doesn't blow up the target
        // process — failure mode is "broker times out", not
        // "target crashes mysteriously".
        let _ = std::panic::catch_unwind(|| unsafe { run_attach() });
    }
    1
}
