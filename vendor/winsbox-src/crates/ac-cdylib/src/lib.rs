//! Production cdylib loaded into the AppContainer target. Phase B
//! scaffolding only — exports a single sentinel function (`cdylib_init`)
//! and a `DllMain` that signals back to the broker over a shared
//! section + event. Phase C will replace `cdylib_init` with the real
//! hook entry points.
//!
//! The handoff protocol mirrors `spike-cdylib`:
//!
//!   1. Broker creates an anonymous file mapping (page-sized) and an
//!      auto-reset event, duplicates both into the suspended target
//!      with PROCESS_DUP_HANDLE, and pre-maps the section view via
//!      NtMapViewOfSection so DllMain doesn't have to.
//!   2. Broker writes a `CdylibBuffer` struct into a `VirtualAllocEx`
//!      region in the target containing the target-side handle/VA values
//!      and a magic sentinel.
//!   3. Broker patches the target's environment block in-place to set
//!      `AC_CDYLIB_BUFFER=<hex VA>` (16 hex chars). Env vars are visible
//!      to DllMain via `std::env::var`.
//!   4. Target loads us via remote `LoadLibraryW(<dll path>)`.
//!   5. Our `DllMain(DLL_PROCESS_ATTACH)` reads `AC_CDYLIB_BUFFER`,
//!      calls `cdylib_init()`, writes the result + sentinel + PID +
//!      version into the mapped section, and `SetEvent`s the wake event.
//!   6. Broker waits on the event, reads the section, logs the report.
//!
//! The named-event variant we considered for the spike (Local\…)
//! requires extra ACL plumbing under AC; anonymous handles +
//! DuplicateHandle is the simpler path.

#![cfg(windows)]

use std::ffi::c_void;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Threading::SetEvent;

const DLL_PROCESS_ATTACH: u32 = 1;

/// Cdylib version stamp. Bumps whenever the layout of `CdylibResult`
/// or the protocol changes. Broker compares to its own constant on
/// readback to catch broker/cdylib skew (e.g. forgot to rebuild the
/// dll after touching the wire format).
pub const CDYLIB_VERSION: u32 = 1;

/// Phase-B sentinel return value for `cdylib_init`. Phase C replaces
/// this function with real hook entry points.
pub const CDYLIB_INIT_OK: u32 = 0xACDC_0001;

/// One-shot init callable by the broker (or DllMain) to confirm the
/// cdylib is loaded and its symbols are resolvable. Returns
/// [`CDYLIB_INIT_OK`].
#[no_mangle]
pub extern "system" fn cdylib_init() -> u32 {
    CDYLIB_INIT_OK
}

/// Layout of the broker-allocated scratch buffer in the target.
/// MUST match `CdylibBuffer` in the broker (`cdylib_inject.rs`).
#[repr(C)]
struct CdylibBuffer {
    /// Target-side HANDLE for the result section. Currently unused
    /// by DllMain (broker pre-mapped the view) but included for
    /// completeness.
    _section: u64,
    /// Target-side HANDLE for the wake event.
    event: u64,
    /// Target-side VA where the section is mapped.
    view: u64,
    /// Sanity sentinel.
    magic: u64,
}

/// Magic value the broker stamps into [`CdylibBuffer::magic`].
pub const CDYLIB_MAGIC: u64 = 0xAC11_DEAD_BEEF_CAFEu64;

/// Layout of the result section the broker reads back. MUST match
/// `CdylibResult` in the broker.
#[repr(C)]
struct CdylibResult {
    /// `cdylib_init()` return value. Broker expects [`CDYLIB_INIT_OK`].
    init_result: u32,
    /// Cdylib version (= [`CDYLIB_VERSION`]).
    version: u32,
    /// Sentinel so the broker can tell "DllMain ran" from
    /// "section was zero-initialised".
    sentinel: u32,
    /// PID we ran in (sanity check the right process attached).
    pid: u32,
}

/// Sentinel placed in [`CdylibResult::sentinel`] to mark a real reply.
pub const RESULT_SENTINEL: u32 = 0xACDC_BABE;

fn env_u64(key: &str) -> Option<u64> {
    let v = std::env::var(key).ok()?;
    u64::from_str_radix(v.trim_start_matches("0x"), 16).ok()
}

unsafe fn run_attach() {
    let Some(buf_addr) = env_u64("AC_CDYLIB_BUFFER") else { return };
    let buf = &*(buf_addr as *const CdylibBuffer);
    if buf.magic != CDYLIB_MAGIC {
        return;
    }
    let view = buf.view as *mut CdylibResult;
    if view.is_null() {
        return;
    }
    let pid = windows::Win32::System::Threading::GetCurrentProcessId();
    let result = CdylibResult {
        init_result: cdylib_init(),
        version: CDYLIB_VERSION,
        sentinel: RESULT_SENTINEL,
        pid,
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
        // Catch panics so a bug here doesn't kill the target — failure
        // mode is "broker times out", not "target crashes mysteriously".
        let _ = std::panic::catch_unwind(|| unsafe { run_attach() });
    }
    1
}
