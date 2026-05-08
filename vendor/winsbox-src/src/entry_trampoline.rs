//! Redirect a suspended target's initial PC to a stub that fires
//! *after* the loader has mapped every static import. The stub signals
//! `ev_loaded`, blocks on `ev_go`, then restores the original first
//! two argument registers and tail-jumps to the original entry point.
//! The broker uses the rendezvous to patch exports in modules that
//! aren't mapped at `CREATE_SUSPENDED` time
//! (`kernelbase!CreateProcessInternalW`).
//!
//! Phase H split this module per-arch (mirror of the
//! `interception_x64.rs` / `interception_arm64.rs` split). The façade
//! here owns:
//!   * `EntrySync` — the broker-side handle pair returned by `install`,
//!   * `EntryWait` + `wait_loaded_or_exit_detail` — the diagnostic
//!     wait helper added in E-5a,
//!   * `cpw_address` — kernelbase!CreateProcessInternalW resolution
//!     (arch-independent: same DLL, same export, same VA across the
//!     session).
//!
//! The per-arch stub emitter and `install` entry point live in
//! `entry_trampoline_x64.rs` / `entry_trampoline_arm64.rs`.

use anyhow::{Context, Result};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Threading::{SetEvent, INFINITE};

// Per-arch emitter dispatch. The actual module `mod entry_trampoline_xNN;`
// declarations live in `main.rs` (sibling-file resolution), mirroring
// the `interception_x64` / `interception_arm64` split. We re-export
// the arch's `install` here so all callers can use
// `crate::entry_trampoline::install(...)` regardless of target.
#[cfg(target_arch = "x86_64")]
pub use crate::entry_trampoline_x64::install;

#[cfg(target_arch = "aarch64")]
pub use crate::entry_trampoline_arm64::install;

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub fn install(_t: HANDLE, _th: HANDLE, _s: bool) -> Result<EntrySync> {
    anyhow::bail!("entry_trampoline: only x86_64 and aarch64 are supported")
}

pub struct EntrySync {
    pub(crate) ev_loaded: HANDLE,
    pub(crate) ev_go: HANDLE,
}

/// Phase E-4: detail return for the entry rendezvous wait. Distinguishes
/// the three failure modes for diagnostic clarity.
#[derive(Debug, Clone, Copy)]
pub enum EntryWait {
    Loaded,
    TargetExited,
    Timeout,
    Other(u32),
}

impl EntrySync {
    /// Block until the target's loader has finished and the stub
    /// has signalled, OR the target process exited (loader
    /// failed). Returns false on timeout or process exit.
    pub fn wait_loaded_or_exit(&self, target: HANDLE, timeout_ms: u32) -> bool {
        let r = self.wait_loaded_or_exit_detail(target, timeout_ms);
        matches!(r, EntryWait::Loaded)
    }

    /// Phase E-4: caller wants to distinguish between "loader finished"
    /// (good), "target exited before signalling" (loader crashed),
    /// "timeout" (loader is stuck or so slow we should give up). All
    /// three were folded into a single `false` previously, which made
    /// debugging the cygwin1.dll DllMain crash look like a timeout.
    pub fn wait_loaded_or_exit_detail(
        &self, target: HANDLE, timeout_ms: u32,
    ) -> EntryWait {
        use windows::Win32::System::Threading::WaitForMultipleObjects;
        use windows::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
        unsafe {
            let handles = [self.ev_loaded, target];
            let r = WaitForMultipleObjects(&handles, false, timeout_ms);
            if r == WAIT_OBJECT_0 {
                EntryWait::Loaded
            } else if r.0 == WAIT_OBJECT_0.0 + 1 {
                EntryWait::TargetExited
            } else if r == WAIT_TIMEOUT {
                EntryWait::Timeout
            } else {
                EntryWait::Other(r.0)
            }
        }
    }

    pub fn go(&self) {
        unsafe { let _ = SetEvent(self.ev_go); }
    }
}

impl Drop for EntrySync {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.ev_loaded);
            let _ = CloseHandle(self.ev_go);
        }
    }
}

/// Resolve `kernelbase!CreateProcessInternalW`. Valid only after the
/// loader has run in *some* process in this session — system DLLs
/// share one base per boot, so the broker's own kernelbase address
/// is the target's too.
pub fn cpw_address() -> Result<usize> {
    use windows::core::{PCSTR, PCWSTR};
    use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
    unsafe {
        let m = GetModuleHandleW(PCWSTR(crate::util::wstr("kernelbase.dll").as_ptr()))
            .context("GetModuleHandleW(kernelbase)")?;
        let p = GetProcAddress(m, PCSTR(b"CreateProcessInternalW\0".as_ptr()))
            .ok_or_else(|| anyhow::anyhow!("GetProcAddress(CreateProcessInternalW)"))?;
        Ok(p as usize)
    }
}

#[allow(dead_code)]
pub const ENTRY_SYNC_TIMEOUT_MS: u32 = INFINITE;
