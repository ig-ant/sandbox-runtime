//! Inline-hook installer for the in-AC target. Façade module: per-arch
//! thunk emitters live in [`interception_x64`] and [`interception_arm64`];
//! this file holds the public API the broker calls (`install_fs`,
//! `install_reg`, `install_cpw`) plus the cross-arch remote-memory and
//! ntdll-resolution helpers.
//!
//! Phase C reshape:
//!   * The 5 "compat hooks" — `NtOpenSection`,
//!     `NtCreate/OpenDirectoryObject`, `NtCreateNamedPipeFile`, and
//!     `CreateProcessInternalW` — patch in a *thin* dispatcher that
//!     tail-calls into the in-AC `ac-cdylib`'s exported hook function.
//!     The hook body (IPC framing, event signalling, response demux)
//!     lives in safe Rust in the cdylib.
//!   * The remaining FS/Reg/Attr hooks (`NtCreateFile`, `NtOpenFile`,
//!     `NtQueryAttributesFile`, `NtQueryFullAttributesFile`,
//!     `NtOpenKey`, `NtOpenKeyEx`) keep the legacy inline-asm
//!     prologue + IPC framing — they'll be removed wholesale in Phase D
//!     when ACL stamping replaces broker-mediated FS/Reg policy.
//!
//! Public API stays byte-identical so `launch.rs` doesn't change shape.

use anyhow::{anyhow, bail, Context, Result};
use std::ffi::c_void;
use std::mem::size_of;
use windows::core::{PCSTR, PCWSTR};
use windows::Win32::Foundation::{GetLastError, HANDLE};
use windows::Win32::System::Diagnostics::Debug::{
    FlushInstructionCache, ReadProcessMemory, WriteProcessMemory,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Memory::{
    VirtualAllocEx, VirtualProtectEx, MEM_COMMIT, MEM_RESERVE,
    VIRTUAL_ALLOCATION_TYPE,
    PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS,
    PAGE_READWRITE,
};

use crate::ipc::StubAddrs;

#[cfg(target_arch = "x86_64")]
use crate::interception_x64 as arch;
#[cfg(target_arch = "aarch64")]
use crate::interception_arm64 as arch;

/// Cdylib export VAs the slim dispatchers tail-call. Resolved post-load
/// from the broker-side `GetProcAddress` (system DLLs share base per
/// session, so the broker's resolved VA is also valid in the target).
#[derive(Clone, Copy, Default)]
pub struct CdylibHookEntries {
    pub nt_open_section: usize,
    pub nt_create_directory_object: usize,
    pub nt_open_directory_object: usize,
    pub nt_create_named_pipe_file: usize,
    pub create_process_internal_w: usize,
}

impl CdylibHookEntries {
    pub fn is_ready(&self) -> bool {
        self.nt_open_section != 0
            && self.nt_create_directory_object != 0
            && self.nt_open_directory_object != 0
            && self.nt_create_named_pipe_file != 0
            && self.create_process_internal_w != 0
    }
}

/// Patch `ntdll!{NtCreateFile,NtOpenFile,NtCreateNamedPipeFile,
/// NtQueryAttributesFile,NtQueryFullAttributesFile}` in `target`.
/// Installed pre-resume so the loader's own opens are brokered.
///
/// Phase C: when `cdylib` is set, `NtCreateNamedPipeFile` is patched
/// to dispatch into the cdylib instead of the inline-asm IPC stub.
/// The other FS hooks keep the legacy stub until Phase D.
pub fn install_fs(
    target: HANDLE,
    a: &StubAddrs,
    cdylib: Option<&CdylibHookEntries>,
) -> Result<()> {
    arch::install_fs(target, a, cdylib)
}

/// Patch the registry/section/dirobj hooks. Installed pre-resume.
///
/// Phase C: the 4 compat hooks (`NtOpenSection`,
/// `NtCreate/OpenDirectoryObject`) dispatch into the cdylib when
/// `cdylib` is supplied. `NtOpenKey`/`NtOpenKeyEx` keep legacy stubs.
pub fn install_reg(
    target: HANDLE,
    a: &StubAddrs,
    cdylib: Option<&CdylibHookEntries>,
) -> Result<()> {
    arch::install_reg(target, a, cdylib)
}

/// Patch `kernelbase!CreateProcessInternalW` in `target`. Must run
/// after the loader has mapped kernelbase.
pub fn install_cpw(
    target: HANDLE,
    a: &StubAddrs,
    cpw_va: usize,
    cdylib: Option<&CdylibHookEntries>,
) -> Result<()> {
    arch::install_cpw(target, a, cpw_va, cdylib)
}

// ─── shared helpers ────────────────────────────────────────────────

pub fn ntdll_export(name: &str) -> Result<usize> {
    unsafe {
        let m = GetModuleHandleW(PCWSTR(crate::util::wstr("ntdll.dll").as_ptr()))
            .context("GetModuleHandleW(ntdll)")?;
        let cname = std::ffi::CString::new(name).unwrap();
        let p = GetProcAddress(m, PCSTR(cname.as_ptr() as *const u8))
            .ok_or_else(|| anyhow!("GetProcAddress(ntdll!{name})"))?;
        Ok(p as usize)
    }
}

pub fn write_remote_bytes(proc: HANDLE, addr: usize, data: &[u8]) -> Result<()> {
    unsafe {
        let mut old = PAGE_PROTECTION_FLAGS(0);
        VirtualProtectEx(proc, addr as *const c_void, data.len(),
                         PAGE_EXECUTE_READWRITE, &mut old)
            .with_context(|| format!("VirtualProtectEx RW @ {addr:#x}"))?;
        let mut n = 0usize;
        WriteProcessMemory(proc, addr as *const c_void,
                           data.as_ptr() as *const c_void, data.len(), Some(&mut n))
            .with_context(|| format!("WriteProcessMemory @ {addr:#x}"))?;
        let mut tmp = PAGE_PROTECTION_FLAGS(0);
        let _ = VirtualProtectEx(proc, addr as *const c_void, data.len(), old, &mut tmp);
        let _ = FlushInstructionCache(proc, Some(addr as *const c_void), data.len());
        Ok(())
    }
}

pub fn alloc_remote_rx(proc: HANDLE, data: &[u8]) -> Result<usize> {
    unsafe {
        // MEM_TOP_DOWN: Cygwin fork() remaps the parent's
        // heap/data sections at the SAME VA in the child;
        // stub/trampoline/section pages allocated low could
        // collide. Top-down keeps them in high address space
        // the Cygwin heap won't reach.
        const MEM_TOP_DOWN: VIRTUAL_ALLOCATION_TYPE =
            VIRTUAL_ALLOCATION_TYPE(0x00100000);
        let p = VirtualAllocEx(proc, None, data.len().max(4096),
                               MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE);
        if p.is_null() { bail!("VirtualAllocEx: {:?}", GetLastError()); }
        let mut n = 0usize;
        WriteProcessMemory(proc, p, data.as_ptr() as *const c_void,
                           data.len(), Some(&mut n))?;
        let mut old = PAGE_PROTECTION_FLAGS(0);
        VirtualProtectEx(proc, p, data.len().max(4096), PAGE_EXECUTE_READ, &mut old)?;
        Ok(p as usize)
    }
}

/// Read raw bytes from `addr` in `proc`.
pub fn read_remote_bytes(proc: HANDLE, addr: usize, out: &mut [u8]) -> Result<()> {
    unsafe {
        let mut n = 0usize;
        ReadProcessMemory(proc, addr as *const c_void,
                          out.as_mut_ptr() as *mut c_void, out.len(), Some(&mut n))
            .with_context(|| format!("ReadProcessMemory {} bytes @ {addr:#x}", out.len()))?;
        Ok(())
    }
}

pub fn read_remote<T: Copy>(proc: HANDLE, addr: usize) -> Result<T> {
    unsafe {
        let mut out: T = std::mem::zeroed();
        let mut n = 0usize;
        ReadProcessMemory(proc, addr as *const c_void,
                          &mut out as *mut _ as *mut c_void,
                          size_of::<T>(), Some(&mut n))
            .with_context(|| format!("ReadProcessMemory @ {addr:#x}"))?;
        Ok(out)
    }
}

pub fn write_remote<T: Copy>(proc: HANDLE, addr: usize, val: &T) -> Result<()> {
    unsafe {
        let mut n = 0usize;
        WriteProcessMemory(proc, addr as *const c_void,
                           val as *const _ as *const c_void,
                           size_of::<T>(), Some(&mut n))
            .with_context(|| format!("WriteProcessMemory<{}> @ {addr:#x}",
                                      std::any::type_name::<T>()))?;
        Ok(())
    }
}

pub fn read_remote_wstr(proc: HANDLE, addr: usize, byte_len: usize) -> Result<String> {
    unsafe {
        let mut buf = vec![0u16; byte_len / 2];
        let mut n = 0usize;
        ReadProcessMemory(proc, addr as *const c_void,
                          buf.as_mut_ptr() as *mut c_void, byte_len, Some(&mut n))
            .with_context(|| format!("ReadProcessMemory wstr @ {addr:#x}"))?;
        Ok(String::from_utf16_lossy(&buf))
    }
}

// ─── arch-specific shims for archs we don't support yet ─────────────

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
mod arch {
    use super::*;
    pub fn install_fs(_t: HANDLE, _a: &StubAddrs, _c: Option<&CdylibHookEntries>) -> Result<()> {
        bail!("interception: only x86_64 and aarch64 supported")
    }
    pub fn install_reg(_t: HANDLE, _a: &StubAddrs, _c: Option<&CdylibHookEntries>) -> Result<()> {
        bail!("interception: only x86_64 and aarch64 supported")
    }
    pub fn install_cpw(_t: HANDLE, _a: &StubAddrs, _v: usize, _c: Option<&CdylibHookEntries>)
        -> Result<()>
    {
        bail!("interception: only x86_64 and aarch64 supported")
    }
}
