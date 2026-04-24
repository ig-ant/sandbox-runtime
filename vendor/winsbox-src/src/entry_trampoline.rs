//! Redirect a suspended target's initial PC (`RtlUserThreadStart`)
//! to a stub that fires *after* the loader has mapped every static
//! import. The stub signals `ev_loaded`, blocks on `ev_go`, then
//! restores `rcx`/`rdx` and tail-jumps to the original
//! `RtlUserThreadStart`. The broker uses the rendezvous to patch
//! exports in modules that aren't mapped at `CREATE_SUSPENDED` time
//! (`kernelbase!CreateProcessInternalW`). PoC P7 validated the
//! mechanism; this is the productionised x64 version.

use crate::interception::{alloc_remote_rx, ntdll_export};
use crate::ipc::dup_into;
#[allow(unused_imports)] use anyhow::{bail, Context, Result};
use std::mem::size_of;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::System::Diagnostics::Debug::{
    GetThreadContext, SetThreadContext, CONTEXT, CONTEXT_FULL_AMD64,
};
use windows::Win32::System::Threading::{
    CreateEventW, SetEvent, WaitForSingleObject, INFINITE,
};

#[cfg(not(target_arch = "x86_64"))]
pub fn install(_t: HANDLE, _th: HANDLE) -> Result<EntrySync> {
    bail!("entry_trampoline: x86_64 only")
}

pub struct EntrySync {
    ev_loaded: HANDLE,
    ev_go: HANDLE,
}
impl EntrySync {
    /// Block until the target's loader has finished and the stub
    /// has signalled. Returns false on timeout.
    pub fn wait_loaded(&self, timeout_ms: u32) -> bool {
        unsafe {
            WaitForSingleObject(self.ev_loaded, timeout_ms)
                == windows::Win32::Foundation::WAIT_OBJECT_0
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

#[cfg(target_arch = "x86_64")]
pub fn install(target: HANDLE, thread: HANDLE) -> Result<EntrySync> {
    unsafe {
        let sa = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: std::ptr::null_mut(),
            bInheritHandle: false.into(),
        };
        let ev_loaded = CreateEventW(Some(&sa), false, false, None)
            .context("CreateEventW(loaded)")?;
        let ev_go = CreateEventW(Some(&sa), false, false, None)
            .context("CreateEventW(go)")?;
        let t_loaded = dup_into(target, ev_loaded)?;
        let t_go = dup_into(target, ev_go)?;

        // CONTEXT must be 16-byte aligned; box it.
        let mut ctx: Box<CONTEXT> = Box::new(std::mem::zeroed());
        ctx.ContextFlags = CONTEXT_FULL_AMD64;
        GetThreadContext(thread, &mut *ctx).context("GetThreadContext")?;
        let orig_rip = ctx.Rip;
        let orig_rcx = ctx.Rcx;
        let orig_rdx = ctx.Rdx;

        let nt_set_event = ntdll_export("NtSetEvent")? as u64;
        let nt_wait = ntdll_export("NtWaitForSingleObject")? as u64;

        let stub = emit_stub(t_loaded, t_go, nt_set_event, nt_wait,
                             orig_rcx, orig_rdx, orig_rip);
        let stub_va = alloc_remote_rx(target, &stub)?;

        ctx.Rip = stub_va as u64;
        SetThreadContext(thread, &*ctx).context("SetThreadContext")?;
        eprintln!(
            "[sbox-exec] entry_trampoline: rtlstart={:#x} → stub @ {:#x}",
            orig_rip, stub_va,
        );
        Ok(EntrySync { ev_loaded, ev_go })
    }
}

#[cfg(target_arch = "x86_64")]
fn emit_stub(
    t_loaded: u64, t_go: u64,
    nt_set_event: u64, nt_wait: u64,
    orig_rcx: u64, orig_rdx: u64, orig_rip: u64,
) -> Vec<u8> {
    // The loader APC has already run by the time this executes, so
    // kernelbase et al. are mapped. We only need ntdll exports for
    // the calls themselves. rcx/rdx at entry hold RtlUserThreadStart's
    // (entry, arg) but we don't trust them surviving the APC; restore
    // from the values captured at install time.
    let mut s = Vec::<u8>::with_capacity(160);
    let mov_rcx = |s: &mut Vec<u8>, v: u64| {
        s.extend_from_slice(&[0x48, 0xB9]); s.extend_from_slice(&v.to_le_bytes());
    };
    let mov_rdx = |s: &mut Vec<u8>, v: u64| {
        s.extend_from_slice(&[0x48, 0xBA]); s.extend_from_slice(&v.to_le_bytes());
    };
    let mov_rax = |s: &mut Vec<u8>, v: u64| {
        s.extend_from_slice(&[0x48, 0xB8]); s.extend_from_slice(&v.to_le_bytes());
    };
    // sub rsp,0x28  (shadow + align)
    s.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);
    // NtSetEvent(t_loaded, NULL)
    mov_rcx(&mut s, t_loaded);
    s.extend_from_slice(&[0x31, 0xD2]);            // xor edx,edx
    mov_rax(&mut s, nt_set_event);
    s.extend_from_slice(&[0xFF, 0xD0]);            // call rax
    // NtWaitForSingleObject(t_go, FALSE, NULL)
    mov_rcx(&mut s, t_go);
    s.extend_from_slice(&[0x31, 0xD2]);            // xor edx,edx
    s.extend_from_slice(&[0x4D, 0x31, 0xC0]);      // xor r8,r8
    mov_rax(&mut s, nt_wait);
    s.extend_from_slice(&[0xFF, 0xD0]);            // call rax
    // add rsp,0x28
    s.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]);
    // restore rcx/rdx, jmp orig_rip
    mov_rcx(&mut s, orig_rcx);
    mov_rdx(&mut s, orig_rdx);
    mov_rax(&mut s, orig_rip);
    s.extend_from_slice(&[0xFF, 0xE0]);            // jmp rax
    s
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
