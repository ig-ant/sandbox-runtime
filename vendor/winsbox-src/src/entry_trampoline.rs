//! Redirect a suspended target's initial PC (`RtlUserThreadStart`)
//! to a stub that fires *after* the loader has mapped every static
//! import. The stub signals `ev_loaded`, blocks on `ev_go`, then
//! restores `rcx`/`rdx` and tail-jumps to the original
//! `RtlUserThreadStart`. The broker uses the rendezvous to patch
//! exports in modules that aren't mapped at `CREATE_SUSPENDED` time
//! (`kernelbase!CreateProcessInternalW`). PoC P7 validated the
//! mechanism; this is the productionised x64 version.

#[allow(unused_imports)]
use crate::interception::{alloc_remote_rx, ntdll_export};
#[allow(unused_imports)]
use crate::ipc::dup_into;
#[allow(unused_imports)] use anyhow::{bail, Context, Result};
#[allow(unused_imports)]
use std::mem::size_of;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
#[allow(unused_imports)]
use windows::Win32::Security::SECURITY_ATTRIBUTES;
#[allow(unused_imports)]
use windows::Win32::System::Diagnostics::Debug::{
    GetThreadContext, SetThreadContext, CONTEXT, CONTEXT_FULL_AMD64,
};
#[allow(unused_imports)]
use windows::Win32::System::Threading::{
    CreateEventW, SetEvent, WaitForSingleObject, INFINITE,
};

#[cfg(not(target_arch = "x86_64"))]
pub fn install(_t: HANDLE, _th: HANDLE, _s: bool) -> Result<EntrySync> {
    bail!("entry_trampoline: x86_64 only")
}

pub struct EntrySync {
    ev_loaded: HANDLE,
    ev_go: HANDLE,
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

#[cfg(target_arch = "x86_64")]
pub fn install(
    target: HANDLE, thread: HANDLE, suspend_after: bool,
) -> Result<EntrySync> {
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
        let nt_set_info_thread = ntdll_export("NtSetInformationThread")? as u64;
        let nt_suspend = ntdll_export("NtSuspendThread")? as u64;

        let stub = emit_stub(
            t_loaded, t_go, nt_set_event, nt_wait, nt_set_info_thread,
            nt_suspend, suspend_after, orig_rcx, orig_rdx, orig_rip,
        );
        let stub_va = alloc_remote_rx(target, &stub)?;

        ctx.Rip = stub_va as u64;
        SetThreadContext(thread, &*ctx).context("SetThreadContext")?;
        eprintln!(
            "[sbox-exec] entry_trampoline: rtlstart={:#x} → stub @ {:#x}{}",
            orig_rip, stub_va,
            if suspend_after { " (suspend-after)" } else { "" },
        );
        Ok(EntrySync { ev_loaded, ev_go })
    }
}

#[cfg(target_arch = "x86_64")]
#[allow(clippy::too_many_arguments)]
fn emit_stub(
    t_loaded: u64, t_go: u64,
    nt_set_event: u64, nt_wait: u64,
    nt_set_info_thread: u64, nt_suspend: u64, suspend_after: bool,
    orig_rcx: u64, orig_rdx: u64, orig_rip: u64,
) -> Vec<u8> {
    // The loader APC has already run by the time this executes, so
    // kernelbase et al. are mapped. We only need ntdll exports for
    // the calls themselves. rcx/rdx at entry hold RtlUserThreadStart's
    // (entry, arg) but we don't trust them surviving the APC; restore
    // from the values captured at install time.
    let mut s = Vec::<u8>::with_capacity(256);
    let mov_rcx = |s: &mut Vec<u8>, v: u64| {
        s.extend_from_slice(&[0x48, 0xB9]); s.extend_from_slice(&v.to_le_bytes());
    };
    let mov_rdx = |s: &mut Vec<u8>, v: u64| {
        s.extend_from_slice(&[0x48, 0xBA]); s.extend_from_slice(&v.to_le_bytes());
    };
    let mov_rax = |s: &mut Vec<u8>, v: u64| {
        s.extend_from_slice(&[0x48, 0xB8]); s.extend_from_slice(&v.to_le_bytes());
    };
    // sub rsp,0x28  (shadow + align; [rsp+0x20] is scratch)
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
    // RevertToSelf:
    //   NtSetInformationThread(NtCurrentThread()=-2,
    //     ThreadImpersonationToken=5, &NULL, 8)
    s.extend_from_slice(&[0x48, 0x31, 0xC0]);                  // xor rax,rax
    s.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x20]);      // mov [rsp+0x20],rax
    s.extend_from_slice(&[0x48, 0xC7, 0xC1, 0xFE, 0xFF, 0xFF, 0xFF]); // mov rcx,-2
    s.extend_from_slice(&[0xBA, 0x05, 0x00, 0x00, 0x00]);      // mov edx,5
    s.extend_from_slice(&[0x4C, 0x8D, 0x44, 0x24, 0x20]);      // lea r8,[rsp+0x20]
    s.extend_from_slice(&[0x41, 0xB9, 0x08, 0x00, 0x00, 0x00]); // mov r9d,8
    mov_rax(&mut s, nt_set_info_thread);
    s.extend_from_slice(&[0xFF, 0xD0]);            // call rax
    if suspend_after {
        // NtSuspendThread(NtCurrentThread(), NULL) — caller asked for
        // CREATE_SUSPENDED; the broker had to resume for the
        // rendezvous, so re-suspend here. The caller's eventual
        // ResumeThread on the duplicated handle wakes us.
        s.extend_from_slice(&[0x48, 0xC7, 0xC1, 0xFE, 0xFF, 0xFF, 0xFF]); // mov rcx,-2
        s.extend_from_slice(&[0x31, 0xD2]);        // xor edx,edx
        mov_rax(&mut s, nt_suspend);
        s.extend_from_slice(&[0xFF, 0xD0]);        // call rax
    }
    // add rsp,0x28
    s.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]);
    // restore rcx/rdx, jmp orig_rip
    mov_rcx(&mut s, orig_rcx);
    mov_rdx(&mut s, orig_rdx);
    mov_rax(&mut s, orig_rip);
    s.extend_from_slice(&[0xFF, 0xE0]);            // jmp rax
    let _ = nt_suspend; // referenced even when !suspend_after
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
