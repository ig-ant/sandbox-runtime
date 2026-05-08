//! x86_64 entry-trampoline emitter.
//!
//! Captures original `Rip`/`Rcx`/`Rdx` from `RtlUserThreadStart`'s
//! suspended-thread CONTEXT, allocates a remote RX page with a stub
//! that signals `ev_loaded`, blocks on `ev_go`, optionally re-suspends,
//! restores `Rcx`/`Rdx`, and tail-jumps to the original entry point.
//!
//! Phase H split this out from the (formerly monolithic)
//! `entry_trampoline.rs`; the ARM64 mirror lives in
//! `entry_trampoline_arm64.rs`. The shared `EntrySync` /
//! `EntryWait` types and `cpw_address` helper live in the façade.

use anyhow::{Context, Result};
use std::mem::size_of;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::System::Diagnostics::Debug::{
    GetThreadContext, SetThreadContext, CONTEXT, CONTEXT_FULL_AMD64,
};
use windows::Win32::System::Threading::CreateEventW;

use crate::interception::{alloc_remote_rx, ntdll_export};
use crate::ipc::dup_into;

use crate::entry_trampoline::EntrySync;

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
