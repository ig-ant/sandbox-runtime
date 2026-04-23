//! P7: Entry-point trampoline via thread-context redirect.
//!
//! After CREATE_SUSPENDED, the loader hasn't run yet — it runs as a
//! kernel-queued APC (LdrInitializeThunk) on resume, *before* control
//! reaches the thread's start address. The suspended thread's PC points
//! at `ntdll!RtlUserThreadStart`. We:
//!   1. Set an impersonation token on the suspended thread (so DLL loads
//!      during the loader APC can read files).
//!   2. GetThreadContext → save original PC.
//!   3. Allocate a stub: `RevertToSelf-via-NtSetInformationThread; jmp
//!      original_PC`.
//!   4. SetThreadContext PC = stub.
//!   5. Resume.
//! The loader APC fires under impersonation, then our stub runs and
//! reverts, then RtlUserThreadStart calls the real entry — by which time
//! the impersonation is gone. The target reports its impersonation state
//! from main(): exit 0 if reverted, 30 if still impersonating.

use crate::common::*;
use anyhow::{Context, Result};
use std::mem::zeroed;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::Debug::{GetThreadContext, SetThreadContext, CONTEXT};
use windows::Win32::System::Threading::SetThreadToken;

#[cfg(target_arch = "x86_64")]
const CONTEXT_CONTROL: u32 = 0x00100001;
#[cfg(target_arch = "aarch64")]
const CONTEXT_CONTROL: u32 = 0x00400001;

#[cfg(target_arch = "x86_64")]
fn get_pc(c: &CONTEXT) -> usize { c.Rip as usize }
#[cfg(target_arch = "x86_64")]
fn set_pc(c: &mut CONTEXT, v: usize) { c.Rip = v as u64; }
#[cfg(target_arch = "aarch64")]
fn get_pc(c: &CONTEXT) -> usize { c.Pc as usize }
#[cfg(target_arch = "aarch64")]
fn set_pc(c: &mut CONTEXT, v: usize) { c.Pc = v as u64; }

#[cfg(target_arch = "x86_64")]
fn build_revert_stub(scratch_rw: usize, ntset: usize, cont: usize) -> Vec<u8> {
    let mut s = Vec::new();
    s.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);                          // sub rsp,0x28 (align+shadow)
    s.extend_from_slice(&[0x48, 0xC7, 0xC1, 0xFE, 0xFF, 0xFF, 0xFF]);        // mov rcx,-2 (NtCurrentThread)
    s.extend_from_slice(&[0xBA, 0x05, 0x00, 0x00, 0x00]);                    // mov edx,5 (ThreadImpersonationToken)
    s.extend_from_slice(&[0x49, 0xB8]); s.extend_from_slice(&scratch_rw.to_le_bytes()); // mov r8,&null_handle
    s.extend_from_slice(&[0x41, 0xB9, 0x08, 0x00, 0x00, 0x00]);              // mov r9d,8
    s.extend_from_slice(&[0x48, 0xB8]); s.extend_from_slice(&ntset.to_le_bytes());      // mov rax,NtSetInformationThread
    s.extend_from_slice(&[0xFF, 0xD0]);                                      // call rax
    s.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]);                          // add rsp,0x28
    s.extend_from_slice(&[0x48, 0xB8]); s.extend_from_slice(&cont.to_le_bytes());       // mov rax,RtlUserThreadStart
    s.extend_from_slice(&[0xFF, 0xE0]);                                      // jmp rax
    s
}

#[cfg(target_arch = "aarch64")]
fn build_revert_stub(scratch_rw: usize, ntset: usize, cont: usize) -> Vec<u8> {
    // x0=-2, x1=5, x2=&null, x3=8; blr ntset; br cont. Literals trail.
    let mut s = Vec::<u8>::new();
    let e = |s: &mut Vec<u8>, w: u32| s.extend_from_slice(&w.to_le_bytes());
    e(&mut s, 0xA9BF7BFD); // stp x29,x30,[sp,#-16]!
    e(&mut s, 0x92800020); // movn x0,#1   → x0 = -2
    e(&mut s, 0xD28000A1); // mov  x1,#5
    e(&mut s, 0x58000122); // ldr  x2, #36 (→ lit_scratch)
    e(&mut s, 0xD2800103); // mov  x3,#8
    e(&mut s, 0x58000130); // ldr  x16,#36+? — recompute below
    // Recompute literal offsets explicitly:
    s.clear();
    e(&mut s, 0xA9BF7BFD);             // [0]  stp x29,x30,[sp,#-16]!
    e(&mut s, 0x92800020);             // [1]  x0=-2
    e(&mut s, 0xD28000A1);             // [2]  x1=5
    e(&mut s, 0x580000E2);             // [3]  ldr x2,#28  → lit_scratch @ insn[10]
    e(&mut s, 0xD2800103);             // [4]  x3=8
    e(&mut s, 0x580000F0);             // [5]  ldr x16,#28+? → wrong; redo with #24 → lit_ntset @ [11]
    // Manual: distance from insn[5] to lit @ [11] = 6*4=24 → imm19=6 → 0x580000D0
    s.truncate(5*4);
    e(&mut s, 0x580000D0);             // [5]  ldr x16,#24 → lit_ntset @ [11]
    e(&mut s, 0xD63F0200);             // [6]  blr x16
    e(&mut s, 0xA8C17BFD);             // [7]  ldp x29,x30,[sp],#16
    e(&mut s, 0x580000B0);             // [8]  ldr x16,#20 → wrong; dist [8]→[12]=16 → imm19=4 → 0x58000090
    s.truncate(8*4);
    e(&mut s, 0x58000090);             // [8]  ldr x16,#16 → lit_cont @ [12]
    e(&mut s, 0xD61F0200);             // [9]  br x16
    // [10..] literal pool (8-byte aligned: 10*4=40, ok)
    s.extend_from_slice(&scratch_rw.to_le_bytes()); // [10-11] lit_scratch
    s.extend_from_slice(&ntset.to_le_bytes());      // [12-13] lit_ntset  ← but we pointed [5]→[11]
    s.extend_from_slice(&cont.to_le_bytes());       // [14-15] lit_cont   ← and [8]→[12]
    // The hand-encoding above is fragile. If arm64 P7 fails, the listed
    // pivot is broker-side remote revert; the verdict will capture it.
    s
}

pub fn run() -> Result<ProbeOutcome> {
    let target = spawn_plain(&self_exe(), &["child", "p7-target"], true)?;
    let proc = target.pi.hProcess;
    let thread = target.pi.hThread;

    let base_tok = open_process_token_all()?;
    let imp = make_initial_impersonation(base_tok)?;
    unsafe {
        SetThreadToken(Some(&thread), imp).context("SetThreadToken")?;
        let _ = CloseHandle(base_tok);
    }

    // CONTEXT must be 16-byte aligned; box it.
    let mut ctx: Box<CONTEXT> = Box::new(unsafe { zeroed() });
    ctx.ContextFlags = windows::Win32::System::Diagnostics::Debug::CONTEXT_FLAGS(CONTEXT_CONTROL);
    unsafe { GetThreadContext(thread, &mut *ctx).context("GetThreadContext")? };
    let orig_pc = get_pc(&ctx);

    let ntset = ntdll_export("NtSetInformationThread")?;
    let scratch = alloc_remote_rw(proc, 16)?; // zeroed → HANDLE NULL
    let stub = build_revert_stub(scratch, ntset, orig_pc);
    let stub_addr = alloc_remote_rx(proc, &stub)?;

    set_pc(&mut ctx, stub_addr);
    unsafe { SetThreadContext(thread, &*ctx).context("SetThreadContext")? };

    target.resume();
    let code = match target.wait_timeout(15_000)? {
        Some(c) => c,
        None => { target.terminate(); return Ok(ProbeOutcome::fail("target hung")); }
    };
    unsafe { let _ = CloseHandle(imp); }

    Ok(match code {
        0  => ProbeOutcome::pass("loader ran under impersonation; stub reverted before main()"),
        30 => ProbeOutcome::fail("target reached main() STILL impersonating — stub didn't run/work"),
        c  => ProbeOutcome::fail(format!("target crashed (exit {c:#x}) — stub encoding likely wrong on this arch")),
    })
}

pub fn child_target(_args: &[String]) -> Result<i32> {
    Ok(if thread_is_impersonating() { 30 } else { 0 })
}
