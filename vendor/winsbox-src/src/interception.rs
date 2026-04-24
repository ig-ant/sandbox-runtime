//! Inline-hook `kernelbase!CreateProcessInternalW` so the broker
//! performs every spawn. The hook is installed *after* the loader
//! has run (kernelbase isn't mapped at `CREATE_SUSPENDED` time) via
//! the `entry_trampoline` rendezvous. The injected stub spills the
//! 12 arguments into the IPC section, signals the broker, blocks on
//! the response, writes `PROCESS_INFORMATION` + last-error back, and
//! returns the broker's `BOOL`. Hooking at this layer means the
//! caller's `dwCreationFlags`/`lpStartupInfo` arrive verbatim and
//! `CreateProcessInternalW`'s post-`NtCreateUserProcess` machinery
//! (CSR, AppCompat, Safer, conhost) runs exactly once — in the broker.
//!
//! x86_64 only. arm64 falls back to Mode::AppContainer at runtime.

use crate::ipc::StubAddrs;
use anyhow::{anyhow, bail, Context, Result};
use std::ffi::c_void;
use windows::core::{PCSTR, PCWSTR};
use windows::Win32::Foundation::{GetLastError, HANDLE};
use windows::Win32::System::Diagnostics::Debug::{
    FlushInstructionCache, ReadProcessMemory, WriteProcessMemory,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Memory::{
    VirtualAllocEx, VirtualProtectEx, MEM_COMMIT, MEM_RESERVE,
    PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS,
    PAGE_READWRITE,
};

#[cfg(not(target_arch = "x86_64"))]
pub fn install_fs(_target: HANDLE, _a: &StubAddrs) -> Result<()> {
    bail!("interception: x86_64 only in this build");
}
#[cfg(not(target_arch = "x86_64"))]
pub fn install_cpw(_target: HANDLE, _a: &StubAddrs, _cpw: usize) -> Result<()> {
    bail!("interception: x86_64 only in this build");
}

#[cfg(target_arch = "x86_64")]
fn stub_env(a: &StubAddrs) -> Result<StubEnv> {
    Ok(StubEnv {
        section: a.section as u64,
        ev_req: a.ev_req, ev_resp: a.ev_resp, mutex: a.mutex,
        nt_set_event: ntdll_export("NtSetEvent")? as u64,
        nt_wait: ntdll_export("NtWaitForSingleObject")? as u64,
        nt_release_mutant: ntdll_export("NtReleaseMutant")? as u64,
    })
}

/// Patch `ntdll!{NtCreateFile,NtOpenFile}` in `target`. Installed
/// **before** `ResumeThread` so the loader's own opens are
/// brokered — under USER_LOCKDOWN the parallel-loader worker
/// threads run under the NULL-restricting process token and
/// fail every file open otherwise (P12 / `0xc0000135`). Loader
/// opens the broker can't resolve (object-directory-relative,
/// `\Device\*`) get an `FS_PASSTHROUGH` reply and the stub
/// tail-jmps a saved 32-byte copy of the original syscall stub
/// — those run under the initial impersonation token on the
/// main thread, or under the lockdown token on workers (which
/// is fine for KnownDlls section opens; non-KnownDll file opens
/// are exactly what the broker handles). The 172f260 revert was
/// for the try-original-first stub's in-loader AV, not for
/// pre-loader hooking itself.
#[cfg(target_arch = "x86_64")]
pub fn install_fs(target: HANDLE, a: &StubAddrs) -> Result<()> {
    let env = stub_env(a)?;
    for (name, op, n_args) in [
        ("NtCreateFile", crate::ipc::OP_NTCREATEFILE, 11usize),
        ("NtOpenFile",   crate::ipc::OP_NTOPENFILE,    6usize),
    ] {
        let va = ntdll_export(name)?;
        let mut orig = [0u8; 32];
        read_remote_bytes(target, va, &mut orig)?;
        let saved = alloc_remote_rx(target, &orig)?;
        patch_with_stub(target, name, va,
                        &emit_fs_stub(&env, op, n_args, saved as u64))?;
    }
    // GetFileAttributes/PathFileExists go through these — not
    // hooking them means existence checks on paths the lockdown
    // token can't read (third-party installs without an ALL APP
    // PACKAGES ACE) fail, e.g. git-for-windows' bin\git.exe
    // wrapper checking for ..\mingw64\bin\git.exe.
    for (name, op, out_qwords) in [
        // FILE_BASIC_INFORMATION = 40 bytes = 5 qwords;
        // FILE_NETWORK_OPEN_INFORMATION = 56 bytes = 7.
        ("NtQueryAttributesFile",     crate::ipc::OP_NTQUERYATTR,     5u32),
        ("NtQueryFullAttributesFile", crate::ipc::OP_NTQUERYFULLATTR, 7u32),
    ] {
        let va = ntdll_export(name)?;
        let mut orig = [0u8; 32];
        read_remote_bytes(target, va, &mut orig)?;
        let saved = alloc_remote_rx(target, &orig)?;
        patch_with_stub(target, name, va,
                        &emit_attr_stub(&env, op, out_qwords, saved as u64))?;
    }
    Ok(())
}

/// Patch `ntdll!{NtOpenKey,NtOpenKeyEx}` in `target`. Installed
/// alongside the FS hooks (pre-resume) so post-`RevertToSelf`
/// registry reads work under USER_LOCKDOWN — `BCryptGenRandom`'s
/// lazy init reads `HKLM\…\Cryptography\Configuration` and
/// `WSAStartup` reads `HKLM\…\WinSock2\Parameters`; both fail
/// under NULL restricting otherwise. v1: default-allow-read,
/// deny any write bit. `NtCreateKey` is left unhooked — it
/// fails under the lockdown token, which is the desired write
/// policy.
#[cfg(target_arch = "x86_64")]
pub fn install_reg(target: HANDLE, a: &StubAddrs) -> Result<()> {
    let env = stub_env(a)?;
    for (name, op, n_args) in [
        ("NtOpenKey",     crate::ipc::OP_NTOPENKEY,     3usize),
        ("NtOpenKeyEx",   crate::ipc::OP_NTOPENKEYEX,   4usize),
        ("NtOpenSection", crate::ipc::OP_NTOPENSECTION, 3usize),
    ] {
        let va = ntdll_export(name)?;
        let mut orig = [0u8; 32];
        read_remote_bytes(target, va, &mut orig)?;
        let saved = alloc_remote_rx(target, &orig)?;
        patch_with_stub(target, name, va,
                        &emit_handle_stub(&env, op, n_args, saved as u64))?;
    }
    Ok(())
}
#[cfg(not(target_arch = "x86_64"))]
pub fn install_reg(_target: HANDLE, _a: &StubAddrs) -> Result<()> {
    Ok(())
}

/// Patch `kernelbase!CreateProcessInternalW` in `target`. Must run
/// after the loader has mapped kernelbase — i.e. after the
/// entry-trampoline rendezvous.
#[cfg(target_arch = "x86_64")]
pub fn install_cpw(target: HANDLE, a: &StubAddrs, cpw_va: usize) -> Result<()> {
    let env = stub_env(a)?;
    patch_with_stub(target, "CreateProcessInternalW", cpw_va,
                    &emit_cpw_stub(&env))?;
    Ok(())
}

#[cfg(target_arch = "x86_64")]
fn patch_with_stub(target: HANDLE, name: &str, va: usize, stub: &[u8]) -> Result<()> {
    let stub_va = alloc_remote_rx(target, stub)?;
    let mut patch = enc_abs_jmp(stub_va);
    while patch.len() < ABS_JMP_LEN { patch.push(0x90); }
    write_remote_bytes(target, va, &patch)?;
    eprintln!("[sbox-exec] interception: {name} @ {va:#x} → stub @ {stub_va:#x}");
    Ok(())
}

// ─── x64 stub emitters ─────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
struct StubEnv {
    section: u64, ev_req: u64, ev_resp: u64, mutex: u64,
    nt_set_event: u64, nt_wait: u64, nt_release_mutant: u64,
}

/// `NtReleaseMutant(mutex, NULL)` preserving eax across the
/// call. 34 bytes. r10 and rcx/rdx/r8/r9 are clobbered. Stack
/// alignment: stub entry is rsp%16==8; push rax → 0; sub 0x20
/// → 0; call sees aligned-then-pushed.
#[cfg(target_arch = "x86_64")]
fn emit_release_keep_eax(s: &mut Vec<u8>, e: &StubEnv) {
    s.push(0x50);                                    // push rax
    s.extend_from_slice(&[0x48, 0x83, 0xEC, 0x20]);  // sub rsp,0x20
    s.extend_from_slice(&[0x48, 0xB9]);              // mov rcx, mutex
    s.extend_from_slice(&e.mutex.to_le_bytes());
    s.extend_from_slice(&[0x31, 0xD2]);              // xor edx,edx
    s.extend_from_slice(&[0x48, 0xB8]);              // mov rax, NtReleaseMutant
    s.extend_from_slice(&e.nt_release_mutant.to_le_bytes());
    s.extend_from_slice(&[0xFF, 0xD0]);              // call rax
    s.extend_from_slice(&[0x48, 0x83, 0xC4, 0x20]);  // add rsp,0x20
    s.push(0x58);                                    // pop rax
}

/// Release the mutant, restore rcx/rdx/r8/r9 from the caller's
/// shadow space (per-thread, immune to section reuse), and
/// tail-jmp the saved original syscall stub. 64 bytes.
#[cfg(target_arch = "x86_64")]
fn emit_passthrough(s: &mut Vec<u8>, e: &StubEnv, saved_orig: u64) {
    s.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);  // sub rsp,0x28
    s.extend_from_slice(&[0x48, 0xB9]);              // mov rcx, mutex
    s.extend_from_slice(&e.mutex.to_le_bytes());
    s.extend_from_slice(&[0x31, 0xD2]);              // xor edx,edx
    s.extend_from_slice(&[0x48, 0xB8]);              // mov rax, NtReleaseMutant
    s.extend_from_slice(&e.nt_release_mutant.to_le_bytes());
    s.extend_from_slice(&[0xFF, 0xD0]);              // call rax
    s.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]);  // add rsp,0x28
    // restore from shadow space
    s.extend_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x08]); // mov rcx,[rsp+8]
    s.extend_from_slice(&[0x48, 0x8B, 0x54, 0x24, 0x10]); // mov rdx,[rsp+0x10]
    s.extend_from_slice(&[0x4C, 0x8B, 0x44, 0x24, 0x18]); // mov r8, [rsp+0x18]
    s.extend_from_slice(&[0x4C, 0x8B, 0x4C, 0x24, 0x20]); // mov r9, [rsp+0x20]
    s.extend_from_slice(&[0x48, 0xB8]);              // mov rax, saved_orig
    s.extend_from_slice(&saved_orig.to_le_bytes());
    s.extend_from_slice(&[0xFF, 0xE0]);              // jmp rax
}
const PASSTHROUGH_LEN: u8 = 64;

/// Phase A: save rcx/rdx/r8/r9 to caller's shadow space
/// (per-thread; survives the mutex/event calls below);
/// `NtWaitForSingleObject(mutex, FALSE, NULL)` — abandoned
/// returns `STATUS_ABANDONED` and ownership is granted, so no
/// status check; load r10=section; write op; spill shadow-
/// space + stack args to section. Phase B: signal req, wait
/// resp. Reload r10. The caller appends Phase C and is
/// responsible for `emit_release_keep_eax` on every exit.
#[cfg(target_arch = "x86_64")]
fn emit_prologue(s: &mut Vec<u8>, e: &StubEnv, op: u64, n_args: usize) {
    // ── save args to caller's shadow space
    s.extend_from_slice(&[0x48, 0x89, 0x4C, 0x24, 0x08]); // [rsp+8]  = rcx
    s.extend_from_slice(&[0x48, 0x89, 0x54, 0x24, 0x10]); // [rsp+10] = rdx
    s.extend_from_slice(&[0x4C, 0x89, 0x44, 0x24, 0x18]); // [rsp+18] = r8
    s.extend_from_slice(&[0x4C, 0x89, 0x4C, 0x24, 0x20]); // [rsp+20] = r9
    // ── acquire mutex (clobbers volatiles; args saved above)
    s.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);       // sub rsp,0x28
    s.extend_from_slice(&[0x48, 0xB9]);                   // mov rcx, mutex
    s.extend_from_slice(&e.mutex.to_le_bytes());
    s.extend_from_slice(&[0x31, 0xD2]);                   // xor edx,edx (Alertable)
    s.extend_from_slice(&[0x45, 0x31, 0xC0]);             // xor r8d,r8d (Timeout)
    s.extend_from_slice(&[0x48, 0xB8]);                   // mov rax, NtWaitForSingleObject
    s.extend_from_slice(&e.nt_wait.to_le_bytes());
    s.extend_from_slice(&[0xFF, 0xD0]);                   // call rax
    s.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]);       // add rsp,0x28
    // ── load section base
    s.extend_from_slice(&[0x49, 0xBA]);                   // mov r10, section
    s.extend_from_slice(&e.section.to_le_bytes());
    // ── op
    s.extend_from_slice(&[0x48, 0xB8]); s.extend_from_slice(&op.to_le_bytes());
    s.extend_from_slice(&[0x49, 0x89, 0x02]);             // mov [r10], rax
    // ── spill shadow-space args to section
    for (sp, dst) in [(0x08u8, 0x08u8), (0x10, 0x10), (0x18, 0x18), (0x20, 0x20)] {
        s.extend_from_slice(&[0x48, 0x8B, 0x44, 0x24, sp]); // mov rax,[rsp+sp]
        s.extend_from_slice(&[0x49, 0x89, 0x42, dst]);      // mov [r10+dst],rax
    }
    // ── stack args 5..n at [rsp+0x28..]
    for i in 4..n_args {
        let sp_off = 0x28 + (i - 4) * 8;
        let dst = 0x08 + i * 8;
        s.extend_from_slice(&[0x48, 0x8B, 0x44, 0x24, sp_off as u8]);
        s.extend_from_slice(&[0x49, 0x89, 0x42, dst as u8]);
    }
    // ── Phase B
    s.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]); // sub rsp,0x28
    s.extend_from_slice(&[0x48, 0xB9]); s.extend_from_slice(&e.ev_req.to_le_bytes());
    s.extend_from_slice(&[0x31, 0xD2]);
    s.extend_from_slice(&[0x48, 0xB8]); s.extend_from_slice(&e.nt_set_event.to_le_bytes());
    s.extend_from_slice(&[0xFF, 0xD0]);
    s.extend_from_slice(&[0x48, 0xB9]); s.extend_from_slice(&e.ev_resp.to_le_bytes());
    s.extend_from_slice(&[0x31, 0xD2]);
    s.extend_from_slice(&[0x45, 0x31, 0xC0]);
    s.extend_from_slice(&[0x48, 0xB8]); s.extend_from_slice(&e.nt_wait.to_le_bytes());
    s.extend_from_slice(&[0xFF, 0xD0]);
    s.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]); // add rsp,0x28
    // ── reload r10 for Phase C
    s.extend_from_slice(&[0x49, 0xBA]); s.extend_from_slice(&e.section.to_le_bytes());
}

#[cfg(target_arch = "x86_64")]
fn emit_cpw_stub(e: &StubEnv) -> Vec<u8> {
    let mut s = Vec::<u8>::with_capacity(320);
    emit_prologue(&mut s, e, crate::ipc::OP_CPW, 12);
    // ── Phase C (CPW)
    // rcx = args[10] = lpProcessInformation @ +0x58
    s.extend_from_slice(&[0x49, 0x8B, 0x4A, 0x58]);
    s.extend_from_slice(&[0x48, 0x85, 0xC9, 0x74, 0x1D]); // jz +0x1D
    //   [rcx+0]  = r0 @ +0x68 (hProcess)
    s.extend_from_slice(&[0x49, 0x8B, 0x42, 0x68, 0x48, 0x89, 0x01]);
    //   [rcx+8]  = r1 @ +0x70 (hThread)
    s.extend_from_slice(&[0x49, 0x8B, 0x42, 0x70, 0x48, 0x89, 0x41, 0x08]);
    //   [rcx+0x10] = r2 @ +0x78 (dwProcessId)
    s.extend_from_slice(&[0x41, 0x8B, 0x42, 0x78, 0x89, 0x41, 0x10]);
    //   [rcx+0x14] = r3 @ +0x7c (dwThreadId)
    s.extend_from_slice(&[0x41, 0x8B, 0x42, 0x7C, 0x89, 0x41, 0x14]);
    // rcx = args[11] = phRestrictedToken @ +0x60
    s.extend_from_slice(&[0x49, 0x8B, 0x4A, 0x60]);
    s.extend_from_slice(&[0x48, 0x85, 0xC9, 0x74, 0x07]);
    s.extend_from_slice(&[0x48, 0x31, 0xC0, 0x48, 0x89, 0x01, 0x90]);
    // gs:[0x68] = r_error @ +0x84
    s.extend_from_slice(&[0x41, 0x8B, 0x82, 0x84, 0x00, 0x00, 0x00]); // mov eax,[r10+0x84]
    s.extend_from_slice(&[0x65, 0x89, 0x04, 0x25, 0x68, 0x00, 0x00, 0x00]);
    // eax = r_status @ +0x80 (BOOL)
    s.extend_from_slice(&[0x41, 0x8B, 0x82, 0x80, 0x00, 0x00, 0x00]);
    emit_release_keep_eax(&mut s, e);
    s.push(0xC3);
    s
}

// FOLLOW-UP: a try-original-first stub (tail-call the saved
// copy, only IPC on STATUS_ACCESS_DENIED) would cut IPC volume
// dramatically. The hand-emitted version (14da6b9) AVs
// in-loader; needs WinDbg. Until then the broker decides
// per-request whether to handle the open itself or reply
// FS_PASSTHROUGH and have the stub tail-jmp the saved original.
#[cfg(target_arch = "x86_64")]
fn emit_fs_stub(e: &StubEnv, op: u64, n_args: usize, saved_orig: u64) -> Vec<u8> {
    let mut s = Vec::<u8>::with_capacity(512);
    emit_prologue(&mut s, e, op, n_args);
    // r10 = section. Passthrough check: r_status ==
    // FS_PASSTHROUGH → release mutex, restore args from
    // shadow space (per-thread), tail-jmp saved original
    // (its `ret` returns to *our* caller; out-params are
    // written by the kernel; stack args at [rsp+0x28..] are
    // unchanged — every sub/add cancelled).
    s.extend_from_slice(&[0x41, 0x8B, 0x82, 0x80, 0x00, 0x00, 0x00]); // mov eax,[r10+0x80]
    s.extend_from_slice(&[0x3D]);                                      // cmp eax, FS_PASSTHROUGH
    s.extend_from_slice(&(crate::ipc::FS_PASSTHROUGH as u32).to_le_bytes().as_slice());
    s.extend_from_slice(&[0x75, PASSTHROUGH_LEN]);                     // jne broker_reply (+64)
    emit_passthrough(&mut s, e, saved_orig);
    // broker_reply: out-params from section (mutex still
    // held), then release, then ret. Pointer args come from
    // shadow space — same value as section, but per-thread.
    // *args[0] = r0 (FileHandle)
    s.extend_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x08]);              // mov rcx,[rsp+8]
    s.extend_from_slice(&[0x49, 0x8B, 0x42, 0x68, 0x48, 0x89, 0x01]);
    // *args[3] = {r_status, r1} (IO_STATUS_BLOCK)
    s.extend_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x20]);              // mov rcx,[rsp+0x20]
    s.extend_from_slice(&[0x48, 0x85, 0xC9, 0x74, 0x12]);              // jz +0x12
    s.extend_from_slice(&[0x49, 0x63, 0x82, 0x80, 0x00, 0x00, 0x00]);  // movsxd rax,[r10+0x80]
    s.extend_from_slice(&[0x48, 0x89, 0x01]);
    s.extend_from_slice(&[0x49, 0x8B, 0x42, 0x70, 0x48, 0x89, 0x41, 0x08]);
    // eax = r_status (NTSTATUS)
    s.extend_from_slice(&[0x41, 0x8B, 0x82, 0x80, 0x00, 0x00, 0x00]);
    emit_release_keep_eax(&mut s, e);
    s.push(0xC3);
    s
}

/// Stub for syscalls whose only out-param is `*args[0] = HANDLE`
/// — `NtOpenKey`, `NtOpenKeyEx`, `NtOpenSection`. Same prologue
/// + passthrough as `emit_fs_stub`; Phase C writes `r0` to
/// `*args[0]` and returns `r_status`.
#[cfg(target_arch = "x86_64")]
fn emit_handle_stub(e: &StubEnv, op: u64, n_args: usize, saved_orig: u64) -> Vec<u8> {
    let mut s = Vec::<u8>::with_capacity(384);
    emit_prologue(&mut s, e, op, n_args);
    s.extend_from_slice(&[0x41, 0x8B, 0x82, 0x80, 0x00, 0x00, 0x00]); // mov eax,[r10+0x80]
    s.extend_from_slice(&[0x3D]);
    s.extend_from_slice(&(crate::ipc::FS_PASSTHROUGH as u32).to_le_bytes().as_slice());
    s.extend_from_slice(&[0x75, PASSTHROUGH_LEN]);                     // jne broker_reply (+64)
    emit_passthrough(&mut s, e, saved_orig);
    // broker_reply: *args[0] = r0
    s.extend_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x08]);              // mov rcx,[rsp+8]
    s.extend_from_slice(&[0x49, 0x8B, 0x42, 0x68, 0x48, 0x89, 0x01]);
    s.extend_from_slice(&[0x41, 0x8B, 0x82, 0x80, 0x00, 0x00, 0x00]);  // mov eax,[r10+0x80]
    emit_release_keep_eax(&mut s, e);
    s.push(0xC3);
    s
}

/// `NtQueryAttributesFile` / `NtQueryFullAttributesFile`:
/// args[0]=POBJECT_ATTRIBUTES, args[1]=out struct. Phase C
/// copies `out_qwords` qwords from `[r10+ATTR_OFF]` to
/// `*args[1]` (rdx, saved at `[rsp+0x10]`). The copy length
/// MUST match the syscall's output struct exactly — the
/// caller allocated that size and writing past it corrupts
/// their stack.
#[cfg(target_arch = "x86_64")]
fn emit_attr_stub(e: &StubEnv, op: u64, out_qwords: u32, saved_orig: u64) -> Vec<u8> {
    let mut s = Vec::<u8>::with_capacity(384);
    emit_prologue(&mut s, e, op, 2);
    s.extend_from_slice(&[0x41, 0x8B, 0x82, 0x80, 0x00, 0x00, 0x00]); // mov eax,[r10+0x80]
    s.extend_from_slice(&[0x3D]);
    s.extend_from_slice(&(crate::ipc::FS_PASSTHROUGH as u32).to_le_bytes().as_slice());
    s.extend_from_slice(&[0x75, PASSTHROUGH_LEN]);                     // jne broker_reply
    emit_passthrough(&mut s, e, saved_orig);
    // broker_reply: rcx = args[1] = out-struct ptr (was rdx)
    s.extend_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x10]); // mov rcx,[rsp+0x10]
    // Only copy on success — on failure the caller's buffer
    // is left untouched (matches kernel behaviour) and rcx
    // may legitimately be a probe pointer.
    s.extend_from_slice(&[0x85, 0xC0]);                   // test eax,eax
    let jnz_off = s.len();
    s.extend_from_slice(&[0x75, 0x00]);                   // jnz skip (patched below)
    let copy_start = s.len();
    for i in 0..out_qwords {
        let src = crate::ipc::ATTR_OFF as u32 + i * 8;
        // mov rax, [r10 + src]   (disp32: ATTR_OFF >= 0x90 > 0x7F)
        s.extend_from_slice(&[0x49, 0x8B, 0x82]);
        s.extend_from_slice(&src.to_le_bytes());
        // mov [rcx + i*8], rax   (disp8: i*8 ≤ 0x30)
        if i == 0 {
            s.extend_from_slice(&[0x48, 0x89, 0x01]);
        } else {
            s.extend_from_slice(&[0x48, 0x89, 0x41, (i * 8) as u8]);
        }
    }
    let copy_len = s.len() - copy_start;
    s[jnz_off + 1] = copy_len as u8;
    // skip: copy clobbered rax; reload r_status.
    s.extend_from_slice(&[0x41, 0x8B, 0x82, 0x80, 0x00, 0x00, 0x00]);
    emit_release_keep_eax(&mut s, e);
    s.push(0xC3);
    s
}

// ─── Remote-memory helpers (lifted from PoC P6) ────────────────────

const ABS_JMP_LEN: usize = 12;
fn enc_abs_jmp(target: usize) -> Vec<u8> {
    let mut s = Vec::with_capacity(12);
    s.extend_from_slice(&[0x48, 0xB8]);
    s.extend_from_slice(&(target as u64).to_le_bytes());
    s.extend_from_slice(&[0xFF, 0xE0]);
    s
}

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

fn write_remote_bytes(proc: HANDLE, addr: usize, data: &[u8]) -> Result<()> {
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
        let p = VirtualAllocEx(proc, None, data.len().max(4096),
                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if p.is_null() { bail!("VirtualAllocEx: {:?}", GetLastError()); }
        let mut n = 0usize;
        WriteProcessMemory(proc, p, data.as_ptr() as *const c_void,
                           data.len(), Some(&mut n))?;
        let mut old = PAGE_PROTECTION_FLAGS(0);
        VirtualProtectEx(proc, p, data.len().max(4096), PAGE_EXECUTE_READ, &mut old)?;
        Ok(p as usize)
    }
}

/// Read a `T` from `addr` in `proc`. Used by the broker IPC handler
/// to chase `RTL_USER_PROCESS_PARAMETERS→CommandLine` in the target.
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

use std::mem::size_of;
