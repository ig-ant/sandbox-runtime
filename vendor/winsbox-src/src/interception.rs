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
        ev_req: a.ev_req, ev_resp: a.ev_resp,
        nt_set_event: ntdll_export("NtSetEvent")? as u64,
        nt_wait: ntdll_export("NtWaitForSingleObject")? as u64,
    })
}

/// Patch `ntdll!{NtCreateFile,NtOpenFile}` in `target`. Installed
/// post-rendezvous (after the loader has run) so the loader's
/// own opens — which include object-directory-relative ones the
/// broker can't resolve — go through unhooked under the initial
/// impersonation token. Loader-time read access to the exe's
/// own DLL directory is granted by a per-spawn ACL in
/// `broker_spawn` instead.
#[cfg(target_arch = "x86_64")]
pub fn install_fs(target: HANDLE, a: &StubAddrs) -> Result<()> {
    let env = stub_env(a)?;
    let ntcf = ntdll_export("NtCreateFile")?;
    let ntof = ntdll_export("NtOpenFile")?;
    patch_with_stub(target, "NtCreateFile", ntcf,
                    &emit_fs_stub(&env, crate::ipc::OP_NTCREATEFILE, 11))?;
    patch_with_stub(target, "NtOpenFile", ntof,
                    &emit_fs_stub(&env, crate::ipc::OP_NTOPENFILE, 6))?;
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
    section: u64, ev_req: u64, ev_resp: u64,
    nt_set_event: u64, nt_wait: u64,
}

/// Phase A (load r10=section; write op; spill `n_args` from
/// rcx,rdx,r8,r9,[rsp+0x28..]) + Phase B (signal req, wait resp)
/// + reload r10. The caller appends Phase C.
#[cfg(target_arch = "x86_64")]
fn emit_prologue(s: &mut Vec<u8>, e: &StubEnv, op: u64, n_args: usize) {
    // mov r10, section
    s.extend_from_slice(&[0x49, 0xBA]); s.extend_from_slice(&e.section.to_le_bytes());
    // mov rax, op; mov [r10+0], rax
    s.extend_from_slice(&[0x48, 0xB8]); s.extend_from_slice(&op.to_le_bytes());
    s.extend_from_slice(&[0x49, 0x89, 0x02]);
    // [r10+0x08]=rcx, +0x10=rdx, +0x18=r8, +0x20=r9
    s.extend_from_slice(&[0x49, 0x89, 0x4A, 0x08]);
    s.extend_from_slice(&[0x49, 0x89, 0x52, 0x10]);
    s.extend_from_slice(&[0x4D, 0x89, 0x42, 0x18]);
    s.extend_from_slice(&[0x4D, 0x89, 0x4A, 0x20]);
    // stack args 5..n at [rsp+0x28..]
    for i in 4..n_args {
        let sp_off = 0x28 + (i - 4) * 8;
        let dst = 0x08 + i * 8;
        s.extend_from_slice(&[0x48, 0x8B, 0x44, 0x24, sp_off as u8]); // mov rax,[rsp+off]
        s.extend_from_slice(&[0x49, 0x89, 0x42, dst as u8]);          // mov [r10+dst],rax
    }
    // ── Phase B
    s.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]); // sub rsp,0x28
    s.extend_from_slice(&[0x48, 0xB9]); s.extend_from_slice(&e.ev_req.to_le_bytes()); // mov rcx,ev_req
    s.extend_from_slice(&[0x31, 0xD2]); // xor edx,edx
    s.extend_from_slice(&[0x48, 0xB8]); s.extend_from_slice(&e.nt_set_event.to_le_bytes());
    s.extend_from_slice(&[0xFF, 0xD0]); // call rax
    s.extend_from_slice(&[0x48, 0xB9]); s.extend_from_slice(&e.ev_resp.to_le_bytes()); // mov rcx,ev_resp
    s.extend_from_slice(&[0x31, 0xD2]);
    s.extend_from_slice(&[0x4D, 0x31, 0xC0]); // xor r8,r8
    s.extend_from_slice(&[0x48, 0xB8]); s.extend_from_slice(&e.nt_wait.to_le_bytes());
    s.extend_from_slice(&[0xFF, 0xD0]);
    s.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]); // add rsp,0x28
    // reload r10 for Phase C
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
    s.push(0xC3);
    s
}

// FOLLOW-UP: a try-original-first stub (tail-call a saved copy of
// the syscall stub, only IPC on STATUS_ACCESS_DENIED) is the right
// architecture — it lets the loader's object-directory-relative
// opens and device opens succeed natively without the broker
// having to whitelist them, and cuts IPC volume. The hand-emitted
// version (14da6b9) AVs in-loader and needs WinDbg on a real box
// to root-cause; until then the FS hook is installed
// post-rendezvous and the loader's DLL-directory access is
// covered by a per-spawn ACL grant in `broker_spawn`.
#[cfg(target_arch = "x86_64")]
fn emit_fs_stub(e: &StubEnv, op: u64, n_args: usize) -> Vec<u8> {
    let mut s = Vec::<u8>::with_capacity(256);
    emit_prologue(&mut s, e, op, n_args);
    // ── Phase C (FS)
    // rcx = args[0] = PHANDLE FileHandle @ +0x08; *rcx = r0 @ +0x68
    s.extend_from_slice(&[0x49, 0x8B, 0x4A, 0x08]);
    s.extend_from_slice(&[0x49, 0x8B, 0x42, 0x68, 0x48, 0x89, 0x01]);
    // rcx = args[3] = PIO_STATUS_BLOCK @ +0x20
    s.extend_from_slice(&[0x49, 0x8B, 0x4A, 0x20]);
    s.extend_from_slice(&[0x48, 0x85, 0xC9, 0x74, 0x12]);             // jz +0x12
    //   [rcx+0] = sign-extended r_status @ +0x80 (iosb.Status)
    s.extend_from_slice(&[0x49, 0x63, 0x82, 0x80, 0x00, 0x00, 0x00]); // movsxd rax,[r10+0x80]
    s.extend_from_slice(&[0x48, 0x89, 0x01]);
    //   [rcx+8] = r1 @ +0x70 (iosb.Information)
    s.extend_from_slice(&[0x49, 0x8B, 0x42, 0x70, 0x48, 0x89, 0x41, 0x08]);
    // eax = r_status @ +0x80 (NTSTATUS)
    s.extend_from_slice(&[0x41, 0x8B, 0x82, 0x80, 0x00, 0x00, 0x00]);
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
