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

use crate::ipc::Channel;
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
pub fn install(_target: HANDLE, _ch: &Channel, _cpw: usize) -> Result<()> {
    bail!("interception: x86_64 only in this build");
}

/// Patch `kernelbase!CreateProcessInternalW` (at `cpw_va`) in
/// `target` with an absolute jmp to a freshly-allocated stub.
#[cfg(target_arch = "x86_64")]
pub fn install(target: HANDLE, ch: &Channel, cpw_va: usize) -> Result<()> {
    let nt_set_event = ntdll_export("NtSetEvent")?;
    let nt_wait = ntdll_export("NtWaitForSingleObject")?;

    let stub = emit_stub(ch.target_view, ch.t_ev_req, ch.t_ev_resp,
                         nt_set_event, nt_wait);
    let stub_va = alloc_remote_rx(target, &stub)?;

    // The stub never tail-calls the original, so the overwritten
    // prologue bytes are never executed.
    let mut patch = enc_abs_jmp(stub_va);
    while patch.len() < ABS_JMP_LEN { patch.push(0x90); }
    write_remote_bytes(target, cpw_va, &patch)?;
    eprintln!(
        "[sbox-exec] interception: CreateProcessInternalW @ {:#x} → stub @ {:#x} (section @ {:#x})",
        cpw_va, stub_va, ch.target_view,
    );
    Ok(())
}

// ─── x64 stub emitter ──────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
fn emit_stub(
    section: usize, ev_req: u64, ev_resp: u64,
    nt_set_event: usize, nt_wait: usize,
) -> Vec<u8> {
    // r10 = section base.
    // Phase A: spill rcx,rdx,r8,r9 + [rsp+0x28..0x60] (8 stack args)
    //          to section[0..0x60].
    // Phase B: sub rsp,0x28; NtSetEvent(ev_req,0);
    //          NtWaitForSingleObject(ev_resp,0,0); add rsp,0x28.
    // Phase C: reload r10; rcx = saved lpProcessInformation
    //          (args[10] @ section+0x50); write
    //          {hProcess,hThread,dwProcessId,dwThreadId}; rcx =
    //          saved phRestrictedToken (args[11] @ +0x58), if
    //          non-null write 0; TEB→LastErrorValue = out_error;
    //          eax = out_result; ret.
    let mut s = Vec::<u8>::with_capacity(320);
    let mov_r10_imm = |s: &mut Vec<u8>, v: u64| {
        s.extend_from_slice(&[0x49, 0xBA]); s.extend_from_slice(&v.to_le_bytes());
    };
    let mov_rax_imm = |s: &mut Vec<u8>, v: u64| {
        s.extend_from_slice(&[0x48, 0xB8]); s.extend_from_slice(&v.to_le_bytes());
    };
    let mov_rcx_imm = |s: &mut Vec<u8>, v: u64| {
        s.extend_from_slice(&[0x48, 0xB9]); s.extend_from_slice(&v.to_le_bytes());
    };

    // ── Phase A
    mov_r10_imm(&mut s, section as u64);
    s.extend_from_slice(&[0x49, 0x89, 0x4A, 0x00]); // [r10+0]=rcx
    s.extend_from_slice(&[0x49, 0x89, 0x52, 0x08]); // [r10+8]=rdx
    s.extend_from_slice(&[0x4D, 0x89, 0x42, 0x10]); // [r10+0x10]=r8
    s.extend_from_slice(&[0x4D, 0x89, 0x4A, 0x18]); // [r10+0x18]=r9
    // stack args 5..12 at [rsp+0x28..0x60]
    for (i, off) in (0x28u8..=0x60).step_by(8).enumerate() {
        s.extend_from_slice(&[0x48, 0x8B, 0x44, 0x24, off]);          // mov rax,[rsp+off]
        s.extend_from_slice(&[0x49, 0x89, 0x42, (0x20 + i * 8) as u8]); // mov [r10+d],rax
    }

    // ── Phase B
    s.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);   // sub rsp,0x28
    mov_rcx_imm(&mut s, ev_req);
    s.extend_from_slice(&[0x31, 0xD2]);               // xor edx,edx
    mov_rax_imm(&mut s, nt_set_event as u64);
    s.extend_from_slice(&[0xFF, 0xD0]);               // call rax
    mov_rcx_imm(&mut s, ev_resp);
    s.extend_from_slice(&[0x31, 0xD2]);               // xor edx,edx
    s.extend_from_slice(&[0x4D, 0x31, 0xC0]);         // xor r8,r8
    mov_rax_imm(&mut s, nt_wait as u64);
    s.extend_from_slice(&[0xFF, 0xD0]);               // call rax
    s.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]);   // add rsp,0x28

    // ── Phase C
    mov_r10_imm(&mut s, section as u64);
    // rcx = [r10+0x50] (saved lpProcessInformation)
    s.extend_from_slice(&[0x49, 0x8B, 0x4A, 0x50]);
    // test rcx,rcx; jz skip_pi (+0x1D = 29 bytes of writes below)
    s.extend_from_slice(&[0x48, 0x85, 0xC9, 0x74, 0x1D]);
    //   [rcx+0]  = [r10+0x60] (hProcess)
    s.extend_from_slice(&[0x49, 0x8B, 0x42, 0x60, 0x48, 0x89, 0x01]);
    //   [rcx+8]  = [r10+0x68] (hThread)
    s.extend_from_slice(&[0x49, 0x8B, 0x42, 0x68, 0x48, 0x89, 0x41, 0x08]);
    //   [rcx+0x10] = dword [r10+0x70] (dwProcessId)
    s.extend_from_slice(&[0x41, 0x8B, 0x42, 0x70, 0x89, 0x41, 0x10]);
    //   [rcx+0x14] = dword [r10+0x74] (dwThreadId)
    s.extend_from_slice(&[0x41, 0x8B, 0x42, 0x74, 0x89, 0x41, 0x14]);
    // skip_pi:
    // rcx = [r10+0x58] (saved phRestrictedToken)
    s.extend_from_slice(&[0x49, 0x8B, 0x4A, 0x58]);
    // test rcx,rcx; jz skip_rt
    s.extend_from_slice(&[0x48, 0x85, 0xC9, 0x74, 0x07]);
    //   xor rax,rax; [rcx]=rax
    s.extend_from_slice(&[0x48, 0x31, 0xC0, 0x48, 0x89, 0x01, 0x90]);
    // skip_rt:
    // TEB→LastErrorValue (gs:[0x68]) = [r10+0x7c]
    s.extend_from_slice(&[0x41, 0x8B, 0x42, 0x7C]);                  // mov eax,[r10+0x7c]
    s.extend_from_slice(&[0x65, 0x89, 0x04, 0x25, 0x68, 0x00, 0x00, 0x00]); // mov gs:[0x68],eax
    // eax = [r10+0x78] (BOOL)
    s.extend_from_slice(&[0x41, 0x8B, 0x42, 0x78]);
    s.push(0xC3); // ret

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
