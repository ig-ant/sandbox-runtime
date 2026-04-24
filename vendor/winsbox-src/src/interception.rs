//! Inline-hook `ntdll!NtCreateUserProcess` in a suspended target so
//! the broker performs every spawn. The injected stub spills the 11
//! raw arguments into the IPC section, signals the broker, blocks
//! on the response, writes the broker's process/thread handles into
//! the caller's out-pointers, and returns the broker's NTSTATUS.
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
pub fn install(_target: HANDLE, _ch: &Channel) -> Result<()> {
    bail!("interception: x86_64 only in this build");
}

#[cfg(target_arch = "x86_64")]
pub fn install(target: HANDLE, ch: &Channel) -> Result<()> {
    let nt_cup = ntdll_export("NtCreateUserProcess")?;
    let nt_set_event = ntdll_export("NtSetEvent")?;
    let nt_wait = ntdll_export("NtWaitForSingleObject")?;

    let stub = emit_stub(ch.target_view, ch.t_ev_req, ch.t_ev_resp,
                         nt_set_event, nt_wait);
    let stub_va = alloc_remote_rx(target, &stub)?;

    // Patch the export prologue with an absolute jmp to the stub.
    // ntdll syscall stubs are tiny and the patched bytes are never
    // re-executed — the stub returns directly to the caller.
    let mut patch = enc_abs_jmp(stub_va);
    while patch.len() < ABS_JMP_LEN { patch.push(0x90); }
    write_remote_bytes(target, nt_cup, &patch)?;
    eprintln!(
        "[sbox-exec] interception: NtCreateUserProcess @ {:#x} → stub @ {:#x} (section @ {:#x})",
        nt_cup, stub_va, ch.target_view,
    );
    Ok(())
}

// ─── x64 stub emitter ──────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
fn emit_stub(
    section: usize, ev_req: u64, ev_resp: u64,
    nt_set_event: usize, nt_wait: usize,
) -> Vec<u8> {
    // r10 = section base (volatile, not an arg register).
    // Phase A: spill rcx,rdx,r8,r9 + stack args [rsp+0x28..0x58] to
    //          section[0..0x58]. rsp is unmodified at this point so
    //          the caller's stack-arg offsets are intact.
    // Phase B: sub rsp,0x28; NtSetEvent(ev_req,0);
    //          NtWaitForSingleObject(ev_resp,0,0); add rsp,0x28.
    // Phase C: reload r10; *[section+0]=out_process → write to *rcx
    //          (saved at section[0]); same for thread; eax=status; ret.
    let mut s = Vec::<u8>::with_capacity(256);
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
    // mov [r10+disp8], reg
    s.extend_from_slice(&[0x49, 0x89, 0x4A, 0x00]); // [r10+0]=rcx
    s.extend_from_slice(&[0x49, 0x89, 0x52, 0x08]); // [r10+8]=rdx
    s.extend_from_slice(&[0x4D, 0x89, 0x42, 0x10]); // [r10+0x10]=r8
    s.extend_from_slice(&[0x4D, 0x89, 0x4A, 0x18]); // [r10+0x18]=r9
    // stack args 5..11 at [rsp+0x28..0x58]
    for (i, off) in (0x28u8..=0x58).step_by(8).enumerate() {
        // mov rax, [rsp+off]
        s.extend_from_slice(&[0x48, 0x8B, 0x44, 0x24, off]);
        // mov [r10+(0x20+i*8)], rax
        s.extend_from_slice(&[0x49, 0x89, 0x42, (0x20 + i * 8) as u8]);
    }

    // ── Phase B
    s.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);   // sub rsp,0x28
    // NtSetEvent(ev_req, NULL)
    mov_rcx_imm(&mut s, ev_req);
    s.extend_from_slice(&[0x31, 0xD2]);               // xor edx,edx
    mov_rax_imm(&mut s, nt_set_event as u64);
    s.extend_from_slice(&[0xFF, 0xD0]);               // call rax
    // NtWaitForSingleObject(ev_resp, FALSE, NULL)
    mov_rcx_imm(&mut s, ev_resp);
    s.extend_from_slice(&[0x31, 0xD2]);               // xor edx,edx
    s.extend_from_slice(&[0x4D, 0x31, 0xC0]);         // xor r8,r8
    mov_rax_imm(&mut s, nt_wait as u64);
    s.extend_from_slice(&[0xFF, 0xD0]);               // call rax
    s.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]);   // add rsp,0x28

    // ── Phase C
    mov_r10_imm(&mut s, section as u64);
    // rcx = [r10+0] (orig PHANDLE Process); rax = [r10+0x60]; [rcx]=rax
    s.extend_from_slice(&[0x49, 0x8B, 0x4A, 0x00]);
    s.extend_from_slice(&[0x49, 0x8B, 0x42, 0x60]);
    s.extend_from_slice(&[0x48, 0x89, 0x01]);
    // rcx = [r10+8] (orig PHANDLE Thread); rax = [r10+0x68]; [rcx]=rax
    s.extend_from_slice(&[0x49, 0x8B, 0x4A, 0x08]);
    s.extend_from_slice(&[0x49, 0x8B, 0x42, 0x68]);
    s.extend_from_slice(&[0x48, 0x89, 0x01]);
    // eax = [r10+0x70]
    s.extend_from_slice(&[0x41, 0x8B, 0x42, 0x70]);
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

fn ntdll_export(name: &str) -> Result<usize> {
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

fn alloc_remote_rx(proc: HANDLE, data: &[u8]) -> Result<usize> {
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
