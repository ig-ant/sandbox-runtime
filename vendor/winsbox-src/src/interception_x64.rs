//! x86_64 thunk emitter (slim).
//!
//! Phase D-4 dropped the legacy inline-asm IPC stub emitters
//! (`emit_fs_stub`, `emit_handle_stub`, `emit_attr_stub`) along with
//! the FS/Reg/Attr broker hooks they fed. What remains is a single
//! shape: a 12-byte `mov rax, <cdylib_export>; jmp rax` tail-call
//! that replaces the first 12 bytes of the patched function. The
//! cdylib's exported `hook_*` function runs the IPC + reply demux
//! in safe Rust under the standard Win64 ABI; the broker's only
//! per-hook bookkeeping is the saved-original "passthrough thunk"
//! the cdylib calls when it wants the kernel to handle the open.

use anyhow::Result;
use windows::Win32::Foundation::HANDLE;

use crate::interception::{
    alloc_remote_rx, ntdll_export, read_remote_bytes, write_remote_bytes,
    CdylibHookEntries, PassthroughThunks,
};
use crate::ipc::StubAddrs;

/// Phase E-5b: build a "saved-original" passthrough thunk for the
/// syscall stub at `va`. Snapshots 32 bytes verbatim — the entire
/// syscall stub including the trailing `ret`. The cdylib calls this
/// thunk on `FS_PASSTHROUGH` so the kernel handles the open under
/// the target's own token.
///
/// 32 bytes covers the standard ntdll syscall layout
/// (`mov r10,rcx; mov eax,ssn; test [...], 1; jne alt; syscall; ret;
/// int 2e; ret`). All addressing inside is absolute (`ds:0x7ffe0308`)
/// or RIP-relative within the saved region (`jne` to an offset within
/// the same 32 bytes). Copying verbatim is safe.
///
/// Must be called *before* `patch_with_abs_jmp` overwrites the first
/// 12 bytes — otherwise we'd snapshot our own patch.
fn build_passthrough_thunk(target: HANDLE, va: usize) -> Result<usize> {
    let mut orig = [0u8; 32];
    read_remote_bytes(target, va, &mut orig)?;
    alloc_remote_rx(target, &orig)
}

// ─── Public install API (called from interception.rs façade) ───────

pub fn install_fs(
    target: HANDLE, _a: &StubAddrs, cdylib: Option<&CdylibHookEntries>,
    pt: &mut PassthroughThunks,
) -> Result<()> {
    // D-4: only NtCreateNamedPipeFile remains here. NtCreateFile /
    // NtOpenFile / NtQuery*AttributesFile no longer have hooks —
    // ACL stamps own FS policy.
    let Some(c) = cdylib.filter(|c| c.nt_create_named_pipe_file != 0) else {
        return Ok(());
    };
    let pipe_va = ntdll_export("NtCreateNamedPipeFile")?;
    pt.nt_create_named_pipe_file = build_passthrough_thunk(target, pipe_va)?;
    patch_with_abs_jmp(target, "NtCreateNamedPipeFile",
                       pipe_va, c.nt_create_named_pipe_file)?;
    Ok(())
}

pub fn install_reg(
    target: HANDLE, _a: &StubAddrs, cdylib: Option<&CdylibHookEntries>,
    pt: &mut PassthroughThunks,
) -> Result<()> {
    // D-4: NtOpenKey / NtOpenKeyEx hooks dropped (registry policy
    // moves to ACL stamping). The 3 namespace hooks remain —
    // Cygwin's BNO + section bootstrap still need redirection.
    // Closures captured into an array slot must share a type; none
    // capture state, so coerce each to a `fn` pointer.
    let Some(c) = cdylib else { return Ok(()); };
    type GetVa = fn(&CdylibHookEntries) -> usize;
    type SetPt = fn(&mut PassthroughThunks, usize);
    for (name, get_va, set_pt) in [
        ("NtOpenSection",
         (|c: &CdylibHookEntries| c.nt_open_section) as GetVa,
         (|p: &mut PassthroughThunks, v| p.nt_open_section = v) as SetPt),
        ("NtCreateDirectoryObject",
         (|c: &CdylibHookEntries| c.nt_create_directory_object) as GetVa,
         (|p: &mut PassthroughThunks, v| p.nt_create_directory_object = v) as SetPt),
        ("NtOpenDirectoryObject",
         (|c: &CdylibHookEntries| c.nt_open_directory_object) as GetVa,
         (|p: &mut PassthroughThunks, v| p.nt_open_directory_object = v) as SetPt),
    ] {
        if get_va(c) == 0 { continue; }
        let va = ntdll_export(name)?;
        let thunk_va = build_passthrough_thunk(target, va)?;
        set_pt(pt, thunk_va);
        patch_with_abs_jmp(target, name, va, get_va(c))?;
    }
    Ok(())
}

pub fn install_cpw(
    target: HANDLE, _a: &StubAddrs, cpw_va: usize,
    cdylib: Option<&CdylibHookEntries>,
    pt: &mut PassthroughThunks,
) -> Result<()> {
    let Some(c) = cdylib.filter(|c| c.create_process_internal_w != 0) else {
        anyhow::bail!("install_cpw: no cdylib entry available");
    };
    pt.create_process_internal_w = build_passthrough_thunk(target, cpw_va)?;
    patch_with_abs_jmp(target, "CreateProcessInternalW", cpw_va,
                       c.create_process_internal_w)?;
    Ok(())
}

// ─── Patch primitive ───────────────────────────────────────────────

/// Slim dispatcher path: write a 12-byte ABS_JMP directly to the
/// cdylib's hook export. The cdylib follows the same Win64 ABI as
/// the patched function so no intermediate stub is needed.
fn patch_with_abs_jmp(target: HANDLE, name: &str, va: usize, dest: usize) -> Result<()> {
    let mut patch = enc_abs_jmp(dest);
    while patch.len() < ABS_JMP_LEN { patch.push(0x90); }
    write_remote_bytes(target, va, &patch)?;
    eprintln!("[sbox-exec] interception: {name} @ {va:#x} → cdylib @ {dest:#x} (slim)");
    Ok(())
}

const ABS_JMP_LEN: usize = 12;
fn enc_abs_jmp(target: usize) -> Vec<u8> {
    let mut s = Vec::with_capacity(12);
    s.extend_from_slice(&[0x48, 0xB8]);
    s.extend_from_slice(&(target as u64).to_le_bytes());
    s.extend_from_slice(&[0xFF, 0xE0]);
    s
}
