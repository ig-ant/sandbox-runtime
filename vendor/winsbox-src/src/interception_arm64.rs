//! ARM64 thunk emitter. ARM64 instructions are fixed 32-bit.
//!
//! On ARM64 we patch the syscall stub with a 16-byte
//!   `LDR x16, .+8 ; BR x16 ; <8-byte target VA>`
//! sequence. Encoded:
//!   LDR x16, [PC + #8]  (PC-relative literal, opcode 0x58000050)
//!   BR x16              (branch to address in x16, opcode 0xD61F0200)
//!   <addr lo dword>
//!   <addr hi dword>
//!
//! The cdylib hook export is reachable from any address via this
//! literal-load + branch dance — no ±128 MB BL range concern.
//!
//! The legacy inline-asm IPC stub (FS/Reg/Attr) is **not** ported to
//! ARM64. Phase D removes those hooks wholesale; until then, a Phase-C
//! cdylib-only ARM64 build skips the FS/Reg/Attr install steps. The
//! function signature accepts a `cdylib` argument that, when populated,
//! installs the 5 compat hooks via the slim dispatcher path.

use anyhow::{bail, Result};
use windows::Win32::Foundation::HANDLE;

use crate::interception::{
    alloc_remote_rx, ntdll_export, read_remote_bytes, write_remote_bytes,
    CdylibHookEntries, PassthroughThunks,
};
use crate::ipc::StubAddrs;

/// Phase E-5b: build a "saved-original" passthrough thunk for the
/// syscall stub at `va`. Snapshots 32 bytes verbatim — covers the
/// `svc #X; ret` syscall plus a buffer for any prologue. The saved
/// `ret` returns to the cdylib's caller; no jump-back needed.
///
/// 32 bytes is well past any actual syscall stub on ARM64
/// (typically `svc; ret` = 8 bytes; some have a `paciasp` prologue
/// which adds 4 more). All ARM64 instructions are 4-byte aligned and
/// position-independent (PC-relative branches/loads); copying verbatim
/// is safe as long as no branch targets memory outside the snapshot.
/// The standard ntdll syscall layout is fully self-contained.
///
/// Must be called *before* `patch_with_abs_jmp` overwrites the first
/// 16 bytes — otherwise we'd snapshot our own patch.
fn build_passthrough_thunk(target: HANDLE, va: usize) -> Result<usize> {
    let mut orig = [0u8; 32];
    read_remote_bytes(target, va, &mut orig)?;
    alloc_remote_rx(target, &orig)
}

pub fn install_fs(
    target: HANDLE, _a: &StubAddrs, cdylib: Option<&CdylibHookEntries>,
    pt: &mut PassthroughThunks,
) -> Result<()> {
    // ARM64 path: only the compat NtCreateNamedPipeFile hook survives
    // here, dispatched into the cdylib. The other FS hooks
    // (NtCreateFile/NtOpenFile/NtQuery*Attr) require the legacy inline
    // IPC stub which we don't port to ARM64; they'll go away in Phase D.
    let Some(c) = cdylib else {
        // No-op on ARM64 without a cdylib: launch.rs's broker_fs/lockdown
        // paths haven't been exercised on ARM64 yet, so skipping FS hooks
        // is acceptable for the Phase-C scope.
        return Ok(());
    };
    if c.nt_create_named_pipe_file != 0 {
        let va = ntdll_export("NtCreateNamedPipeFile")?;
        pt.nt_create_named_pipe_file = build_passthrough_thunk(target, va)?;
        patch_with_abs_jmp(target, "NtCreateNamedPipeFile", va,
                           c.nt_create_named_pipe_file)?;
    }
    Ok(())
}

pub fn install_reg(
    target: HANDLE, _a: &StubAddrs, cdylib: Option<&CdylibHookEntries>,
    pt: &mut PassthroughThunks,
) -> Result<()> {
    let Some(c) = cdylib else { return Ok(()); };
    if c.nt_open_section != 0 {
        let va = ntdll_export("NtOpenSection")?;
        pt.nt_open_section = build_passthrough_thunk(target, va)?;
        patch_with_abs_jmp(target, "NtOpenSection", va, c.nt_open_section)?;
    }
    if c.nt_create_directory_object != 0 {
        let va = ntdll_export("NtCreateDirectoryObject")?;
        pt.nt_create_directory_object = build_passthrough_thunk(target, va)?;
        patch_with_abs_jmp(target, "NtCreateDirectoryObject", va,
                           c.nt_create_directory_object)?;
    }
    if c.nt_open_directory_object != 0 {
        let va = ntdll_export("NtOpenDirectoryObject")?;
        pt.nt_open_directory_object = build_passthrough_thunk(target, va)?;
        patch_with_abs_jmp(target, "NtOpenDirectoryObject", va,
                           c.nt_open_directory_object)?;
    }
    Ok(())
}

pub fn install_cpw(
    target: HANDLE, _a: &StubAddrs, cpw_va: usize,
    cdylib: Option<&CdylibHookEntries>,
    pt: &mut PassthroughThunks,
) -> Result<()> {
    let Some(c) = cdylib.filter(|c| c.create_process_internal_w != 0) else {
        bail!("ARM64 install_cpw: no cdylib entry available");
    };
    pt.create_process_internal_w = build_passthrough_thunk(target, cpw_va)?;
    patch_with_abs_jmp(target, "CreateProcessInternalW", cpw_va,
                       c.create_process_internal_w)?;
    Ok(())
}

// ─── Patch primitive ───────────────────────────────────────────────

pub const ABS_JMP_LEN: usize = 16;

/// Encode the ARM64 16-byte absolute-jump:
///   00: 50 00 00 58   LDR  X16, .+8
///   04: 00 02 1F D6   BR   X16
///   08: <target-VA[31:0]>
///   0C: <target-VA[63:32]>
pub fn enc_abs_jmp(target: usize) -> [u8; ABS_JMP_LEN] {
    let mut out = [0u8; ABS_JMP_LEN];
    // LDR X16, [PC, #8] — opcode 0x58000050 (little-endian)
    out[0..4].copy_from_slice(&0x58000050u32.to_le_bytes());
    // BR X16 — opcode 0xD61F0200 (little-endian)
    out[4..8].copy_from_slice(&0xD61F0200u32.to_le_bytes());
    out[8..16].copy_from_slice(&(target as u64).to_le_bytes());
    out
}

fn patch_with_abs_jmp(target: HANDLE, name: &str, va: usize, dest: usize) -> Result<()> {
    let patch = enc_abs_jmp(dest);
    write_remote_bytes(target, va, &patch)?;
    eprintln!("[sbox-exec] interception(arm64): {name} @ {va:#x} → cdylib @ {dest:#x}");
    Ok(())
}
