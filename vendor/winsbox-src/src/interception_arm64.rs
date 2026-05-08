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

// ─── Patch primitive + ABS_JMP template (Phase I) ─────────────────
//
// Phase I rationale (mirrors interception_x64.rs): the patched-in
// 16-byte sequence used to be hand-encoded as four little-endian u32s
// of opcode bits, hiding the actual instructions. We now emit the
// instructions via `global_asm!` and copy from the resulting template,
// patching the embedded literal at install time.
//
// The shape is the standard ARM64 "absolute jump via literal":
//   LDR X16, target_literal   — load the 8-byte target VA into X16
//   BR  X16                   — branch (no link) to the address in X16
//   target_literal:
//     .quad 0xCC..CC          — the literal, patched at install time
//
// All ARM64 instructions are 4-byte fixed-width and position-
// independent (PC-relative literal load + register-indirect branch),
// so the template is freely relocatable: we copy it to any VA in the
// remote process and it still works. The runtime byte-patch step
// fills in the .quad with the actual hook target.

core::arch::global_asm!(
    ".section .text",
    ".p2align 4",
    ".global abs_jmp_template_arm64_start",
    ".global abs_jmp_template_arm64_end",
    "abs_jmp_template_arm64_start:",
    "    ldr x16, abs_jmp_template_arm64_literal",
    "    br  x16",
    "abs_jmp_template_arm64_literal:",
    "    .quad 0xCCCCCCCCCCCCCCCC", // patched at install time
    "abs_jmp_template_arm64_end:",
);

extern "C" {
    static abs_jmp_template_arm64_start: u8;
    static abs_jmp_template_arm64_end: u8;
}

pub const ABS_JMP_LEN: usize = 16;

/// Offset of the embedded literal inside the template:
///   bytes 0..4:  LDR X16, target_literal  (PC+8 in this layout)
///   bytes 4..8:  BR X16
///   bytes 8..16: .quad <target VA>        (← patched here)
const ABS_JMP_LITERAL_OFFSET: usize = 8;

/// Encode the ARM64 16-byte absolute-jump:
///   00: LDR X16, .+8       (PC-relative literal load)
///   04: BR  X16             (branch to address in X16)
///   08..10: <target VA, little-endian>
///
/// Returns a fixed-size array because every caller writes exactly
/// `ABS_JMP_LEN` bytes; no NOP-padding pass is needed.
pub fn enc_abs_jmp(target: usize) -> [u8; ABS_JMP_LEN] {
    // SAFETY: `abs_jmp_template_arm64_{start,end}` are linker-visible
    // labels emitted by the global_asm! block above. We only read
    // their byte representation here.
    let (start, end) = unsafe {
        (
            &abs_jmp_template_arm64_start as *const u8,
            &abs_jmp_template_arm64_end as *const u8,
        )
    };
    let len = unsafe { end.offset_from(start) as usize };
    debug_assert_eq!(
        len, ABS_JMP_LEN,
        "abs_jmp template length drift: expected {ABS_JMP_LEN} got {len}"
    );
    let mut out = [0u8; ABS_JMP_LEN];
    out.copy_from_slice(unsafe { core::slice::from_raw_parts(start, ABS_JMP_LEN) });
    out[ABS_JMP_LITERAL_OFFSET..ABS_JMP_LITERAL_OFFSET + 8]
        .copy_from_slice(&(target as u64).to_le_bytes());
    out
}

fn patch_with_abs_jmp(target: HANDLE, name: &str, va: usize, dest: usize) -> Result<()> {
    let patch = enc_abs_jmp(dest);
    write_remote_bytes(target, va, &patch)?;
    eprintln!("[sbox-exec] interception(arm64): {name} @ {va:#x} → cdylib @ {dest:#x}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip: the encoded sequence must match the reference
    /// little-endian opcodes for `LDR X16, .+8` (`0x58000050`) and
    /// `BR X16` (`0xD61F0200`), with the target VA at offset 8.
    #[test]
    fn enc_abs_jmp_round_trip() {
        let target: usize = 0x1234_5678_9ABC_DEF0;
        let bytes = enc_abs_jmp(target);
        assert_eq!(bytes.len(), ABS_JMP_LEN);
        // LDR X16, [PC, #8]
        assert_eq!(&bytes[0..4], &0x58000050u32.to_le_bytes());
        // BR X16
        assert_eq!(&bytes[4..8], &0xD61F0200u32.to_le_bytes());
        // Embedded literal target VA
        assert_eq!(&bytes[8..16], &(target as u64).to_le_bytes());
    }

    /// Template length must match the install-time patch slot.
    /// `patch_with_abs_jmp` writes exactly `ABS_JMP_LEN` bytes;
    /// any toolchain drift here would either overrun or under-run
    /// the remote write.
    #[test]
    fn abs_jmp_template_len_matches_constant() {
        let (start, end) = unsafe {
            (
                &abs_jmp_template_arm64_start as *const u8,
                &abs_jmp_template_arm64_end as *const u8,
            )
        };
        let len = unsafe { end.offset_from(start) as usize };
        assert_eq!(len, ABS_JMP_LEN);
    }
}
