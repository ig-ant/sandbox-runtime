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
    CdylibHookEntries, PassthroughThunks, TracePassthroughs,
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

/// Phase K: install the 12 trace hooks. Resolves each `Nt*` export
/// from ntdll, builds a passthrough thunk (32-byte snapshot + tail-
/// call to the un-hooked syscall), and patches in an ABS_JMP to the
/// matching `hook_*_trace` cdylib export.
///
/// Failures partway through are non-fatal *for the trace surface* —
/// we log and continue so a missing export on an older Windows
/// build doesn't kill the whole trace install. The thunk slot stays
/// zero, the cdylib's `hook_*_trace` for that syscall returns
/// STATUS_NOT_IMPLEMENTED if invoked, but since we also skipped the
/// patch the kernel runs the syscall normally.
pub fn install_trace(
    target: HANDLE,
    trace_hook_vas: &[usize; crate::ipc::TRACE_SYSCALL_COUNT],
    out_pt: &mut TracePassthroughs,
) -> Result<()> {
    for (i, &name) in crate::ipc::TRACE_SYSCALL_NAMES.iter().enumerate() {
        let dest = trace_hook_vas[i];
        if dest == 0 {
            eprintln!("[sbox-exec] interception(trace): cdylib export missing for {name}; skip");
            continue;
        }
        let va = match ntdll_export(name) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[sbox-exec] interception(trace): ntdll!{name} unresolved ({e:#}); skip");
                continue;
            }
        };
        let thunk_va = match build_passthrough_thunk(target, va) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("[sbox-exec] interception(trace): {name} thunk build failed ({e:#}); skip");
                continue;
            }
        };
        out_pt.thunks[i] = thunk_va;
        if let Err(e) = patch_with_abs_jmp(target, name, va, dest) {
            eprintln!("[sbox-exec] interception(trace): {name} patch failed ({e:#}); skip");
            // Roll back the thunk slot so the cdylib doesn't think a
            // (now-uninstalled) hook has a passthrough.
            out_pt.thunks[i] = 0;
        }
    }
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

// ─── ABS_JMP template (Phase I) ────────────────────────────────────
//
// Phase I rationale: the patched-in 12-byte sequence used to be
// hand-encoded as `Vec::extend_from_slice(&[0x48, 0xB8, …, 0xFF, 0xE0])`,
// which hides the actual instructions behind their opcode bytes. Per
// the user's standing directive, any assembly we emit should live in
// `asm!` / `global_asm!` form so the toolchain checks it semantically.
//
// We declare a `global_asm!` template containing the exact two
// instructions we want patched in (`movabs rax, imm64; jmp rax`) and
// expose its start/end as `extern "C"` symbols. `enc_abs_jmp` then:
//   1. Computes the template length from `end - start` (asserted
//      against `ABS_JMP_LEN` to catch toolchain drift).
//   2. Copies the template bytes verbatim.
//   3. Patches the imm64 at the known offset (after the REX.W + opcode
//      prefix = 2 bytes).
//
// The runtime byte-patch step is unavoidable: we are constructing
// code for *another* process at a target VA we won't know until
// installation time. The win is that the source for the instruction
// shape now reads as assembly, not as hex.

core::arch::global_asm!(
    ".section .text",
    ".p2align 4",
    ".global abs_jmp_template_x64_start",
    ".global abs_jmp_template_x64_end",
    "abs_jmp_template_x64_start:",
    "    movabs rax, 0xCCCCCCCCCCCCCCCC", // imm64 patched at install time
    "    jmp rax",
    "abs_jmp_template_x64_end:",
);

extern "C" {
    static abs_jmp_template_x64_start: u8;
    static abs_jmp_template_x64_end: u8;
}

const ABS_JMP_LEN: usize = 12;

/// Offset of the imm64 inside the template:
///   byte 0: 0x48  (REX.W)
///   byte 1: 0xB8  (`mov rax, imm64` opcode)
///   bytes 2..10: imm64 (little-endian)
///   bytes 10..12: 0xFF 0xE0 (`jmp rax`)
const ABS_JMP_IMM_OFFSET: usize = 2;

fn enc_abs_jmp(target: usize) -> Vec<u8> {
    // SAFETY: `abs_jmp_template_x64_{start,end}` are linker-visible
    // labels emitted by the global_asm! block above. They live in the
    // `.text` section of *this* binary; we never execute through them
    // here — we just read them as bytes to copy into the remote process.
    let (start, end) = unsafe {
        (
            &abs_jmp_template_x64_start as *const u8,
            &abs_jmp_template_x64_end as *const u8,
        )
    };
    let len = unsafe { end.offset_from(start) as usize };
    debug_assert_eq!(
        len, ABS_JMP_LEN,
        "abs_jmp template length drift: expected {ABS_JMP_LEN} got {len}"
    );
    let mut v = unsafe { core::slice::from_raw_parts(start, len) }.to_vec();
    v[ABS_JMP_IMM_OFFSET..ABS_JMP_IMM_OFFSET + 8]
        .copy_from_slice(&(target as u64).to_le_bytes());
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip: `enc_abs_jmp(target)` should produce a 12-byte
    /// sequence whose bytes match the reference encoding
    /// `48 B8 <target_le8> FF E0`. This catches toolchain drift in
    /// either the template emission *or* the imm-patch offset.
    #[test]
    fn enc_abs_jmp_round_trip() {
        let target: usize = 0x1234_5678_9ABC_DEF0;
        let bytes = enc_abs_jmp(target);
        assert_eq!(bytes.len(), ABS_JMP_LEN);
        assert_eq!(&bytes[0..2], &[0x48, 0xB8]);
        assert_eq!(&bytes[2..10], &(target as u64).to_le_bytes());
        assert_eq!(&bytes[10..12], &[0xFF, 0xE0]);
    }

    /// Template length must match the install-time patch slot.
    /// Several broker call sites assume exactly 12 bytes are written
    /// (`patch_with_abs_jmp` pads up to `ABS_JMP_LEN` with NOPs); the
    /// passthrough thunk likewise snapshots 32 bytes specifically
    /// because the patch will only overwrite the first 12.
    #[test]
    fn abs_jmp_template_len_matches_constant() {
        let (start, end) = unsafe {
            (
                &abs_jmp_template_x64_start as *const u8,
                &abs_jmp_template_x64_end as *const u8,
            )
        };
        let len = unsafe { end.offset_from(start) as usize };
        assert_eq!(len, ABS_JMP_LEN);
    }
}
