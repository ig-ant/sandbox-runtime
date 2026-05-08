//! x86_64 thunk emitter. Two stub shapes:
//!
//!   * **Inline-asm IPC stub** (`emit_fs_stub`, `emit_handle_stub`,
//!     `emit_attr_stub`): the legacy hooked-syscall body. Spills 4–11
//!     args into the broker IPC section, signals/waits on events, then
//!     copies broker reply back into out-params. Used for the FS / Reg
//!     / Attr hooks that still talk directly to the broker — these stay
//!     until Phase D.
//!
//!   * **Slim cdylib dispatcher** (`emit_cdylib_dispatch`): a 12-byte
//!     `mov rax, <cdylib_export>; jmp rax` tail-call. The cdylib's
//!     exported `hook_*` function runs the IPC + reply demux in safe
//!     Rust under the standard Win64 ABI. Used for the 5 Phase-C
//!     compat hooks.
//!
//! `patch_with_stub` is the install primitive: VirtualAllocEx the
//! stub bytes RX, then overwrite the 12-byte ABS_JMP at the
//! ntdll/kernelbase entry to jump to the stub. For the slim
//! dispatcher path we skip the intermediate stub allocation entirely
//! and write the 12-byte ABS_JMP straight to the cdylib export.

use anyhow::Result;
use windows::Win32::Foundation::HANDLE;

use crate::interception::{
    alloc_remote_rx, ntdll_export, read_remote_bytes, write_remote_bytes,
    CdylibHookEntries, PassthroughThunks,
};
use crate::ipc::StubAddrs;

/// Phase E-5b: build a "saved-original" passthrough thunk for the
/// syscall stub at `va`. Snapshots 32 bytes verbatim — the entire
/// syscall stub including the trailing `ret`. The legacy inline-asm
/// stub used the same trick: jump to the saved bytes, the saved
/// `syscall; ret` returns to the caller. No jump-back needed.
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
    target: HANDLE, a: &StubAddrs, cdylib: Option<&CdylibHookEntries>,
    pt: &mut PassthroughThunks,
) -> Result<()> {
    let env = stub_env(a)?;
    for (name, op, n_args) in [
        ("NtCreateFile",          crate::ipc::OP_NTCREATEFILE,      11usize),
        ("NtOpenFile",            crate::ipc::OP_NTOPENFILE,         6usize),
    ] {
        let va = ntdll_export(name)?;
        let mut orig = [0u8; 32];
        read_remote_bytes(target, va, &mut orig)?;
        let saved = alloc_remote_rx(target, &orig)?;
        patch_with_stub(target, name, va,
                        &emit_fs_stub(&env, op, n_args, saved as u64))?;
    }
    // NtCreateNamedPipeFile: Phase C dispatches into cdylib if
    // available; legacy inline IPC stub otherwise.
    let pipe_va = ntdll_export("NtCreateNamedPipeFile")?;
    if let Some(c) = cdylib.filter(|c| c.nt_create_named_pipe_file != 0) {
        // Phase E-5b: build passthrough thunk BEFORE patching so we
        // snapshot the original syscall bytes, not our ABS_JMP.
        pt.nt_create_named_pipe_file = build_passthrough_thunk(target, pipe_va)?;
        patch_with_abs_jmp(target, "NtCreateNamedPipeFile",
                           pipe_va, c.nt_create_named_pipe_file)?;
    } else {
        let mut orig = [0u8; 32];
        read_remote_bytes(target, pipe_va, &mut orig)?;
        let saved = alloc_remote_rx(target, &orig)?;
        patch_with_stub(target, "NtCreateNamedPipeFile", pipe_va,
                        &emit_fs_stub(&env, crate::ipc::OP_NTCREATENAMEDPIPE, 12, saved as u64))?;
    }
    for (name, op, out_qwords) in [
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

pub fn install_reg(
    target: HANDLE, a: &StubAddrs, cdylib: Option<&CdylibHookEntries>,
    pt: &mut PassthroughThunks,
) -> Result<()> {
    let env = stub_env(a)?;
    // Registry hooks: legacy inline IPC stub. Removed in Phase D.
    for (name, op, n_args) in [
        ("NtOpenKey",   crate::ipc::OP_NTOPENKEY,   3usize),
        ("NtOpenKeyEx", crate::ipc::OP_NTOPENKEYEX, 4usize),
    ] {
        let va = ntdll_export(name)?;
        let mut orig = [0u8; 32];
        read_remote_bytes(target, va, &mut orig)?;
        let saved = alloc_remote_rx(target, &orig)?;
        patch_with_stub(target, name, va,
                        &emit_handle_stub(&env, op, n_args, saved as u64))?;
    }
    // Compat hooks: Phase C dispatches into cdylib.
    // Closures captured into an array slot must share a type; none of
    // these capture anything, so coerce each to a `fn` pointer.
    type GetVa = fn(&CdylibHookEntries) -> usize;
    type SetPt = fn(&mut PassthroughThunks, usize);
    for (name, _op, get_va, set_pt) in [
        ("NtOpenSection",
         crate::ipc::OP_NTOPENSECTION,
         (|c: &CdylibHookEntries| c.nt_open_section) as GetVa,
         (|p: &mut PassthroughThunks, v| p.nt_open_section = v) as SetPt),
        ("NtCreateDirectoryObject",
         crate::ipc::OP_NTCREATEDIROBJ,
         (|c: &CdylibHookEntries| c.nt_create_directory_object) as GetVa,
         (|p: &mut PassthroughThunks, v| p.nt_create_directory_object = v) as SetPt),
        ("NtOpenDirectoryObject",
         crate::ipc::OP_NTOPENDIROBJ,
         (|c: &CdylibHookEntries| c.nt_open_directory_object) as GetVa,
         (|p: &mut PassthroughThunks, v| p.nt_open_directory_object = v) as SetPt),
    ] {
        let va = ntdll_export(name)?;
        if let Some(c) = cdylib.filter(|c| get_va(c) != 0) {
            // Phase E-5b: build passthrough BEFORE patching.
            let thunk_va = build_passthrough_thunk(target, va)?;
            set_pt(pt, thunk_va);
            patch_with_abs_jmp(target, name, va, get_va(c))?;
        } else {
            let mut orig = [0u8; 32];
            read_remote_bytes(target, va, &mut orig)?;
            let saved = alloc_remote_rx(target, &orig)?;
            patch_with_stub(target, name, va,
                            &emit_handle_stub(&env, _op, 3, saved as u64))?;
        }
    }
    Ok(())
}

pub fn install_cpw(
    target: HANDLE, a: &StubAddrs, cpw_va: usize,
    cdylib: Option<&CdylibHookEntries>,
    pt: &mut PassthroughThunks,
) -> Result<()> {
    if let Some(c) = cdylib.filter(|c| c.create_process_internal_w != 0) {
        // Phase E-5b: passthrough thunk for CPW. Built BEFORE patching.
        // CPW's first 12 bytes get overwritten by ABS_JMP — same shape
        // as the ntdll syscall stubs.
        pt.create_process_internal_w = build_passthrough_thunk(target, cpw_va)?;
        patch_with_abs_jmp(target, "CreateProcessInternalW", cpw_va,
                           c.create_process_internal_w)?;
    } else {
        let env = stub_env(a)?;
        patch_with_stub(target, "CreateProcessInternalW", cpw_va,
                        &emit_cpw_stub(&env))?;
    }
    Ok(())
}

// ─── Patch primitive ───────────────────────────────────────────────

fn patch_with_stub(target: HANDLE, name: &str, va: usize, stub: &[u8]) -> Result<()> {
    let stub_va = alloc_remote_rx(target, stub)?;
    let mut patch = enc_abs_jmp(stub_va);
    while patch.len() < ABS_JMP_LEN { patch.push(0x90); }
    write_remote_bytes(target, va, &patch)?;
    eprintln!("[sbox-exec] interception: {name} @ {va:#x} → stub @ {stub_va:#x}");
    Ok(())
}

/// Slim dispatcher path: write a 12-byte ABS_JMP directly to the
/// cdylib's hook export. Saves the intermediate stub allocation since
/// the cdylib follows the same Win64 ABI as the patched function.
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

// ─── Stub-emitter machinery (legacy FS/Reg/Attr) ───────────────────

struct StubEnv {
    section: u64, ev_req: u64, ev_resp: u64, mutex: u64,
    nt_set_event: u64, nt_wait: u64, nt_release_mutant: u64,
}

fn stub_env(a: &StubAddrs) -> Result<StubEnv> {
    Ok(StubEnv {
        section: a.section as u64,
        ev_req: a.ev_req, ev_resp: a.ev_resp, mutex: a.mutex,
        nt_set_event: ntdll_export("NtSetEvent")? as u64,
        nt_wait: ntdll_export("NtWaitForSingleObject")? as u64,
        nt_release_mutant: ntdll_export("NtReleaseMutant")? as u64,
    })
}

/// `NtReleaseMutant(mutex, NULL)` preserving eax across the
/// call. 34 bytes. r10 and rcx/rdx/r8/r9 are clobbered. Stack
/// alignment: stub entry is rsp%16==8; push rax → 0; sub 0x20
/// → 0; call sees aligned-then-pushed.
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
/// shadow space, and tail-jmp the saved original syscall stub.
fn emit_passthrough(s: &mut Vec<u8>, e: &StubEnv, saved_orig: u64) {
    s.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);  // sub rsp,0x28
    s.extend_from_slice(&[0x48, 0xB9]);              // mov rcx, mutex
    s.extend_from_slice(&e.mutex.to_le_bytes());
    s.extend_from_slice(&[0x31, 0xD2]);              // xor edx,edx
    s.extend_from_slice(&[0x48, 0xB8]);              // mov rax, NtReleaseMutant
    s.extend_from_slice(&e.nt_release_mutant.to_le_bytes());
    s.extend_from_slice(&[0xFF, 0xD0]);              // call rax
    s.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]);  // add rsp,0x28
    s.extend_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x08]); // mov rcx,[rsp+8]
    s.extend_from_slice(&[0x48, 0x8B, 0x54, 0x24, 0x10]); // mov rdx,[rsp+0x10]
    s.extend_from_slice(&[0x4C, 0x8B, 0x44, 0x24, 0x18]); // mov r8, [rsp+0x18]
    s.extend_from_slice(&[0x4C, 0x8B, 0x4C, 0x24, 0x20]); // mov r9, [rsp+0x20]
    s.extend_from_slice(&[0x48, 0xB8]);              // mov rax, saved_orig
    s.extend_from_slice(&saved_orig.to_le_bytes());
    s.extend_from_slice(&[0xFF, 0xE0]);              // jmp rax
}
const PASSTHROUGH_LEN: u8 = 64;

fn emit_prologue(s: &mut Vec<u8>, e: &StubEnv, op: u64, n_args: usize) {
    s.extend_from_slice(&[0x48, 0x89, 0x4C, 0x24, 0x08]); // [rsp+8]  = rcx
    s.extend_from_slice(&[0x48, 0x89, 0x54, 0x24, 0x10]); // [rsp+10] = rdx
    s.extend_from_slice(&[0x4C, 0x89, 0x44, 0x24, 0x18]); // [rsp+18] = r8
    s.extend_from_slice(&[0x4C, 0x89, 0x4C, 0x24, 0x20]); // [rsp+20] = r9
    s.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);       // sub rsp,0x28
    s.extend_from_slice(&[0x48, 0xB9]);                   // mov rcx, mutex
    s.extend_from_slice(&e.mutex.to_le_bytes());
    s.extend_from_slice(&[0x31, 0xD2]);                   // xor edx,edx
    s.extend_from_slice(&[0x45, 0x31, 0xC0]);             // xor r8d,r8d
    s.extend_from_slice(&[0x48, 0xB8]);                   // mov rax, NtWaitForSingleObject
    s.extend_from_slice(&e.nt_wait.to_le_bytes());
    s.extend_from_slice(&[0xFF, 0xD0]);                   // call rax
    s.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]);       // add rsp,0x28
    s.extend_from_slice(&[0x49, 0xBA]);                   // mov r10, section
    s.extend_from_slice(&e.section.to_le_bytes());
    s.extend_from_slice(&[0x48, 0xB8]); s.extend_from_slice(&op.to_le_bytes());
    s.extend_from_slice(&[0x49, 0x89, 0x02]);             // mov [r10], rax
    for (sp, dst) in [(0x08u8, 0x08u8), (0x10, 0x10), (0x18, 0x18), (0x20, 0x20)] {
        s.extend_from_slice(&[0x48, 0x8B, 0x44, 0x24, sp]);
        s.extend_from_slice(&[0x49, 0x89, 0x42, dst]);
    }
    for i in 4..n_args {
        let sp_off = 0x28 + (i - 4) * 8;
        let dst = 0x08 + i * 8;
        s.extend_from_slice(&[0x48, 0x8B, 0x44, 0x24, sp_off as u8]);
        s.extend_from_slice(&[0x49, 0x89, 0x42, dst as u8]);
    }
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
    s.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]);
    s.extend_from_slice(&[0x49, 0xBA]); s.extend_from_slice(&e.section.to_le_bytes());
}

fn emit_cpw_stub(e: &StubEnv) -> Vec<u8> {
    let mut s = Vec::<u8>::with_capacity(320);
    emit_prologue(&mut s, e, crate::ipc::OP_CPW, 12);
    s.extend_from_slice(&[0x49, 0x8B, 0x4A, 0x58]);
    s.extend_from_slice(&[0x48, 0x85, 0xC9, 0x74, 0x1D]);
    s.extend_from_slice(&[0x49, 0x8B, 0x42, 0x68, 0x48, 0x89, 0x01]);
    s.extend_from_slice(&[0x49, 0x8B, 0x42, 0x70, 0x48, 0x89, 0x41, 0x08]);
    s.extend_from_slice(&[0x41, 0x8B, 0x42, 0x78, 0x89, 0x41, 0x10]);
    s.extend_from_slice(&[0x41, 0x8B, 0x42, 0x7C, 0x89, 0x41, 0x14]);
    s.extend_from_slice(&[0x49, 0x8B, 0x4A, 0x60]);
    s.extend_from_slice(&[0x48, 0x85, 0xC9, 0x74, 0x07]);
    s.extend_from_slice(&[0x48, 0x31, 0xC0, 0x48, 0x89, 0x01, 0x90]);
    s.extend_from_slice(&[0x41, 0x8B, 0x82, 0x84, 0x00, 0x00, 0x00]);
    s.extend_from_slice(&[0x65, 0x89, 0x04, 0x25, 0x68, 0x00, 0x00, 0x00]);
    s.extend_from_slice(&[0x41, 0x8B, 0x82, 0x80, 0x00, 0x00, 0x00]);
    emit_release_keep_eax(&mut s, e);
    s.push(0xC3);
    s
}

fn emit_fs_stub(e: &StubEnv, op: u64, n_args: usize, saved_orig: u64) -> Vec<u8> {
    let mut s = Vec::<u8>::with_capacity(512);
    emit_prologue(&mut s, e, op, n_args);
    s.extend_from_slice(&[0x41, 0x8B, 0x82, 0x80, 0x00, 0x00, 0x00]);
    s.extend_from_slice(&[0x3D]);
    s.extend_from_slice((crate::ipc::FS_PASSTHROUGH as u32).to_le_bytes().as_slice());
    s.extend_from_slice(&[0x75, PASSTHROUGH_LEN]);
    emit_passthrough(&mut s, e, saved_orig);
    s.extend_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x08]);
    s.extend_from_slice(&[0x49, 0x8B, 0x42, 0x68, 0x48, 0x89, 0x01]);
    s.extend_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x20]);
    s.extend_from_slice(&[0x48, 0x85, 0xC9, 0x74, 0x12]);
    s.extend_from_slice(&[0x49, 0x63, 0x82, 0x80, 0x00, 0x00, 0x00]);
    s.extend_from_slice(&[0x48, 0x89, 0x01]);
    s.extend_from_slice(&[0x49, 0x8B, 0x42, 0x70, 0x48, 0x89, 0x41, 0x08]);
    s.extend_from_slice(&[0x41, 0x8B, 0x82, 0x80, 0x00, 0x00, 0x00]);
    emit_release_keep_eax(&mut s, e);
    s.push(0xC3);
    s
}

fn emit_handle_stub(e: &StubEnv, op: u64, n_args: usize, saved_orig: u64) -> Vec<u8> {
    let mut s = Vec::<u8>::with_capacity(384);
    emit_prologue(&mut s, e, op, n_args);
    s.extend_from_slice(&[0x41, 0x8B, 0x82, 0x80, 0x00, 0x00, 0x00]);
    s.extend_from_slice(&[0x3D]);
    s.extend_from_slice((crate::ipc::FS_PASSTHROUGH as u32).to_le_bytes().as_slice());
    s.extend_from_slice(&[0x75, PASSTHROUGH_LEN]);
    emit_passthrough(&mut s, e, saved_orig);
    s.extend_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x08]);
    s.extend_from_slice(&[0x49, 0x8B, 0x42, 0x68, 0x48, 0x89, 0x01]);
    s.extend_from_slice(&[0x41, 0x8B, 0x82, 0x80, 0x00, 0x00, 0x00]);
    emit_release_keep_eax(&mut s, e);
    s.push(0xC3);
    s
}

fn emit_attr_stub(e: &StubEnv, op: u64, out_qwords: u32, saved_orig: u64) -> Vec<u8> {
    let mut s = Vec::<u8>::with_capacity(384);
    emit_prologue(&mut s, e, op, 2);
    s.extend_from_slice(&[0x41, 0x8B, 0x82, 0x80, 0x00, 0x00, 0x00]);
    s.extend_from_slice(&[0x3D]);
    s.extend_from_slice((crate::ipc::FS_PASSTHROUGH as u32).to_le_bytes().as_slice());
    s.extend_from_slice(&[0x75, PASSTHROUGH_LEN]);
    emit_passthrough(&mut s, e, saved_orig);
    s.extend_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x10]);
    s.extend_from_slice(&[0x85, 0xC0]);
    let jnz_off = s.len();
    s.extend_from_slice(&[0x75, 0x00]);
    let copy_start = s.len();
    for i in 0..out_qwords {
        let src = crate::ipc::ATTR_OFF as u32 + i * 8;
        s.extend_from_slice(&[0x49, 0x8B, 0x82]);
        s.extend_from_slice(&src.to_le_bytes());
        if i == 0 {
            s.extend_from_slice(&[0x48, 0x89, 0x01]);
        } else {
            s.extend_from_slice(&[0x48, 0x89, 0x41, (i * 8) as u8]);
        }
    }
    let copy_len = s.len() - copy_start;
    s[jnz_off + 1] = copy_len as u8;
    s.extend_from_slice(&[0x41, 0x8B, 0x82, 0x80, 0x00, 0x00, 0x00]);
    emit_release_keep_eax(&mut s, e);
    s.push(0xC3);
    s
}
