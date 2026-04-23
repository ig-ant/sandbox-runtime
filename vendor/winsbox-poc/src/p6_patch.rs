//! P6: Spawn a controlled target CREATE_SUSPENDED, locate ntdll!NtCreateFile
//! (per-boot constant base, so local addr == child addr), allocate an RX
//! page in the child, write a stub that increments a shared counter then
//! tail-calls the original prologue, overwrite the export prologue with a
//! jump to the stub, resume, wait, read the counter back. If the counter
//! moved, hooking works.

use crate::common::*;
use anyhow::{Context, Result};

#[cfg(target_arch = "x86_64")]
pub const PROLOGUE_LEN: usize = 12;
#[cfg(target_arch = "aarch64")]
pub const PROLOGUE_LEN: usize = 16;

#[cfg(target_arch = "x86_64")]
fn build_stub(counter_addr: usize, orig_bytes: &[u8], cont_addr: usize) -> Vec<u8> {
    // lock inc qword [counter]; <orig prologue>; mov r11, cont; jmp r11
    let mut s = Vec::new();
    s.extend_from_slice(&[0xF0, 0x48, 0xFF, 0x04, 0x25]);          // lock inc qword ptr [imm32]
    // RIP-relative is awkward without knowing stub VA up front; instead use
    // mov rax, imm64; lock inc qword ptr [rax]
    s.clear();
    s.extend_from_slice(&[0x50]);                                   // push rax
    s.extend_from_slice(&[0x48, 0xB8]); s.extend_from_slice(&counter_addr.to_le_bytes()); // mov rax, imm64
    s.extend_from_slice(&[0xF0, 0x48, 0xFF, 0x00]);                 // lock inc qword ptr [rax]
    s.extend_from_slice(&[0x58]);                                   // pop rax
    s.extend_from_slice(orig_bytes);                                // re-execute stolen prologue
    s.extend_from_slice(&[0x49, 0xBB]); s.extend_from_slice(&cont_addr.to_le_bytes()); // mov r11, imm64
    s.extend_from_slice(&[0x41, 0xFF, 0xE3]);                       // jmp r11
    s
}

#[cfg(target_arch = "aarch64")]
fn build_stub(counter_addr: usize, orig_bytes: &[u8], cont_addr: usize) -> Vec<u8> {
    // ldr x16,#counter_lit; ldaddal x17,x17,[x16] (overkill) — keep simple:
    // we just store 1 to the counter; lossless count not required for the probe.
    let mut s = Vec::<u8>::new();
    let emit = |s: &mut Vec<u8>, w: u32| s.extend_from_slice(&w.to_le_bytes());
    // ldr x16, #lit_counter
    let lit_off_counter = 7 * 4; // 7 insns ahead
    emit(&mut s, 0x58000010 | (((lit_off_counter as u32) >> 2) << 5)); // ldr x16, #off
    emit(&mut s, 0xD2800031);                                          // mov x17, #1
    emit(&mut s, 0xF9000211);                                          // str x17, [x16]
    // ldr x16, #lit_cont
    let lit_off_cont = 5 * 4;
    emit(&mut s, 0x58000010 | (((lit_off_cont as u32) >> 2) << 5));
    // re-exec stolen prologue (4 insns) before branch — append below
    // We'll branch first, so just place stolen bytes in a trampoline:
    // Actually simplest: br x16 to a second region containing orig_bytes + br to cont.
    // For PoC, we accept clobbering x16/x17 (callee-saved? x16/x17 are IP0/IP1, scratch).
    // Append stolen prologue then br x16.
    s.extend_from_slice(orig_bytes);
    emit(&mut s, 0xD61F0200);                                          // br x16
    // literal pool (must be 8-aligned; pad)
    while s.len() % 8 != 0 { emit(&mut s, 0xD503201F); }               // nop
    s.extend_from_slice(&counter_addr.to_le_bytes());
    s.extend_from_slice(&cont_addr.to_le_bytes());
    s
}

pub fn run() -> Result<ProbeOutcome> {
    let target = spawn_plain(&self_exe(), &["child", "p5-target"], true)
        .context("spawn suspended target")?;
    let proc = target.pi.hProcess;

    let nt_createfile = ntdll_export("NtCreateFile")?;
    let orig = read_remote_bytes(proc, nt_createfile, PROLOGUE_LEN)?;
    let cont_addr = nt_createfile + PROLOGUE_LEN;

    let counter_addr = alloc_remote_rw(proc, 16)?;
    let stub = build_stub(counter_addr, &orig, cont_addr);
    let stub_addr = alloc_remote_rx(proc, &stub)?;

    let mut patch = enc_abs_jmp(stub_addr);
    if patch.len() > PROLOGUE_LEN {
        target.terminate();
        return Ok(ProbeOutcome::fail(format!(
            "jmp encoding {}B > prologue {}B", patch.len(), PROLOGUE_LEN)));
    }
    pad_nops(&mut patch, PROLOGUE_LEN);
    write_remote_bytes(proc, nt_createfile, &patch).context("patch NtCreateFile")?;
    target.resume();

    let code = match target.wait_timeout(15_000)? {
        Some(c) => c,
        None => { target.terminate(); return Ok(ProbeOutcome::fail("target hung after patch")); }
    };
    let counter: u64 = read_remote::<u64>(proc, counter_addr).unwrap_or(0);

    if code != 0 {
        return Ok(ProbeOutcome::fail(format!(
            "target crashed after patch (exit {code:#x}); counter={counter}")));
    }
    if counter == 0 {
        return Ok(ProbeOutcome::fail("target ran but hook never fired (counter=0)"));
    }
    Ok(ProbeOutcome::pass(format!(
        "ntdll!NtCreateFile inline-hooked in suspended child; hook fired {counter}× before exit")))
}
