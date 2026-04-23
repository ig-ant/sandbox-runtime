//! P6: Spawn a controlled target CREATE_SUSPENDED, locate ntdll!NtCreateFile
//! (per-boot constant base, so local addr == child addr), allocate an RX
//! page in the child, write a stub that increments a shared counter then
//! tail-calls the original prologue, overwrite the export prologue with a
//! jump to the stub, resume, wait, read the counter back. If the counter
//! moved, hooking works.

use crate::common::*;
use anyhow::{Context, Result};

/// ntdll syscall stubs are ~24 bytes on x64 and ~16 on arm64, self-
/// contained (end in `ret`) and contain only PC-relative branches that
/// stay inside the stub. Copying the whole thing means we never split an
/// instruction and never need to jump back.
pub const SYSCALL_STUB_LEN: usize = 32;

#[cfg(target_arch = "x86_64")]
pub fn build_count_stub(counter: usize, full_orig: &[u8]) -> Vec<u8> {
    let mut s = Vec::with_capacity(20 + full_orig.len());
    s.extend_from_slice(&[0x50]);                                   // push rax
    s.extend_from_slice(&[0x48, 0xB8]); s.extend_from_slice(&counter.to_le_bytes()); // mov rax, imm64
    s.extend_from_slice(&[0xF0, 0x48, 0xFF, 0x00]);                 // lock inc qword [rax]
    s.extend_from_slice(&[0x58]);                                   // pop rax
    s.extend_from_slice(full_orig);                                 // entire original stub → syscall → ret
    s
}

#[cfg(target_arch = "aarch64")]
pub fn build_count_stub(counter: usize, full_orig: &[u8]) -> Vec<u8> {
    // x16/x17 are intra-procedure scratch; safe to clobber pre-call.
    // ldr x16,#lit ; mov x17,#1 ; str x17,[x16] ; <orig stub incl. ret>
    // ; .align 8 ; .quad counter
    let mut s = Vec::<u8>::new();
    let e = |s: &mut Vec<u8>, w: u32| s.extend_from_slice(&w.to_le_bytes());
    let body_insns: usize = 3;
    let lit_off = (body_insns * 4 + full_orig.len()) as u32; // bytes from ldr to literal
    let lit_off_padded = (lit_off + 7) & !7;
    let imm19 = (lit_off_padded / 4) << 5;
    e(&mut s, 0x58000010 | imm19);          // ldr x16, #lit_off_padded
    e(&mut s, 0xD2800031);                  // mov x17, #1
    e(&mut s, 0xF9000211);                  // str x17, [x16]
    s.extend_from_slice(full_orig);         // entire original stub (ends in ret)
    while (s.len() as u32) < lit_off_padded { e(&mut s, 0xD503201F); } // nop pad
    s.extend_from_slice(&counter.to_le_bytes());
    s
}

pub fn run() -> Result<ProbeOutcome> {
    let target = spawn_plain(&self_exe(), &["child", "p5-target", "linger"], true)
        .context("spawn suspended target")?;
    let proc = target.pi.hProcess;

    let nt_createfile = ntdll_export("NtCreateFile")?;
    let orig = read_remote_bytes(proc, nt_createfile, SYSCALL_STUB_LEN)?;
    let counter_addr = alloc_remote_rw(proc, 16)?;
    let stub = build_count_stub(counter_addr, &orig);
    let stub_addr = alloc_remote_rx(proc, &stub)?;

    let mut patch = enc_abs_jmp(stub_addr);
    pad_nops(&mut patch, ABS_JMP_LEN);
    write_remote_bytes(proc, nt_createfile, &patch).context("patch NtCreateFile")?;
    target.resume();

    // Sample the counter while the child is alive — once it exits the VAS
    // is torn down and ReadProcessMemory fails.
    let mut counter: u64 = 0;
    let code = loop {
        match target.wait_timeout(100)? {
            Some(c) => break c,
            None => {
                if let Ok(v) = read_remote::<u64>(proc, counter_addr) { counter = v; }
                if counter > 0 { /* keep sampling until exit */ }
            }
        }
    };
    if let Ok(v) = read_remote::<u64>(proc, counter_addr) { counter = counter.max(v); }

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
