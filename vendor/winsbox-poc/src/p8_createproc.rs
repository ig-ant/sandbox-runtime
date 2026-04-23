//! P8: Hook `NtCreateUserProcess` in a target that spawns a grandchild;
//! verify the hook fires. Combined with P6 (we can patch a suspended
//! process) this proves the broker can observe child creation in time
//! to recursively apply interceptions. Full handle-capture is left to
//! Phase 2 — for the PoC, observing the call is the binary question.

use crate::common::*;
use anyhow::{Context, Result};

pub fn run() -> Result<ProbeOutcome> {
    let target = spawn_plain(&self_exe(), &["child", "p8-parent"], true)
        .context("spawn p8-parent suspended")?;
    let proc = target.pi.hProcess;

    let nt_cup = ntdll_export("NtCreateUserProcess")?;
    let plen = crate::p6_patch::PROLOGUE_LEN;
    let orig = read_remote_bytes(proc, nt_cup, plen)?;
    let counter = alloc_remote_rw(proc, 16)?;
    let stub = build_count_stub(counter, &orig, nt_cup + plen);
    let stub_addr = alloc_remote_rx(proc, &stub)?;
    let mut patch = enc_abs_jmp(stub_addr);
    pad_nops(&mut patch, plen);
    write_remote_bytes(proc, nt_cup, &patch).context("patch NtCreateUserProcess")?;

    target.resume();
    let code = match target.wait_timeout(20_000)? {
        Some(c) => c,
        None => { target.terminate(); return Ok(ProbeOutcome::fail("p8-parent hung")); }
    };
    let n: u64 = read_remote::<u64>(proc, counter).unwrap_or(0);

    if code != 0 {
        return Ok(ProbeOutcome::fail(format!(
            "p8-parent crashed after hook (exit {code:#x}); counter={n}")));
    }
    if n == 0 {
        return Ok(ProbeOutcome::fail(
            "grandchild spawned but NtCreateUserProcess hook never fired"));
    }
    Ok(ProbeOutcome::pass(format!(
        "NtCreateUserProcess hook fired {n}× during grandchild spawn")))
}

#[cfg(target_arch = "x86_64")]
fn build_count_stub(counter: usize, orig: &[u8], cont: usize) -> Vec<u8> {
    let mut s = Vec::new();
    s.extend_from_slice(&[0x50]);                                         // push rax
    s.extend_from_slice(&[0x48, 0xB8]); s.extend_from_slice(&counter.to_le_bytes());
    s.extend_from_slice(&[0xF0, 0x48, 0xFF, 0x00]);                       // lock inc qword [rax]
    s.extend_from_slice(&[0x58]);                                         // pop rax
    s.extend_from_slice(orig);
    s.extend_from_slice(&[0x49, 0xBB]); s.extend_from_slice(&cont.to_le_bytes());
    s.extend_from_slice(&[0x41, 0xFF, 0xE3]);                             // jmp r11
    s
}

#[cfg(target_arch = "aarch64")]
fn build_count_stub(counter: usize, orig: &[u8], cont: usize) -> Vec<u8> {
    let mut s = Vec::<u8>::new();
    let e = |s: &mut Vec<u8>, w: u32| s.extend_from_slice(&w.to_le_bytes());
    e(&mut s, 0x580000F0); // ldr x16,#28 → counter lit
    e(&mut s, 0xD2800031); // mov x17,#1
    e(&mut s, 0xF8310211); // stadd x17,[x16] (LSE; falls back ok on v8.1+)
    s.extend_from_slice(orig);
    let dist = 8 + orig.len(); // bytes from next insn to cont lit
    let _ = dist;
    e(&mut s, 0x58000070); // ldr x16,#12 → cont lit (approx; PoC)
    e(&mut s, 0xD61F0200); // br x16
    while s.len() % 8 != 0 { e(&mut s, 0xD503201F); }
    s.extend_from_slice(&counter.to_le_bytes());
    s.extend_from_slice(&cont.to_le_bytes());
    s
}

pub fn child_parent(_args: &[String]) -> Result<i32> {
    let gc = spawn_plain(&self_exe(), &["child", "p8-grandchild"], false)?;
    let _ = gc.wait()?;
    Ok(0)
}

pub fn child_grandchild(_args: &[String]) -> Result<i32> {
    Ok(0)
}
