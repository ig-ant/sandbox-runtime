//! P8: Hook `NtCreateUserProcess` in a target that spawns a grandchild;
//! verify the hook fires. Combined with P6 this proves the broker can
//! observe child creation in time to recursively apply interceptions.

use crate::common::*;
use crate::p6_patch::{build_count_stub, SYSCALL_STUB_LEN};
use anyhow::{Context, Result};

pub fn run() -> Result<ProbeOutcome> {
    let target = spawn_plain(&self_exe(), &["child", "p8-parent"], true)
        .context("spawn p8-parent suspended")?;
    let proc = target.pi.hProcess;

    let nt_cup = ntdll_export("NtCreateUserProcess")?;
    let orig = read_remote_bytes(proc, nt_cup, SYSCALL_STUB_LEN)?;
    let counter = alloc_remote_rw(proc, 16)?;
    let stub = build_count_stub(counter, &orig);
    let stub_addr = alloc_remote_rx(proc, &stub)?;
    let mut patch = enc_abs_jmp(stub_addr);
    pad_nops(&mut patch, ABS_JMP_LEN);
    write_remote_bytes(proc, nt_cup, &patch).context("patch NtCreateUserProcess")?;

    target.resume();
    let mut n: u64 = 0;
    let code = loop {
        match target.wait_timeout(100)? {
            Some(c) => break c,
            None => { if let Ok(v) = read_remote::<u64>(proc, counter) { n = v; } }
        }
    };
    if let Ok(v) = read_remote::<u64>(proc, counter) { n = n.max(v); }

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

pub fn child_parent(_args: &[String]) -> Result<i32> {
    let gc = spawn_plain(&self_exe(), &["child", "p8-grandchild"], false)?;
    let _ = gc.wait()?;
    // Linger so the broker can sample the counter before our VAS goes.
    std::thread::sleep(std::time::Duration::from_millis(1500));
    Ok(0)
}

pub fn child_grandchild(_args: &[String]) -> Result<i32> {
    Ok(0)
}
