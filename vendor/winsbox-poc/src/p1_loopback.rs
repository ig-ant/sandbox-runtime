//! P1: Inside an AppContainer with no capabilities, can a process bind
//! 127.0.0.1:0 and connect to itself? This underpins the Phase-1
//! `--relay-inside` design.

use crate::common::*;
use anyhow::Result;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

pub fn run() -> Result<ProbeOutcome> {
    let ac = create_appcontainer("p1")?;
    // The AC must be able to read/execute this exe to launch.
    grant_sid_on_path(&self_exe(), ac.sid, 0x1200A9 /* FILE_GENERIC_READ|EXECUTE */)?;
    let child = spawn_in_ac(&ac, &self_exe(), &["child", "p1-loopback"], false)?;
    let code = child.wait()?;
    Ok(match code {
        0 => ProbeOutcome::pass("intra-AC 127.0.0.1 bind+connect ok"),
        10 => ProbeOutcome::fail("bind 127.0.0.1:0 refused inside AppContainer"),
        11 => ProbeOutcome::fail("connect to own listener refused inside AppContainer"),
        c => ProbeOutcome::fail(format!("child exit {c}")),
    })
}

pub fn child_main(_args: &[String]) -> Result<i32> {
    if !process_is_appcontainer() {
        eprintln!("p1: NOT in AppContainer (test invalid)");
        return Ok(92);
    }
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(l) => l,
        Err(e) => { eprintln!("p1: bind failed: {e}"); return Ok(10); }
    };
    let addr = listener.local_addr()?;
    let jh = std::thread::spawn(move || {
        if let Ok((mut s, _)) = listener.accept() {
            let _ = s.write_all(b"ok");
        }
    });
    let mut c = match TcpStream::connect(addr) {
        Ok(c) => c,
        Err(e) => { eprintln!("p1: connect failed: {e}"); return Ok(11); }
    };
    let mut buf = [0u8; 2];
    let _ = c.read(&mut buf);
    let _ = jh.join();
    Ok(if &buf == b"ok" { 0 } else { 11 })
}
