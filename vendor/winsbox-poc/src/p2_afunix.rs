//! P2: AF_UNIX cross-boundary. Broker (this process, full token) listens on
//! an AF_UNIX SOCK_STREAM at a path inside the AppContainer's package
//! folder; a child inside the AC connects. Then reverse direction.

use crate::common::*;
use anyhow::{bail, Context, Result};
use std::mem::{size_of, zeroed};
use windows::Win32::Networking::WinSock::{
    accept, bind, closesocket, connect, listen, recv, send, socket, WSACleanup, WSAStartup,
    AF_UNIX, SEND_RECV_FLAGS, SOCKADDR, SOCKET, SOCK_STREAM, WSADATA,
};

#[repr(C)]
struct SockaddrUn {
    sun_family: u16,
    sun_path: [u8; 108],
}

fn make_addr(path: &str) -> Result<(SockaddrUn, i32)> {
    let bytes = path.as_bytes();
    if bytes.len() >= 108 { bail!("AF_UNIX path too long"); }
    let mut a = SockaddrUn { sun_family: AF_UNIX as u16, sun_path: [0; 108] };
    a.sun_path[..bytes.len()].copy_from_slice(bytes);
    Ok((a, size_of::<SockaddrUn>() as i32))
}

fn wsa_init() -> Result<()> {
    unsafe {
        let mut d: WSADATA = zeroed();
        if WSAStartup(0x0202, &mut d) != 0 { bail!("WSAStartup"); }
    }
    Ok(())
}

fn unix_listen(path: &str) -> Result<SOCKET> {
    let _ = std::fs::remove_file(path);
    let (addr, len) = make_addr(path)?;
    unsafe {
        let s = socket(AF_UNIX as i32, SOCK_STREAM, 0).context("socket(AF_UNIX)")?;
        if bind(s, &addr as *const _ as *const SOCKADDR, len) != 0 {
            bail!("bind({path}): {:?}", windows::Win32::Networking::WinSock::WSAGetLastError());
        }
        if listen(s, 1) != 0 { bail!("listen"); }
        Ok(s)
    }
}

fn unix_connect(path: &str) -> Result<SOCKET> {
    let (addr, len) = make_addr(path)?;
    unsafe {
        let s = socket(AF_UNIX as i32, SOCK_STREAM, 0).context("socket(AF_UNIX)")?;
        if connect(s, &addr as *const _ as *const SOCKADDR, len) != 0 {
            bail!("connect({path}): {:?}", windows::Win32::Networking::WinSock::WSAGetLastError());
        }
        Ok(s)
    }
}

pub fn run() -> Result<ProbeOutcome> {
    wsa_init()?;
    let ac = create_appcontainer("p2")?;
    grant_sid_on_path(&self_exe(), ac.sid, 0x1200A9)?;
    std::fs::create_dir_all(&ac.folder).ok();
    let sock_path = ac.folder.join("p2.sock");
    let sock_str = sock_path.to_string_lossy().to_string();

    // Direction A: broker listens, AC child connects.
    let lsock = unix_listen(&sock_str).context("broker AF_UNIX listen")?;
    let lsock_for_thread = lsock;
    let jh = std::thread::spawn(move || unsafe {
        if let Ok(c) = accept(lsock_for_thread, None, None) {
            let _ = send(c, b"A", SEND_RECV_FLAGS(0));
            closesocket(c);
        }
    });
    let child = spawn_in_ac(&ac, &self_exe(), &["child", "p2-uds-connect", &sock_str], false)?;
    let code_a = child.wait()?;
    let _ = jh.join();
    unsafe { closesocket(lsock); }
    let _ = std::fs::remove_file(&sock_path);

    // Direction B: AC child listens, broker connects.
    let child_b = spawn_in_ac(&ac, &self_exe(), &["child", "p2-uds-listen", &sock_str], false)?;
    // Wait for the socket file to appear.
    let mut connected = false;
    for _ in 0..50 {
        std::thread::sleep(std::time::Duration::from_millis(100));
        if sock_path.exists() {
            if let Ok(s) = unix_connect(&sock_str) {
                let mut buf = [0u8; 1];
                unsafe { recv(s, &mut buf, SEND_RECV_FLAGS(0)); closesocket(s); }
                connected = buf[0] == b'B';
            }
            break;
        }
    }
    child_b.terminate();
    let _ = child_b.wait_timeout(2000);
    let _ = std::fs::remove_file(&sock_path);
    unsafe { WSACleanup(); }

    let a_ok = code_a == 0;
    match (a_ok, connected) {
        (true, true)  => Ok(ProbeOutcome::pass("AF_UNIX both directions cross AC boundary")),
        (true, false) => Ok(ProbeOutcome::pass("AF_UNIX broker→AC ok; AC→broker FAILED (acceptable: bridge only needs A)")),
        (false, _)    => Ok(ProbeOutcome::fail(format!("AC child could not connect to broker AF_UNIX (exit {code_a})"))),
    }
}

pub fn child_connect(args: &[String]) -> Result<i32> {
    wsa_init()?;
    if !process_is_appcontainer() { return Ok(92); }
    let path = args.get(0).cloned().unwrap_or_default();
    match unix_connect(&path) {
        Ok(s) => unsafe {
            let mut buf = [0u8; 1];
            recv(s, &mut buf, SEND_RECV_FLAGS(0));
            closesocket(s);
            Ok(if buf[0] == b'A' { 0 } else { 12 })
        },
        Err(e) => { eprintln!("p2 child connect: {e}"); Ok(11) }
    }
}

pub fn child_listen(args: &[String]) -> Result<i32> {
    wsa_init()?;
    if !process_is_appcontainer() { return Ok(92); }
    let path = args.get(0).cloned().unwrap_or_default();
    let l = match unix_listen(&path) {
        Ok(l) => l,
        Err(e) => { eprintln!("p2 child listen: {e}"); return Ok(11); }
    };
    unsafe {
        if let Ok(c) = accept(l, None, None) {
            let _ = send(c, b"B", SEND_RECV_FLAGS(0));
            closesocket(c);
        }
        closesocket(l);
    }
    Ok(0)
}
