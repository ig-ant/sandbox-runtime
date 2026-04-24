//! AF_UNIX bridge between an AppContainer process and the SRT proxy on
//! the host. The AC has no `internetClient` capability, so it cannot
//! reach the host's `127.0.0.1:<proxyPort>` directly; but P2 proved it
//! CAN connect to an AF_UNIX socket in its package folder. The broker
//! listens on that socket and pumps bytes to the host proxy. Inside
//! the AC, a relay process binds `127.0.0.1:0` (intra-AC loopback works
//! per P1) and pumps to the AF_UNIX socket, so the target sees a normal
//! `HTTP_PROXY=http://127.0.0.1:<port>`.

use anyhow::{bail, Context, Result};
use std::io::{Read, Write};
use std::mem::{size_of, zeroed};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::thread;
use windows::Win32::Networking::WinSock::{
    accept, bind, closesocket, connect, listen, recv, send, socket, WSAGetLastError,
    WSAStartup, AF_UNIX, SEND_RECV_FLAGS, SOCKADDR, SOCKET, SOCK_STREAM, WSADATA,
};

#[repr(C)]
struct SockaddrUn { sun_family: u16, sun_path: [u8; 108] }

fn wsa_init() -> Result<()> {
    unsafe {
        let mut d: WSADATA = zeroed();
        if WSAStartup(0x0202, &mut d) != 0 { bail!("WSAStartup"); }
    }
    Ok(())
}

fn make_addr(path: &str) -> Result<(SockaddrUn, i32)> {
    let bytes = path.as_bytes();
    if bytes.len() >= 108 { bail!("AF_UNIX path too long ({} bytes)", bytes.len()); }
    let mut a = SockaddrUn { sun_family: AF_UNIX, sun_path: [0; 108] };
    a.sun_path[..bytes.len()].copy_from_slice(bytes);
    Ok((a, size_of::<SockaddrUn>() as i32))
}

fn unix_listen(path: &str) -> Result<SOCKET> {
    let _ = std::fs::remove_file(path);
    let (a, l) = make_addr(path)?;
    unsafe {
        let s = socket(AF_UNIX as i32, SOCK_STREAM, 0).context("socket(AF_UNIX)")?;
        if bind(s, &a as *const _ as *const SOCKADDR, l) != 0 {
            bail!("bind({path}): {:?}", WSAGetLastError());
        }
        if listen(s, 64) != 0 { bail!("listen: {:?}", WSAGetLastError()); }
        Ok(s)
    }
}

fn unix_connect(path: &str) -> Result<SOCKET> {
    let (a, l) = make_addr(path)?;
    unsafe {
        let s = socket(AF_UNIX as i32, SOCK_STREAM, 0).context("socket(AF_UNIX)")?;
        if connect(s, &a as *const _ as *const SOCKADDR, l) != 0 {
            bail!("connect({path}): {:?}", WSAGetLastError());
        }
        Ok(s)
    }
}

/// Bidirectional byte pump between a Winsock SOCKET and a std TcpStream.
fn pump_socket_tcp(ws: SOCKET, mut tcp: TcpStream) {
    let mut tcp_r = match tcp.try_clone() { Ok(t) => t, Err(_) => return };
    // ws→tcp
    let ws2 = ws;
    let t1 = thread::spawn(move || {
        let mut buf = [0u8; 16 * 1024];
        loop {
            let n = unsafe { recv(ws2, &mut buf, SEND_RECV_FLAGS(0)) };
            if n <= 0 { break; }
            if tcp.write_all(&buf[..n as usize]).is_err() { break; }
        }
        let _ = tcp.shutdown(std::net::Shutdown::Write);
    });
    // tcp→ws
    let mut buf = [0u8; 16 * 1024];
    loop {
        match tcp_r.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => unsafe {
                if send(ws, &buf[..n], SEND_RECV_FLAGS(0)) <= 0 { break; }
            },
        }
    }
    unsafe { closesocket(ws); }
    let _ = t1.join();
}

/// Broker-side: listen on AF_UNIX `sock_path`, forward each accepted
/// connection to `127.0.0.1:upstream_port`. Returns once the listener
/// is bound; the accept loop runs on a background thread for the
/// process lifetime.
pub fn spawn_outside_relay(sock_path: PathBuf, upstream_port: u16) -> Result<()> {
    wsa_init()?;
    if let Some(parent) = sock_path.parent() { std::fs::create_dir_all(parent).ok(); }
    let lsock = unix_listen(sock_path.to_str().context("non-utf8 sock path")?)?;
    thread::spawn(move || loop {
        let c = unsafe { accept(lsock, None, None) };
        let c = match c { Ok(c) => c, Err(_) => break };
        let up = match TcpStream::connect(("127.0.0.1", upstream_port)) {
            Ok(t) => t,
            Err(_) => { unsafe { closesocket(c); } continue; }
        };
        thread::spawn(move || pump_socket_tcp(c, up));
    });
    Ok(())
}

/// AC-side relay process: bind `127.0.0.1:0`, print the port to stdout
/// (one line), then accept loop forwarding each TCP connection to the
/// AF_UNIX `sock_path` (which the broker is listening on). Never
/// returns; the Job's KILL_ON_JOB_CLOSE tears it down with the target.
pub fn run_inside_relay(sock_paths: &[String]) -> Result<()> {
    wsa_init()?;
    let mut listeners = Vec::new();
    for sp in sock_paths {
        let l = TcpListener::bind("127.0.0.1:0")
            .with_context(|| format!("bind 127.0.0.1:0 for {sp}"))?;
        let port = l.local_addr()?.port();
        println!("{port}");
        listeners.push((l, sp.clone()));
    }
    use std::io::Write as _;
    std::io::stdout().flush().ok();

    let mut handles = Vec::new();
    for (l, sp) in listeners {
        handles.push(thread::spawn(move || {
            for conn in l.incoming() {
                let tcp = match conn { Ok(c) => c, Err(_) => continue };
                let sp = sp.clone();
                thread::spawn(move || {
                    if let Ok(ws) = unix_connect(&sp) {
                        pump_socket_tcp(ws, tcp);
                    }
                });
            }
        }));
    }
    for h in handles { let _ = h.join(); }
    Ok(())
}

/// sun_path is 108 bytes. Returns a usable directory for the bridge
/// sockets — the AC package folder if it's short enough (preferred:
/// the AC can already reach it), otherwise a short temp dir that the
/// caller must ACL to the AC SID.
pub fn socket_dir(ac_folder: &Path) -> (PathBuf, bool) {
    if ac_folder.as_os_str().len() + 8 < 108 {
        return (ac_folder.to_path_buf(), false);
    }
    let d = std::env::temp_dir().join(format!("srtsk{}", std::process::id()));
    std::fs::create_dir_all(&d).ok();
    (d, true)
}
