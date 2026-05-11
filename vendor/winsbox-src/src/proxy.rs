//! Loopback SOCKS5 proxy server. The broker runs this; the sandboxed
//! child reaches it via `HTTP_PROXY=socks5h://127.0.0.1:<port>` etc.
//!
//! NO AUTH + CONNECT only. ATYP IPv4 / hostname / IPv6.
//! Thread-per-connection. PID lookup is informational only (WFP is the
//! security boundary).

use anyhow::{anyhow, Context, Result};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

pub enum Host<'a> {
    Ip(IpAddr),
    Name(&'a str),
}

impl<'a> std::fmt::Display for Host<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Host::Ip(ip) => write!(f, "{ip}"),
            Host::Name(s) => write!(f, "{s}"),
        }
    }
}

/// Pluggable dialer so a future upstream HTTP/SOCKS proxy can be
/// chained in without rewiring the SOCKS5 server.
pub trait Dialer: Send + Sync + 'static {
    fn dial(&self, host: &Host<'_>, port: u16) -> io::Result<TcpStream>;
}

/// v1 default — directly `TcpStream::connect` from the broker identity.
pub struct DirectDialer;

impl Dialer for DirectDialer {
    fn dial(&self, h: &Host<'_>, p: u16) -> io::Result<TcpStream> {
        let timeout = Duration::from_secs(30);
        match h {
            Host::Ip(ip) => TcpStream::connect_timeout(&SocketAddr::new(*ip, p), timeout),
            Host::Name(name) => {
                let addrs = (*name, p).to_socket_addrs()?;
                let mut last_err: Option<io::Error> = None;
                for sa in addrs {
                    match TcpStream::connect_timeout(&sa, timeout) {
                        Ok(s) => return Ok(s),
                        Err(e) => last_err = Some(e),
                    }
                }
                Err(last_err.unwrap_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "no addresses")))
            }
        }
    }
}

/// Skeleton — upstream SOCKS5 chaining. Phase 2 / later.
#[allow(dead_code)]
pub struct UpstreamSocks5 {
    pub host: String,
    pub port: u16,
}

/// Running proxy handle. Drop joins the listener thread.
pub struct Proxy {
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    #[allow(dead_code)]
    pub port: u16,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        // Trigger accept loop exit by connecting once to ourselves.
        let _ = std::net::TcpStream::connect_timeout(
            &SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), self.port),
            Duration::from_millis(250),
        );
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Start the SOCKS5 listener on `127.0.0.1:<port>` and return a handle
/// the caller keeps alive for the lifetime of the sandboxed child.
pub fn start(port: u16, dialer: Box<dyn Dialer>) -> Result<Proxy> {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let listener = TcpListener::bind(addr).with_context(|| {
        format!(
            "TcpListener::bind({addr}); if WSAEADDRINUSE inspect `Get-NetTCPConnection -LocalPort {port}` and reinstall with --port"
        )
    })?;
    // Short timeout so we can periodically check shutdown.
    listener.set_nonblocking(false).ok();

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_c = Arc::clone(&shutdown);
    let dialer: Arc<dyn Dialer> = Arc::from(dialer);

    let handle = std::thread::Builder::new()
        .name("winsbox-proxy-accept".to_string())
        .spawn(move || {
            for incoming in listener.incoming() {
                if shutdown_c.load(Ordering::SeqCst) {
                    break;
                }
                match incoming {
                    Ok(client) => {
                        let dialer = Arc::clone(&dialer);
                        std::thread::spawn(move || {
                            if let Err(e) = handle_client(client, dialer) {
                                eprintln!("[winsbox-proxy] client error: {e:#}");
                            }
                        });
                    }
                    Err(e) => {
                        eprintln!("[winsbox-proxy] accept: {e}");
                    }
                }
            }
        })
        .context("spawn proxy accept thread")?;

    Ok(Proxy { shutdown, handle: Some(handle), port })
}

fn read_exact(s: &mut TcpStream, n: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    s.read_exact(&mut buf)?;
    Ok(buf)
}

fn handle_client(mut client: TcpStream, dialer: Arc<dyn Dialer>) -> Result<()> {
    client.set_read_timeout(Some(Duration::from_secs(30)))?;
    client.set_write_timeout(Some(Duration::from_secs(30)))?;

    // SOCKS5 greeting: [VER, NMETHODS, METHODS...]
    let hdr = read_exact(&mut client, 2)?;
    if hdr[0] != 0x05 {
        return Err(anyhow!("bad SOCKS version: {}", hdr[0]));
    }
    let nm = hdr[1] as usize;
    let methods = read_exact(&mut client, nm)?;
    if !methods.contains(&0x00) {
        let _ = client.write_all(&[0x05, 0xFF]);
        return Err(anyhow!("no NO-AUTH method offered"));
    }
    client.write_all(&[0x05, 0x00])?;

    // Request: [VER, CMD, RSV, ATYP, ADDR, PORT]
    let req_hdr = read_exact(&mut client, 4)?;
    if req_hdr[0] != 0x05 {
        return Err(anyhow!("bad SOCKS version on request"));
    }
    if req_hdr[1] != 0x01 {
        // Command not supported.
        let _ = client.write_all(&[0x05, 0x07, 0x00, 0x01, 0,0,0,0, 0,0]);
        return Err(anyhow!("unsupported SOCKS cmd: {}", req_hdr[1]));
    }
    let atyp = req_hdr[3];
    let (host_owned, host_repr): (Vec<u8>, String) = match atyp {
        0x01 => {
            // IPv4: 4 bytes.
            let a = read_exact(&mut client, 4)?;
            let ip = Ipv4Addr::new(a[0], a[1], a[2], a[3]);
            (a, ip.to_string())
        }
        0x03 => {
            // DOMAINNAME: 1-byte length + N bytes.
            let l = read_exact(&mut client, 1)?[0] as usize;
            let n = read_exact(&mut client, l)?;
            let s = String::from_utf8_lossy(&n).to_string();
            (n, s)
        }
        0x04 => {
            // IPv6: 16 bytes.
            let a = read_exact(&mut client, 16)?;
            let arr: [u8; 16] = a.as_slice().try_into().unwrap();
            let ip = Ipv6Addr::from(arr);
            (a, ip.to_string())
        }
        _ => {
            let _ = client.write_all(&[0x05, 0x08, 0x00, 0x01, 0,0,0,0, 0,0]);
            return Err(anyhow!("bad ATYP: {atyp}"));
        }
    };
    let port_bytes = read_exact(&mut client, 2)?;
    let port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);

    let host = match atyp {
        0x01 => {
            let arr: [u8; 4] = host_owned.as_slice().try_into().unwrap();
            Host::Ip(IpAddr::V4(Ipv4Addr::from(arr)))
        }
        0x04 => {
            let arr: [u8; 16] = host_owned.as_slice().try_into().unwrap();
            Host::Ip(IpAddr::V6(Ipv6Addr::from(arr)))
        }
        _ => Host::Name(host_repr.as_str()),
    };

    // PID lookup (informational).
    let pid = pid_for_connection(&client).unwrap_or(0);
    eprintln!(
        "[winsbox-proxy] accept pid={pid} dst={host_repr}:{port} via=direct"
    );

    let upstream = match dialer.dial(&host, port) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[winsbox-proxy] dial {host_repr}:{port} failed: {e}");
            let _ = client.write_all(&[0x05, 0x05, 0x00, 0x01, 0,0,0,0, 0,0]);
            return Err(anyhow!("dial: {e}"));
        }
    };
    // Success reply with BND.ADDR=0.0.0.0:0.
    client.write_all(&[0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0])?;

    // Splice client <-> upstream.
    splice(client, upstream);
    Ok(())
}

fn splice(client: TcpStream, upstream: TcpStream) {
    let c1 = client.try_clone().expect("clone client");
    let u1 = upstream.try_clone().expect("clone upstream");

    let t1 = std::thread::spawn(move || {
        let mut a = c1;
        let mut b = u1;
        let _ = std::io::copy(&mut a, &mut b);
        let _ = b.shutdown(Shutdown::Write);
        let _ = a.shutdown(Shutdown::Read);
    });
    let t2 = std::thread::spawn(move || {
        let mut a = upstream;
        let mut b = client;
        let _ = std::io::copy(&mut a, &mut b);
        let _ = b.shutdown(Shutdown::Write);
        let _ = a.shutdown(Shutdown::Read);
    });
    let _ = t1.join();
    let _ = t2.join();
}

/// Look up the owning PID of a connected TCP socket. Used for logging
/// only; WFP is the actual security boundary.
fn pid_for_connection(client: &TcpStream) -> Option<u32> {
    use windows::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_CONNECTIONS,
    };
    use windows::Win32::Networking::WinSock::AF_INET;
    let local = client.local_addr().ok()?;
    let peer = client.peer_addr().ok()?;
    let local_v4 = match local {
        SocketAddr::V4(v) => v,
        _ => return None,
    };
    let peer_v4 = match peer {
        SocketAddr::V4(v) => v,
        _ => return None,
    };

    unsafe {
        let mut size: u32 = 0;
        let _ = GetExtendedTcpTable(
            None, &mut size, false, AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_CONNECTIONS, 0,
        );
        if size == 0 {
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        let rc = GetExtendedTcpTable(
            Some(buf.as_mut_ptr() as *mut std::ffi::c_void),
            &mut size, false, AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_CONNECTIONS, 0,
        );
        if rc != 0 {
            return None;
        }
        let table = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
        let n = table.dwNumEntries as usize;
        let rows = std::slice::from_raw_parts(table.table.as_ptr(), n);
        for r in rows {
            // GetExtendedTcpTable stores ports in network byte order in
            // the low 16 bits of the u32. Local/remote addresses are in
            // network byte order (big-endian) inside a u32.
            let r_local_port = u16::from_be_bytes([(r.dwLocalPort & 0xff) as u8, ((r.dwLocalPort >> 8) & 0xff) as u8]);
            let r_remote_port = u16::from_be_bytes([(r.dwRemotePort & 0xff) as u8, ((r.dwRemotePort >> 8) & 0xff) as u8]);
            // Compare both ends. The server-side socket sees:
            //   local = (its listen addr, listen port)
            //   peer  = (client ip, client ephemeral port)
            // The GetExtendedTcpTable row whose local=server-local and
            // remote=client-peer is the matching server-side row; the
            // row with local=client-peer and remote=server-local is the
            // client's row — that's what we want (the connecting PID).
            let row_local_ip = Ipv4Addr::from(r.dwLocalAddr.to_le_bytes());
            let row_remote_ip = Ipv4Addr::from(r.dwRemoteAddr.to_le_bytes());

            // Look for the client side: row_local=peer, row_remote=local.
            if row_local_ip == *peer_v4.ip()
                && r_local_port == peer_v4.port()
                && row_remote_ip == *local_v4.ip()
                && r_remote_port == local_v4.port()
            {
                return Some(r.dwOwningPid);
            }
        }
        None
    }
}

