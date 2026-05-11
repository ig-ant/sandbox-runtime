//! Loopback SOCKS5 proxy server. The broker runs this; the sandboxed
//! child reaches it via `HTTP_PROXY=socks5h://127.0.0.1:<port>` etc.
//!
//! Phase 2 responsibilities:
//!   - Bind `TcpListener` on `127.0.0.1:<port>` (fail fast on
//!     WSAEADDRINUSE with a hint to inspect `Get-NetTCPConnection`).
//!   - SOCKS5 NO-AUTH + CONNECT only; reject BIND/UDP-ASSOCIATE.
//!   - ATYP IPv4 / hostname / IPv6.
//!   - Spawn one `std::thread::spawn` per accepted connection (v1).
//!   - Log each accept to stderr (`accept pid=… dst=… status=…`).
//!   - PID lookup via `GetExtendedTcpTable(TCP_TABLE_OWNER_PID_CONNECTIONS)`
//!     for informational logging (WFP is the actual security boundary).

use std::io;
use std::net::{IpAddr, TcpStream};

pub enum Host<'a> {
    Ip(IpAddr),
    Name(&'a str),
}

/// Pluggable dialer so a future upstream HTTP/SOCKS proxy can be
/// chained in without rewiring the SOCKS5 server.
pub trait Dialer: Send + Sync + 'static {
    fn dial(&self, host: &Host<'_>, port: u16) -> io::Result<TcpStream>;
}

/// v1 default — directly `TcpStream::connect` from the broker identity.
pub struct DirectDialer;

impl Dialer for DirectDialer {
    fn dial(&self, _h: &Host<'_>, _p: u16) -> io::Result<TcpStream> {
        todo!("phase 2")
    }
}

/// Skeleton — upstream SOCKS5 chaining. Phase 2 / later.
pub struct UpstreamSocks5 {
    pub host: String,
    pub port: u16,
}

/// Running proxy handle. Drop joins the listener thread.
pub struct Proxy {
    // TODO(phase2): JoinHandle, shutdown channel.
    _private: (),
}

/// Start the SOCKS5 listener on `127.0.0.1:<port>` and return a handle
/// the caller keeps alive for the lifetime of the sandboxed child.
pub fn start(_port: u16, _dialer: Box<dyn Dialer>) -> anyhow::Result<Proxy> {
    todo!("phase 2: TcpListener::bind, thread-per-connection SOCKS5")
}
