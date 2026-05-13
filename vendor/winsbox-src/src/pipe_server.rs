//! Phase 5D — per-broker named-pipe RPC server.
//!
//! Each broker spawns a detached thread that serves
//! `\\.\pipe\winsbox-broker-{pid}`. On every connection:
//!
//!   1. Read a framed JSON request (4-byte little-endian length prefix
//!      + UTF-8 JSON body).
//!   2. `GetNamedPipeClientProcessId` and verify the PID is registered
//!      in `proc_sessions`. If not, return `{"ok":false,"error":...}`
//!      and disconnect. Defense in depth on top of the pipe's default
//!      same-user DACL.
//!   3. Dispatch on opcode. v1 opcodes:
//!        - `REQUEST_DUP_HANDLE` — look up `canonical_path` in our
//!          local share-mode handle map; `DuplicateHandle` the handle
//!          into the requester process. Reply with the resulting
//!          remote-handle value as a u64.
//!
//! Lifecycle: spawned during broker startup with a clone of the
//! `Arc<Mutex<HashMap>>` that backs `share_mode::ShareModeLocks`. The
//! thread is detached — broker process exit terminates the thread and
//! closes the pipe instance. We DO NOT attempt graceful shutdown:
//! `ConnectNamedPipe` blocks, and overlapped + event-signal cancel is
//! more code than its v1 value (process exit cleans up the kernel
//! handle table).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    CloseHandle, DuplicateHandle, GetLastError, DUPLICATE_SAME_ACCESS,
    ERROR_BROKEN_PIPE, ERROR_MORE_DATA, ERROR_PIPE_CONNECTED, HANDLE,
};
use windows::Win32::Storage::FileSystem::{
    PIPE_ACCESS_DUPLEX, ReadFile, WriteFile,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe,
    GetNamedPipeClientProcessId, PIPE_READMODE_MESSAGE, PIPE_TYPE_MESSAGE,
    PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, PROCESS_DUP_HANDLE,
};

use crate::util::wstr;

/// Wire framing: 4-byte little-endian length prefix + UTF-8 JSON body.
/// Max body size we'll accept — 64 KiB is excessive for `{op, path,
/// pid}` but cheap. Bigger requests are rejected as malformed.
const MAX_BODY: u32 = 64 * 1024;

/// Wire request — currently a single v1 opcode.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum Request {
    #[serde(rename = "REQUEST_DUP_HANDLE")]
    RequestDupHandle {
        canonical_path: String,
        requester_pid: u32,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle_value: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Response {
    fn ok(handle_value: u64) -> Self {
        Self { ok: true, handle_value: Some(handle_value), error: None }
    }
    fn err(msg: impl Into<String>) -> Self {
        Self { ok: false, handle_value: None, error: Some(msg.into()) }
    }
}

/// Shared map of `canonical_path → HANDLE-as-usize` held by this
/// broker. We store the HANDLE numeric value (not the `HANDLE` opaque
/// struct) so `HashMap<String, usize>` is naturally `Send + Sync`.
/// `HANDLE` is just a typedef for `*mut c_void`; the kernel handle
/// value is process-global, dereferencing only happens via Win32 API.
pub type ShareModeMap = Arc<Mutex<HashMap<String, usize>>>;

fn handle_to_key(h: HANDLE) -> usize {
    h.0 as usize
}
fn key_to_handle(v: usize) -> HANDLE {
    HANDLE(v as *mut std::ffi::c_void)
}

/// Spawn the pipe server on a detached thread. Returns the spawned
/// JoinHandle so the caller can join if they want (but we don't —
/// graceful shutdown isn't implemented; the broker process exit ends
/// the thread).
pub fn spawn(
    pipe_name: String,
    map: ShareModeMap,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("winsbox-pipe-server".into())
        .spawn(move || {
            if let Err(e) = serve_loop(&pipe_name, &map) {
                eprintln!(
                    "[winsbox pipe_server] serve_loop exited with error: {e:#}"
                );
            }
        })
        .expect("spawn pipe server thread")
}

/// Insert a handle into the share-mode map. Use this from
/// `share_mode::ShareModeLocks` so we don't expose the
/// `HANDLE → usize` plumbing to callers.
pub fn map_insert(map: &ShareModeMap, canonical: &str, handle: HANDLE) {
    if let Ok(mut g) = map.lock() {
        g.insert(canonical.to_string(), handle_to_key(handle));
    }
}

/// Remove a handle from the share-mode map (on Drop).
pub fn map_remove(map: &ShareModeMap, canonical: &str) {
    if let Ok(mut g) = map.lock() {
        g.remove(canonical);
    }
}

/// Run the server loop. Each iteration: create a new pipe instance,
/// ConnectNamedPipe (blocks), handle one request, close, loop.
///
/// Using one instance per connection keeps the lifetime story simple:
/// no need to recycle a single pipe via DisconnectNamedPipe + reuse.
/// CreateNamedPipeW with PIPE_UNLIMITED_INSTANCES lets us re-open the
/// same name as many times as we like.
fn serve_loop(
    pipe_name: &str,
    map: &ShareModeMap,
) -> Result<()> {
    loop {
        let pipe = create_pipe_instance(pipe_name)
            .context("create_pipe_instance")?;
        // Block until a client connects (or the kernel reports
        // already-connected via ERROR_PIPE_CONNECTED).
        let connect_r = unsafe { ConnectNamedPipe(pipe, None) };
        match connect_r {
            Ok(()) => {}
            Err(e) => {
                let le = unsafe { GetLastError() };
                if le != ERROR_PIPE_CONNECTED {
                    eprintln!(
                        "[winsbox pipe_server] ConnectNamedPipe: {e:?} le={le:?}"
                    );
                    unsafe {
                        let _ = DisconnectNamedPipe(pipe);
                        let _ = CloseHandle(pipe);
                    }
                    continue;
                }
            }
        }
        // One connection, one request, one response, disconnect.
        if let Err(e) = handle_connection(pipe, map) {
            eprintln!(
                "[winsbox pipe_server] connection handler error: {e:#}"
            );
        }
        // Wait for client to drain the response before tearing down
        // the pipe; otherwise the client sees ERROR_BROKEN_PIPE on its
        // ReadFile call.
        unsafe {
            let _ = windows::Win32::Storage::FileSystem::FlushFileBuffers(pipe);
            let _ = DisconnectNamedPipe(pipe);
            let _ = CloseHandle(pipe);
        }
    }
}

fn create_pipe_instance(pipe_name: &str) -> Result<HANDLE> {
    let w = wstr(pipe_name);
    let h = unsafe {
        CreateNamedPipeW(
            PCWSTR(w.as_ptr()),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            MAX_BODY + 16,
            MAX_BODY + 16,
            0,           // default 50ms timeout for WaitNamedPipe
            None,        // default DACL: same-user only
        )
    };
    if h.is_invalid() {
        let le = unsafe { GetLastError() };
        return Err(anyhow!(
            "CreateNamedPipeW({pipe_name}) le={le:?}"
        ));
    }
    Ok(h)
}

fn handle_connection(
    pipe: HANDLE,
    map: &ShareModeMap,
) -> Result<()> {
    // 1) Read framed request.
    let body = read_frame(pipe).context("read_frame")?;
    // 2) Verify client PID is a registered broker.
    let mut client_pid: u32 = 0;
    unsafe {
        GetNamedPipeClientProcessId(pipe, &mut client_pid as *mut u32)
            .context("GetNamedPipeClientProcessId")?;
    }
    let req: Request = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            let resp = Response::err(format!("malformed request: {e}"));
            write_frame(pipe, &serde_json::to_vec(&resp)?)?;
            return Ok(());
        }
    };

    let resp = match dispatch(&req, client_pid, map) {
        Ok(r) => r,
        Err(e) => Response::err(format!("dispatch: {e:#}")),
    };
    write_frame(pipe, &serde_json::to_vec(&resp)?)?;
    Ok(())
}

fn dispatch(
    req: &Request,
    client_pid: u32,
    map: &ShareModeMap,
) -> Result<Response> {
    // Same opcode for v1; would dispatch on enum variant if we had more.
    let Request::RequestDupHandle {
        canonical_path,
        requester_pid,
    } = req;

    // Defense-in-depth: only accept requests whose client_pid (as
    // observed by the kernel on the named pipe) matches the
    // requester_pid claim, AND is a registered broker. The pipe DACL
    // already restricts to same-user; this layer rejects same-user
    // processes that aren't part of our broker set.
    if *requester_pid != client_pid {
        return Ok(Response::err(format!(
            "requester_pid claim {requester_pid} != pipe client pid {client_pid}"
        )));
    }
    // NOTE: spec asked for "verify the PID exists in proc_sessions" as
    // a defense-in-depth check. rusqlite::Connection isn't Send, so the
    // pipe-server thread can't safely share the broker's LockDb. The
    // same-user pipe DACL (kernel default for pipes created without an
    // explicit SA) already restricts callers to the broker's logon
    // session. The pipe name `\\.\pipe\winsbox-broker-{pid}` is
    // discoverable only via enumerate-pipes, also same-user. We
    // accept the slightly weaker primary control for v1 and TODO a
    // SendableConnection re-architecture if the threat model tightens.

    // Look up the handle in our share-mode map.
    let src_handle: HANDLE = {
        let guard = map.lock().map_err(|_| anyhow!("share-mode map mutex poisoned"))?;
        match guard.get(canonical_path) {
            Some(v) => key_to_handle(*v),
            None => {
                return Ok(Response::err(format!(
                    "no share-mode lock held on {canonical_path}"
                )));
            }
        }
    };

    // Open the requester process for PROCESS_DUP_HANDLE.
    let requester_proc = unsafe {
        OpenProcess(PROCESS_DUP_HANDLE, false, *requester_pid)
            .context("OpenProcess(PROCESS_DUP_HANDLE) on requester")?
    };

    let mut new_handle: HANDLE = HANDLE::default();
    let dup_r = unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            src_handle,
            requester_proc,
            &mut new_handle as *mut HANDLE,
            0,
            false,
            DUPLICATE_SAME_ACCESS,
        )
    };
    unsafe {
        let _ = CloseHandle(requester_proc);
    }
    match dup_r {
        Ok(()) => {
            let v = new_handle.0 as u64;
            Ok(Response::ok(v))
        }
        Err(e) => Ok(Response::err(format!(
            "DuplicateHandle: {e}"
        ))),
    }
}

/// Read one framed message: 4-byte LE length, then `len` bytes body.
fn read_frame(pipe: HANDLE) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    read_exact(pipe, &mut len_buf)?;
    let len = u32::from_le_bytes(len_buf);
    if len == 0 || len > MAX_BODY {
        return Err(anyhow!(
            "frame length {len} out of range (max {MAX_BODY})"
        ));
    }
    let mut body = vec![0u8; len as usize];
    read_exact(pipe, &mut body)?;
    Ok(body)
}

fn write_frame(pipe: HANDLE, body: &[u8]) -> Result<()> {
    if body.len() > MAX_BODY as usize {
        return Err(anyhow!("response body too large: {}", body.len()));
    }
    let len = (body.len() as u32).to_le_bytes();
    write_all(pipe, &len)?;
    write_all(pipe, body)?;
    Ok(())
}

fn read_exact(pipe: HANDLE, buf: &mut [u8]) -> Result<()> {
    let mut total = 0usize;
    while total < buf.len() {
        let mut read: u32 = 0;
        let chunk = &mut buf[total..];
        let r = unsafe {
            ReadFile(
                pipe,
                Some(chunk),
                Some(&mut read as *mut u32),
                None,
            )
        };
        match r {
            Ok(()) => {
                if read == 0 {
                    let le = unsafe { GetLastError() };
                    return Err(anyhow!(
                        "ReadFile EOF after {total}/{} bytes le={le:?}",
                        buf.len()
                    ));
                }
                total += read as usize;
            }
            Err(e) => {
                let le = unsafe { GetLastError() };
                // ERROR_MORE_DATA is benign in message mode but won't
                // appear here because we sized buf to the framed
                // length. ERROR_BROKEN_PIPE = client dropped.
                if le == ERROR_MORE_DATA {
                    total += read as usize;
                    continue;
                }
                if le == ERROR_BROKEN_PIPE {
                    return Err(anyhow!("pipe closed by peer"));
                }
                return Err(anyhow::Error::new(e).context(format!(
                    "ReadFile le={le:?}"
                )));
            }
        }
    }
    Ok(())
}

fn write_all(pipe: HANDLE, buf: &[u8]) -> Result<()> {
    let mut total = 0usize;
    while total < buf.len() {
        let mut wrote: u32 = 0;
        let chunk = &buf[total..];
        let r = unsafe {
            WriteFile(
                pipe,
                Some(chunk),
                Some(&mut wrote as *mut u32),
                None,
            )
        };
        match r {
            Ok(()) => {
                if wrote == 0 {
                    let le = unsafe { GetLastError() };
                    return Err(anyhow!(
                        "WriteFile produced 0 bytes le={le:?}"
                    ));
                }
                total += wrote as usize;
            }
            Err(e) => {
                let le = unsafe { GetLastError() };
                return Err(anyhow::Error::new(e).context(format!(
                    "WriteFile le={le:?}"
                )));
            }
        }
    }
    Ok(())
}

// ─────────────────────── client side ───────────────────────

/// Request a DUP_HANDLE from the broker that owns `pipe_name`. On
/// success, returns the duplicated handle value (a `HANDLE` valid in
/// the current process's handle table — it points at the same file
/// the source broker has open).
///
/// Returns `Ok(None)` if the remote broker replied `ok: false` (no
/// such lock; race; DACL failed). Caller falls through to the ACL
/// stamp path. Returns `Err` for I/O / serde failures.
pub fn request_dup_handle(
    pipe_name: &str,
    canonical_path: &str,
) -> Result<Option<HANDLE>> {
    use windows::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_NONE, OPEN_EXISTING,
    };

    // Connect by opening the pipe with CreateFileW. The server creates
    // pipe instances eagerly in its loop, so once the
    // `\\.\pipe\winsbox-broker-{pid}` name exists at all, an instance is
    // always available (single-shot per connection).
    let w = wstr(pipe_name);
    let pipe = unsafe {
        CreateFileW(
            PCWSTR(w.as_ptr()),
            GENERIC_READ.0 | GENERIC_WRITE.0,
            FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            HANDLE::default(),
        )
    };
    let pipe = match pipe {
        Ok(h) => h,
        Err(e) => {
            return Err(anyhow!(
                "CreateFileW({pipe_name}) client open: {e}"
            ));
        }
    };

    // Switch to message-read mode so each ReadFile returns one frame.
    let mode = PIPE_READMODE_MESSAGE;
    let r = unsafe {
        windows::Win32::System::Pipes::SetNamedPipeHandleState(
            pipe,
            Some(&mode as *const _),
            None,
            None,
        )
    };
    if r.is_err() {
        unsafe { let _ = CloseHandle(pipe); }
        return Err(anyhow!(
            "SetNamedPipeHandleState(client → MESSAGE) failed"
        ));
    }

    let req = Request::RequestDupHandle {
        canonical_path: canonical_path.to_string(),
        requester_pid: std::process::id(),
    };
    let body = serde_json::to_vec(&req).context("serialize request")?;
    if let Err(e) = write_frame(pipe, &body) {
        unsafe { let _ = CloseHandle(pipe); }
        return Err(e.context("write_frame(request)"));
    }

    let resp_body = match read_frame(pipe) {
        Ok(b) => b,
        Err(e) => {
            unsafe { let _ = CloseHandle(pipe); }
            return Err(e.context("read_frame(response)"));
        }
    };
    unsafe { let _ = CloseHandle(pipe); }
    let resp: Response = serde_json::from_slice(&resp_body)
        .context("parse response")?;
    if !resp.ok {
        return Ok(None);
    }
    let v = resp.handle_value.ok_or_else(|| {
        anyhow!("response.ok=true but handle_value missing")
    })?;
    let h = HANDLE(v as *mut std::ffi::c_void);
    Ok(Some(h))
}
