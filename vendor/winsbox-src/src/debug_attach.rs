//! Phase N-6 step 3: minimal Win32 debug-attach for bash-AV capture.
//!
//! Activated by `WINSBOX_DEBUG_ATTACH=1`. Spawns the target with
//! `DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED`, drains the initial
//! `CREATE_PROCESS_DEBUG_EVENT` on the main thread, then
//! `run_to_completion` resumes + drains debug events on the same
//! broker thread until target exit.
//!
//! `WaitForDebugEvent` is thread-affine to the spawning thread — the
//! whole loop must run on that thread. Cdylib injection is disabled
//! in debug-attach mode (the bash AV fires before any cdylib hook,
//! and the entry-rendezvous would deadlock the debug-event loop).
//!
//! Output: broker stderr (`[debug-attach] …`). Stack/frame walk only
//! when broker is x86_64; cross-arch skips that part.
//!
//! Known limitation: when the broker runs inside a parent Job that
//! has `JOB_OBJECT_LIMIT_BREAKAWAY_OK = 0` and the user lacks
//! `SeDebugPrivilege`, the kernel silently suppresses DebugObject
//! delivery and `WaitForDebugEvent` times out. Run the broker
//! outside such a Job (plain PowerShell, not under Claude Code or
//! a CI agent) to use this diagnostic. See
//! `docs/n6_step3_debug_attach_findings.md`.

use anyhow::{Context, Result};
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use windows::Win32::Foundation::{
    CloseHandle, DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED, EXCEPTION_ACCESS_VIOLATION, HANDLE,
};
use windows::Win32::System::Diagnostics::Debug::{
    ContinueDebugEvent, ReadProcessMemory, WaitForDebugEvent, DEBUG_EVENT,
    CREATE_PROCESS_DEBUG_EVENT, EXCEPTION_DEBUG_EVENT, EXIT_PROCESS_DEBUG_EVENT,
    LOAD_DLL_DEBUG_EVENT, OUTPUT_DEBUG_STRING_EVENT, UNLOAD_DLL_DEBUG_EVENT,
};
#[cfg(target_arch = "x86_64")]
use windows::Win32::System::Diagnostics::Debug::{
    GetThreadContext, CONTEXT, CONTEXT_FULL_AMD64,
};
use windows::Win32::System::Threading::{ResumeThread, INFINITE};
#[cfg(target_arch = "x86_64")]
use windows::Win32::System::Threading::{OpenThread, THREAD_GET_CONTEXT};

#[derive(Clone)]
struct Module { base: u64, name: String }

pub struct DebugSession {
    target_pid: u32,
    modules: Vec<Module>,
    av_logged: bool,
}

impl DebugSession {
    pub fn new(target_pid: u32) -> Self {
        Self { target_pid, modules: Vec::new(), av_logged: false }
    }

    /// Drain the initial `CREATE_PROCESS_DEBUG_EVENT` queued by the
    /// kernel when a `DEBUG_ONLY_THIS_PROCESS` process is created.
    /// 10s timeout: if the kernel didn't queue an event (parent-job
    /// constraint, missing SeDebugPrivilege), surface the failure
    /// instead of hanging.
    pub fn drain_initial(&mut self, target_proc: HANDLE) -> Result<()> {
        eprintln!("[debug-attach] waiting for initial CREATE_PROCESS_DEBUG_EVENT…");
        let mut ev: DEBUG_EVENT = unsafe { zeroed() };
        unsafe { WaitForDebugEvent(&mut ev, 10_000) }
            .context("WaitForDebugEvent(initial)")?;
        self.handle_event(&ev, target_proc);
        let cont = if ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT {
            DBG_EXCEPTION_NOT_HANDLED
        } else { DBG_CONTINUE };
        unsafe { ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont) }
            .context("ContinueDebugEvent(initial)")?;
        Ok(())
    }

    /// Resume the target's main thread and drain debug events until
    /// the target exits. Replaces `WaitForSingleObject(pi.hProcess)`
    /// in DEBUG_ATTACH mode.
    pub fn run_to_completion(
        &mut self, target_proc: HANDLE, target_main_thread: HANDLE,
    ) -> Result<()> {
        unsafe { ResumeThread(target_main_thread); }
        eprintln!("[debug-attach] resumed target main thread; entering event loop");
        loop {
            let mut ev: DEBUG_EVENT = unsafe { zeroed() };
            if let Err(e) = unsafe { WaitForDebugEvent(&mut ev, INFINITE) } {
                eprintln!("[debug-attach] WaitForDebugEvent err: {e:#}");
                break;
            }
            let is_exit = ev.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT
                && ev.dwProcessId == self.target_pid;
            self.handle_event(&ev, target_proc);
            let cont = if ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT {
                DBG_EXCEPTION_NOT_HANDLED
            } else { DBG_CONTINUE };
            let _ = unsafe { ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont) };
            if is_exit { break; }
        }
        Ok(())
    }

    fn handle_event(&mut self, ev: &DEBUG_EVENT, target_proc: HANDLE) {
        match ev.dwDebugEventCode {
            CREATE_PROCESS_DEBUG_EVENT => unsafe {
                let info = ev.u.CreateProcessInfo;
                let base = info.lpBaseOfImage as u64;
                let entry = info.lpStartAddress.map(|f| f as usize).unwrap_or(0);
                let name = read_image_name(target_proc, info.lpImageName as u64, info.fUnicode != 0)
                    .unwrap_or_else(|| "<main_image>".into());
                eprintln!(
                    "[debug-attach] CREATE_PROCESS pid={} tid={} image_base={:#x} entry={:#x} name={:?}",
                    ev.dwProcessId, ev.dwThreadId, base, entry, name,
                );
                self.modules.push(Module { base, name });
                if !info.hFile.is_invalid() { let _ = CloseHandle(info.hFile); }
            },
            LOAD_DLL_DEBUG_EVENT => unsafe {
                let info = ev.u.LoadDll;
                let base = info.lpBaseOfDll as u64;
                let name = read_image_name(target_proc, info.lpImageName as u64, info.fUnicode != 0)
                    .unwrap_or_else(|| "<unnamed>".into());
                eprintln!("[debug-attach] LOAD_DLL base={:#x} name={:?}", base, name);
                self.modules.push(Module { base, name });
                if !info.hFile.is_invalid() { let _ = CloseHandle(info.hFile); }
            },
            UNLOAD_DLL_DEBUG_EVENT => unsafe {
                let base = ev.u.UnloadDll.lpBaseOfDll as u64;
                eprintln!("[debug-attach] UNLOAD_DLL base={:#x}", base);
                self.modules.retain(|m| m.base != base);
            },
            OUTPUT_DEBUG_STRING_EVENT => unsafe {
                let info = ev.u.DebugString;
                let s = read_debug_string(
                    target_proc, info.lpDebugStringData.0 as u64,
                    info.nDebugStringLength as usize, info.fUnicode != 0,
                );
                eprintln!("[debug-attach] OUTPUT_DEBUG_STRING {:?}", s);
            },
            EXCEPTION_DEBUG_EVENT => unsafe {
                let info = ev.u.Exception;
                let code = info.ExceptionRecord.ExceptionCode.0 as u32;
                let addr = info.ExceptionRecord.ExceptionAddress as u64;
                let first = info.dwFirstChance != 0;
                eprintln!(
                    "[debug-attach] EXCEPTION first_chance={} code={:#010x} address={:#x}",
                    if first { 1 } else { 0 }, code, addr,
                );
                if !first && code == EXCEPTION_ACCESS_VIOLATION.0 as u32 && !self.av_logged {
                    self.av_logged = true;
                    self.dump_av(target_proc, ev.dwThreadId, &info.ExceptionRecord);
                }
            },
            EXIT_PROCESS_DEBUG_EVENT => unsafe {
                eprintln!("[debug-attach] EXIT_PROCESS pid={} exit={:#x}",
                    ev.dwProcessId, ev.u.ExitProcess.dwExitCode);
            },
            _ => {}
        }
    }

    fn module_for(&self, addr: u64) -> Option<(&Module, u64)> {
        let mut best: Option<&Module> = None;
        for m in &self.modules {
            if m.base <= addr && best.map_or(true, |b| m.base > b.base) { best = Some(m); }
        }
        best.map(|m| (m, addr - m.base))
    }

    fn dump_av(
        &self, target: HANDLE, tid: u32,
        rec: &windows::Win32::System::Diagnostics::Debug::EXCEPTION_RECORD,
    ) {
        let rip = rec.ExceptionAddress as u64;
        match self.module_for(rip) {
            Some((m, off)) => eprintln!(
                "[debug-attach] AV: RIP={:#x} module={}+{:#x}", rip, m.name, off,
            ),
            None => eprintln!("[debug-attach] AV: RIP={:#x} module=<unknown>", rip),
        }
        if rec.NumberParameters >= 2 {
            let kind = rec.ExceptionInformation[0];
            let acc_addr = rec.ExceptionInformation[1] as u64;
            let kind_s = match kind { 0 => "read", 1 => "write", 8 => "DEP", _ => "?" };
            eprintln!(
                "[debug-attach]     access_kind={}({}) access_addr={:#x}",
                kind, kind_s, acc_addr,
            );
        }
        #[cfg(target_arch = "x86_64")]
        self.dump_stack_x64(target, tid);
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = (target, tid);
            eprintln!("[debug-attach]     (stack walk skipped: broker is not x86_64)");
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn dump_stack_x64(&self, target: HANDLE, tid: u32) {
        let th = match unsafe { OpenThread(THREAD_GET_CONTEXT, false, tid) } {
            Ok(h) => h,
            Err(e) => { eprintln!("[debug-attach]     OpenThread: {e:#}"); return; }
        };
        let mut ctx: Box<CONTEXT> = Box::new(unsafe { zeroed() });
        ctx.ContextFlags = CONTEXT_FULL_AMD64;
        if let Err(e) = unsafe { GetThreadContext(th, &mut *ctx) } {
            eprintln!("[debug-attach]     GetThreadContext: {e:#}");
            unsafe { let _ = CloseHandle(th); }
            return;
        }
        let rsp = ctx.Rsp; let rbp = ctx.Rbp;
        eprintln!("[debug-attach]     rsp={:#x} rbp={:#x}", rsp, rbp);
        let mut buf = [0u64; 8];
        let mut n = 0usize;
        unsafe {
            let _ = ReadProcessMemory(
                target, rsp as *const c_void, buf.as_mut_ptr() as *mut c_void,
                size_of::<[u64; 8]>(), Some(&mut n),
            );
        }
        for i in 0..(n / 8) {
            let v = buf[i];
            match self.module_for(v) {
                Some((m, off)) => eprintln!(
                    "[debug-attach]     stack[{}]={:#x} ({}+{:#x})", i, v, m.name, off,
                ),
                None => eprintln!("[debug-attach]     stack[{}]={:#x}", i, v),
            }
        }
        // Best-effort RBP-chain walk; release MSVC may use FPO so
        // most frames will be unreadable. Stop on first failure.
        let mut cur_rbp = rbp;
        for f in 1..=5u32 {
            if cur_rbp == 0 { break; }
            let mut pair = [0u64; 2];
            let mut nn = 0usize;
            let ok = unsafe {
                ReadProcessMemory(
                    target, cur_rbp as *const c_void, pair.as_mut_ptr() as *mut c_void,
                    16, Some(&mut nn),
                ).is_ok()
            };
            if !ok || nn < 16 { break; }
            let saved_rbp = pair[0]; let ret = pair[1];
            match self.module_for(ret) {
                Some((m, off)) => eprintln!(
                    "[debug-attach]     frame_{}: rbp={:#x} ret={:#x} ({}+{:#x})",
                    f, cur_rbp, ret, m.name, off,
                ),
                None => eprintln!(
                    "[debug-attach]     frame_{}: rbp={:#x} ret={:#x}",
                    f, cur_rbp, ret,
                ),
            }
            if saved_rbp <= cur_rbp { break; }
            cur_rbp = saved_rbp;
        }
        unsafe { let _ = CloseHandle(th); }
    }
}

/// Resolve `lpImageName` (a `*const *const wchar` in target memory).
/// Two-step indirection; either step may fail or yield NULL.
fn read_image_name(target: HANDLE, lp_image_name: u64, unicode: bool) -> Option<String> {
    if lp_image_name == 0 { return None; }
    let mut name_va: u64 = 0;
    let mut n = 0usize;
    unsafe {
        ReadProcessMemory(
            target, lp_image_name as *const c_void,
            &mut name_va as *mut _ as *mut c_void, size_of::<u64>(), Some(&mut n),
        ).ok()?;
    }
    if name_va == 0 { return None; }
    let mut buf = vec![0u8; 1024];
    let mut nn = 0usize;
    unsafe {
        ReadProcessMemory(
            target, name_va as *const c_void, buf.as_mut_ptr() as *mut c_void,
            buf.len(), Some(&mut nn),
        ).ok()?;
    }
    buf.truncate(nn);
    Some(decode_target_string(&buf, unicode))
}

fn read_debug_string(target: HANDLE, va: u64, len: usize, unicode: bool) -> String {
    if va == 0 || len == 0 { return String::new(); }
    let cap = len.min(2048);
    let mut buf = vec![0u8; cap];
    let mut n = 0usize;
    unsafe {
        if ReadProcessMemory(
            target, va as *const c_void, buf.as_mut_ptr() as *mut c_void,
            cap, Some(&mut n),
        ).is_err() { return String::new(); }
    }
    buf.truncate(n);
    decode_target_string(&buf, unicode)
}

fn decode_target_string(buf: &[u8], unicode: bool) -> String {
    if unicode {
        let mut us = Vec::<u16>::with_capacity(buf.len() / 2);
        for ch in buf.chunks_exact(2) {
            let w = u16::from_le_bytes([ch[0], ch[1]]);
            if w == 0 { break; }
            us.push(w);
        }
        String::from_utf16_lossy(&us)
    } else {
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        String::from_utf8_lossy(&buf[..end]).into_owned()
    }
}
