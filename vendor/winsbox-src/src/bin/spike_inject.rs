//! Phase B0 spike: inject `spike_cdylib.dll` into a suspended
//! AppContainer-confined target, call its `probe()` from `DllMain`,
//! read back the result via shared memory.
//!
//! Pattern: classic remote-thread injection. Validates that
//! `LoadLibraryW` from a remote thread + Rust cdylib `DllMain`
//! survive an AC token. Phase B will replace the remote-thread
//! trigger with the post-loader entry_trampoline rendezvous
//! (entry_trampoline.rs is currently x86_64-only; the spike
//! deliberately uses the simpler trigger so it works on ARM64
//! today and provides a baseline for the trampoline port).
//!
//! Usage:
//!   spike-inject <target.exe> [extra args...]
//!
//! Exit codes:
//!   0  - probe returned 42 (spike PASS)
//!   1  - injection failed
//!   2  - DllMain ran but probe value mismatch
//!   3  - timeout waiting for DllMain

#[cfg(not(windows))]
fn main() {
    eprintln!("windows only");
    std::process::exit(2);
}

#[cfg(windows)]
#[path = "../util.rs"]
mod util;
#[cfg(windows)]
#[path = "../appcontainer.rs"]
mod appcontainer;
#[cfg(windows)]
#[path = "../acl.rs"]
mod acl;
#[cfg(windows)]
#[path = "../job.rs"]
mod job;

#[cfg(windows)]
fn main() {
    use anyhow::{anyhow, bail, Context, Result};
    use std::ffi::c_void;
    use std::mem::{size_of, zeroed};
    use std::path::PathBuf;
    use util::{pcwstr, wstr};
    use windows::core::{PCSTR, PCWSTR, PWSTR};
    use windows::Win32::Foundation::{
        CloseHandle, DuplicateHandle, GetLastError, DUPLICATE_SAME_ACCESS, HANDLE,
        INVALID_HANDLE_VALUE, NTSTATUS, WAIT_OBJECT_0,
    };
    use windows::Win32::Security::{SECURITY_ATTRIBUTES, SECURITY_CAPABILITIES};
    use windows::Win32::System::Console::{
        GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    };
    use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
    use windows::Win32::System::Memory::{
        CreateFileMappingW, MapViewOfFile, UnmapViewOfFile, VirtualAllocEx,
        FILE_MAP_ALL_ACCESS, MEMORY_MAPPED_VIEW_ADDRESS, MEM_COMMIT, MEM_RESERVE,
        PAGE_READWRITE,
    };
    use windows::Win32::System::Threading::{
        CreateEventW, CreateProcessW, CreateRemoteThread, DeleteProcThreadAttributeList,
        GetCurrentProcess, GetExitCodeProcess, InitializeProcThreadAttributeList,
        ResumeThread, TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
        CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT,
        LPPROC_THREAD_ATTRIBUTE_LIST, LPTHREAD_START_ROUTINE, PROCESS_INFORMATION,
        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, STARTF_USESTDHANDLES,
        STARTUPINFOEXW,
    };

    macro_rules! log {
        ($($a:tt)*) => { eprintln!("[spike-inject] {}", format_args!($($a)*)) };
    }

    /// Layout MUST match `crates/spike-cdylib/src/lib.rs::SpikeBuffer`.
    #[repr(C)]
    struct SpikeBuffer {
        section: u64,
        event: u64,
        view: u64,
        magic: u64,
    }
    const SPIKE_MAGIC: u64 = 0xB0B0_DEAD_BEEF_CAFEu64;

    /// Layout MUST match `crates/spike-cdylib/src/lib.rs::SpikeResult`.
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct SpikeResult {
        probe_result: u32,
        sentinel: u32,
        pid: u32,
        _pad: u32,
    }
    const RESULT_SENTINEL: u32 = 0xCAFE_BABE;

    /// `NtMapViewOfSection` into the target. ipc.rs has a private
    /// equivalent — duplicated here so the spike binary stays
    /// standalone (no module entanglement with the broker IPC).
    fn map_into_target(section: HANDLE, target: HANDLE) -> Result<usize> {
        #[link(name = "ntdll")]
        extern "system" {
            fn NtMapViewOfSection(
                section: HANDLE,
                process: HANDLE,
                base: *mut *mut c_void,
                zero_bits: usize,
                commit: usize,
                offset: *mut i64,
                view_size: *mut usize,
                inherit: u32,
                alloc_type: u32,
                protect: u32,
            ) -> NTSTATUS;
        }
        unsafe {
            let mut base: *mut c_void = std::ptr::null_mut();
            let mut size: usize = 0;
            let mut off: i64 = 0;
            let st = NtMapViewOfSection(
                section, target, &mut base, 0, 0, &mut off, &mut size,
                2, /* ViewUnmap */
                0, /* alloc_type */
                PAGE_READWRITE.0,
            );
            if st.0 < 0 {
                bail!("NtMapViewOfSection: {:#x}", st.0);
            }
            Ok(base as usize)
        }
    }

    fn dup_into(target: HANDLE, src: HANDLE) -> Result<u64> {
        unsafe {
            let mut out = HANDLE::default();
            DuplicateHandle(
                GetCurrentProcess(), src, target, &mut out,
                0, false, DUPLICATE_SAME_ACCESS,
            )
            .context("DuplicateHandle into target")?;
            Ok(out.0 as u64)
        }
    }

    /// Build a wide-char environment block from `(key, value)` pairs.
    /// Format: `K=V\0K=V\0...\0`. Required for CREATE_UNICODE_ENVIRONMENT.
    fn build_env_block(pairs: &[(String, String)]) -> Vec<u16> {
        let mut out = Vec::<u16>::new();
        for (k, v) in pairs {
            out.extend(k.encode_utf16());
            out.push('=' as u16);
            out.extend(v.encode_utf16());
            out.push(0);
        }
        out.push(0);
        out
    }

    /// Locate `spike_cdylib.dll` next to the running binary, falling
    /// back to the workspace target dirs that the project's build
    /// commands populate.
    fn locate_cdylib() -> Result<PathBuf> {
        let exe = std::env::current_exe().context("current_exe")?;
        let exe_dir = exe.parent().ok_or_else(|| anyhow!("exe has no parent"))?;
        let candidates = [
            // Co-located (Phase B production layout).
            exe_dir.join("spike_cdylib.dll"),
            // Workspace target/release for `cargo build -p spike-cdylib --release`.
            exe_dir.parent().unwrap_or(exe_dir).join("release").join("spike_cdylib.dll"),
            // CARGO_TARGET_DIR override: exe in `<target>/debug/`,
            // cdylib in `<target>/release/`.
            exe_dir.parent().map(|p| p.join("release").join("spike_cdylib.dll"))
                .unwrap_or_default(),
        ];
        for c in &candidates {
            if c.exists() {
                return Ok(c.canonicalize().unwrap_or_else(|_| c.clone()));
            }
        }
        // Final fall-through: search CARGO_TARGET_DIR if set.
        if let Ok(td) = std::env::var("CARGO_TARGET_DIR") {
            let p = std::path::Path::new(&td).join("release").join("spike_cdylib.dll");
            if p.exists() {
                return Ok(p);
            }
        }
        bail!(
            "spike_cdylib.dll not found; build with `cargo build -p spike-cdylib --release` first.\n\
             Searched: {candidates:#?}"
        )
    }

    fn run() -> Result<i32> {
        let args: Vec<String> = std::env::args().collect();
        if args.len() < 2 {
            bail!("usage: spike-inject <target.exe> [args...]");
        }
        let target_exe = &args[1];
        let target_args = args[2..].join(" ");
        let dll_path = locate_cdylib()?;
        log!("dll path: {}", dll_path.display());
        log!("target:   {} {}", target_exe, target_args);

        // ── 1. Create AppContainer.
        let ac = appcontainer::AppContainer::create("spike")?;
        log!("AC sid={} folder={}", ac.sid_string, ac.folder.display());

        // ── 2. Job (kill-on-close, UI restrictions).
        let job = job::Job::new()?;

        // ── 3. ACL grants.
        let mut acls = acl::AclJournal::default();
        // Target exe + parent dir (so the AC can read the exe and any
        // adjacent satellite DLLs the loader may look up).
        let target_path = std::path::Path::new(target_exe);
        if let Some(parent) = target_path.parent() {
            // System32/Program Files paths typically already grant
            // "ALL APPLICATION PACKAGES" — these calls become no-ops
            // (icacls returns success) or harmless duplicates.
            let _ = acls.grant(
                parent.to_str().unwrap(), &ac.sid_string, acl::READ_EXECUTE,
            );
        }
        // The cdylib's directory MUST be readable by the AC SID
        // because LoadLibraryW will try to map it.
        let dll_dir = dll_path.parent().ok_or_else(|| anyhow!("dll has no parent"))?;
        acls.grant(dll_dir.to_str().unwrap(), &ac.sid_string, acl::READ_EXECUTE)
            .context("grant cdylib dir")?;
        log!("granted cdylib dir to AC: {}", dll_dir.display());

        // ── 4. Create the result section + event in the broker.
        let sa = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: std::ptr::null_mut(),
            bInheritHandle: false.into(),
        };
        let section = unsafe {
            CreateFileMappingW(
                INVALID_HANDLE_VALUE, Some(&sa), PAGE_READWRITE,
                0, 4096, None,
            )
            .context("CreateFileMappingW")?
        };
        let view_local = unsafe { MapViewOfFile(section, FILE_MAP_ALL_ACCESS, 0, 0, 4096) };
        if view_local.Value.is_null() {
            bail!("MapViewOfFile (broker)");
        }
        unsafe { std::ptr::write_bytes(view_local.Value, 0, 4096) };
        let event = unsafe {
            CreateEventW(Some(&sa), false, false, None).context("CreateEventW")?
        };

        // ── 5. Spawn the target SUSPENDED in the AC.
        //   Build env: target inherits the broker's environment plus
        //   SPIKE_BUFFER, which DllMain reads to find the SpikeBuffer
        //   address (target-VA). We compute that VA AFTER spawn (it's
        //   a VirtualAllocEx result), so we have to either:
        //     (a) write SPIKE_BUFFER to the env BEFORE spawn — then
        //         we need to know the address before allocating,
        //         OR
        //     (b) allocate a *fixed-by-name* token in the env and
        //         patch the SpikeBuffer location into the target's
        //         RTL_USER_PROCESS_PARAMETERS post-spawn.
        //   Easier path (b'): allocate the SpikeBuffer first by
        //   creating-suspended-then-VirtualAllocEx, then PATCH the
        //   target's environment block *before* the loader runs by
        //   writing back into the env memory that
        //   RTL_USER_PROCESS_PARAMETERS points at. That's fragile.
        //
        //   Instead: choose a reserved address range. Tell
        //   VirtualAllocEx to land at a specific high address using
        //   `lpAddress`. ASLR + the AC's memory layout make a fixed
        //   address risky too.
        //
        //   Pragmatic choice: post-spawn, VirtualAllocEx, then
        //   WriteProcessMemory the SPIKE_BUFFER value into the env
        //   block at the location of an env var we placed there with
        //   a 16-char hex placeholder. The placeholder is at a
        //   known offset in our env buffer; we keep that buffer
        //   around (CreateProcess copies it into the child but
        //   we still know its in-broker layout to compute the
        //   in-child VA).
        //
        //   ACTUAL simplest approach: don't use env vars at all.
        //   The cdylib looks at a *named section* whose name is
        //   `spike-buffer-<target-pid>`. Broker creates that section
        //   with explicit AC SID in the SD. After the target is
        //   created and we know its PID, broker creates a section
        //   with that PID in the name, AC SID granted, and writes
        //   the SpikeBuffer into it. Cdylib opens the section by
        //   name from inside DllMain.
        //
        //   But named-object ACL on AC is itself fiddly.
        //
        //   FINAL approach: VirtualAllocEx with a request for a
        //   high address, expect it to land somewhere, then PATCH
        //   the target's env block in-place via
        //   WriteProcessMemory before resuming. We find the env
        //   block by reading the target's PEB ->
        //   ProcessParameters -> Environment.
        //
        //   To keep the spike straightforward we instead use the
        //   simplest variant that works:
        //     - Set SPIKE_BUFFER to a 16-char placeholder in the
        //       env we pass to CreateProcessW.
        //     - After CreateProcessW (suspended) but before
        //       resume, VirtualAllocEx the SpikeBuffer; we now
        //       know its target-VA.
        //     - Read PEB->ProcessParameters->Environment from the
        //       target, scan for "SPIKE_BUFFER=", overwrite the 16
        //       hex chars in-place with the new address.
        //
        //   This is what the code below does.
        let placeholder = "0000000000000000";
        let env_pairs: Vec<(String, String)> = std::env::vars()
            .map(|(k, v)| (k, v))
            .chain(std::iter::once((
                "SPIKE_BUFFER".to_string(),
                placeholder.to_string(),
            )))
            .collect();
        let mut env_block = build_env_block(&env_pairs);

        // CreateProcess proc-thread attribute list with the AC SID.
        let pi = unsafe {
            let mut size = 0usize;
            let _ = InitializeProcThreadAttributeList(
                LPPROC_THREAD_ATTRIBUTE_LIST::default(), 1, 0, &mut size,
            );
            let mut attr_buf = vec![0u8; size];
            let attrs = LPPROC_THREAD_ATTRIBUTE_LIST(attr_buf.as_mut_ptr() as *mut c_void);
            InitializeProcThreadAttributeList(attrs, 1, 0, &mut size)
                .context("InitializeProcThreadAttributeList")?;
            let caps = SECURITY_CAPABILITIES {
                AppContainerSid: ac.sid,
                Capabilities: std::ptr::null_mut(),
                CapabilityCount: 0,
                Reserved: 0,
            };
            UpdateProcThreadAttribute(
                attrs, 0,
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
                Some(&caps as *const _ as *const c_void),
                size_of::<SECURITY_CAPABILITIES>(),
                None, None,
            )
            .context("UpdateProcThreadAttribute(SEC_CAPS)")?;

            let mut si: STARTUPINFOEXW = zeroed();
            si.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
            si.lpAttributeList = attrs;
            si.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
            si.StartupInfo.hStdInput  = GetStdHandle(STD_INPUT_HANDLE).unwrap_or_default();
            si.StartupInfo.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE).unwrap_or_default();
            si.StartupInfo.hStdError  = GetStdHandle(STD_ERROR_HANDLE).unwrap_or_default();

            let cmdline_str = if target_args.is_empty() {
                format!("\"{}\"", target_exe)
            } else {
                format!("\"{}\" {}", target_exe, target_args)
            };
            let mut cmd = wstr(&cmdline_str);
            let cwd = ac.folder.to_string_lossy().to_string();
            let cwd_w = wstr(&cwd);

            let flags = EXTENDED_STARTUPINFO_PRESENT
                | CREATE_UNICODE_ENVIRONMENT
                | CREATE_SUSPENDED;
            let mut pi: PROCESS_INFORMATION = zeroed();
            CreateProcessW(
                None, PWSTR(cmd.as_mut_ptr()), None, None, true,
                flags, Some(env_block.as_mut_ptr() as *mut c_void),
                pcwstr(&cwd_w),
                &si.StartupInfo, &mut pi,
            )
            .with_context(|| format!("CreateProcessW({})", target_exe))?;
            DeleteProcThreadAttributeList(attrs);
            let _ = &caps;
            pi
        };
        log!("spawned suspended pid={}", pi.dwProcessId);

        // Best-effort job assignment. Some AC + parent-process
        // combinations refuse later AssignProcessToJobObject on
        // already-jobbed processes; not fatal for the spike.
        if let Err(e) = job.assign(pi.hProcess) {
            log!("job.assign failed (non-fatal for spike): {e:#}");
        }

        // ── 6. Set up the result section + event in the target.
        let target_section_h = dup_into(pi.hProcess, section)?;
        let target_event_h = dup_into(pi.hProcess, event)?;
        let target_view = map_into_target(section, pi.hProcess)?;
        log!(
            "target: section={:#x} event={:#x} view@{:#x}",
            target_section_h, target_event_h, target_view
        );

        // ── 7. Allocate the SpikeBuffer in the target and write it.
        let buf_va = unsafe {
            let p = VirtualAllocEx(
                pi.hProcess, None, 4096,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE,
            );
            if p.is_null() {
                bail!("VirtualAllocEx(SpikeBuffer): {:?}", GetLastError());
            }
            let buf = SpikeBuffer {
                section: target_section_h,
                event: target_event_h,
                view: target_view as u64,
                magic: SPIKE_MAGIC,
            };
            let mut n = 0usize;
            WriteProcessMemory(
                pi.hProcess, p,
                &buf as *const _ as *const c_void,
                size_of::<SpikeBuffer>(),
                Some(&mut n),
            )
            .context("WriteProcessMemory(SpikeBuffer)")?;
            p as usize
        };
        log!("SpikeBuffer @ {:#x} (target VA)", buf_va);

        // ── 8. Patch the target's env block: replace the 16-char
        //      placeholder for SPIKE_BUFFER with the real hex VA.
        //      The env block is an exact copy of the buffer we
        //      passed in `env_block`, located via
        //      PEB->ProcessParameters->Environment in the target.
        patch_target_env_for_spike_buffer(pi.hProcess, &env_block, placeholder, buf_va)?;
        log!("env block patched with SPIKE_BUFFER={:016x}", buf_va);

        // ── 9. Resume the main thread; let the loader run.
        unsafe { ResumeThread(pi.hThread) };

        // Brief settle so the loader has a moment to map system
        // DLLs before we drop a remote thread on it. CreateRemoteThread
        // serialises with the loader lock anyway, so this is mostly
        // for cleaner logs in the timeout-fail mode.
        // SPIKE_SLEEP_MS overrides the default 150ms (set 0 to skip).
        let sleep_ms: u64 = std::env::var("SPIKE_SLEEP_MS")
            .ok().and_then(|v| v.parse().ok()).unwrap_or(150);
        if sleep_ms > 0 {
            std::thread::sleep(std::time::Duration::from_millis(sleep_ms));
        }
        // Check whether the target is still alive at this point.
        let mut pcode: u32 = 0;
        unsafe { let _ = GetExitCodeProcess(pi.hProcess, &mut pcode); }
        const STILL_ACTIVE: u32 = 259;
        if pcode != STILL_ACTIVE {
            log!("target exited before injection (code {:#x}) — typical \
                  AC-incompatible loader (see P13 for MSYS2)", pcode);
            unsafe {
                let _ = CloseHandle(pi.hThread);
                let _ = CloseHandle(pi.hProcess);
                let _ = UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS {
                    Value: view_local.Value,
                });
                let _ = CloseHandle(section);
                let _ = CloseHandle(event);
            }
            return Ok(1);
        }

        // ── 10. Inject: CreateRemoteThread → LoadLibraryW(dll_path).
        // System DLL bases match between processes per session, so
        // the broker's kernel32!LoadLibraryW VA is also valid in the
        // target. (Same invariant entry_trampoline.cpw_address relies on.)
        let load_library_w = unsafe {
            let m = GetModuleHandleW(PCWSTR(wstr("kernel32.dll").as_ptr()))
                .context("GetModuleHandleW(kernel32)")?;
            GetProcAddress(m, PCSTR(b"LoadLibraryW\0".as_ptr()))
                .ok_or_else(|| anyhow!("GetProcAddress(LoadLibraryW)"))?
        };
        let dll_path_w: Vec<u16> = dll_path.to_string_lossy().encode_utf16()
            .chain(std::iter::once(0)).collect();
        let dll_path_remote = unsafe {
            let p = VirtualAllocEx(
                pi.hProcess, None, dll_path_w.len() * 2,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE,
            );
            if p.is_null() {
                bail!("VirtualAllocEx(dll_path): {:?}", GetLastError());
            }
            let mut n = 0usize;
            WriteProcessMemory(
                pi.hProcess, p,
                dll_path_w.as_ptr() as *const c_void,
                dll_path_w.len() * 2, Some(&mut n),
            )
            .context("WriteProcessMemory(dll_path)")?;
            p
        };
        let inject_thread = unsafe {
            let start: LPTHREAD_START_ROUTINE = Some(std::mem::transmute(load_library_w));
            CreateRemoteThread(
                pi.hProcess, None, 0, start,
                Some(dll_path_remote), 0, None,
            )
            .context("CreateRemoteThread(LoadLibraryW)")?
        };
        log!("CreateRemoteThread → LoadLibraryW dispatched");

        // ── 11. Wait for DllMain to signal completion.
        let result_status = unsafe { WaitForSingleObject(event, 10_000) };
        let outcome: i32 = if result_status == WAIT_OBJECT_0 {
            // Read the section.
            let res = unsafe {
                std::ptr::read_volatile(view_local.Value as *const SpikeResult)
            };
            log!(
                "DllMain reported: probe={} sentinel={:#x} pid={}",
                res.probe_result, res.sentinel, res.pid
            );
            if res.sentinel != RESULT_SENTINEL {
                log!("FAIL: sentinel mismatch (got {:#x}, want {:#x})",
                     res.sentinel, RESULT_SENTINEL);
                2
            } else if res.probe_result != 42 {
                log!("FAIL: probe returned {} not 42", res.probe_result);
                2
            } else if res.pid != pi.dwProcessId {
                log!("FAIL: pid mismatch (DllMain saw {}, broker spawned {})",
                     res.pid, pi.dwProcessId);
                2
            } else {
                log!("PASS: probe()=42 from pid {}", res.pid);
                0
            }
        } else {
            log!("FAIL: timed out (10s) waiting for DllMain signal");
            // Wait briefly on the inject thread to learn the
            // LoadLibraryW return value (HMODULE; 0 = failure).
            let _ = unsafe { WaitForSingleObject(inject_thread, 500) };
            let mut tcode: u32 = 0;
            unsafe { let _ = GetExitCodeProcess(inject_thread, &mut tcode); }
            log!("LoadLibraryW thread exit code = {:#x} (HMODULE; 0 = load failed)", tcode);
            // Also check whether the target process is still alive.
            let mut pcode: u32 = 0;
            unsafe { let _ = GetExitCodeProcess(pi.hProcess, &mut pcode); }
            const STILL_ACTIVE: u32 = 259;
            if pcode != STILL_ACTIVE {
                log!("target process exited with code {:#x} (likely crashed)", pcode);
            } else {
                log!("target process still running; LoadLibraryW failed for other reason");
            }
            3
        };

        // ── 12. Clean up: terminate target + handles + AC profile.
        unsafe {
            let _ = TerminateProcess(pi.hProcess, 0);
            let _ = CloseHandle(inject_thread);
            let _ = CloseHandle(pi.hThread);
            let _ = CloseHandle(pi.hProcess);
            let _ = UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS {
                Value: view_local.Value,
            });
            let _ = CloseHandle(section);
            let _ = CloseHandle(event);
        }
        drop(acls);
        drop(job);
        drop(ac);
        Ok(outcome)
    }

    /// Read the target's PEB→RTL_USER_PROCESS_PARAMETERS→Environment
    /// pointer, scan for `SPIKE_BUFFER=<placeholder>`, and overwrite
    /// the placeholder bytes with the real hex VA.
    fn patch_target_env_for_spike_buffer(
        target: HANDLE,
        local_env: &[u16],
        placeholder: &str,
        buf_va: usize,
    ) -> Result<()> {
        use windows::Wdk::System::Threading::{NtQueryInformationProcess, PROCESSINFOCLASS};
        use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
        use windows::Win32::System::Threading::PROCESS_BASIC_INFORMATION;
        unsafe {
            let mut pbi: PROCESS_BASIC_INFORMATION = zeroed();
            let mut ret = 0u32;
            let st = NtQueryInformationProcess(
                target, PROCESSINFOCLASS(0), /* ProcessBasicInformation */
                &mut pbi as *mut _ as *mut c_void,
                size_of::<PROCESS_BASIC_INFORMATION>() as u32,
                &mut ret,
            );
            if st.0 < 0 {
                bail!("NtQueryInformationProcess: {:#x}", st.0);
            }
            let peb_addr = pbi.PebBaseAddress as usize;

            // PEB.ProcessParameters at offset 0x20 on x64/ARM64 user-mode PEB.
            let mut params_ptr: usize = 0;
            let mut n = 0usize;
            ReadProcessMemory(
                target, (peb_addr + 0x20) as *const c_void,
                &mut params_ptr as *mut _ as *mut c_void,
                size_of::<usize>(), Some(&mut n),
            )
            .context("read PEB.ProcessParameters")?;

            // RTL_USER_PROCESS_PARAMETERS.Environment is at offset 0x80
            // and EnvironmentSize at 0x3F0 on x64/ARM64. Use the
            // documented field offsets — these are stable since
            // Windows 7 and identical for ARM64 (the struct is
            // arch-independent in user-mode PEB layout for 64-bit).
            let mut env_ptr: usize = 0;
            ReadProcessMemory(
                target, (params_ptr + 0x80) as *const c_void,
                &mut env_ptr as *mut _ as *mut c_void,
                size_of::<usize>(), Some(&mut n),
            )
            .context("read PROC_PARAMS.Environment")?;

            // RTL_USER_PROCESS_PARAMETERS.EnvironmentSize is at
            // offset 0x3F0 (Windows 7+ x64/ARM64). Read it to know
            // exactly how big the target's env block is.
            let mut env_size: usize = 0;
            ReadProcessMemory(
                target, (params_ptr + 0x3F0) as *const c_void,
                &mut env_size as *mut _ as *mut c_void,
                size_of::<usize>(), Some(&mut n),
            )
            .context("read PROC_PARAMS.EnvironmentSize")?;
            // Fall back to local size if EnvironmentSize is
            // implausible (some struct-offset shifts have happened
            // historically; guard against reading nonsense).
            let env_byte_len = if env_size > 0 && env_size < 1 << 20 {
                env_size
            } else {
                (local_env.len() * 2).max(65536)
            };
            eprintln!(
                "[spike-inject] env_ptr={:#x} env_size={} (local would be {})",
                env_ptr, env_byte_len, local_env.len() * 2,
            );
            let mut env_buf = vec![0u8; env_byte_len];
            ReadProcessMemory(
                target, env_ptr as *const c_void,
                env_buf.as_mut_ptr() as *mut c_void,
                env_byte_len, Some(&mut n),
            )
            .context("read target env block")?;

            // Find "SPIKE_BUFFER=" + placeholder in the wide block.
            let needle: Vec<u16> = format!("SPIKE_BUFFER={placeholder}")
                .encode_utf16().collect();
            let needle_bytes: &[u8] = std::slice::from_raw_parts(
                needle.as_ptr() as *const u8, needle.len() * 2,
            );
            let pos = env_buf.windows(needle_bytes.len())
                .position(|w| w == needle_bytes);
            let pos = match pos {
                Some(p) => p,
                None => {
                    // Diagnostics: search for the bare key, and
                    // dump the first 1 KiB of env content as wide.
                    let key_only: Vec<u16> = "SPIKE_BUFFER=".encode_utf16().collect();
                    let key_bytes: &[u8] = std::slice::from_raw_parts(
                        key_only.as_ptr() as *const u8, key_only.len() * 2,
                    );
                    let key_pos = env_buf.windows(key_bytes.len())
                        .position(|w| w == key_bytes);
                    eprintln!(
                        "[spike-inject] needle (with placeholder) not found; \
                         bare key at {:?}",
                        key_pos
                    );
                    if let Some(kp) = key_pos {
                        // Show the 64 wide chars after the key for context.
                        let from = kp + key_bytes.len();
                        let len = std::cmp::min(env_buf.len() - from, 128);
                        let slice = &env_buf[from..from + len];
                        let words: Vec<u16> = slice.chunks(2)
                            .filter(|c| c.len() == 2)
                            .map(|c| u16::from_le_bytes([c[0], c[1]]))
                            .collect();
                        let s: String = words.iter().take_while(|&&w| w != 0)
                            .map(|&w| char::from_u32(w as u32).unwrap_or('?')).collect();
                        eprintln!("[spike-inject] SPIKE_BUFFER value in target = {s:?}");
                    }
                    bail!("SPIKE_BUFFER placeholder not found in target env block");
                }
            };
            // Position of the placeholder's first wide character in
            // the env block (bytes).
            let placeholder_byte_off = pos + ("SPIKE_BUFFER=".len() * 2);

            // Build the replacement: 16 lower-case hex chars (UTF-16).
            let hex = format!("{:016x}", buf_va);
            let hex_w: Vec<u16> = hex.encode_utf16().collect();
            assert_eq!(hex_w.len(), 16);
            let hex_bytes: &[u8] = std::slice::from_raw_parts(
                hex_w.as_ptr() as *const u8, 16 * 2,
            );

            let mut wn = 0usize;
            WriteProcessMemory(
                target, (env_ptr + placeholder_byte_off) as *mut c_void,
                hex_bytes.as_ptr() as *const c_void,
                hex_bytes.len(), Some(&mut wn),
            )
            .context("WriteProcessMemory(env placeholder)")?;
        }
        Ok(())
    }

    let code = match run() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[spike-inject] ERROR: {e:#}");
            1
        }
    };
    std::process::exit(code);
}
