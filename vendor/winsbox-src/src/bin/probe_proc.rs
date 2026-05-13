//! `probe_proc` — Phase 4.5 v3 helper. Exercises one of:
//!   - `open-process <pid> <access-mask-hex>` — `OpenProcess(mask, FALSE, pid)`.
//!     `<pid>` may be the literal string `"broker"` to read the PID
//!     from the `WINSBOX_BROKER_PID` env var (set by launch.rs).
//!   - `open-process-via-env <access-mask-hex>` — same as above but
//!     always reads PID from `WINSBOX_BROKER_PID`. Used by Layer 5
//!     tests (G4, G6) so the broker PID doesn't need to traverse CLI
//!     quoting layers.
//!   - `set-windows-hook`                     — `SetWindowsHookExW(WH_GETMESSAGE,
//!                                              hmod=&self_image, threadid=0)`.
//!                                              Global hook *requires* DLL
//!                                              injection; without
//!                                              EXTENSION_POINT_DISABLE the
//!                                              call gets as far as
//!                                              `ERROR_HOOK_NEEDS_HMOD`
//!                                              (1428); with the mitigation
//!                                              it returns 5 (ACCESS_DENIED)
//!                                              up front.
//!   - `mitigation-query`                     — print the active process
//!                                              mitigation policies (CFG,
//!                                              Extension-Point disable,
//!                                              Image-Load policy, Font
//!                                              disable). Used by G5 to
//!                                              confirm the Layer-1 stack
//!                                              actually reaches the child.
//!   - `enum-windows`                         — `EnumWindows` (count desktop windows).
//!   - `read-clipboard`                       — `OpenClipboard(NULL)` + `GetClipboardData`.
//!   - `write-clipboard <text>`               — `OpenClipboard` + `SetClipboardData`.
//!   - `global-atom-add <name>`               — `GlobalAddAtomW` (no delete; see fn note).
//!   - `global-atom-find <name>`              — `GlobalFindAtomW` (host-side companion).
//!   - `set-system-param`                     — `SystemParametersInfoW(SPI_SETMOUSESPEED)`.
//!   - `read-file <path>`                     — `CreateFileW(GENERIC_READ, FILE_SHARE_READ,
//!                                              OPEN_EXISTING)` + ReadFile a few bytes.
//!                                              Phase 5B (J1) uses this to assert the broker's
//!                                              share-mode-0 lock causes the sandbox child's
//!                                              read to fail with SHARING_VIOLATION (err=32).
//!
//! Each subcommand exits 0 on success, prints `<NAME>_OK` then `<NAME>_FAIL hr=0x<hex>` on failure.
//! Used by the winsbox-wfp matrix to verify Phase 4.5 v3 layers actually
//! block the expected primitives.

#[cfg(not(windows))]
fn main() {
    eprintln!("probe_proc: Windows only");
    std::process::exit(2);
}

#[cfg(windows)]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: probe_proc <subcommand> [args...]");
        std::process::exit(2);
    }
    let code = match args[1].as_str() {
        "open-process" => {
            if args.len() < 4 {
                eprintln!("usage: probe_proc open-process <pid> <access-mask-hex>");
                2
            } else {
                // PID may be the literal "broker" → resolve from env.
                let pid_opt: Option<u32> = if args[2].eq_ignore_ascii_case("broker") {
                    std::env::var("WINSBOX_BROKER_PID")
                        .ok()
                        .and_then(|s| s.parse().ok())
                } else {
                    args[2].parse().ok()
                };
                let mask: u32 = u32::from_str_radix(
                    args[3].trim_start_matches("0x").trim_start_matches("0X"),
                    16,
                )
                .unwrap_or(0);
                match pid_opt {
                    Some(pid) => open_process(pid, mask),
                    None => {
                        println!("OPEN_FAIL no-broker-pid-in-env");
                        1
                    }
                }
            }
        }
        "open-process-via-env" => {
            if args.len() < 3 {
                eprintln!("usage: probe_proc open-process-via-env <access-mask-hex>");
                2
            } else {
                let pid_opt: Option<u32> = std::env::var("WINSBOX_BROKER_PID")
                    .ok()
                    .and_then(|s| s.parse().ok());
                let mask: u32 = u32::from_str_radix(
                    args[2].trim_start_matches("0x").trim_start_matches("0X"),
                    16,
                )
                .unwrap_or(0);
                match pid_opt {
                    Some(pid) => open_process(pid, mask),
                    None => {
                        println!("OPEN_FAIL no-broker-pid-in-env");
                        1
                    }
                }
            }
        }
        "set-windows-hook" => set_windows_hook(),
        "mitigation-query" => mitigation_query(),
        "enum-windows" => enum_windows(),
        "read-clipboard" => read_clipboard(),
        "write-clipboard" => {
            let text = args.get(2).cloned().unwrap_or_default();
            write_clipboard(&text)
        }
        "global-atom-add" => {
            let name = args.get(2).cloned().unwrap_or_else(|| "wsbx".to_string());
            global_atom_add(&name)
        }
        "global-atom-find" => {
            let name = args.get(2).cloned().unwrap_or_else(|| "wsbx".to_string());
            global_atom_find(&name)
        }
        "set-system-param" => set_system_param(),
        "read-file" => {
            if args.len() < 3 {
                eprintln!("usage: probe_proc read-file <path>");
                2
            } else {
                read_file(&args[2])
            }
        }
        "hold-file" => {
            if args.len() < 3 {
                eprintln!("usage: probe_proc hold-file <path>");
                2
            } else {
                hold_file(&args[2])
            }
        }
        other => {
            eprintln!("probe_proc: unknown subcommand: {other}");
            2
        }
    };
    std::process::exit(code);
}

#[cfg(windows)]
fn open_process(pid: u32, mask: u32) -> i32 {
    use windows::Win32::Foundation::{CloseHandle, GetLastError};
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_ACCESS_RIGHTS};
    unsafe {
        let r = OpenProcess(PROCESS_ACCESS_RIGHTS(mask), false, pid);
        match r {
            Ok(h) => {
                println!("OPEN_OK pid={pid} mask=0x{mask:x}");
                let _ = CloseHandle(h);
                0
            }
            Err(e) => {
                let hr = e.code();
                let le = GetLastError().0;
                println!(
                    "OPEN_FAIL pid={pid} mask=0x{mask:x} hr=0x{:08x} err={le}",
                    hr.0 as u32
                );
                1
            }
        }
    }
}

#[cfg(windows)]
fn set_windows_hook() -> i32 {
    use windows::Win32::Foundation::{GetLastError, HINSTANCE, LPARAM, LRESULT, WPARAM};
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::UI::WindowsAndMessaging::{
        SetWindowsHookExW, UnhookWindowsHookEx, WH_GETMESSAGE,
    };
    use windows::core::PCWSTR;
    // WH_GETMESSAGE is a per-message global hook that REQUIRES the hook
    // proc to live in a DLL. We point hmod at our own image (the EXE's
    // module handle) and threadid=0 (system-wide). Windows will try to
    // inject the EXE into every other process's address space; with
    // EXTENSION_POINT_DISABLE_ALWAYS_ON the call is rejected up front
    // with ERROR_ACCESS_DENIED, which is what G5 asserts.
    //
    // (Without the mitigation, SetWindowsHookExW will still fail later
    // for "EXE is not a DLL" reasons, but the failure mode and timing
    // differ — Windows attempts injection first.)
    unsafe extern "system" fn hook_proc(_n: i32, _w: WPARAM, _l: LPARAM) -> LRESULT {
        LRESULT(0)
    }
    unsafe {
        let hmod = match GetModuleHandleW(PCWSTR::null()) {
            Ok(h) => HINSTANCE(h.0),
            Err(e) => {
                println!("HOOK_FAIL stage=getmod hr=0x{:08x}", e.code().0 as u32);
                return 1;
            }
        };
        let r = SetWindowsHookExW(WH_GETMESSAGE, Some(hook_proc), hmod, 0);
        match r {
            Ok(h) => {
                println!("HOOK_OK");
                let _ = UnhookWindowsHookEx(h);
                0
            }
            Err(e) => {
                let hr = e.code();
                let le = GetLastError().0;
                println!("HOOK_FAIL hr=0x{:08x} err={le}", hr.0 as u32);
                1
            }
        }
    }
}

#[cfg(windows)]
fn mitigation_query() -> i32 {
    use windows::Win32::System::Threading::{
        GetProcessMitigationPolicy, GetCurrentProcess, PROCESS_MITIGATION_POLICY,
        ProcessExtensionPointDisablePolicy, ProcessImageLoadPolicy,
        ProcessFontDisablePolicy, ProcessControlFlowGuardPolicy,
    };
    // The kernel returns a tagged union-shaped struct, but it always
    // serializes the first DWORD as a bitfield. For each policy we
    // know about, decode a small set of named bits.
    #[repr(C)] #[derive(Default, Copy, Clone)] struct EpDisable { flags: u32 }
    #[repr(C)] #[derive(Default, Copy, Clone)] struct ImgLoad { flags: u32 }
    #[repr(C)] #[derive(Default, Copy, Clone)] struct FontDis { flags: u32 }
    #[repr(C)] #[derive(Default, Copy, Clone)] struct Cfg { flags: u32 }

    unsafe fn query<T: Default + Copy>(p: PROCESS_MITIGATION_POLICY) -> Option<T> {
        let mut buf = T::default();
        let r = GetProcessMitigationPolicy(
            GetCurrentProcess(),
            p,
            &mut buf as *mut _ as *mut std::ffi::c_void,
            std::mem::size_of::<T>(),
        );
        if r.is_ok() { Some(buf) } else { None }
    }
    unsafe {
        let ep = query::<EpDisable>(ProcessExtensionPointDisablePolicy)
            .map(|x| x.flags).unwrap_or(0);
        let img = query::<ImgLoad>(ProcessImageLoadPolicy)
            .map(|x| x.flags).unwrap_or(0);
        let font = query::<FontDis>(FontDisablePolicy_default(ProcessFontDisablePolicy))
            .map(|x| x.flags).unwrap_or(0);
        let cfg = query::<Cfg>(ProcessControlFlowGuardPolicy)
            .map(|x| x.flags).unwrap_or(0);
        // Bit 0 of each is the "always on" or "enabled" flag.
        let ep_disabled = (ep & 1) != 0;
        let img_no_remote = (img & (1 << 0)) != 0;
        let img_no_low = (img & (1 << 1)) != 0;
        let img_prefer_sys32 = (img & (1 << 2)) != 0;
        let font_disabled = (font & 1) != 0;
        let cfg_enabled = (cfg & 1) != 0;
        println!(
            "MITQ ep_disable={ep_disabled} img_no_remote={img_no_remote} \
             img_no_low={img_no_low} img_prefer_sys32={img_prefer_sys32} \
             font_disable={font_disabled} cfg_enabled={cfg_enabled} \
             raw_ep=0x{ep:08x} raw_img=0x{img:08x} raw_font=0x{font:08x} raw_cfg=0x{cfg:08x}"
        );
        // Exit 0 if any of the Phase 4.5 v3 bits is set; 1 otherwise.
        if ep_disabled || img_no_remote || img_no_low || img_prefer_sys32
            || font_disabled || cfg_enabled { 0 } else { 1 }
    }
}

// `ProcessFontDisablePolicy` is just a discriminant; no special helper.
#[cfg(windows)]
fn FontDisablePolicy_default(
    p: windows::Win32::System::Threading::PROCESS_MITIGATION_POLICY,
) -> windows::Win32::System::Threading::PROCESS_MITIGATION_POLICY {
    p
}

#[cfg(windows)]
fn enum_windows() -> i32 {
    use std::sync::atomic::{AtomicU32, Ordering};
    use windows::Win32::Foundation::{BOOL, GetLastError, HWND, LPARAM};
    use windows::Win32::UI::WindowsAndMessaging::EnumWindows;
    static COUNT: AtomicU32 = AtomicU32::new(0);
    unsafe extern "system" fn cb(_h: HWND, _l: LPARAM) -> BOOL {
        COUNT.fetch_add(1, Ordering::Relaxed);
        BOOL(1) // continue
    }
    unsafe {
        let r = EnumWindows(Some(cb), LPARAM(0));
        let n = COUNT.load(Ordering::Relaxed);
        match r {
            Ok(()) => {
                println!("ENUM_OK count={n}");
                0
            }
            Err(e) => {
                let hr = e.code();
                let le = GetLastError().0;
                // EnumWindows returns FALSE if the callback returns FALSE
                // OR if it can't enumerate (e.g. no desktop access). Print
                // BOTH the count we got and the error.
                println!("ENUM_FAIL count={n} hr=0x{:08x} err={le}", hr.0 as u32);
                // For the "separate desktop" assertion we want exit 0 with
                // count=0; report success if no error and count==0.
                if n == 0 { 0 } else { 1 }
            }
        }
    }
}

#[cfg(windows)]
fn read_clipboard() -> i32 {
    use windows::Win32::Foundation::{GetLastError, HWND};
    use windows::Win32::System::DataExchange::{
        CloseClipboard, GetClipboardData, OpenClipboard,
    };
    // CF_UNICODETEXT and CF_TEXT — try both because what's on the
    // clipboard depends on the host. Either succeeding under
    // JOB_OBJECT_UILIMIT_READCLIPBOARD == "the bit does not fire".
    const CF_TEXT: u32 = 1;
    const CF_UNICODETEXT: u32 = 13;
    unsafe {
        if let Err(e) = OpenClipboard(HWND::default()) {
            let hr = e.code();
            let le = GetLastError().0;
            println!(
                "READ_FAIL stage=open hr=0x{:08x} err={le}",
                hr.0 as u32
            );
            return 1;
        }
        // Per-bit semantics: JOB_OBJECT_UILIMIT_READCLIPBOARD blocks
        // the actual data read, not OpenClipboard. So OpenClipboard
        // may succeed; the bit fires at GetClipboardData time with
        // ERROR_ACCESS_DENIED.
        let h_uni = GetClipboardData(CF_UNICODETEXT);
        let h_txt = GetClipboardData(CF_TEXT);
        let _ = CloseClipboard();
        // Either handle being valid (Ok with non-null inner) means
        // the read succeeded → READ_OK. Both errors → READ_FAIL.
        let ok = match (h_uni, h_txt) {
            (Ok(h), _) if h.0 != std::ptr::null_mut() => true,
            (_, Ok(h)) if h.0 != std::ptr::null_mut() => true,
            _ => false,
        };
        if ok {
            println!("READ_OK");
            0
        } else {
            let le = GetLastError().0;
            println!("READ_FAIL stage=get err={le}");
            1
        }
    }
}

#[cfg(windows)]
fn write_clipboard(text: &str) -> i32 {
    use windows::Win32::Foundation::{GetLastError, HANDLE, HWND};
    use windows::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData,
    };
    use windows::Win32::System::Memory::{
        GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE,
    };
    const CF_UNICODETEXT: u32 = 13;
    unsafe {
        if let Err(e) = OpenClipboard(HWND::default()) {
            let hr = e.code();
            let le = GetLastError().0;
            println!("WRITE_FAIL stage=open hr=0x{:08x} err={le}", hr.0 as u32);
            return 1;
        }
        let _ = EmptyClipboard();
        // Allocate UTF-16 buffer (text len + NUL).
        let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
        let bytes = wide.len() * 2;
        let h = match GlobalAlloc(GMEM_MOVEABLE, bytes) {
            Ok(h) => h,
            Err(e) => {
                let hr = e.code();
                let le = GetLastError().0;
                println!(
                    "WRITE_FAIL stage=alloc hr=0x{:08x} err={le}",
                    hr.0 as u32
                );
                let _ = CloseClipboard();
                return 1;
            }
        };
        let p = GlobalLock(h) as *mut u16;
        std::ptr::copy_nonoverlapping(wide.as_ptr(), p, wide.len());
        let _ = GlobalUnlock(h);
        let r = SetClipboardData(CF_UNICODETEXT, HANDLE(h.0));
        let _ = CloseClipboard();
        match r {
            Ok(_) => {
                println!("WRITE_OK len={}", text.len());
                0
            }
            Err(e) => {
                let hr = e.code();
                let le = GetLastError().0;
                println!(
                    "WRITE_FAIL stage=set hr=0x{:08x} err={le}",
                    hr.0 as u32
                );
                1
            }
        }
    }
}

#[cfg(windows)]
fn global_atom_add(name: &str) -> i32 {
    use windows::Win32::Foundation::GetLastError;
    use windows::Win32::System::DataExchange::GlobalAddAtomW;
    use windows::core::PCWSTR;
    // NOTE: under JOB_OBJECT_UILIMIT_GLOBALATOMS the kernel silently
    // redirects this call to the job's private atom table — the call
    // SUCCEEDS but writes to a per-job table not the global one. So
    // `ADD_OK` alone does not prove the bit is off. Pair with
    // `global-atom-find` from an ambient (host) process to assert the
    // atom is NOT visible globally.
    unsafe {
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let r = GlobalAddAtomW(PCWSTR(wide.as_ptr()));
        if r == 0 {
            let le = GetLastError().0;
            println!("ADD_FAIL hr=0x{:08x} err={le}", le);
            return 1;
        }
        // Deliberately do NOT delete the atom here — H4 follows up
        // with an ambient `global-atom-find` to assert the GLOBALATOMS
        // bit silently re-scoped the add. The atom will be cleaned up
        // by the kernel when the job (and thus the per-job atom table)
        // is destroyed at child exit.
        println!("ADD_OK atom={r}");
        0
    }
}

#[cfg(windows)]
fn global_atom_find(name: &str) -> i32 {
    use windows::Win32::Foundation::GetLastError;
    use windows::Win32::System::DataExchange::GlobalFindAtomW;
    use windows::core::PCWSTR;
    unsafe {
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let r = GlobalFindAtomW(PCWSTR(wide.as_ptr()));
        if r == 0 {
            let le = GetLastError().0;
            println!("FIND_MISS err={le}");
            1
        } else {
            println!("FIND_HIT atom={r}");
            0
        }
    }
}

#[cfg(windows)]
fn set_system_param() -> i32 {
    use windows::Win32::Foundation::GetLastError;
    use windows::Win32::UI::WindowsAndMessaging::{
        SystemParametersInfoW, SPI_SETMOUSESPEED, SPIF_SENDCHANGE, SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS,
    };
    unsafe {
        // SPI_SETMOUSESPEED is the "uiParam carries the value, pvParam ignored"
        // form. Use uiParam=10 (Windows default speed), pvParam=NULL.
        let _ = SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS::default();
        let r = SystemParametersInfoW(
            SPI_SETMOUSESPEED,
            10,
            None,
            SPIF_SENDCHANGE,
        );
        match r {
            Ok(()) => {
                println!("SPI_OK");
                0
            }
            Err(e) => {
                let hr = e.code();
                let le = GetLastError().0;
                println!("SPI_FAIL hr=0x{:08x} err={le}", hr.0 as u32);
                1
            }
        }
    }
}

#[cfg(windows)]
fn read_file(path: &str) -> i32 {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, GetLastError, HANDLE};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, ReadFile, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
        OPEN_EXISTING,
    };
    // Phase 5B (J1): the sandbox child must NOT be able to read a file
    // that the broker share-mode-locked. We try the natural read shape
    // — GENERIC_READ + FILE_SHARE_READ + OPEN_EXISTING — and expect
    // ERROR_SHARING_VIOLATION (32) / hr=0x80070020.
    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        let h = CreateFileW(
            PCWSTR(wide.as_ptr()),
            GENERIC_READ.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            HANDLE::default(),
        );
        match h {
            Ok(h) => {
                let mut buf = [0u8; 256];
                let mut nread: u32 = 0;
                let r = ReadFile(h, Some(&mut buf), Some(&mut nread), None);
                let _ = CloseHandle(h);
                match r {
                    Ok(()) => {
                        println!("READ_OK bytes={nread}");
                        0
                    }
                    Err(e) => {
                        let hr = e.code();
                        let le = GetLastError().0;
                        println!(
                            "READ_FAIL stage=read hr=0x{:08x} err={le}",
                            hr.0 as u32
                        );
                        1
                    }
                }
            }
            Err(e) => {
                let hr = e.code();
                let le = GetLastError().0;
                println!(
                    "READ_FAIL stage=open hr=0x{:08x} err={le}",
                    hr.0 as u32
                );
                1
            }
        }
    }
}

#[cfg(windows)]
fn hold_file(path: &str) -> i32 {
    // Phase 5C (J2/J3): emulate a third-party app that has the file
    // open with permissive sharing — broker's share-mode-0 attempt
    // will fail with SHARING_VIOLATION, forcing ACL fallback.
    //
    // Print HOLD_OK as soon as the handle is open so the test wrapper
    // knows we're ready, then block on a flush of stdout + sleep
    // forever. Parent kills us with the SIGTERM equivalent (Node's
    // ChildProcess.kill()) at end of test.
    use std::io::Write;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, GetLastError, HANDLE};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        let h = CreateFileW(
            PCWSTR(wide.as_ptr()),
            GENERIC_READ.0,
            // FULL share: READ | WRITE | DELETE. The broker's
            // CreateFileW(share=0) call will still fail with
            // SHARING_VIOLATION because we don't include "no share"
            // bits — kernel's share-mode check is symmetric.
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            HANDLE::default(),
        );
        match h {
            Ok(h) => {
                println!("HOLD_OK pid={}", std::process::id());
                let _ = std::io::stdout().flush();
                // Sleep until killed.
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(60));
                }
                #[allow(unreachable_code)]
                {
                    let _ = CloseHandle(h);
                    0
                }
            }
            Err(e) => {
                let hr = e.code();
                let le = GetLastError().0;
                println!("HOLD_FAIL hr=0x{:08x} err={le}", hr.0 as u32);
                1
            }
        }
    }
}
