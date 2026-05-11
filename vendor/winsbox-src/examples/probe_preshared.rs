//! probe_preshared — bare-AC bash probe with broker pre-created Cygwin
//! shared section.
//!
//! Hypothesis: Cygwin's `msys_dll_init` AVs because its `NtCreateSection`
//! for `shared.5` returns `STATUS_ACCESS_DENIED` inside the bare AC on
//! Win11 25H2 ARM64. Procmon trace `docs/n6_bash_il_low_trace.log` line
//! 256 captures this exact failure:
//!
//!     [DENY] NtCreateSection name="shared.5" access=0xf0007 → 0xc0000022
//!
//! followed immediately by Cygwin's `api_fatal` ("CreateFileMapping
//! shared.5, Win32 error 5. Terminating.") and the AV cascade.
//!
//! Cygwin's `kernel32.cc::CreateFileMappingW` resolves the bare name
//! `shared.5` against `get_shared_parent_dir()`, which is
//!
//!   \BaseNamedObjects\<dll_id>S5-<install_key>
//!
//! In an AC, that resolves to
//!
//!   \Sessions\<sess>\AppContainerNamedObjects\<ac-sid>\<dll_id>S5-<install_key>
//!
//! The trace shows the AC successfully creates the parent dir (status
//! `0x0`); only the section create inside it is denied. So the fix
//! shape is: have the broker (which has full access to the AC
//! namespace) pre-create the section at the expected path with a NULL
//! DACL (matching Cygwin's `sec_all_nih`). When Cygwin then calls
//! `NtCreateSection` with `OBJ_OPENIF`, the kernel returns
//! `STATUS_OBJECT_NAME_EXISTS` (success) and Cygwin opens our handle.
//!
//! `install_key` is Cygwin's hash of the NT-form path to msys-2.0.dll
//! (16-hex `RtlInt64ToHexUnicodeString` of a 64-bit accumulating hash).
//! We replicate the algorithm in `cygwin_installation_key()` below.
//!
//! Run:
//!   ./probe_preshared.exe                # uses Git's bash by default
//!   ./probe_preshared.exe <path-to-exe>  # overrides bash path
//!
//! Outcomes:
//!   exit 0 + "hello" → hypothesis confirmed; broker integration sketch
//!     follows in `docs/preshared_probe_findings.md`.
//!   exit 0xC0000005  → bash still AVs; the section pre-create is
//!     necessary but not sufficient; capture context and recommend
//!     next experiment (probably: contents init).
//!   any other exit  → see stderr + classified outcome line.

#[cfg(not(windows))]
fn main() {
    eprintln!("probe_preshared: windows only");
    std::process::exit(1);
}

#[cfg(windows)]
fn main() {
    use std::ffi::c_void;
    use std::mem::{size_of, zeroed};
    use std::path::PathBuf;
    use windows::core::PWSTR;
    use windows::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows::Win32::Foundation::{
        CloseHandle, GetLastError, HANDLE, NTSTATUS, UNICODE_STRING, WAIT_OBJECT_0,
    };
    use windows::Win32::Security::{
        DuplicateTokenEx, SecurityImpersonation, TokenPrimary, TOKEN_ALL_ACCESS,
        SECURITY_ATTRIBUTES,
    };
    use windows::Win32::System::Pipes::CreatePipe;
    use windows::Win32::System::Threading::{
        CreateProcessAsUserW, GetCurrentProcess, GetExitCodeProcess, OpenProcessToken,
        WaitForSingleObject, CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION,
        STARTF_USESTDHANDLES, STARTUPINFOW,
    };
    use windows::Win32::Foundation::{HANDLE_FLAGS, SetHandleInformation};
    const HANDLE_FLAG_INHERIT: HANDLE_FLAGS = HANDLE_FLAGS(1);

    use sbox_exec::appcontainer::AppContainer;
    use sbox_exec::token::{create_ac_bno, make_lowbox};
    use sbox_exec::util::{pcwstr, wstr};

    macro_rules! say { ($($a:tt)*) => { eprintln!("[probe-preshared] {}", format!($($a)*)) } }

    let bash = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Program Files\Git\usr\bin\bash.exe"));
    if !bash.exists() {
        say!("FAIL: bash not found at {} (set argv[1] to override)", bash.display());
        std::process::exit(1);
    }
    say!("bash = {}", bash.display());

    // Locate the Cygwin/MSYS DLL that bash.exe will link against.
    // For Git-for-Windows that's `<bashdir>\msys-2.0.dll`; for raw
    // Cygwin it'd be `cygwin1.dll`. We need it to compute the
    // installation_key the way Cygwin's init code does (hash of the
    // NT-form DLL path).
    let bashdir = bash.parent().unwrap();
    let dll_candidates = [
        bashdir.join("msys-2.0.dll"),
        bashdir.join("cygwin1.dll"),
    ];
    let (cyg_dll, dll_id): (PathBuf, &str) = dll_candidates
        .iter()
        .find_map(|p| {
            if !p.exists() { return None; }
            let id = if p.file_name().unwrap().to_string_lossy().starts_with("msys") {
                "msys-2.0"
            } else {
                "cygwin1"
            };
            Some((p.clone(), id))
        })
        .unwrap_or_else(|| {
            say!("FAIL: neither msys-2.0.dll nor cygwin1.dll next to bash");
            std::process::exit(1);
        });
    say!("cyg_dll = {} (id={})", cyg_dll.display(), dll_id);

    // Compute the installation_key the same way Cygwin's
    // init_cygheap::init_installation_root does:
    //   hash_path_name(0, nt_path) — uppercases each WCHAR and folds
    //   it into a 64-bit accumulator:  h = ucase + (h<<6) + (h<<16) - h
    // Then RtlInt64ToHexUnicodeString as a 16-char hex (lowercase).
    //
    // The NT-form path Cygwin uses is `\??\C:\…` (uppercased '?'). It's
    // the result of GetFinalPathNameByHandleW(NORMALIZED) with the
    // first two backslashes preserved and `[1] = '?'`.
    let key_hex = cygwin_installation_key(&cyg_dll);
    say!("computed installation_key = {} (used for shared parent dir)", key_hex);

    // 1. AC profile (bare — no policy stamping, no hooks).
    let ac = AppContainer::create("preshared")
        .unwrap_or_else(|e| { say!("FAIL: CreateAppContainerProfile: {e:#}"); std::process::exit(1); });
    say!("AC sid={} folder={}", ac.sid_string, ac.folder.display());

    // 2. Bootstrap the AC's namespace root. For a fresh AC, the
    //    `\Sessions\<n>\AppContainerNamedObjects\<sid>` directory
    //    doesn't yet exist — the kernel creates it lazily on the
    //    first reference *from inside the AC*. Since we're the
    //    broker (outside the AC) trying to plant a child object,
    //    we have to create it ourselves. `create_ac_bno` builds
    //    both `<sid>` and `<sid>\RPC Control`.
    let (bno_base, _ac_root_handles) = create_ac_bno(&ac.sid_string)
        .unwrap_or_else(|e| {
            say!("FAIL: create_ac_bno: {e:#}");
            std::process::exit(1);
        });
    say!("AC BNO root = {}", bno_base);

    // 3. Pre-create the Cygwin shared-section *directory + section*
    //    in the AC's namespace. The section is the load-bearing one
    //    (procmon shows the dir create succeeds inside the AC); we
    //    create the dir too so the broker-owned section sits exactly
    //    where bash will look.
    let parent_dir = format!(r"{}\{}S5-{}", bno_base, dll_id, key_hex);
    let section_path = format!(r"{}\shared.5", parent_dir);
    say!("parent_dir = {}", parent_dir);
    say!("section    = {}", section_path);

    // sizeof(shared_info) per docs/bash_arm64_root_cause_synthesis +
    // cdb-verified earlier diagnosis. Cygwin's CreateFileMapping
    // wrapper passes this exact size when calling NtCreateSection;
    // the kernel returns ERROR_ALREADY_EXISTS only if the existing
    // section is at least as large.
    const SHARED_INFO_SIZE: i64 = 0xE7B8;

    #[link(name = "ntdll")]
    extern "system" {
        fn NtCreateDirectoryObject(
            h: *mut HANDLE, access: u32, oa: *const OBJECT_ATTRIBUTES,
        ) -> NTSTATUS;
        fn NtCreateSection(
            section: *mut HANDLE,
            desired_access: u32,
            oa: *const OBJECT_ATTRIBUTES,
            max_size: *mut i64,
            page_protection: u32,
            allocation_attributes: u32,
            file: HANDLE,
        ) -> NTSTATUS;
        fn NtOpenSection(
            section: *mut HANDLE,
            desired_access: u32,
            oa: *const OBJECT_ATTRIBUTES,
        ) -> NTSTATUS;
        fn RtlInitUnicodeString(
            dst: *mut UNICODE_STRING, src: windows::core::PCWSTR,
        );
    }

    // Build a security descriptor with a NULL DACL = everyone full
    // access. This matches Cygwin's `sec_all_nih` ("null_sdp" with
    // PSECURITY_ATTRIBUTES). With the default kernel DACL on the
    // AC-namespace directory we get inherited ACEs that may *exclude*
    // the AC SID from creating-via-name — we sidestep by stamping an
    // explicit NULL DACL on our objects.
    use windows::Win32::Security::{
        InitializeSecurityDescriptor, SetSecurityDescriptorDacl,
        SECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR,
    };
    use windows::Win32::System::SystemServices::SECURITY_DESCRIPTOR_REVISION;
    let mut sd_storage: SECURITY_DESCRIPTOR = unsafe { zeroed() };
    unsafe {
        InitializeSecurityDescriptor(
            PSECURITY_DESCRIPTOR(&mut sd_storage as *mut _ as *mut c_void),
            SECURITY_DESCRIPTOR_REVISION,
        ).expect("InitializeSecurityDescriptor");
        SetSecurityDescriptorDacl(
            PSECURITY_DESCRIPTOR(&mut sd_storage as *mut _ as *mut c_void),
            true,                  // DACL present
            None,                  // NULL DACL — allow everyone
            false,                 // not defaulted
        ).expect("SetSecurityDescriptorDacl(NULL=allow-all)");
    }
    let sd_ptr: *mut c_void = &mut sd_storage as *mut _ as *mut c_void;

    // --- 2a: parent directory (OBJ_OPENIF — fine if AC's lookup
    // already auto-created it via some other path).
    const OBJ_CASE_INSENSITIVE: u32 = 0x40;
    const OBJ_OPENIF: u32 = 0x80;
    const DIRECTORY_ALL_ACCESS: u32 = 0x000F000F;

    let dir_handle: HANDLE = unsafe {
        let wpath = wstr(&parent_dir);
        let mut us: UNICODE_STRING = zeroed();
        RtlInitUnicodeString(&mut us, pcwstr(&wpath));
        let oa = OBJECT_ATTRIBUTES {
            Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: HANDLE::default(),
            ObjectName: &us as *const _ as *mut _,
            Attributes: OBJ_CASE_INSENSITIVE | OBJ_OPENIF,
            SecurityDescriptor: sd_ptr,
            SecurityQualityOfService: std::ptr::null_mut(),
        };
        let mut h = HANDLE::default();
        let st = NtCreateDirectoryObject(&mut h, DIRECTORY_ALL_ACCESS, &oa);
        if st.0 < 0 {
            say!("FAIL: NtCreateDirectoryObject({}): {:#x}", parent_dir, st.0);
            std::process::exit(1);
        }
        say!("dir create: NTSTATUS={:#x} (NULL DACL = allow-all)", st.0);
        std::mem::drop(wpath);
        h
    };

    // --- 2b: the section. SEC_COMMIT, PAGE_READWRITE, NULL DACL via
    // a default security descriptor (everyone-full-access, matches
    // Cygwin's `sec_all_nih`). NtCreateSection with `file=NULL` is
    // pagefile-backed exactly like `CreateFileMappingW(INVALID_HANDLE_VALUE)`.
    const SECTION_ALL_ACCESS: u32 = 0x000F001F;
    const PAGE_READWRITE: u32 = 0x04;
    const SEC_COMMIT: u32 = 0x0800_0000;

    let section_handle: HANDLE = unsafe {
        let wpath = wstr(&section_path);
        let mut us: UNICODE_STRING = zeroed();
        RtlInitUnicodeString(&mut us, pcwstr(&wpath));
        let oa = OBJECT_ATTRIBUTES {
            Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: HANDLE::default(),
            ObjectName: &us as *const _ as *mut _,
            Attributes: OBJ_CASE_INSENSITIVE | OBJ_OPENIF,
            SecurityDescriptor: sd_ptr,
            SecurityQualityOfService: std::ptr::null_mut(),
        };
        let mut size = SHARED_INFO_SIZE;
        let mut h = HANDLE::default();
        let st = NtCreateSection(
            &mut h, SECTION_ALL_ACCESS, &oa, &mut size,
            PAGE_READWRITE, SEC_COMMIT, HANDLE::default(),
        );
        if st.0 < 0 {
            say!("FAIL: NtCreateSection({}): {:#x}", section_path, st.0);
            let _ = CloseHandle(dir_handle);
            std::process::exit(1);
        }
        say!("section create: NTSTATUS={:#x} (0 = STATUS_SUCCESS; 0x40000000 = STATUS_OBJECT_NAME_EXISTS)", st.0);
        std::mem::drop(wpath);
        h
    };
    say!("pre-created section handle={:?} dir handle={:?}", section_handle, dir_handle);

    // Sanity check: can the broker re-open the section by name? If
    // yes, the named lookup we just planted is structurally valid.
    // (We're still outside the AC, so this confirms broker-side
    // visibility; it doesn't yet prove visibility from inside the AC.)
    let reopen_status = unsafe {
        let wpath = wstr(&section_path);
        let mut us: UNICODE_STRING = zeroed();
        RtlInitUnicodeString(&mut us, pcwstr(&wpath));
        let oa = OBJECT_ATTRIBUTES {
            Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: HANDLE::default(),
            ObjectName: &us as *const _ as *mut _,
            Attributes: OBJ_CASE_INSENSITIVE,
            SecurityDescriptor: std::ptr::null_mut(),
            SecurityQualityOfService: std::ptr::null_mut(),
        };
        let mut h2 = HANDLE::default();
        let st = NtOpenSection(&mut h2, SECTION_ALL_ACCESS, &oa);
        if st.0 >= 0 { let _ = CloseHandle(h2); }
        std::mem::drop(wpath);
        st.0
    };
    say!("section reopen-by-name status: {:#x}", reopen_status);

    // 3. Self token → primary duplicate (same as probe_vanilla_ac).
    let primary = unsafe {
        let mut tok = HANDLE::default();
        if let Err(e) = OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &mut tok) {
            say!("FAIL: OpenProcessToken: {e:#}");
            std::process::exit(1);
        }
        let mut dup = HANDLE::default();
        if let Err(e) = DuplicateTokenEx(
            tok, TOKEN_ALL_ACCESS, None,
            SecurityImpersonation, TokenPrimary, &mut dup,
        ) {
            say!("FAIL: DuplicateTokenEx(primary): {e:#}");
            std::process::exit(1);
        }
        let _ = CloseHandle(tok);
        dup
    };

    // 4. Bare lowbox (no caps, no saved-handles — the section is
    //    addressed by name, not by handle inheritance).
    let lowbox = match make_lowbox(primary, ac.sid, &[]) {
        Ok(h) => h,
        Err(e) => { say!("FAIL: make_lowbox: {e:#}"); std::process::exit(1); }
    };
    say!("lowbox token built (NtCreateLowBoxToken)");

    // 5. CreateProcessAsUserW with pipes (same setup as probe_vanilla_ac).
    let inheritable = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: windows::Win32::Foundation::BOOL(1),
    };
    let mut stdout_r = HANDLE::default();
    let mut stdout_w = HANDLE::default();
    let mut stderr_r = HANDLE::default();
    let mut stderr_w = HANDLE::default();
    unsafe {
        if let Err(e) = CreatePipe(&mut stdout_r, &mut stdout_w, Some(&inheritable), 0) {
            say!("FAIL: CreatePipe(stdout): {e:#}");
            std::process::exit(1);
        }
        if let Err(e) = CreatePipe(&mut stderr_r, &mut stderr_w, Some(&inheritable), 0) {
            say!("FAIL: CreatePipe(stderr): {e:#}");
            std::process::exit(1);
        }
        let _ = SetHandleInformation(stdout_r, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0));
        let _ = SetHandleInformation(stderr_r, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0));
    }

    let cmdline = format!("\"{}\" -c \"echo hello\"", bash.display());
    let mut cmd_w: Vec<u16> = cmdline.encode_utf16().chain(std::iter::once(0)).collect();
    let cwd = std::env::var("TEMP").unwrap_or_else(|_| "C:\\Windows\\Temp".to_string());
    let cwd_w: Vec<u16> = cwd.encode_utf16().chain(std::iter::once(0)).collect();

    let mut si: STARTUPINFOW = unsafe { zeroed() };
    si.cb = size_of::<STARTUPINFOW>() as u32;
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = HANDLE(std::ptr::null_mut());
    si.hStdOutput = stdout_w;
    si.hStdError = stderr_w;

    use windows::Win32::System::Threading::{CREATE_SUSPENDED, ResumeThread};
    use windows::Win32::System::Diagnostics::Debug::CheckRemoteDebuggerPresent;
    let pause_for_debugger = std::env::var("WINSBOX_PAUSE_FOR_DEBUGGER").as_deref() == Ok("1");
    let create_flags = if pause_for_debugger {
        CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED
    } else {
        CREATE_UNICODE_ENVIRONMENT
    };
    let mut pi: PROCESS_INFORMATION = unsafe { zeroed() };
    let ok = unsafe {
        CreateProcessAsUserW(
            lowbox, None, PWSTR(cmd_w.as_mut_ptr()),
            None, None, true, create_flags, None,
            windows::core::PCWSTR(cwd_w.as_ptr()),
            &si, &mut pi,
        )
    };
    if let Err(e) = ok {
        let last = unsafe { GetLastError() };
        say!("FAIL: CreateProcessAsUserW: {e:#} (GetLastError={:#x})", last.0);
        std::process::exit(1);
    }
    say!("target pid={}", pi.dwProcessId);
    if pause_for_debugger {
        say!("WINSBOX_PAUSE_FOR_DEBUGGER=1: target SUSPENDED at PID {}; attach with `cdb -p {0}`", pi.dwProcessId);
        say!("polling for debugger attach...");
        loop {
            let mut is_debugged = windows::Win32::Foundation::BOOL(0);
            let _ = unsafe { CheckRemoteDebuggerPresent(pi.hProcess, &mut is_debugged) };
            if is_debugged.as_bool() {
                say!("debugger attached; resuming");
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        unsafe { ResumeThread(pi.hThread); }
    }

    // Close our write ends so EOF propagates.
    unsafe {
        let _ = CloseHandle(stdout_w);
        let _ = CloseHandle(stderr_w);
    }

    // Drain stdout/stderr concurrently (Send-safe wrapper).
    use std::os::windows::io::FromRawHandle;
    use std::io::Read;
    struct SendHandle(usize);
    unsafe impl Send for SendHandle {}
    let stdout_r_send = SendHandle(stdout_r.0 as usize);
    let stderr_r_send = SendHandle(stderr_r.0 as usize);
    let t_out = std::thread::spawn(move || -> Vec<u8> {
        let h = stdout_r_send.0 as *mut c_void;
        let mut f = unsafe { std::fs::File::from_raw_handle(h as _) };
        let mut buf = Vec::new();
        let _ = f.read_to_end(&mut buf);
        buf
    });
    let t_err = std::thread::spawn(move || -> Vec<u8> {
        let h = stderr_r_send.0 as *mut c_void;
        let mut f = unsafe { std::fs::File::from_raw_handle(h as _) };
        let mut buf = Vec::new();
        let _ = f.read_to_end(&mut buf);
        buf
    });

    let wait = unsafe { WaitForSingleObject(pi.hProcess, 30_000) };
    if wait != WAIT_OBJECT_0 {
        say!("WARN: WaitForSingleObject != WAIT_OBJECT_0 ({:#x})", wait.0);
    }
    let mut exit_code = 0u32;
    let _ = unsafe { GetExitCodeProcess(pi.hProcess, &mut exit_code) };

    let stdout_bytes = t_out.join().unwrap_or_default();
    let stderr_bytes = t_err.join().unwrap_or_default();
    let stdout_s = String::from_utf8_lossy(&stdout_bytes);
    let stderr_s = String::from_utf8_lossy(&stderr_bytes);

    say!("exit code = {:#x} ({})", exit_code, exit_code as i32);
    say!("--- stdout ({} bytes) ---", stdout_bytes.len());
    eprintln!("{}", stdout_s);
    say!("--- stderr ({} bytes) ---", stderr_bytes.len());
    eprintln!("{}", stderr_s);
    say!("--- end ---");

    // 6. Cleanup. Drop the section + dir handles AFTER the target
    //    exits so the section stays alive throughout bash's run.
    unsafe {
        let _ = CloseHandle(pi.hThread);
        let _ = CloseHandle(pi.hProcess);
        let _ = CloseHandle(lowbox);
        let _ = CloseHandle(primary);
        let _ = CloseHandle(section_handle);
        let _ = CloseHandle(dir_handle);
    }

    // Classify outcome.
    if exit_code == 0 && stdout_s.contains("hello") {
        say!("OUTCOME: bare-AC bash WORKS with pre-created shared.5 section. Hypothesis CONFIRMED.");
        std::process::exit(0);
    } else if exit_code == 0xC0000005 {
        say!("OUTCOME: bare-AC bash AVs (0xC0000005) even with pre-created section. Hypothesis WRONG or insufficient — need section *contents* or another resource.");
        std::process::exit(2);
    } else {
        say!("OUTCOME: bare-AC bash failed non-AV ({:#x}) — see stderr above", exit_code);
        std::process::exit(2);
    }
}

/// Compute Cygwin's `installation_key` — 16 lowercase-hex chars of a
/// 64-bit hash over the NT-form path to the Cygwin/MSYS DLL.
///
/// Replicates `init_cygheap::init_installation_root()` from
/// `winsup/cygwin/mm/cygheap.cc`. The exact algorithm:
///
///   1. NT-form the DLL path: `GetFinalPathNameByHandleW` ⇒ `\\?\C:\…`
///      then `[1] = '?'` ⇒ `\??\C:\…`. We approximate by prepending
///      `\??\` to the canonicalised absolute path.
///   2. Hash each WCHAR after `RtlUpcaseUnicodeChar`:
///        h = upcased + (h<<6) + (h<<16) - h
///      starting from h = 0.
///   3. `RtlInt64ToHexUnicodeString(h, &out, FALSE)` — 16 lowercase
///      hex chars, no leading "0x".
///
/// We use `wcsupcase`-equivalent via `to_uppercase` for ASCII; for
/// non-ASCII Cygwin uses NT's case table which we approximate with
/// `char::to_uppercase` (close enough — installation paths in
/// practice are ASCII). If the resulting key doesn't match
/// Cygwin's, the section sits at a path bash won't look up; the
/// probe will report a section-path mismatch via continued AV.
#[cfg(windows)]
fn cygwin_installation_key(dll_path: &std::path::Path) -> String {
    use std::path::PathBuf;
    // Canonicalise to get the same form GetFinalPathNameByHandleW
    // would return. std::fs::canonicalize emits `\\?\C:\…`.
    let canon: PathBuf = std::fs::canonicalize(dll_path)
        .unwrap_or_else(|_| dll_path.to_path_buf());
    let s = canon.to_string_lossy();
    // Convert `\\?\C:\…` → `\??\C:\…` to match Cygwin's `[1]='?'`.
    let nt: String = if let Some(rest) = s.strip_prefix(r"\\?\") {
        format!(r"\??\{rest}")
    } else if let Some(rest) = s.strip_prefix(r"\\") {
        // UNC — Cygwin's transform is different; skip for now and
        // pass through (bash on a UNC share is exotic enough that
        // the probe report can flag it).
        format!(r"\??\{rest}")
    } else {
        format!(r"\??\{s}")
    };

    let mut h: u64 = 0;
    for c in nt.encode_utf16() {
        // ASCII fast path — Cygwin uses NT RtlUpcaseUnicodeChar
        // which for ASCII is plain `to_ascii_uppercase`. For
        // non-ASCII we'd need to call the kernel; in practice
        // install paths are ASCII, so we approximate.
        let upc = if c <= 0x7f {
            (c as u8).to_ascii_uppercase() as u16
        } else {
            // Best-effort for the rare non-ASCII install path.
            let ch = char::from_u32(c as u32).unwrap_or('?');
            ch.to_uppercase().next().map(|c2| c2 as u16).unwrap_or(c)
        };
        h = (upc as u64)
            .wrapping_add(h.wrapping_shl(6))
            .wrapping_add(h.wrapping_shl(16))
            .wrapping_sub(h);
    }
    // RtlInt64ToHexUnicodeString with `Value < 0x100000000` uses 8
    // chars; for full 64-bit it's 16 chars. The signature implies
    // no zero-padding for the upper half. Cygwin's
    // `installation_key_buf[18]` accommodates "0xHHHHHHHHHHHHHHHH\0"
    // worth of width. The format string `%S` in the BNO name uses
    // a UNICODE_STRING whose `.Length` is whatever
    // RtlInt64ToHexUnicodeString wrote, so we emit *all 16 chars*
    // unconditionally to match the captured trace
    // (`1888ae32e00d56aa` in `docs/n6_bash_il_low_trace.log`).
    format!("{:016x}", h)
}
