//! `probe_priv` — print the calling token's privilege LUIDs in
//! `0xHIGH:0xLOW` form. Drop-in replacement for `whoami /priv` from
//! the windows.test.ts suite.
//!
//! Background: under the broker's lowbox AppContainer token, LSA's
//! ALPC port (`\RPC Control\lsasspirpc`) is unreachable, so anything
//! that calls into LSA fails. `whoami /priv` calls
//! `LookupPrivilegeNameW` to translate each LUID to a friendly string;
//! that's an LSA round trip. This probe avoids LSA entirely:
//!
//!   1. `OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY)`
//!   2. `GetTokenInformation(TokenPrivileges)` — pure-ntdll syscall
//!   3. print one line per privilege as `0xHIGH:0xLOW`
//!
//! Exit code 0 on success; 1 on any API failure. The test asserts
//! exactly one line: `0x0:0x17` (SeChangeNotifyPrivilege's well-known
//! LUID on every current Windows release).

#[cfg(not(windows))]
fn main() { eprintln!("windows only"); std::process::exit(2); }

#[cfg(windows)]
fn main() {
    use std::ffi::c_void;
    use std::mem::size_of;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        GetTokenInformation, LUID_AND_ATTRIBUTES, TOKEN_PRIVILEGES, TOKEN_QUERY,
        TokenPrivileges,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut tok = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok).is_err() {
            eprintln!("OpenProcessToken failed");
            std::process::exit(1);
        }
        let mut len = 0u32;
        // First call: probe required size (returns ERROR_INSUFFICIENT_BUFFER).
        let _ = GetTokenInformation(tok, TokenPrivileges, None, 0, &mut len);
        let mut buf = vec![0u8; len as usize];
        if GetTokenInformation(
            tok, TokenPrivileges,
            Some(buf.as_mut_ptr() as *mut c_void), len, &mut len,
        ).is_err() {
            eprintln!("GetTokenInformation failed");
            let _ = CloseHandle(tok);
            std::process::exit(1);
        }
        let _ = CloseHandle(tok);
        // TOKEN_PRIVILEGES = u32 PrivilegeCount, then [LUID_AND_ATTRIBUTES].
        // The struct's `Privileges` field is declared as a 1-element
        // array; the actual array is the trailing flex section.
        let header = &*(buf.as_ptr() as *const TOKEN_PRIVILEGES);
        let count = header.PrivilegeCount as usize;
        let arr_ptr = (buf.as_ptr() as *const u8)
            .add(size_of::<u32>()) as *const LUID_AND_ATTRIBUTES;
        let arr = std::slice::from_raw_parts(arr_ptr, count);
        for la in arr {
            // LUID is u32 LowPart + i32 HighPart. Print high:low so the
            // test can match against a hardcoded SeChangeNotifyPrivilege
            // LUID (0x0:0x17 on every shipping Windows release).
            println!("0x{:x}:0x{:x}", la.Luid.HighPart, la.Luid.LowPart);
        }
    }
}
