use std::ffi::c_void;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{LocalFree, HLOCAL};

pub fn wstr(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub fn from_pwstr(p: PWSTR) -> String {
    if p.is_null() { return String::new(); }
    let mut len = 0usize;
    unsafe { while *p.0.add(len) != 0 { len += 1; } }
    let slice = unsafe { std::slice::from_raw_parts(p.0, len) };
    String::from_utf16_lossy(slice)
}

pub fn local_free(p: *mut c_void) {
    unsafe { let _ = LocalFree(HLOCAL(p)); }
}

pub fn pcwstr(buf: &[u16]) -> PCWSTR {
    PCWSTR(buf.as_ptr())
}
