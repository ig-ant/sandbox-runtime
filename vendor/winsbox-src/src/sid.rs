// Cribbed: SID-string helpers from acl_stamper.rs in winsbox-msys2-iter.
//! Deterministic per-machine SANDBOX_SID for the WFP+SID network sandbox.
//!
//! Responsibilities:
//!   - Read `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` and SHA-256
//!     it to derive 4 u32 subauthorities.
//!   - Build the SID via `AllocateAndInitializeSid` with identifier
//!     authority `SECURITY_RESOURCE_MANAGER_AUTHORITY` (9) and five
//!     subauthorities ending in a fixed RID of `1` so the same machine
//!     can mint variant SIDs later by changing only the RID.
//!   - Cache the result in a `OnceLock` so callers can hold static refs.

use anyhow::{anyhow, Context, Result};
use std::ffi::c_void;
use std::sync::OnceLock;
use windows::core::PWSTR;
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{
    AllocateAndInitializeSid, GetLengthSid, PSID, SECURITY_RESOURCE_MANAGER_AUTHORITY,
};
use windows::Win32::System::Registry::{
    RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE,
    KEY_READ, REG_VALUE_TYPE,
};

use crate::util::{from_pwstr, pcwstr, wstr};

/// Convert a string SID like `"S-1-15-2-1"` to a heap-owned PSID.
/// Caller frees with `free_psid` / `LocalFree`.
pub fn psid_from_string(sid_str: &str) -> Result<PSID> {
    use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
    let mut sid = PSID::default();
    let w = wstr(sid_str);
    unsafe {
        ConvertStringSidToSidW(pcwstr(&w), &mut sid)
            .map_err(|e| anyhow!("ConvertStringSidToSidW({sid_str}): {e}"))?;
    }
    Ok(sid)
}

/// Free a SID returned by `psid_from_string`.
pub fn free_psid(sid: PSID) {
    if !sid.0.is_null() {
        unsafe { let _ = LocalFree(HLOCAL(sid.0)); }
    }
}

/// Return the string form of a PSID. Convenience for marker-file
/// serialization and logging.
pub fn psid_to_string(sid: PSID) -> Result<String> {
    let mut p = PWSTR::null();
    unsafe {
        ConvertSidToStringSidW(sid, &mut p)
            .map_err(|e| anyhow!("ConvertSidToStringSidW: {e}"))?;
    }
    let s = from_pwstr(p);
    crate::util::local_free(p.0 as *mut c_void);
    Ok(s)
}

static SANDBOX_SID_BYTES: OnceLock<&'static [u8]> = OnceLock::new();
static SANDBOX_SID_STR: OnceLock<String> = OnceLock::new();

/// Read `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` (REG_SZ).
fn read_machine_guid() -> Result<String> {
    unsafe {
        let mut hkey = HKEY::default();
        let subkey = wstr("SOFTWARE\\Microsoft\\Cryptography");
        let err = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            pcwstr(&subkey),
            0,
            KEY_READ,
            &mut hkey,
        );
        if err.0 != 0 {
            return Err(anyhow!("RegOpenKeyExW(HKLM\\SOFTWARE\\Microsoft\\Cryptography): {}", err.0));
        }
        // First call: query size.
        let value_name = wstr("MachineGuid");
        let mut data_type = REG_VALUE_TYPE::default();
        let mut cb: u32 = 0;
        let err = RegQueryValueExW(
            hkey,
            pcwstr(&value_name),
            None,
            Some(&mut data_type),
            None,
            Some(&mut cb),
        );
        if err.0 != 0 {
            let _ = RegCloseKey(hkey);
            return Err(anyhow!("RegQueryValueExW(MachineGuid) size: {}", err.0));
        }
        let mut buf = vec![0u8; cb as usize];
        let err = RegQueryValueExW(
            hkey,
            pcwstr(&value_name),
            None,
            Some(&mut data_type),
            Some(buf.as_mut_ptr()),
            Some(&mut cb),
        );
        let _ = RegCloseKey(hkey);
        if err.0 != 0 {
            return Err(anyhow!("RegQueryValueExW(MachineGuid): {}", err.0));
        }
        // Interpret as UTF-16, drop trailing NULs.
        let slice = std::slice::from_raw_parts(
            buf.as_ptr() as *const u16,
            (cb as usize) / 2,
        );
        let mut s = String::from_utf16_lossy(slice);
        while s.ends_with('\0') {
            s.pop();
        }
        Ok(s)
    }
}

/// Return the deterministic per-machine SANDBOX_SID as raw PSID bytes.
/// Cached for process lifetime.
pub fn sandbox_sid() -> Result<&'static [u8]> {
    if let Some(s) = SANDBOX_SID_BYTES.get() {
        return Ok(*s);
    }
    let guid = read_machine_guid().context("read MachineGuid")?;
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(guid.as_bytes());
    // Take 4 u32 subauthorities (little-endian) from the first 16 bytes.
    let sub0 = u32::from_le_bytes(digest[0..4].try_into().unwrap());
    let sub1 = u32::from_le_bytes(digest[4..8].try_into().unwrap());
    let sub2 = u32::from_le_bytes(digest[8..12].try_into().unwrap());
    let sub3 = u32::from_le_bytes(digest[12..16].try_into().unwrap());
    let sub4: u32 = 1;
    let mut psid = PSID::default();
    unsafe {
        AllocateAndInitializeSid(
            &SECURITY_RESOURCE_MANAGER_AUTHORITY,
            5,
            sub0, sub1, sub2, sub3, sub4,
            0, 0, 0,
            &mut psid,
        )
        .map_err(|e| anyhow!("AllocateAndInitializeSid: {e}"))?;
        let len = GetLengthSid(psid) as usize;
        // Copy the SID into a Vec, then heap-leak. AllocateAndInitializeSid
        // returns a SID that must be freed with FreeSid; we copy then free.
        let src = std::slice::from_raw_parts(psid.0 as *const u8, len);
        let owned: Box<[u8]> = src.to_vec().into_boxed_slice();
        windows::Win32::Security::FreeSid(psid);
        let leaked: &'static [u8] = Box::leak(owned);
        let _ = SANDBOX_SID_BYTES.set(leaked);
        Ok(leaked)
    }
}

/// Return the SDDL string form of `sandbox_sid()`. Cached for process
/// lifetime.
pub fn sandbox_sid_string() -> Result<&'static str> {
    if let Some(s) = SANDBOX_SID_STR.get() {
        return Ok(s.as_str());
    }
    let bytes = sandbox_sid()?;
    let psid = PSID(bytes.as_ptr() as *mut c_void);
    let s = psid_to_string(psid)?;
    let _ = SANDBOX_SID_STR.set(s);
    Ok(SANDBOX_SID_STR.get().unwrap().as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn psid_string_round_trip() {
        // Well-known Everyone SID.
        let p = psid_from_string("S-1-1-0").expect("from_string");
        let s = psid_to_string(p).expect("to_string");
        assert_eq!(s, "S-1-1-0");
        free_psid(p);
    }
}
