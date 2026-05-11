//! N-7p+: opt-in pre-create of Cygwin's `shared.5` named section in the
//! per-AC namespace.
//!
//! Cygwin's `kernel32.cc::CreateFileMappingW` resolves the bare name
//! `shared.5` against `get_shared_parent_dir()`, which inside an
//! AppContainer evaluates to
//!
//!   \Sessions\<sess>\AppContainerNamedObjects\<ac-sid>\<dll_id>S5-<install_key>
//!
//! Trace evidence (`docs/n6_bash_il_low_trace.log:256`) shows that in
//! the FULL sandbox config (USER_LIMITED + IL_LOW + lowbox + cdylib +
//! hooks) bash reaches this section create — and is denied with
//! `STATUS_ACCESS_DENIED`. By pre-creating the section from the broker
//! (which has full access to the AC namespace) with a NULL DACL, we
//! plant a section Cygwin can open with `OBJ_OPENIF`.
//!
//! This module is the broker-side counterpart to
//! `examples/probe_preshared.rs`. It's invoked from `launch.rs` when
//! `WINSBOX_PRECREATE_CYGSHARED=1` is set in the broker's env.
//!
//! The returned `PrecreatedSharedSection` owns the section + directory
//! handles. Keep it alive in `run_confined`'s stack frame until after
//! `WaitForSingleObject(target)` returns; dropping it closes the
//! handles which (since broker is the only owner of named refs from
//! outside the AC) will tear down the section.

use anyhow::{Context, Result};
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::path::{Path, PathBuf};

use windows::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows::Win32::Foundation::{CloseHandle, HANDLE, NTSTATUS, UNICODE_STRING};
use windows::Win32::Security::{
    InitializeSecurityDescriptor, SetSecurityDescriptorDacl, PSECURITY_DESCRIPTOR,
    SECURITY_DESCRIPTOR,
};
use windows::Win32::System::SystemServices::SECURITY_DESCRIPTOR_REVISION;

use crate::util::{pcwstr, wstr};

/// Section + parent-dir handles for one pre-created `shared.5`.
/// Handles are closed on Drop. Owner is `run_confined` for the
/// target's full lifetime.
pub struct PrecreatedSharedSection {
    section: HANDLE,
    dir: HANDLE,
    /// Diagnostic — the full NT path of the section we created.
    pub section_path: String,
}

impl Drop for PrecreatedSharedSection {
    fn drop(&mut self) {
        unsafe {
            if !self.section.is_invalid() {
                let _ = CloseHandle(self.section);
            }
            if !self.dir.is_invalid() {
                let _ = CloseHandle(self.dir);
            }
        }
    }
}

const OBJ_CASE_INSENSITIVE: u32 = 0x40;
const OBJ_OPENIF: u32 = 0x80;
const DIRECTORY_ALL_ACCESS: u32 = 0x000F_000F;
const SECTION_ALL_ACCESS: u32 = 0x000F_001F;
const PAGE_READWRITE: u32 = 0x04;
const SEC_COMMIT: u32 = 0x0800_0000;

/// Empirically determined `sizeof(shared_info)` from
/// `docs/bash_arm64_root_cause_synthesis.md`. Cygwin passes this exact
/// size to `NtCreateSection`; the kernel returns
/// `STATUS_OBJECT_NAME_EXISTS` (success) only if our pre-existing
/// section is at least this large.
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
    fn RtlInitUnicodeString(
        dst: *mut UNICODE_STRING, src: windows::core::PCWSTR,
    );
}

/// Locate the Cygwin/MSYS DLL that lives next to a candidate
/// executable. Returns `(dll_path, dll_id)` where `dll_id` is
/// `"msys-2.0"` or `"cygwin1"` — used as the prefix for Cygwin's
/// shared-parent directory name.
fn locate_cygwin_dll(target_exe: &Path) -> Option<(PathBuf, &'static str)> {
    let dir = target_exe.parent()?;
    for (name, id) in &[("msys-2.0.dll", "msys-2.0"), ("cygwin1.dll", "cygwin1")] {
        let p = dir.join(name);
        if p.exists() {
            return Some((p, *id));
        }
    }
    None
}

/// Compute Cygwin's `installation_key` — 16 lowercase-hex chars of a
/// 64-bit hash over the NT-form path to the Cygwin/MSYS DLL.
///
/// Replicates `init_cygheap::init_installation_root()` from
/// `winsup/cygwin/mm/cygheap.cc`. Algorithm:
///   1. NT-form the DLL path: `\??\C:\…`
///   2. Hash each UTF-16 unit after upper-casing:
///        h = upcased + (h<<6) + (h<<16) - h    (h starts at 0)
///   3. Emit 16 lowercase hex chars.
///
/// Verified byte-for-byte against the captured trace (`1888ae32e00d56aa`)
/// in `docs/preshared_probe_findings.md`. Ported from
/// `examples/probe_preshared.rs::cygwin_installation_key`.
pub fn cygwin_installation_key(dll_path: &Path) -> String {
    let canon: PathBuf = std::fs::canonicalize(dll_path)
        .unwrap_or_else(|_| dll_path.to_path_buf());
    let s = canon.to_string_lossy();
    let nt: String = if let Some(rest) = s.strip_prefix(r"\\?\") {
        format!(r"\??\{rest}")
    } else if let Some(rest) = s.strip_prefix(r"\\") {
        format!(r"\??\{rest}")
    } else {
        format!(r"\??\{s}")
    };

    let mut h: u64 = 0;
    for c in nt.encode_utf16() {
        let upc = if c <= 0x7f {
            (c as u8).to_ascii_uppercase() as u16
        } else {
            let ch = char::from_u32(c as u32).unwrap_or('?');
            ch.to_uppercase().next().map(|c2| c2 as u16).unwrap_or(c)
        };
        h = (upc as u64)
            .wrapping_add(h.wrapping_shl(6))
            .wrapping_add(h.wrapping_shl(16))
            .wrapping_sub(h);
    }
    format!("{:016x}", h)
}

/// Naive command-line parser: returns the first whitespace-separated
/// token, stripping surrounding double-quotes. Adequate for the
/// Cygwin / MSYS workloads we sandbox — the executable path is always
/// the first arg, either bare or "quoted".
fn parse_target_exe(command_line: &str) -> Option<PathBuf> {
    let s = command_line.trim_start();
    let first: String = if let Some(rest) = s.strip_prefix('"') {
        rest.split('"').next()?.to_string()
    } else {
        s.split_whitespace().next()?.to_string()
    };
    if first.is_empty() { None } else { Some(PathBuf::from(first)) }
}

/// Compute the per-AC BNO root path (`\Sessions\<n>\AppContainerNamedObjects\<sid>`)
/// for the current process's session + the given AC SID string. Mirrors
/// `token::create_ac_bno`'s path-build logic, but does NOT create the
/// directory — `create_ac_bno` is already called upstream (in
/// `build_broker_tokens_with` and `try_inject_cdylib_full`), so the
/// directory exists by the time we run.
fn ac_bno_root_for_session(ac_sid: &str) -> String {
    use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
    use windows::Win32::System::Threading::GetCurrentProcessId;
    let mut sess = 0u32;
    unsafe { let _ = ProcessIdToSessionId(GetCurrentProcessId(), &mut sess); }
    format!(r"\Sessions\{sess}\AppContainerNamedObjects\{ac_sid}")
}

/// Pre-create Cygwin's `shared.5` named section + its parent directory
/// inside the per-AC namespace. Both are stamped with a NULL DACL
/// (matches Cygwin's `sec_all_nih`).
///
/// `ac_sid` is the AppContainer SID string (e.g. `"S-1-15-2-…"`); the
/// session number is derived from the current (broker) process.
///
/// `target_command_line` is `pol.command_line`; we extract argv[0] and
/// look for `msys-2.0.dll` / `cygwin1.dll` next to it to compute the
/// install key. If no such DLL is found we return `Ok(None)` — the
/// target isn't a Cygwin/MSYS workload, so pre-create is a no-op.
pub fn precreate_cygwin_shared5(
    ac_sid: &str,
    target_command_line: &str,
) -> Result<Option<PrecreatedSharedSection>> {
    let ac_bno_root = ac_bno_root_for_session(ac_sid);
    let target_exe = match parse_target_exe(target_command_line) {
        Some(p) => p,
        None => {
            return Ok(None);
        }
    };
    let (cyg_dll, dll_id) = match locate_cygwin_dll(&target_exe) {
        Some(v) => v,
        None => {
            return Ok(None);
        }
    };

    let key = cygwin_installation_key(&cyg_dll);
    let parent_dir = format!(r"{}\{}S5-{}", ac_bno_root, dll_id, key);
    let section_path = format!(r"{}\shared.5", parent_dir);

    // Build a NULL-DACL SD that we pass to both creates. The stack
    // descriptor must outlive the OBJECT_ATTRIBUTES; we keep it
    // alive on this frame's stack.
    let mut sd: SECURITY_DESCRIPTOR = unsafe { zeroed() };
    unsafe {
        InitializeSecurityDescriptor(
            PSECURITY_DESCRIPTOR(&mut sd as *mut _ as *mut c_void),
            SECURITY_DESCRIPTOR_REVISION,
        ).context("InitializeSecurityDescriptor")?;
        SetSecurityDescriptorDacl(
            PSECURITY_DESCRIPTOR(&mut sd as *mut _ as *mut c_void),
            true, None, false,
        ).context("SetSecurityDescriptorDacl(NULL=allow-all)")?;
    }
    let sd_ptr: *mut c_void = &mut sd as *mut _ as *mut c_void;

    // Step 1: parent directory. OBJ_OPENIF in case the AC's own
    // namespace-bootstrap already created it.
    let dir_handle = unsafe {
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
        std::mem::drop(wpath);
        if st.0 < 0 {
            anyhow::bail!(
                "NtCreateDirectoryObject({}) -> {:#x}", parent_dir, st.0 as u32,
            );
        }
        h
    };

    // Step 2: the section. SEC_COMMIT pagefile-backed (file=NULL),
    // PAGE_READWRITE, size 0xE7B8.
    let section_handle = unsafe {
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
        std::mem::drop(wpath);
        if st.0 < 0 {
            let _ = CloseHandle(dir_handle);
            anyhow::bail!(
                "NtCreateSection({}) -> {:#x}", section_path, st.0 as u32,
            );
        }
        h
    };

    eprintln!(
        "[sbox-exec] cygwin-compat: pre-created shared.5 at {} \
         (cyg_dll={} dll_id={} install_key={})",
        section_path, cyg_dll.display(), dll_id, key,
    );

    Ok(Some(PrecreatedSharedSection {
        section: section_handle,
        dir: dir_handle,
        section_path,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_quoted_exe() {
        assert_eq!(
            parse_target_exe("\"C:\\Program Files\\Git\\usr\\bin\\bash.exe\" -c hello"),
            Some(PathBuf::from(r"C:\Program Files\Git\usr\bin\bash.exe")),
        );
    }

    #[test]
    fn parse_bare_exe() {
        assert_eq!(
            parse_target_exe("bash.exe -c hello"),
            Some(PathBuf::from("bash.exe")),
        );
    }

    #[test]
    fn parse_empty() {
        assert_eq!(parse_target_exe(""), None);
        assert_eq!(parse_target_exe("   "), None);
    }

    #[test]
    fn install_key_format() {
        // Algorithm sanity: deterministic 16-hex output.
        let k = cygwin_installation_key(&PathBuf::from(r"C:\Windows\System32\notepad.exe"));
        assert_eq!(k.len(), 16);
        assert!(k.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
