#![allow(dead_code)]

use anyhow::{anyhow, bail, Context, Result};
use std::ffi::{c_void, OsString};
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;
use std::ptr::null_mut;

use windows::core::{PCWSTR, PWSTR};
use windows::Wdk::System::Threading::{NtQueryInformationProcess, PROCESSINFOCLASS};
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, HANDLE, LUID,
};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, SetEntriesInAclW, SetNamedSecurityInfoW, EXPLICIT_ACCESS_W,
    NO_MULTIPLE_TRUSTEE, SET_ACCESS, SE_FILE_OBJECT, TRUSTEE_IS_SID, TRUSTEE_IS_WELL_KNOWN_GROUP,
    TRUSTEE_W,
};
use windows::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeleteAppContainerProfile,
    DeriveAppContainerSidFromAppContainerName, GetAppContainerFolderPath,
};
use windows::Win32::Security::{
    AdjustTokenPrivileges, CreateRestrictedToken, DuplicateTokenEx, FreeSid,
    GetTokenInformation, LookupPrivilegeValueW, SecurityImpersonation, SetTokenInformation,
    TokenGroups, TokenImpersonation, TokenIntegrityLevel,
    ACL as WinACL, DACL_SECURITY_INFORMATION, LUID_AND_ATTRIBUTES, PSID,
    SECURITY_CAPABILITIES, SE_PRIVILEGE_ENABLED, SID_AND_ATTRIBUTES,
    TOKEN_ACCESS_MASK, TOKEN_ADJUST_PRIVILEGES, TOKEN_ALL_ACCESS, TOKEN_GROUPS,
    TOKEN_MANDATORY_LABEL, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows::Win32::System::Diagnostics::Debug::{
    ReadProcessMemory, WriteProcessMemory, IMAGE_NT_HEADERS64,
};
use windows::Win32::System::SystemServices::SE_GROUP_LOGON_ID;
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Memory::{
    VirtualAllocEx, VirtualProtectEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
};
use windows::Win32::System::SystemServices::IMAGE_DOS_HEADER;
use windows::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, GetCurrentProcess,
    GetExitCodeProcess, InitializeProcThreadAttributeList, OpenProcessToken, OpenThreadToken,
    ResumeThread, TerminateProcess, UpdateProcThreadAttribute,
    WaitForSingleObject, CREATE_SUSPENDED, EXTENDED_STARTUPINFO_PRESENT,
    INFINITE, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_BASIC_INFORMATION, PROCESS_INFORMATION,
    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, STARTUPINFOEXW, STARTUPINFOW,
};

pub struct ProbeOutcome {
    pub pass: bool,
    pub detail: String,
}
impl ProbeOutcome {
    pub fn pass(d: impl Into<String>) -> Self { Self { pass: true,  detail: d.into() } }
    pub fn fail(d: impl Into<String>) -> Self { Self { pass: false, detail: d.into() } }
}

pub fn wstr(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub fn from_wstr(p: *const u16) -> String {
    if p.is_null() { return String::new(); }
    let mut len = 0usize;
    unsafe { while *p.add(len) != 0 { len += 1; } }
    let slice = unsafe { std::slice::from_raw_parts(p, len) };
    String::from_utf16_lossy(slice)
}

pub fn win_version_string() -> String {
    use windows::Win32::System::SystemInformation::OSVERSIONINFOW;
    #[link(name = "ntdll")]
    extern "system" { fn RtlGetVersion(v: *mut OSVERSIONINFOW) -> i32; }
    let mut v = OSVERSIONINFOW {
        dwOSVersionInfoSize: size_of::<OSVERSIONINFOW>() as u32, ..Default::default()
    };
    unsafe { RtlGetVersion(&mut v); }
    format!("{}.{}.{}", v.dwMajorVersion, v.dwMinorVersion, v.dwBuildNumber)
}

pub fn self_exe() -> PathBuf {
    std::env::current_exe().expect("current_exe")
}

// ──────────────────────────────────────────────────────────────────────────
// AppContainer
// ──────────────────────────────────────────────────────────────────────────

pub struct AppContainer {
    pub name: String,
    pub sid: PSID,
    pub sid_string: String,
    pub folder: PathBuf,
}
impl Drop for AppContainer {
    fn drop(&mut self) {
        unsafe {
            if !self.sid.0.is_null() { FreeSid(self.sid); }
            let n = wstr(&self.name);
            let _ = DeleteAppContainerProfile(PCWSTR(n.as_ptr()));
        }
    }
}

pub fn create_appcontainer(tag: &str) -> Result<AppContainer> {
    let name = format!("srt.poc.{tag}.{}", std::process::id());
    let wname = wstr(&name);
    unsafe {
        // Best-effort delete in case a previous run leaked it.
        let _ = DeleteAppContainerProfile(PCWSTR(wname.as_ptr()));
        let sid = match CreateAppContainerProfile(
            PCWSTR(wname.as_ptr()),
            PCWSTR(wname.as_ptr()),
            PCWSTR(wname.as_ptr()),
            None,
        ) {
            Ok(s) => s,
            Err(e) => {
                // 0x800700B7 = HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)
                if e.code().0 as u32 == 0x800700B7 {
                    DeriveAppContainerSidFromAppContainerName(PCWSTR(wname.as_ptr()))
                        .context("derive existing AC sid")?
                } else {
                    bail!("CreateAppContainerProfile({name}): {e}");
                }
            }
        };
        let mut sid_pwstr = PWSTR::null();
        ConvertSidToStringSidW(sid, &mut sid_pwstr).context("ConvertSidToStringSidW")?;
        let sid_string = from_wstr(sid_pwstr.0);
        windows::Win32::Foundation::LocalFree(windows::Win32::Foundation::HLOCAL(sid_pwstr.0 as _));

        let folder_pwstr = GetAppContainerFolderPath(PCWSTR(wstr(&sid_string).as_ptr()))
            .context("GetAppContainerFolderPath")?;
        let folder = PathBuf::from(OsString::from_wide(std::slice::from_raw_parts(
            folder_pwstr.0,
            (0..).take_while(|&i| *folder_pwstr.0.add(i) != 0).count(),
        )));
        windows::Win32::System::Com::CoTaskMemFree(Some(folder_pwstr.0 as *const c_void));

        Ok(AppContainer { name, sid, sid_string, folder })
    }
}

pub struct AcChild {
    pub pi: PROCESS_INFORMATION,
    pub _attr_buf: Vec<u8>,
}
impl AcChild {
    pub fn wait(&self) -> Result<u32> {
        unsafe {
            WaitForSingleObject(self.pi.hProcess, INFINITE);
            let mut code = 0u32;
            GetExitCodeProcess(self.pi.hProcess, &mut code).context("GetExitCodeProcess")?;
            Ok(code)
        }
    }
    pub fn wait_timeout(&self, ms: u32) -> Result<Option<u32>> {
        unsafe {
            let r = WaitForSingleObject(self.pi.hProcess, ms);
            if r == windows::Win32::Foundation::WAIT_TIMEOUT {
                return Ok(None);
            }
            let mut code = 0u32;
            GetExitCodeProcess(self.pi.hProcess, &mut code).context("GetExitCodeProcess")?;
            Ok(Some(code))
        }
    }
    pub fn resume(&self) {
        unsafe { ResumeThread(self.pi.hThread); }
    }
    pub fn terminate(&self) {
        unsafe { let _ = TerminateProcess(self.pi.hProcess, 1); }
    }
}
impl Drop for AcChild {
    fn drop(&mut self) {
        unsafe {
            if !self.pi.hProcess.is_invalid() { let _ = CloseHandle(self.pi.hProcess); }
            if !self.pi.hThread.is_invalid()  { let _ = CloseHandle(self.pi.hThread);  }
        }
    }
}

/// Spawn `exe args...` inside the given AppContainer, optionally suspended.
/// Inherits the parent's stdio handles so the child can print evidence.
pub fn spawn_in_ac(
    ac: &AppContainer,
    exe: &std::path::Path,
    args: &[&str],
    suspended: bool,
) -> Result<AcChild> {
    unsafe {
        let mut size = 0usize;
        let _ = InitializeProcThreadAttributeList(LPPROC_THREAD_ATTRIBUTE_LIST::default(), 1, 0, &mut size);
        let mut attr_buf = vec![0u8; size];
        let attr_list = LPPROC_THREAD_ATTRIBUTE_LIST(attr_buf.as_mut_ptr() as *mut c_void);
        InitializeProcThreadAttributeList(attr_list, 1, 0, &mut size)
            .context("InitializeProcThreadAttributeList")?;

        let caps = SECURITY_CAPABILITIES {
            AppContainerSid: ac.sid,
            Capabilities: null_mut(),
            CapabilityCount: 0,
            Reserved: 0,
        };
        UpdateProcThreadAttribute(
            attr_list,
            0,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
            Some(&caps as *const _ as *const c_void),
            size_of::<SECURITY_CAPABILITIES>(),
            None,
            None,
        )
        .context("UpdateProcThreadAttribute(SECURITY_CAPABILITIES)")?;

        let mut si: STARTUPINFOEXW = zeroed();
        si.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        si.lpAttributeList = attr_list;

        let mut cmd = format!("\"{}\"", exe.display());
        for a in args { cmd.push(' '); cmd.push('"'); cmd.push_str(a); cmd.push('"'); }
        let mut cmd_w = wstr(&cmd);

        let mut flags = EXTENDED_STARTUPINFO_PRESENT;
        if suspended { flags |= CREATE_SUSPENDED; }

        let mut pi: PROCESS_INFORMATION = zeroed();
        CreateProcessW(
            None,
            PWSTR(cmd_w.as_mut_ptr()),
            None,
            None,
            true,
            flags,
            None,
            None,
            &si.StartupInfo,
            &mut pi,
        )
        .with_context(|| format!("CreateProcessW({cmd}) in AppContainer"))?;

        DeleteProcThreadAttributeList(attr_list);
        Ok(AcChild { pi, _attr_buf: attr_buf })
    }
}

/// Spawn outside any AppContainer (regular CreateProcessW).
pub fn spawn_plain(exe: &std::path::Path, args: &[&str], suspended: bool) -> Result<AcChild> {
    unsafe {
        let mut si: STARTUPINFOW = zeroed();
        si.cb = size_of::<STARTUPINFOW>() as u32;
        let mut cmd = format!("\"{}\"", exe.display());
        for a in args { cmd.push(' '); cmd.push('"'); cmd.push_str(a); cmd.push('"'); }
        let mut cmd_w = wstr(&cmd);
        let mut flags = windows::Win32::System::Threading::PROCESS_CREATION_FLAGS(0);
        if suspended { flags |= CREATE_SUSPENDED; }
        let mut pi: PROCESS_INFORMATION = zeroed();
        CreateProcessW(None, PWSTR(cmd_w.as_mut_ptr()), None, None, true, flags, None, None, &si, &mut pi)
            .with_context(|| format!("CreateProcessW({cmd})"))?;
        Ok(AcChild { pi, _attr_buf: Vec::new() })
    }
}

// ──────────────────────────────────────────────────────────────────────────
// ACL helpers (P3)
// ──────────────────────────────────────────────────────────────────────────

pub fn grant_sid_on_path(path: &std::path::Path, sid: PSID, mask: u32) -> Result<()> {
    unsafe {
        let ea = EXPLICIT_ACCESS_W {
            grfAccessPermissions: mask,
            grfAccessMode: SET_ACCESS,
            grfInheritance: windows::Win32::Security::CONTAINER_INHERIT_ACE
                | windows::Win32::Security::OBJECT_INHERIT_ACE,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
                ptstrName: PWSTR(sid.0 as *mut u16),
            },
        };
        let mut new_acl: *mut WinACL = null_mut();
        let r = SetEntriesInAclW(Some(&[ea]), None, &mut new_acl);
        if r.is_err() { bail!("SetEntriesInAclW: {:?}", r); }
        let p = wstr(path.to_string_lossy().as_ref());
        let r = SetNamedSecurityInfoW(
            PCWSTR(p.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(new_acl),
            None,
        );
        windows::Win32::Foundation::LocalFree(windows::Win32::Foundation::HLOCAL(new_acl as _));
        if r.is_err() { bail!("SetNamedSecurityInfoW({}): {:?}", path.display(), r); }
        Ok(())
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Token helpers (P5/P7)
// ──────────────────────────────────────────────────────────────────────────

pub fn open_process_token_all() -> Result<HANDLE> {
    unsafe {
        let mut h = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &mut h)
            .context("OpenProcessToken")?;
        Ok(h)
    }
}

pub fn enable_privilege(name: &str) -> Result<()> {
    unsafe {
        let mut tok = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut tok)?;
        let wname = wstr(name);
        let mut luid = LUID::default();
        LookupPrivilegeValueW(None, PCWSTR(wname.as_ptr()), &mut luid)?;
        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES { Luid: luid, Attributes: SE_PRIVILEGE_ENABLED }],
        };
        AdjustTokenPrivileges(tok, false, Some(&tp), 0, None, None)?;
        let _ = CloseHandle(tok);
        Ok(())
    }
}

/// Build a Chromium-style lockdown primary token: every group deny-only
/// except the Logon SID, restricting SID = NULL SID, all privileges removed
/// EXCEPT SeChangeNotifyPrivilege (bypass-traverse — without it the loader
/// cannot even reach KnownDlls). The integrity level is set to Low here;
/// Untrusted is applied post-launch (Chromium's "delayed IL").
pub fn make_lockdown_token(base: HANDLE) -> Result<HANDLE> {
    use windows::Win32::Security::{
        AllocateAndInitializeSid, TokenPrivileges, SID_IDENTIFIER_AUTHORITY,
        CREATE_RESTRICTED_TOKEN_FLAGS,
    };
    unsafe {
        // Enumerate groups; mark all non-logon as deny-only.
        let mut len = 0u32;
        let _ = GetTokenInformation(base, TokenGroups, None, 0, &mut len);
        let mut buf = vec![0u8; len as usize];
        GetTokenInformation(base, TokenGroups, Some(buf.as_mut_ptr() as *mut c_void), len, &mut len)?;
        let groups = &*(buf.as_ptr() as *const TOKEN_GROUPS);
        let arr = std::slice::from_raw_parts(groups.Groups.as_ptr(), groups.GroupCount as usize);
        let mut deny: Vec<SID_AND_ATTRIBUTES> = Vec::new();
        for g in arr {
            if g.Attributes & (SE_GROUP_LOGON_ID as u32) == 0 {
                deny.push(SID_AND_ATTRIBUTES { Sid: g.Sid, Attributes: 0 });
            }
        }
        // Privileges to delete: everything except SeChangeNotifyPrivilege
        // (bypass-traverse) and — for the PoC — SeImpersonatePrivilege so the
        // child's main thread can actually USE the impersonation token at
        // SecurityImpersonation level (Chromium drops this later via
        // LowerToken; the PoC just needs the loader to survive).
        let keep: Vec<LUID> = ["SeChangeNotifyPrivilege", "SeImpersonatePrivilege"]
            .iter()
            .filter_map(|n| {
                let mut l = LUID::default();
                LookupPrivilegeValueW(None, PCWSTR(wstr(n).as_ptr()), &mut l).ok()?;
                Some(l)
            })
            .collect();
        let mut plen = 0u32;
        let _ = GetTokenInformation(base, TokenPrivileges, None, 0, &mut plen);
        let mut pbuf = vec![0u8; plen as usize];
        GetTokenInformation(base, TokenPrivileges, Some(pbuf.as_mut_ptr() as *mut c_void), plen, &mut plen)?;
        let privs = &*(pbuf.as_ptr() as *const TOKEN_PRIVILEGES);
        let parr = std::slice::from_raw_parts(privs.Privileges.as_ptr(), privs.PrivilegeCount as usize);
        let mut to_delete: Vec<LUID_AND_ATTRIBUTES> = Vec::new();
        for p in parr {
            let kept = keep.iter().any(|k| k.LowPart == p.Luid.LowPart && k.HighPart == p.Luid.HighPart);
            if !kept {
                to_delete.push(LUID_AND_ATTRIBUTES { Luid: p.Luid, Attributes: Default::default() });
            }
        }
        // Restricting SID = S-1-0-0 (NULL SID).
        let null_auth = SID_IDENTIFIER_AUTHORITY { Value: [0,0,0,0,0,0] };
        let mut null_sid = PSID::default();
        AllocateAndInitializeSid(&null_auth, 1, 0,0,0,0,0,0,0,0, &mut null_sid)?;
        let restrict = [SID_AND_ATTRIBUTES { Sid: null_sid, Attributes: 0 }];

        let mut out = HANDLE::default();
        CreateRestrictedToken(
            base,
            CREATE_RESTRICTED_TOKEN_FLAGS(0),
            Some(&deny),
            if to_delete.is_empty() { None } else { Some(&to_delete) },
            Some(&restrict),
            &mut out,
        ).context("CreateRestrictedToken")?;
        let _ = FreeSid(null_sid);

        // Low IL for launch; Untrusted is applied post-launch.
        set_token_il(out, 0x1000)?;
        Ok(out)
    }
}

/// Build the *initial* impersonation token. It must be flagged restricted
/// and at the same IL as the lockdown token, otherwise the kernel's
/// SeTokenCanImpersonate check silently downgrades it to Identification
/// when a restricted process tries to use it (→ STATUS_BAD_IMPERSONATION_
/// LEVEL in the loader). Chromium's USER_RESTRICTED_SAME_ACCESS does this
/// by putting every group SID + the user SID into the *restricting* list:
/// the token then satisfies "is restricted" while granting the same
/// effective access as the unrestricted base.
pub fn make_initial_impersonation(base: HANDLE, lockdown_il_rid: u32) -> Result<HANDLE> {
    use windows::Win32::Security::{TokenUser, TOKEN_USER, CREATE_RESTRICTED_TOKEN_FLAGS};
    unsafe {
        // Restricting list = user SID + every group SID.
        let mut ulen = 0u32;
        let _ = GetTokenInformation(base, TokenUser, None, 0, &mut ulen);
        let mut ubuf = vec![0u8; ulen as usize];
        GetTokenInformation(base, TokenUser, Some(ubuf.as_mut_ptr() as *mut c_void), ulen, &mut ulen)?;
        let user = &*(ubuf.as_ptr() as *const TOKEN_USER);

        let mut glen = 0u32;
        let _ = GetTokenInformation(base, TokenGroups, None, 0, &mut glen);
        let mut gbuf = vec![0u8; glen as usize];
        GetTokenInformation(base, TokenGroups, Some(gbuf.as_mut_ptr() as *mut c_void), glen, &mut glen)?;
        let groups = &*(gbuf.as_ptr() as *const TOKEN_GROUPS);
        let garr = std::slice::from_raw_parts(groups.Groups.as_ptr(), groups.GroupCount as usize);

        let mut restrict: Vec<SID_AND_ATTRIBUTES> = Vec::with_capacity(garr.len() + 1);
        restrict.push(SID_AND_ATTRIBUTES { Sid: user.User.Sid, Attributes: 0 });
        for g in garr {
            // Skip integrity-label and deny-only groups; everything else
            // goes into the restricting list so the token is "restricted"
            // but with unchanged effective access.
            if g.Attributes & 0x20 /*SE_GROUP_INTEGRITY*/ != 0 { continue; }
            if g.Attributes & 0x10 /*SE_GROUP_USE_FOR_DENY_ONLY*/ != 0 { continue; }
            restrict.push(SID_AND_ATTRIBUTES { Sid: g.Sid, Attributes: 0 });
        }

        let mut restricted = HANDLE::default();
        CreateRestrictedToken(
            base,
            CREATE_RESTRICTED_TOKEN_FLAGS(0),
            None,
            None,
            Some(&restrict),
            &mut restricted,
        ).context("CreateRestrictedToken(initial)")?;

        // Match the lockdown IL so SeTokenCanImpersonate doesn't downgrade.
        set_token_il(restricted, lockdown_il_rid)?;

        let mut out = HANDLE::default();
        DuplicateTokenEx(
            restricted,
            TOKEN_ALL_ACCESS,
            None,
            SecurityImpersonation,
            TokenImpersonation,
            &mut out,
        ).context("DuplicateTokenEx initial")?;
        let _ = CloseHandle(restricted);
        Ok(out)
    }
}

pub fn set_token_il(tok: HANDLE, rid: u32) -> Result<()> {
    use windows::Win32::Security::{AllocateAndInitializeSid, SID_IDENTIFIER_AUTHORITY};
    unsafe {
        let ml_auth = SID_IDENTIFIER_AUTHORITY { Value: [0,0,0,0,0,16] };
        let mut sid = PSID::default();
        AllocateAndInitializeSid(&ml_auth, 1, rid, 0,0,0,0,0,0,0, &mut sid)?;
        let tml = TOKEN_MANDATORY_LABEL {
            Label: SID_AND_ATTRIBUTES { Sid: sid, Attributes: 0x20 /* SE_GROUP_INTEGRITY */ },
        };
        SetTokenInformation(
            tok,
            TokenIntegrityLevel,
            &tml as *const _ as *const c_void,
            size_of::<TOKEN_MANDATORY_LABEL>() as u32 + windows::Win32::Security::GetLengthSid(sid),
        ).context("SetTokenInformation(IntegrityLevel)")?;
        let _ = FreeSid(sid);
        Ok(())
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Remote-process memory helpers (P6/P7/P8)
// ──────────────────────────────────────────────────────────────────────────

pub fn read_remote<T: Copy>(proc: HANDLE, addr: usize) -> Result<T> {
    unsafe {
        let mut out: T = zeroed();
        let mut n = 0usize;
        ReadProcessMemory(proc, addr as *const c_void, &mut out as *mut _ as *mut c_void,
                          size_of::<T>(), Some(&mut n))
            .with_context(|| format!("ReadProcessMemory @ {addr:#x}"))?;
        Ok(out)
    }
}

pub fn read_remote_bytes(proc: HANDLE, addr: usize, len: usize) -> Result<Vec<u8>> {
    unsafe {
        let mut buf = vec![0u8; len];
        let mut n = 0usize;
        ReadProcessMemory(proc, addr as *const c_void, buf.as_mut_ptr() as *mut c_void,
                          len, Some(&mut n))
            .with_context(|| format!("ReadProcessMemory @ {addr:#x} len {len}"))?;
        Ok(buf)
    }
}

pub fn write_remote_bytes(proc: HANDLE, addr: usize, data: &[u8]) -> Result<()> {
    unsafe {
        let mut old = PAGE_PROTECTION_FLAGS(0);
        VirtualProtectEx(proc, addr as *const c_void, data.len(), PAGE_EXECUTE_READWRITE, &mut old)
            .with_context(|| format!("VirtualProtectEx RW @ {addr:#x}"))?;
        let mut n = 0usize;
        WriteProcessMemory(proc, addr as *const c_void, data.as_ptr() as *const c_void,
                           data.len(), Some(&mut n))
            .with_context(|| format!("WriteProcessMemory @ {addr:#x}"))?;
        let mut _tmp = PAGE_PROTECTION_FLAGS(0);
        let _ = VirtualProtectEx(proc, addr as *const c_void, data.len(), old, &mut _tmp);
        let _ = windows::Win32::System::Diagnostics::Debug::FlushInstructionCache(
            proc, Some(addr as *const c_void), data.len());
        Ok(())
    }
}

pub fn alloc_remote_rx(proc: HANDLE, data: &[u8]) -> Result<usize> {
    unsafe {
        let p = VirtualAllocEx(proc, None, data.len().max(4096),
                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if p.is_null() { bail!("VirtualAllocEx: {:?}", GetLastError()); }
        let mut n = 0usize;
        WriteProcessMemory(proc, p, data.as_ptr() as *const c_void, data.len(), Some(&mut n))
            .context("WriteProcessMemory(stub)")?;
        let mut old = PAGE_PROTECTION_FLAGS(0);
        VirtualProtectEx(proc, p, data.len().max(4096), PAGE_EXECUTE_READ, &mut old)
            .context("VirtualProtectEx RX")?;
        Ok(p as usize)
    }
}

pub fn alloc_remote_rw(proc: HANDLE, len: usize) -> Result<usize> {
    unsafe {
        let p = VirtualAllocEx(proc, None, len.max(4096), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if p.is_null() { bail!("VirtualAllocEx RW: {:?}", GetLastError()); }
        Ok(p as usize)
    }
}

/// PEB walk → image base of the target executable in a suspended child.
pub fn remote_image_base(proc: HANDLE) -> Result<usize> {
    unsafe {
        let mut pbi: PROCESS_BASIC_INFORMATION = zeroed();
        let mut ret_len = 0u32;
        let st = NtQueryInformationProcess(
            proc,
            PROCESSINFOCLASS(0), // ProcessBasicInformation
            &mut pbi as *mut _ as *mut c_void,
            size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut ret_len,
        );
        if st.0 < 0 { bail!("NtQueryInformationProcess: {:#x}", st.0); }
        // PEB+0x10 = ImageBaseAddress on x64/arm64.
        let peb = pbi.PebBaseAddress as usize;
        let base: usize = read_remote(proc, peb + 0x10)?;
        Ok(base)
    }
}

/// PE entry-point VA in the target.
pub fn remote_entry_point(proc: HANDLE) -> Result<usize> {
    let base = remote_image_base(proc)?;
    let dos: IMAGE_DOS_HEADER = read_remote(proc, base)?;
    let nt: IMAGE_NT_HEADERS64 = read_remote(proc, base + dos.e_lfanew as usize)?;
    Ok(base + nt.OptionalHeader.AddressOfEntryPoint as usize)
}

/// ntdll base is identical across all processes per boot session, so the
/// local module base is also the child's. Resolve an ntdll export VA.
pub fn ntdll_export(name: &str) -> Result<usize> {
    unsafe {
        let m = GetModuleHandleW(PCWSTR(wstr("ntdll.dll").as_ptr()))
            .context("GetModuleHandleW(ntdll)")?;
        let p = GetProcAddress(m, windows::core::PCSTR(format!("{name}\0").as_ptr()))
            .ok_or_else(|| anyhow!("GetProcAddress(ntdll!{name})"))?;
        Ok(p as usize)
    }
}

pub fn local_module_base(name: &str) -> Result<usize> {
    unsafe {
        let m = GetModuleHandleW(PCWSTR(wstr(name).as_ptr()))
            .with_context(|| format!("GetModuleHandleW({name})"))?;
        Ok(m.0 as usize)
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Child dispatch — invoked via `winsbox-poc child <which> [args...]` from a
// re-exec inside the AppContainer (or as a controlled target for P5/P7/P8).
// Each handler returns a process exit code; the parent probe interprets it.
// ──────────────────────────────────────────────────────────────────────────

pub fn dispatch_child(which: &str, args: &[String]) -> i32 {
    let r = match which {
        "p1-loopback"   => crate::p1_loopback::child_main(args),
        "p2-uds-connect"=> crate::p2_afunix::child_connect(args),
        "p2-uds-listen" => crate::p2_afunix::child_listen(args),
        "p3-write"      => crate::p3_acl::child_write(args),
        "p4-spawn"      => crate::p4_inherit::child_spawn(args),
        "p4-grandchild" => crate::p4_inherit::child_grandchild(args),
        "p5-target"     => crate::p5_lowbox::child_target(args),
        "p7-target"     => crate::p7_entry::child_target(args),
        "p8-parent"     => crate::p8_createproc::child_parent(args),
        "p8-grandchild" => crate::p8_createproc::child_grandchild(args),
        other => { eprintln!("unknown child '{other}'"); return 90; }
    };
    match r {
        Ok(code) => code,
        Err(e) => { eprintln!("child {which} error: {e:?}"); 91 }
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Arch-specific absolute-jmp encoder (shared by P6/P7/P8)
// ──────────────────────────────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
pub const ABS_JMP_LEN: usize = 12;
#[cfg(target_arch = "x86_64")]
pub fn enc_abs_jmp(target: usize) -> Vec<u8> {
    let mut s = Vec::with_capacity(12);
    s.extend_from_slice(&[0x48, 0xB8]);                 // mov rax, imm64
    s.extend_from_slice(&target.to_le_bytes());
    s.extend_from_slice(&[0xFF, 0xE0]);                 // jmp rax
    s
}

#[cfg(target_arch = "aarch64")]
pub const ABS_JMP_LEN: usize = 16;
#[cfg(target_arch = "aarch64")]
pub fn enc_abs_jmp(target: usize) -> Vec<u8> {
    let mut s = Vec::with_capacity(16);
    s.extend_from_slice(&0x58000050u32.to_le_bytes());  // ldr x16, #8
    s.extend_from_slice(&0xD61F0200u32.to_le_bytes());  // br  x16
    s.extend_from_slice(&target.to_le_bytes());         // .quad target
    s
}

pub fn pad_nops(buf: &mut Vec<u8>, to: usize) {
    #[cfg(target_arch = "x86_64")]
    while buf.len() < to { buf.push(0x90); }
    #[cfg(target_arch = "aarch64")]
    while buf.len() < to { buf.extend_from_slice(&0xD503201Fu32.to_le_bytes()); }
}

/// True if the calling thread currently has an impersonation token.
pub fn thread_is_impersonating() -> bool {
    unsafe {
        let mut h = HANDLE::default();
        let ok = OpenThreadToken(
            windows::Win32::System::Threading::GetCurrentThread(),
            TOKEN_QUERY,
            true,
            &mut h,
        );
        if let Ok(()) = ok {
            let _ = CloseHandle(h);
            true
        } else {
            false
        }
    }
}

/// True if the current process token carries an AppContainer SID.
pub fn process_is_appcontainer() -> bool {
    unsafe {
        let mut tok = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok).is_err() {
            return false;
        }
        let mut is_ac: u32 = 0;
        let mut len = 0u32;
        let r = GetTokenInformation(
            tok,
            windows::Win32::Security::TokenIsAppContainer,
            Some(&mut is_ac as *mut _ as *mut c_void),
            size_of::<u32>() as u32,
            &mut len,
        );
        let _ = CloseHandle(tok);
        r.is_ok() && is_ac != 0
    }
}
