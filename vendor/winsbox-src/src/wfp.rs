//! Windows Filtering Platform (WFP) filter install/remove + local group
//! provisioning.
//!
//! Design (deny-only-group fence, locked in May 2026):
//!
//!   - Install creates a local group `winsbox-allowed`, adds the broker
//!     user to it, and persists 6 WFP filters (3 each at IPv4 + IPv6
//!     `FWPM_LAYER_ALE_AUTH_CONNECT_*`):
//!
//!       Filter 1 — PERMIT (high weight)
//!         ALE_USER_ID SD `O:LSD:(A;;CC;;;<group_sid>)`
//!         Hits whenever the `winsbox-allowed` group is ENABLED in the
//!         caller's TokenGroups (broker, Explorer, normal user procs).
//!
//!       Filter 2 — PERMIT (medium weight)
//!         ALE_USER_ID SD `O:LSD:(A;;CC;;;<user_sid>)`
//!         + IP_REMOTE_ADDRESS == 127.0.0.1 (resp. ::1)
//!         + IP_REMOTE_PORT == <proxy_port>
//!         Lets sandbox children reach the SOCKS proxy.
//!
//!       Filter 3 — BLOCK (low weight)
//!         ALE_USER_ID SD `O:LSD:(A;;CC;;;<user_sid>)`
//!         Catches sandbox children that didn't match #1 (their group
//!         is deny-only) and didn't match #2 (off proxy port).
//!
//!   - The broker is the same user as a sandbox child, but the broker's
//!     token has the group ENABLED while the sandbox child's token has
//!     it DENY-ONLY (`CreateRestrictedToken(SidsToDisable=[group_sid])`).
//!     WFP's ALE_USER_ID AccessCheck honors deny-only — see
//!     `Y:\synthetic-sid-probe.md` (S1) and `Y:\denyonly-probe.md` (D2)
//!     for the underlying empirical work.
//!
//! Marker file: `%ProgramData%\winsbox\installed.json` carries port,
//! sublayer GUID, group name + SID, user SID — read by the broker to
//! validate state at every launch.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::ffi::c_void;
use std::path::PathBuf;
use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::{LocalFree, ERROR_MEMBER_IN_ALIAS, HANDLE, HLOCAL};
use windows::Win32::NetworkManagement::NetManagement::{
    NetLocalGroupAdd, NetLocalGroupAddMembers, NetLocalGroupDel,
    NetLocalGroupGetInfo, NERR_GroupExists, NERR_GroupNotFound, NetApiBufferFree,
    LOCALGROUP_INFO_1, LOCALGROUP_MEMBERS_INFO_0,
};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0,
    FwpmFilterCreateEnumHandle0, FwpmFilterDeleteByKey0,
    FwpmFilterDestroyEnumHandle0, FwpmFilterEnum0, FwpmFreeMemory0,
    FwpmSubLayerAdd0, FwpmSubLayerDeleteByKey0, FwpmTransactionAbort0,
    FwpmTransactionBegin0, FwpmTransactionCommit0, FWPM_ACTION0, FWPM_ACTION0_0,
    FWPM_CONDITION_ALE_USER_ID, FWPM_CONDITION_IP_REMOTE_ADDRESS,
    FWPM_CONDITION_IP_REMOTE_PORT, FWPM_DISPLAY_DATA0, FWPM_FILTER0,
    FWPM_FILTER_CONDITION0, FWPM_FILTER_ENUM_TEMPLATE0,
    FWPM_FILTER_FLAG_PERSISTENT, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_SUBLAYER0,
    FWPM_SUBLAYER_FLAG_PERSISTENT, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT,
    FWP_BYTE_ARRAY16, FWP_BYTE_BLOB, FWP_CONDITION_VALUE0,
    FWP_CONDITION_VALUE0_0, FWP_FILTER_ENUM_OVERLAPPING, FWP_MATCH_EQUAL,
    FWP_SECURITY_DESCRIPTOR_TYPE, FWP_UINT16, FWP_UINT32, FWP_VALUE0,
    FWP_VALUE0_0,
};
use windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows::Win32::Security::{
    GetSecurityDescriptorLength, PSECURITY_DESCRIPTOR, PSID,
};

use crate::sid;
use crate::util::{pcwstr, wstr};

/// Default local group name. Stable across installs so the broker can
/// find it by name.
pub const GROUP_NAME: &str = "winsbox-allowed";
const GROUP_COMMENT: &str = "winsbox network sandbox membership group";

// Sublayer GUID — stable, hard-coded for deterministic uninstall.
// New GUID for the deny-only-group design to avoid conflicts with any
// older Phase 2 (SANDBOX_SID restricting-array) install on the same
// host. Sysinternals can still list both for diagnosis.
// {2c5d0ad6-5f3b-4d4e-9b8f-1a3e7c9d0b21}
const SUBLAYER_GUID: GUID =
    GUID::from_u128(0x2c5d0ad6_5f3b_4d4e_9b8f_1a3e7c9d0b21);

// Filter GUIDs derived from sublayer by mutating the low byte of Data4.
const fn filter_guid(tag: u8) -> GUID {
    let mut g = SUBLAYER_GUID;
    g.data4[7] = tag;
    g
}

// Tags 1..=6.
const FILTER_GUIDS: [GUID; 6] = [
    filter_guid(1),
    filter_guid(2),
    filter_guid(3),
    filter_guid(4),
    filter_guid(5),
    filter_guid(6),
];

// Phase 2 sublayer GUID — the SANDBOX_SID restricting-array design's
// persistent filters would race with our deny-only-group filters at
// the cross-sublayer policy-arbitration step. We enumerate-and-delete
// any filters under this GUID at install AND uninstall.
// {a4f4e62c-3d8a-4f3a-9b9e-d2f5e8a17b41}
const LEGACY_SUBLAYER_GUID: GUID =
    GUID::from_u128(0xa4f4e62c_3d8a_4f3a_9b9e_d2f5e8a17b41);

// WFP errors we want to swallow.
const FWP_E_ALREADY_EXISTS: u32 = 0x80320009;
const FWP_E_FILTER_NOT_FOUND: u32 = 0x80320026;
const FWP_E_SUBLAYER_NOT_FOUND: u32 = 0x80320042;

// SDDL revision constant.
const SDDL_REVISION_1: u32 = 1;

/// Marker file shape (`%ProgramData%\winsbox\installed.json`).
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Marker {
    pub port: u16,
    pub sublayer_guid: String,
    pub group_name: String,
    pub group_sid: String,
    pub user_sid: String,
}

fn marker_path() -> PathBuf {
    let base = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("C:\\ProgramData"));
    base.join("winsbox").join("installed.json")
}

fn write_marker(m: &Marker) -> Result<()> {
    let p = marker_path();
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("mkdir {}", parent.display()))?;
    }
    let s = serde_json::to_string_pretty(m)?;
    std::fs::write(&p, s).with_context(|| format!("write {}", p.display()))?;
    Ok(())
}

fn delete_marker() -> Result<()> {
    let p = marker_path();
    if p.exists() {
        std::fs::remove_file(&p).with_context(|| format!("rm {}", p.display()))?;
    }
    Ok(())
}

fn read_marker() -> Result<Option<Marker>> {
    let p = marker_path();
    if !p.exists() {
        return Ok(None);
    }
    let s = std::fs::read_to_string(&p)
        .with_context(|| format!("read {}", p.display()))?;
    Ok(Some(serde_json::from_str(&s)?))
}

/// Heap-allocated security descriptor owned by us. Drop frees via
/// `LocalFree` to mirror
/// `ConvertStringSecurityDescriptorToSecurityDescriptorW`.
struct OwnedSd {
    ptr: PSECURITY_DESCRIPTOR,
    len: u32,
}

impl OwnedSd {
    fn from_sddl(sddl: &str) -> Result<Self> {
        let w = wstr(sddl);
        let mut psd = PSECURITY_DESCRIPTOR::default();
        let mut sz: u32 = 0;
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                pcwstr(&w),
                SDDL_REVISION_1,
                &mut psd,
                Some(&mut sz),
            )
            .map_err(|e| {
                anyhow!(
                    "ConvertStringSecurityDescriptorToSecurityDescriptorW({sddl}): {e}"
                )
            })?;
            if sz == 0 {
                sz = GetSecurityDescriptorLength(psd);
            }
        }
        Ok(Self { ptr: psd, len: sz })
    }
    fn byte_blob(&self) -> FWP_BYTE_BLOB {
        FWP_BYTE_BLOB {
            size: self.len,
            data: self.ptr.0 as *mut u8,
        }
    }
}

impl Drop for OwnedSd {
    fn drop(&mut self) {
        if !self.ptr.0.is_null() {
            unsafe {
                let _ = LocalFree(HLOCAL(self.ptr.0));
            }
        }
    }
}

struct EngineHandle(HANDLE);

impl EngineHandle {
    fn open() -> Result<Self> {
        let mut h = HANDLE::default();
        let rc = unsafe {
            FwpmEngineOpen0(PCWSTR::null(), 0xFFFFFFFF, None, None, &mut h)
        };
        if rc != 0 {
            return Err(anyhow!("FwpmEngineOpen0 failed: 0x{rc:08x}"));
        }
        Ok(Self(h))
    }
    fn as_handle(&self) -> HANDLE {
        self.0
    }
}

impl Drop for EngineHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = FwpmEngineClose0(self.0);
            }
        }
    }
}

#[allow(dead_code)]
fn fwp_uint32(v: u32) -> FWP_VALUE0 {
    FWP_VALUE0 {
        r#type: FWP_UINT32,
        Anonymous: FWP_VALUE0_0 { uint32: v },
    }
}

// Build an FWP_VALUE0 of type FWP_UINT64 pointing at `slot`. WFP
// dereferences this during the FwpmFilterAdd0 call (lesson from Phase 4
// fix in commit 85a6f29 on the parent branch).
fn fwp_uint64(slot: &mut u64) -> FWP_VALUE0 {
    FWP_VALUE0 {
        r#type:
            windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_UINT64,
        Anonymous: FWP_VALUE0_0 {
            uint64: slot as *mut u64,
        },
    }
}

fn cond_uint32(field_key: GUID, v: u32) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field_key,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_UINT32,
            Anonymous: FWP_CONDITION_VALUE0_0 { uint32: v },
        },
    }
}

fn cond_uint16(field_key: GUID, v: u16) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field_key,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_UINT16,
            Anonymous: FWP_CONDITION_VALUE0_0 { uint16: v },
        },
    }
}

fn cond_v6_addr(field_key: GUID, addr: &mut FWP_BYTE_ARRAY16) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field_key,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type:
                windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_BYTE_ARRAY16_TYPE,
            Anonymous: FWP_CONDITION_VALUE0_0 {
                byteArray16: addr as *mut _,
            },
        },
    }
}

fn cond_sd(field_key: GUID, blob: &mut FWP_BYTE_BLOB) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field_key,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_SECURITY_DESCRIPTOR_TYPE,
            Anonymous: FWP_CONDITION_VALUE0_0 {
                sd: blob as *mut _,
            },
        },
    }
}

fn add_filter(
    engine: HANDLE,
    key: GUID,
    layer: GUID,
    name: &str,
    weight: u64,
    action_type: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_ACTION_TYPE,
    conditions: &mut [FWPM_FILTER_CONDITION0],
) -> Result<()> {
    let mut name_w = wstr(name);
    let mut desc_w = wstr("winsbox WFP filter");
    let mut weight_slot: u64 = weight;
    let mut filter = FWPM_FILTER0::default();
    filter.filterKey = key;
    filter.displayData = FWPM_DISPLAY_DATA0 {
        name: PWSTR(name_w.as_mut_ptr()),
        description: PWSTR(desc_w.as_mut_ptr()),
    };
    filter.flags = FWPM_FILTER_FLAG_PERSISTENT;
    filter.layerKey = layer;
    filter.subLayerKey = SUBLAYER_GUID;
    filter.weight = fwp_uint64(&mut weight_slot);
    filter.numFilterConditions = conditions.len() as u32;
    filter.filterCondition = if conditions.is_empty() {
        std::ptr::null_mut()
    } else {
        conditions.as_mut_ptr()
    };
    filter.action = FWPM_ACTION0 {
        r#type: action_type,
        Anonymous: FWPM_ACTION0_0 {
            filterType: GUID::zeroed(),
        },
    };
    if std::env::var_os("WINSBOX_WFP_DEBUG").is_some() {
        eprintln!(
            "[winsbox-wfp] add_filter name={name} weight=0x{weight:016x} \
             action=0x{:x} layer={:?} sublayer={:?} conds={} flags=0x{:x}",
            action_type.0,
            layer,
            SUBLAYER_GUID,
            conditions.len(),
            filter.flags.0,
        );
    }
    let rc = unsafe {
        FwpmFilterAdd0(engine, &filter, PSECURITY_DESCRIPTOR::default(), None)
    };
    if rc != 0 && rc != FWP_E_ALREADY_EXISTS {
        return Err(anyhow!("FwpmFilterAdd0({name}) failed: 0x{rc:08x}"));
    }
    Ok(())
}

// ────────────────────── Local group provisioning ──────────────────────

/// Create the local group if it doesn't already exist. Idempotent on
/// `NERR_GroupExists`.
pub fn ensure_group_exists() -> Result<()> {
    unsafe {
        let name_w = wstr(GROUP_NAME);
        let mut comment_w = wstr(GROUP_COMMENT);
        // Use name_w as a stable backing store referenced inside the
        // info struct.
        let mut name_w_mut = name_w.clone();
        let info = LOCALGROUP_INFO_1 {
            lgrpi1_name: PWSTR(name_w_mut.as_mut_ptr()),
            lgrpi1_comment: PWSTR(comment_w.as_mut_ptr()),
        };
        let rc = NetLocalGroupAdd(
            PCWSTR::null(),
            1,
            &info as *const _ as *const u8,
            None,
        );
        // ERROR_ALIAS_EXISTS (1379) is what SAM actually returns for an
        // existing local group; NERR_GroupExists (2223) is the
        // documented value some paths return. Treat both as idempotent.
        const ERROR_ALIAS_EXISTS: u32 = 1379;
        if rc != 0 && rc != NERR_GroupExists && rc != ERROR_ALIAS_EXISTS {
            return Err(anyhow!("NetLocalGroupAdd({GROUP_NAME}): {rc}"));
        }
        Ok(())
    }
}

/// Add `user_sid_str` to the local group. Idempotent on
/// `ERROR_MEMBER_IN_ALIAS`. `user_sid_str` must be a string SID
/// (`"S-1-5-21-..."`).
pub fn add_user_to_group(user_sid_str: &str) -> Result<()> {
    let psid = sid::psid_from_string(user_sid_str)?;
    let result = unsafe {
        let name_w = wstr(GROUP_NAME);
        let info = LOCALGROUP_MEMBERS_INFO_0 { lgrmi0_sid: psid };
        let rc = NetLocalGroupAddMembers(
            PCWSTR::null(),
            pcwstr(&name_w),
            0,
            &info as *const _ as *const u8,
            1,
        );
        if rc != 0 && rc != ERROR_MEMBER_IN_ALIAS.0 {
            Err(anyhow!(
                "NetLocalGroupAddMembers({GROUP_NAME}, {user_sid_str}): {rc}"
            ))
        } else {
            Ok(())
        }
    };
    sid::free_psid(psid);
    result
}

/// Delete the local group (and implicitly all its memberships) if it
/// exists. Idempotent on `NERR_GroupNotFound`.
pub fn delete_group() -> Result<()> {
    unsafe {
        let name_w = wstr(GROUP_NAME);
        let rc = NetLocalGroupDel(PCWSTR::null(), pcwstr(&name_w));
        if rc != 0 && rc != NERR_GroupNotFound {
            return Err(anyhow!("NetLocalGroupDel({GROUP_NAME}): {rc}"));
        }
        Ok(())
    }
}

/// Return `Ok(true)` if the local group exists, `Ok(false)` otherwise.
pub fn group_exists() -> Result<bool> {
    unsafe {
        let name_w = wstr(GROUP_NAME);
        let mut buf: *mut u8 = std::ptr::null_mut();
        let rc =
            NetLocalGroupGetInfo(PCWSTR::null(), pcwstr(&name_w), 1, &mut buf);
        if rc == 0 {
            let _ = NetApiBufferFree(Some(buf as *const c_void));
            return Ok(true);
        }
        if rc == NERR_GroupNotFound {
            return Ok(false);
        }
        Err(anyhow!("NetLocalGroupGetInfo({GROUP_NAME}): {rc}"))
    }
}

// ────────────────────── WFP install/uninstall ──────────────────────

/// Enumerate every filter at `layer` and delete the ones whose
/// `subLayerKey == target_sublayer`. Used to clean up stragglers from
/// an older install (different sublayer GUID) and to make `install`
/// idempotent against a stale-state machine. Idempotent and best-effort
/// — partial failures inside the enum are logged, not propagated.
fn delete_filters_in_sublayer(
    engine: HANDLE,
    target_sublayer: &GUID,
    layers: &[GUID],
) -> Result<usize> {
    use windows::Win32::Foundation::HANDLE as F_HANDLE;
    let mut total = 0usize;
    for layer in layers {
        let mut tmpl = FWPM_FILTER_ENUM_TEMPLATE0::default();
        tmpl.layerKey = *layer;
        tmpl.enumType = FWP_FILTER_ENUM_OVERLAPPING;
        tmpl.actionMask = 0xFFFF_FFFF;
        let mut h: F_HANDLE = F_HANDLE::default();
        let rc = unsafe {
            FwpmFilterCreateEnumHandle0(engine, Some(&tmpl), &mut h)
        };
        if rc != 0 {
            eprintln!(
                "[sbox-exec] cleanup: FwpmFilterCreateEnumHandle0(layer={layer:?}) \
                 rc=0x{rc:08x} — skipping this layer"
            );
            continue;
        }

        loop {
            let mut entries: *mut *mut FWPM_FILTER0 = std::ptr::null_mut();
            let mut n: u32 = 0;
            let rc = unsafe {
                FwpmFilterEnum0(engine, h, 256, &mut entries, &mut n)
            };
            if rc != 0 {
                eprintln!(
                    "[sbox-exec] cleanup: FwpmFilterEnum0 rc=0x{rc:08x} — stopping"
                );
                break;
            }
            if n == 0 {
                if !entries.is_null() {
                    unsafe { FwpmFreeMemory0(&mut (entries as *mut _)) };
                }
                break;
            }
            let slice = unsafe {
                std::slice::from_raw_parts(entries, n as usize)
            };
            for &fp in slice {
                if fp.is_null() {
                    continue;
                }
                let f = unsafe { &*fp };
                if &f.subLayerKey == target_sublayer {
                    let key = f.filterKey;
                    let rc = unsafe { FwpmFilterDeleteByKey0(engine, &key) };
                    if rc != 0 && rc != FWP_E_FILTER_NOT_FOUND {
                        eprintln!(
                            "[sbox-exec] cleanup: FwpmFilterDeleteByKey0({key:?}) \
                             rc=0x{rc:08x}"
                        );
                    } else {
                        total += 1;
                    }
                }
            }
            unsafe { FwpmFreeMemory0(&mut (entries as *mut _)) };
            if (n as usize) < 256 {
                break;
            }
        }

        let rc = unsafe { FwpmFilterDestroyEnumHandle0(engine, h) };
        if rc != 0 {
            eprintln!(
                "[sbox-exec] cleanup: FwpmFilterDestroyEnumHandle0 rc=0x{rc:08x}"
            );
        }
    }
    Ok(total)
}

/// Delete the legacy Phase 2 sublayer + any filters under it. Run
/// inside the same transaction as the regular install/uninstall so
/// committing the new state is atomic with retiring the old.
fn purge_legacy_sublayer(engine: HANDLE) -> Result<()> {
    let layers = [
        FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    ];
    let removed = delete_filters_in_sublayer(engine, &LEGACY_SUBLAYER_GUID, &layers)?;
    if removed > 0 {
        eprintln!(
            "[sbox-exec] purged {removed} filter(s) from legacy sublayer \
             {LEGACY_SUBLAYER_GUID:?}"
        );
    }
    let rc = unsafe { FwpmSubLayerDeleteByKey0(engine, &LEGACY_SUBLAYER_GUID) };
    if rc == 0 {
        eprintln!(
            "[sbox-exec] removed legacy sublayer {LEGACY_SUBLAYER_GUID:?}"
        );
    } else if rc != FWP_E_FILTER_NOT_FOUND && rc != FWP_E_SUBLAYER_NOT_FOUND {
        eprintln!(
            "[sbox-exec] cleanup: FwpmSubLayerDeleteByKey0(legacy) \
             rc=0x{rc:08x}"
        );
    }
    Ok(())
}

/// Install the 6 persistent WFP filters keyed on `group_sid_str` and
/// `user_sid_str`. `proxy_port` is the loopback port the sandbox child
/// is permitted to reach.
pub fn install_filters(
    proxy_port: u16,
    group_sid_str: &str,
    user_sid_str: &str,
) -> Result<()> {
    // SDDL strings.
    let sddl_group = format!("O:LSD:(A;;CC;;;{group_sid_str})");
    let sddl_user = format!("O:LSD:(A;;CC;;;{user_sid_str})");
    let sd_group = OwnedSd::from_sddl(&sddl_group)?;
    let sd_user = OwnedSd::from_sddl(&sddl_user)?;

    let engine = EngineHandle::open()?;
    let rc = unsafe { FwpmTransactionBegin0(engine.as_handle(), 0) };
    if rc != 0 {
        return Err(anyhow!("FwpmTransactionBegin0 failed: 0x{rc:08x}"));
    }

    // First, retire any Phase 2 (SANDBOX_SID) stragglers so they don't
    // race the new filters in policy arbitration.
    if let Err(e) = purge_legacy_sublayer(engine.as_handle()) {
        eprintln!("[sbox-exec] purge_legacy_sublayer (non-fatal): {e:#}");
    }

    let result: Result<()> = (|| {
        // 1) Sublayer.
        let mut sl_name_w = wstr("winsbox-denyonly-net");
        let mut sl_desc_w = wstr("winsbox WFP sublayer (deny-only-group fence)");
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: SUBLAYER_GUID,
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR(sl_name_w.as_mut_ptr()),
                description: PWSTR(sl_desc_w.as_mut_ptr()),
            },
            flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
            providerKey: std::ptr::null_mut(),
            providerData: FWP_BYTE_BLOB {
                size: 0,
                data: std::ptr::null_mut(),
            },
            weight: 0x8000,
        };
        let rc = unsafe {
            FwpmSubLayerAdd0(
                engine.as_handle(),
                &sublayer,
                PSECURITY_DESCRIPTOR::default(),
            )
        };
        if rc != 0 && rc != FWP_E_ALREADY_EXISTS {
            return Err(anyhow!("FwpmSubLayerAdd0 failed: 0x{rc:08x}"));
        }

        // Weights — high → permit-group, medium → permit-user-on-proxy,
        // low → block-user. All below 2^60 so we don't collide with WFP's
        // auto-weight class (top 4 bits).
        const W_HIGH: u64 = 0x0F00_0000_0000_0000;
        const W_MED: u64 = 0x0C00_0000_0000_0000;
        const W_LOW: u64 = 0x0400_0000_0000_0000;

        let v4_loopback: u32 = 0x7F000001; // 127.0.0.1
        let mut v6_loopback = FWP_BYTE_ARRAY16 {
            byteArray16: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        };

        // Reusable byte-blob views — kept alive on the stack for the
        // duration of each FwpmFilterAdd0 call.
        let mut sd_group_blob = sd_group.byte_blob();
        let mut sd_user_blob = sd_user.byte_blob();

        // ────────────── IPv4 ──────────────
        // F1 V4 PERMIT (group enabled).
        let mut c1 = [cond_sd(FWPM_CONDITION_ALE_USER_ID, &mut sd_group_blob)];
        add_filter(
            engine.as_handle(),
            FILTER_GUIDS[0],
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            "winsbox-v4-permit-group",
            W_HIGH,
            FWP_ACTION_PERMIT,
            &mut c1,
        )?;

        // F2 V4 PERMIT (user on proxy port loopback).
        let mut c2 = [
            cond_uint32(FWPM_CONDITION_IP_REMOTE_ADDRESS, v4_loopback),
            cond_uint16(FWPM_CONDITION_IP_REMOTE_PORT, proxy_port),
            cond_sd(FWPM_CONDITION_ALE_USER_ID, &mut sd_user_blob),
        ];
        add_filter(
            engine.as_handle(),
            FILTER_GUIDS[1],
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            "winsbox-v4-permit-sandbox-to-proxy",
            W_MED,
            FWP_ACTION_PERMIT,
            &mut c2,
        )?;

        // F3 V4 BLOCK (catch-all on user; group is deny-only so F1
        // doesn't apply for sandbox children).
        let mut c3 = [cond_sd(FWPM_CONDITION_ALE_USER_ID, &mut sd_user_blob)];
        add_filter(
            engine.as_handle(),
            FILTER_GUIDS[2],
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            "winsbox-v4-block-user-default",
            W_LOW,
            FWP_ACTION_BLOCK,
            &mut c3,
        )?;

        // ────────────── IPv6 ──────────────
        // F4 V6 PERMIT (group enabled).
        let mut c4 = [cond_sd(FWPM_CONDITION_ALE_USER_ID, &mut sd_group_blob)];
        add_filter(
            engine.as_handle(),
            FILTER_GUIDS[3],
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            "winsbox-v6-permit-group",
            W_HIGH,
            FWP_ACTION_PERMIT,
            &mut c4,
        )?;

        // F5 V6 PERMIT (user on proxy port ::1).
        let mut c5 = [
            cond_v6_addr(FWPM_CONDITION_IP_REMOTE_ADDRESS, &mut v6_loopback),
            cond_uint16(FWPM_CONDITION_IP_REMOTE_PORT, proxy_port),
            cond_sd(FWPM_CONDITION_ALE_USER_ID, &mut sd_user_blob),
        ];
        add_filter(
            engine.as_handle(),
            FILTER_GUIDS[4],
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            "winsbox-v6-permit-sandbox-to-proxy",
            W_MED,
            FWP_ACTION_PERMIT,
            &mut c5,
        )?;

        // F6 V6 BLOCK (catch-all on user).
        let mut c6 = [cond_sd(FWPM_CONDITION_ALE_USER_ID, &mut sd_user_blob)];
        add_filter(
            engine.as_handle(),
            FILTER_GUIDS[5],
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            "winsbox-v6-block-user-default",
            W_LOW,
            FWP_ACTION_BLOCK,
            &mut c6,
        )?;

        Ok(())
    })();

    if result.is_err() {
        unsafe {
            let _ = FwpmTransactionAbort0(engine.as_handle());
        }
        return result;
    }
    let rc = unsafe { FwpmTransactionCommit0(engine.as_handle()) };
    if rc != 0 {
        return Err(anyhow!("FwpmTransactionCommit0 failed: 0x{rc:08x}"));
    }
    Ok(())
}

/// Remove the filters + sublayer installed by `install_filters`.
pub fn uninstall_filters() -> Result<()> {
    let engine = EngineHandle::open()?;
    let rc = unsafe { FwpmTransactionBegin0(engine.as_handle(), 0) };
    if rc != 0 {
        return Err(anyhow!("FwpmTransactionBegin0 failed: 0x{rc:08x}"));
    }
    let result: Result<()> = (|| {
        for guid in &FILTER_GUIDS {
            let rc =
                unsafe { FwpmFilterDeleteByKey0(engine.as_handle(), guid) };
            if rc != 0 && rc != FWP_E_FILTER_NOT_FOUND {
                return Err(anyhow!(
                    "FwpmFilterDeleteByKey0({:?}) failed: 0x{rc:08x}",
                    guid
                ));
            }
        }
        let rc =
            unsafe { FwpmSubLayerDeleteByKey0(engine.as_handle(), &SUBLAYER_GUID) };
        if rc != 0 && rc != FWP_E_FILTER_NOT_FOUND && rc != FWP_E_SUBLAYER_NOT_FOUND
        {
            return Err(anyhow!("FwpmSubLayerDeleteByKey0 failed: 0x{rc:08x}"));
        }

        // Also retire any leftover Phase 2 (SANDBOX_SID) sublayer +
        // filters. Non-fatal: best-effort, matches install_filters.
        if let Err(e) = purge_legacy_sublayer(engine.as_handle()) {
            eprintln!(
                "[sbox-exec] purge_legacy_sublayer (non-fatal): {e:#}"
            );
        }
        Ok(())
    })();
    if result.is_err() {
        unsafe {
            let _ = FwpmTransactionAbort0(engine.as_handle());
        }
        return result;
    }
    let rc = unsafe { FwpmTransactionCommit0(engine.as_handle()) };
    if rc != 0 {
        return Err(anyhow!("FwpmTransactionCommit0 failed: 0x{rc:08x}"));
    }
    Ok(())
}

// ────────────────────── Marker file accessors ──────────────────────

/// Write the full marker after a successful install.
pub fn write_install_marker(m: &Marker) -> Result<()> {
    write_marker(m)
}

/// Remove the marker file (called from `install --remove`).
pub fn remove_install_marker() -> Result<()> {
    delete_marker()
}

/// Return `Some(port)` if the marker file is present, `None` otherwise.
/// Kept for compatibility with callers that only need the port (e.g.
/// `--check`). New callers prefer `read_install_marker`.
#[allow(dead_code)]
pub fn is_installed() -> Result<Option<u16>> {
    Ok(read_marker()?.map(|m| m.port))
}

/// Return the full marker if present.
pub fn read_install_marker() -> Result<Option<Marker>> {
    read_marker()
}

/// Sublayer GUID — exposed for diagnostics (`install --verify`).
pub fn sublayer_guid_string() -> String {
    format!("{:?}", SUBLAYER_GUID)
}

// ────────────────────── Tests ──────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time-ish validation: build the SDDL strings used by
    /// `install_filters` for a representative pair of SIDs and confirm
    /// `ConvertStringSecurityDescriptorToSecurityDescriptorW` parses
    /// them. This catches typos in the SDDL template without requiring
    /// the WFP transaction to run.
    #[test]
    fn sddl_round_trip_for_representative_sids() {
        // Use well-known SIDs that exist on every Windows install so the
        // test is hermetic (no SAM lookup needed).
        //   S-1-5-32-545 = BUILTIN\Users (stands in for the group SID)
        //   S-1-5-18     = NT AUTHORITY\SYSTEM (stands in for the user SID)
        let group_sid = "S-1-5-32-545";
        let user_sid = "S-1-5-18";
        let sddl_group = format!("O:LSD:(A;;CC;;;{group_sid})");
        let sddl_user = format!("O:LSD:(A;;CC;;;{user_sid})");
        let g = OwnedSd::from_sddl(&sddl_group).expect("SDDL group parse");
        assert!(!g.ptr.0.is_null());
        assert!(g.len > 0);
        drop(g);
        let u = OwnedSd::from_sddl(&sddl_user).expect("SDDL user parse");
        assert!(!u.ptr.0.is_null());
        assert!(u.len > 0);
        drop(u);
    }

    #[test]
    fn sddl_rejects_malformed() {
        // Sanity: a clearly malformed SDDL should fail. Catches the
        // case where some future refactor accidentally builds an empty
        // template that nonetheless "parses" as a zero-length SD.
        let bad = "O:LSD:(A;;CC;;;NOT-A-SID)";
        let r = OwnedSd::from_sddl(bad);
        assert!(r.is_err(), "expected SDDL parse error, got Ok");
    }
}

// Keep some imports referenced even if a future refactor elides them.
#[allow(dead_code)]
fn _silence_unused() {
    let _ = FWP_UINT16;
    let _: PSID = PSID::default();
}
