//! Windows Filtering Platform (WFP) filter install/remove.
//!
//! Six filters (3 at IPv4 + 3 at IPv6 ALE_AUTH_CONNECT):
//!   1. PERMIT — match SANDBOX_SID + remote=loopback + remote_port=proxy.
//!   2. BLOCK  — match SANDBOX_SID (lower weight than #1).
//!   3. BLOCK  — remote=loopback + remote_port=proxy + NOT SANDBOX_SID
//!               (speculative: SDDL `O:LSD:(D;;CC;;;<sid>)(A;;CC;;;WD)` so
//!               Everyone passes but SANDBOX_SID is denied). If this
//!               doesn't behave correctly, the alternative is a separate
//!               sublayer with default-block + a higher-weight PERMIT
//!               only for SANDBOX_SID; left for Phase 3 to confirm.
//!
//! Persistent (non-dynamic) filters; survive reboot. Marker file at
//! `%ProgramData%\winsbox\installed.json` records port + sublayer GUID.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use windows::core::{GUID, PCWSTR};
use windows::Win32::Foundation::{LocalFree, HANDLE, HLOCAL};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterDeleteByKey0,
    FwpmSubLayerAdd0, FwpmSubLayerDeleteByKey0, FwpmTransactionAbort0,
    FwpmTransactionBegin0, FwpmTransactionCommit0, FWPM_ACTION0, FWPM_ACTION0_0,
    FWPM_CONDITION_ALE_USER_ID, FWPM_CONDITION_IP_REMOTE_ADDRESS,
    FWPM_CONDITION_IP_REMOTE_PORT, FWPM_DISPLAY_DATA0, FWPM_FILTER0,
    FWPM_FILTER_CONDITION0, FWPM_FILTER_FLAG_PERSISTENT, FWPM_SUBLAYER_FLAG_PERSISTENT,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_SUBLAYER0, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_BYTE_BLOB,
    FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0, FWP_MATCH_EQUAL,
    FWP_SECURITY_DESCRIPTOR_TYPE, FWP_UINT16, FWP_UINT32, FWP_UINT8,
    FWP_VALUE0, FWP_VALUE0_0, FWP_BYTE_ARRAY16,
};
use windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows::Win32::Security::{GetSecurityDescriptorLength, PSECURITY_DESCRIPTOR};

use crate::util::{pcwstr, wstr};

// Sublayer GUID — stable, hard-coded for deterministic uninstall.
// {a4f4e62c-3d8a-4f3a-9b9e-d2f5e8a17b41}
const SUBLAYER_GUID: GUID = GUID::from_u128(0xa4f4e62c_3d8a_4f3a_9b9e_d2f5e8a17b41);

// Filter GUIDs derived from sublayer by mutating the low byte of Data4.
const fn filter_guid(tag: u8) -> GUID {
    let mut g = SUBLAYER_GUID;
    g.data4[7] = tag;
    g
}

// Tags 1..=6.
const FILTER_GUIDS: [GUID; 6] = [
    filter_guid(1), filter_guid(2), filter_guid(3),
    filter_guid(4), filter_guid(5), filter_guid(6),
];

// WFP errors we want to swallow.
const FWP_E_ALREADY_EXISTS: u32 = 0x80320009;
const FWP_E_FILTER_NOT_FOUND: u32 = 0x80320026;
const FWP_E_SUBLAYER_NOT_FOUND: u32 = 0x80320042;

// SDDL revision constant for ConvertStringSecurityDescriptorToSecurityDescriptorW.
const SDDL_REVISION_1: u32 = 1;

// Marker file shape.
#[derive(Debug, Serialize, Deserialize)]
struct Marker {
    port: u16,
    sublayer_guid: String,
}

fn marker_path() -> PathBuf {
    let base = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("C:\\ProgramData"));
    base.join("winsbox").join("installed.json")
}

fn write_marker(port: u16) -> Result<()> {
    let p = marker_path();
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;
    }
    let m = Marker {
        port,
        sublayer_guid: format!("{:?}", SUBLAYER_GUID),
    };
    let s = serde_json::to_string_pretty(&m)?;
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
    let s = std::fs::read_to_string(&p).with_context(|| format!("read {}", p.display()))?;
    Ok(Some(serde_json::from_str(&s)?))
}

/// Heap-allocated security descriptor owned by us. Drop frees via
/// `LocalFree` to mirror `ConvertStringSecurityDescriptorToSecurityDescriptorW`.
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
            .map_err(|e| anyhow!("ConvertStringSecurityDescriptorToSecurityDescriptorW({sddl}): {e}"))?;
            if sz == 0 {
                // Some SKUs don't fill in sz; compute it.
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
            unsafe { let _ = LocalFree(HLOCAL(self.ptr.0)); }
        }
    }
}

struct EngineHandle(HANDLE);

impl EngineHandle {
    fn open() -> Result<Self> {
        let mut h = HANDLE::default();
        // Authn service RPC_C_AUTHN_DEFAULT = 0xFFFFFFFF.
        let rc = unsafe {
            FwpmEngineOpen0(
                PCWSTR::null(),
                0xFFFFFFFF,
                None,
                None,
                &mut h,
            )
        };
        if rc != 0 {
            return Err(anyhow!("FwpmEngineOpen0 failed: 0x{rc:08x}"));
        }
        Ok(Self(h))
    }
    fn as_handle(&self) -> HANDLE { self.0 }
}

impl Drop for EngineHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe { let _ = FwpmEngineClose0(self.0); }
        }
    }
}

fn fwp_uint32(v: u32) -> FWP_VALUE0 {
    FWP_VALUE0 {
        r#type: FWP_UINT32,
        Anonymous: FWP_VALUE0_0 { uint32: v },
    }
}

// Build a single filter condition for a u8/u16/u32 value.
// All pointers in the condition struct must remain valid until
// `FwpmFilterAdd0` returns.

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

// IPv6 address (16 bytes) condition.
fn cond_v6_addr(field_key: GUID, addr: &mut FWP_BYTE_ARRAY16) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field_key,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            // FWP_BYTE_ARRAY16_TYPE = 13.
            r#type: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_BYTE_ARRAY16_TYPE,
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

#[allow(dead_code)]
fn _silence_unused() {
    // Keep these imports referenced even if some filters elide the v6 byte-array
    // condition shape.
    let _ = FWP_UINT8;
    let _ = FWP_UINT16;
}

fn add_filter(
    engine: HANDLE,
    key: GUID,
    layer: GUID,
    name: &str,
    weight: u32,
    action_type: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_ACTION_TYPE,
    conditions: &mut [FWPM_FILTER_CONDITION0],
) -> Result<()> {
    let mut name_w = wstr(name);
    let mut desc_w = wstr("winsbox WFP filter");
    let mut filter = FWPM_FILTER0::default();
    filter.filterKey = key;
    filter.displayData = FWPM_DISPLAY_DATA0 {
        name: windows::core::PWSTR(name_w.as_mut_ptr()),
        description: windows::core::PWSTR(desc_w.as_mut_ptr()),
    };
    filter.flags = FWPM_FILTER_FLAG_PERSISTENT;
    filter.layerKey = layer;
    filter.subLayerKey = SUBLAYER_GUID;
    filter.weight = fwp_uint32(weight);
    filter.numFilterConditions = conditions.len() as u32;
    filter.filterCondition = if conditions.is_empty() {
        std::ptr::null_mut()
    } else {
        conditions.as_mut_ptr()
    };
    filter.action = FWPM_ACTION0 {
        r#type: action_type,
        Anonymous: FWPM_ACTION0_0 { filterType: GUID::zeroed() },
    };
    let rc = unsafe {
        FwpmFilterAdd0(engine, &filter, PSECURITY_DESCRIPTOR::default(), None)
    };
    if rc != 0 && rc != FWP_E_ALREADY_EXISTS {
        return Err(anyhow!("FwpmFilterAdd0({name}) failed: 0x{rc:08x}"));
    }
    Ok(())
}

/// Install the persistent WFP filter set keyed on SANDBOX_SID, with
/// `proxy_port` as the only permitted destination on loopback.
pub fn install_persistent(proxy_port: u16) -> Result<()> {
    let sid_str = crate::sid::sandbox_sid_string()?;

    // Pre-build security descriptors. Kept alive across the whole transaction.
    let sd_allow = OwnedSd::from_sddl(&format!("O:LSD:(A;;CC;;;{sid_str})"))?;
    // Filter #3 SD: deny SANDBOX_SID, allow Everyone. Speculative shape;
    // see module docstring + plan open question. Alternative: separate
    // sublayer with default-block.
    let sd_deny = OwnedSd::from_sddl(&format!("O:LSD:(D;;CC;;;{sid_str})(A;;CC;;;WD)"))?;

    let engine = EngineHandle::open()?;
    let rc = unsafe { FwpmTransactionBegin0(engine.as_handle(), 0) };
    if rc != 0 {
        return Err(anyhow!("FwpmTransactionBegin0 failed: 0x{rc:08x}"));
    }

    let result: Result<()> = (|| {
        // 1) Sublayer.
        let mut sl_name_w = wstr("winsbox-sandbox-net");
        let mut sl_desc_w = wstr("winsbox WFP sublayer");
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: SUBLAYER_GUID,
            displayData: FWPM_DISPLAY_DATA0 {
                name: windows::core::PWSTR(sl_name_w.as_mut_ptr()),
                description: windows::core::PWSTR(sl_desc_w.as_mut_ptr()),
            },
            flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
            providerKey: std::ptr::null_mut(),
            providerData: FWP_BYTE_BLOB { size: 0, data: std::ptr::null_mut() },
            weight: 0x8000,
        };
        let rc = unsafe { FwpmSubLayerAdd0(engine.as_handle(), &sublayer, PSECURITY_DESCRIPTOR::default()) };
        if rc != 0 && rc != FWP_E_ALREADY_EXISTS {
            return Err(anyhow!("FwpmSubLayerAdd0 failed: 0x{rc:08x}"));
        }

        // Loopback addresses.
        let v4_loopback: u32 = 0x7F000001; // 127.0.0.1 in network-host order (FWP expects host order).
        // ::1
        let mut v6_loopback = FWP_BYTE_ARRAY16 {
            byteArray16: [0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1],
        };

        // Two SD byte-blobs — one allow, one deny — kept alive here.
        let mut sd_allow_blob = sd_allow.byte_blob();
        let mut sd_deny_blob = sd_deny.byte_blob();

        // -------- IPv4 --------
        // Filter #1 V4 PERMIT
        let mut c1 = [
            cond_uint32(FWPM_CONDITION_IP_REMOTE_ADDRESS, v4_loopback),
            cond_uint16(FWPM_CONDITION_IP_REMOTE_PORT, proxy_port),
            cond_sd(FWPM_CONDITION_ALE_USER_ID, &mut sd_allow_blob),
        ];
        add_filter(
            engine.as_handle(), FILTER_GUIDS[0], FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            "winsbox-v4-permit-proxy", 0xF000_0000, FWP_ACTION_PERMIT, &mut c1,
        )?;
        // Filter #2 V4 BLOCK (catch-all for SANDBOX_SID)
        let mut c2 = [
            cond_sd(FWPM_CONDITION_ALE_USER_ID, &mut sd_allow_blob),
        ];
        add_filter(
            engine.as_handle(), FILTER_GUIDS[1], FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            "winsbox-v4-block-sandbox-default", 0x4000_0000, FWP_ACTION_BLOCK, &mut c2,
        )?;
        // Filter #3 V4 BLOCK (non-sandbox -> proxy port)
        let mut c3 = [
            cond_uint32(FWPM_CONDITION_IP_REMOTE_ADDRESS, v4_loopback),
            cond_uint16(FWPM_CONDITION_IP_REMOTE_PORT, proxy_port),
            cond_sd(FWPM_CONDITION_ALE_USER_ID, &mut sd_deny_blob),
        ];
        add_filter(
            engine.as_handle(), FILTER_GUIDS[2], FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            "winsbox-v4-block-non-sandbox-proxy", 0xF000_0000, FWP_ACTION_BLOCK, &mut c3,
        )?;

        // -------- IPv6 --------
        let mut c4 = [
            cond_v6_addr(FWPM_CONDITION_IP_REMOTE_ADDRESS, &mut v6_loopback),
            cond_uint16(FWPM_CONDITION_IP_REMOTE_PORT, proxy_port),
            cond_sd(FWPM_CONDITION_ALE_USER_ID, &mut sd_allow_blob),
        ];
        add_filter(
            engine.as_handle(), FILTER_GUIDS[3], FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            "winsbox-v6-permit-proxy", 0xF000_0000, FWP_ACTION_PERMIT, &mut c4,
        )?;
        let mut c5 = [
            cond_sd(FWPM_CONDITION_ALE_USER_ID, &mut sd_allow_blob),
        ];
        add_filter(
            engine.as_handle(), FILTER_GUIDS[4], FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            "winsbox-v6-block-sandbox-default", 0x4000_0000, FWP_ACTION_BLOCK, &mut c5,
        )?;
        let mut c6 = [
            cond_v6_addr(FWPM_CONDITION_IP_REMOTE_ADDRESS, &mut v6_loopback),
            cond_uint16(FWPM_CONDITION_IP_REMOTE_PORT, proxy_port),
            cond_sd(FWPM_CONDITION_ALE_USER_ID, &mut sd_deny_blob),
        ];
        add_filter(
            engine.as_handle(), FILTER_GUIDS[5], FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            "winsbox-v6-block-non-sandbox-proxy", 0xF000_0000, FWP_ACTION_BLOCK, &mut c6,
        )?;

        Ok(())
    })();

    if result.is_err() {
        unsafe { let _ = FwpmTransactionAbort0(engine.as_handle()); }
        return result;
    }
    let rc = unsafe { FwpmTransactionCommit0(engine.as_handle()) };
    if rc != 0 {
        return Err(anyhow!("FwpmTransactionCommit0 failed: 0x{rc:08x}"));
    }
    write_marker(proxy_port).context("write marker file")?;
    Ok(())
}

/// Remove the filters and sublayer installed by `install_persistent`.
pub fn uninstall_persistent() -> Result<()> {
    let engine = EngineHandle::open()?;
    let rc = unsafe { FwpmTransactionBegin0(engine.as_handle(), 0) };
    if rc != 0 {
        return Err(anyhow!("FwpmTransactionBegin0 failed: 0x{rc:08x}"));
    }
    let result: Result<()> = (|| {
        for guid in &FILTER_GUIDS {
            let rc = unsafe { FwpmFilterDeleteByKey0(engine.as_handle(), guid) };
            if rc != 0 && rc != FWP_E_FILTER_NOT_FOUND {
                return Err(anyhow!("FwpmFilterDeleteByKey0({:?}) failed: 0x{rc:08x}", guid));
            }
        }
        let rc = unsafe { FwpmSubLayerDeleteByKey0(engine.as_handle(), &SUBLAYER_GUID) };
        if rc != 0 && rc != FWP_E_FILTER_NOT_FOUND && rc != FWP_E_SUBLAYER_NOT_FOUND {
            return Err(anyhow!("FwpmSubLayerDeleteByKey0 failed: 0x{rc:08x}"));
        }
        Ok(())
    })();
    if result.is_err() {
        unsafe { let _ = FwpmTransactionAbort0(engine.as_handle()); }
        return result;
    }
    let rc = unsafe { FwpmTransactionCommit0(engine.as_handle()) };
    if rc != 0 {
        return Err(anyhow!("FwpmTransactionCommit0 failed: 0x{rc:08x}"));
    }
    let _ = delete_marker();
    Ok(())
}

/// Return `Some(port)` if filters are present (from marker file),
/// `None` if not installed.
pub fn is_installed() -> Result<Option<u16>> {
    Ok(read_marker()?.map(|m| m.port))
}

/// Public accessor for the marker file (used by `install --check`).
pub fn marker_info() -> Result<Option<(u16, String)>> {
    Ok(read_marker()?.map(|m| (m.port, m.sublayer_guid)))
}
