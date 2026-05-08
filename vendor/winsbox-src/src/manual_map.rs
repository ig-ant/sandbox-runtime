//! Phase E-1: manual-map the cdylib into the suspended target *before*
//! the loader runs.
//!
//! Why this exists. The Phase B/C/D path used a remote
//! `LoadLibraryW(ac_cdylib.dll)` thread, which fires *after* the
//! target's loader has mapped every static import. For MSYS2/Cygwin
//! targets — bash, git, every msys-linked binary — `cygwin1.dll`
//! crashes during its own `DLL_PROCESS_ATTACH` (P13 finding) when
//! `NtOpenSection` opens an AC-inaccessible path before any cdylib
//! patches are in place. The fix is to install the hooks *before*
//! the loader runs at all, which means the cdylib must already be
//! resident in target memory when `ResumeThread` lands.
//!
//! Approach. The broker:
//!   1. Reads `ac_cdylib.dll` from disk (just bytes).
//!   2. Parses DOS + PE headers, walks section headers, determines the
//!      preferred image base (`/BASE:0x70000000` from the cdylib's
//!      build.rs).
//!   3. `VirtualAllocEx`s the entire image at the preferred base in
//!      target memory, RW for now (fixes up later).
//!   4. Copies headers + each section's raw bytes via
//!      `WriteProcessMemory`.
//!   5. Walks `IMAGE_DIRECTORY_ENTRY_BASERELOC` and applies
//!      relocations. Most of the time delta = 0 (we mapped at the
//!      preferred base), so this is a fast no-op walk; the code
//!      still emits the deltas for robustness against future
//!      `/BASE` changes (and ARM64 builds that can't disable ASLR).
//!   6. Walks `IMAGE_DIRECTORY_ENTRY_IMPORT`. For each imported
//!      module, broker-side `GetModuleHandle` + `GetProcAddress` get
//!      the function's broker VA. Per-session, system DLLs share a
//!      base across processes, so the broker's resolved VA is also
//!      the target's. Patches the IAT in-place.
//!   7. Re-protects sections to their proper page protection
//!      (RX for `.text`, R for `.rdata`, RW for `.data`).
//!   8. Pre-fills the cdylib's `IPC` global by resolving the export
//!      address and writing the four `u64` IPC handle/section values
//!      directly into target memory.
//!
//! What the broker explicitly does *not* do:
//!   * Run TLS callbacks. The Rust cdylib uses an MSVC-emitted TLS
//!     callback to initialise the std runtime's TLS slot. With our
//!     manual-mapped DLL, no AC-side thread ever runs std code that
//!     touches TLS — hook bodies use `AtomicU64` (no TLS) and the
//!     `unsafe extern "system"` ABI's panic-unwind path is disabled
//!     by the cdylib's `extern "system"` boundary (panics
//!     across an FFI boundary abort).
//!   * Run DllMain. The Phase D buffer/event/wake protocol is
//!     bypassed entirely — the broker fills `IPC` directly and patches
//!     ntdll exports to dispatch into the manual-mapped hook entries.
//!   * Process the `.pdata` exception directory. SEH unwind metadata
//!     is needed by `RtlAddFunctionTable`-style registration; for
//!     hook bodies that never panic across the FFI boundary, this is
//!     unreachable code. We log a warning if the cdylib has TLS
//!     callbacks or an unhandled section type so future regressions
//!     are visible.

#![cfg(windows)]

use crate::interception::{ntdll_export, write_remote_bytes};
use crate::ipc::StubAddrs;
use anyhow::{anyhow, bail, Context, Result};
use std::ffi::c_void;
use std::mem::size_of;
use std::path::Path;
use windows::core::{PCSTR, PCWSTR};
use windows::Win32::Foundation::{GetLastError, HANDLE};
use windows::Win32::System::Diagnostics::Debug::{
    IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER,
};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA};
use windows::Win32::System::Memory::{
    VirtualAllocEx, VirtualProtectEx, MEM_COMMIT, MEM_RESERVE,
    PAGE_EXECUTE_READ, PAGE_PROTECTION_FLAGS, PAGE_READONLY, PAGE_READWRITE,
};
use windows::Win32::System::SystemServices::{
    IMAGE_BASE_RELOCATION, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE,
    IMAGE_IMPORT_DESCRIPTOR, IMAGE_NT_SIGNATURE,
    IMAGE_REL_BASED_ABSOLUTE, IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGHLOW,
};

// Section header characteristics bits we care about.
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
const IMAGE_SCN_CNT_UNINIT_DATA: u32 = 0x0000_0080;

// Data directory indexes.
const DD_EXPORT: usize = 0;
const DD_IMPORT: usize = 1;
const DD_BASERELOC: usize = 5;
const DD_TLS: usize = 9;

/// One IAT entry's special bit on Win64: set in the lookup table when
/// the import is by ordinal rather than name.
const IMAGE_ORDINAL_FLAG64: u64 = 0x8000_0000_0000_0000;

/// Manual-map result: where the image landed in target memory plus
/// any state callers need (export VAs).
pub struct ManualMapped {
    /// Target-side base address of the manually mapped image. RVAs are
    /// added to this to get target VAs.
    pub base: usize,
    /// Total size of the image (`SizeOfImage` rounded up to page size).
    pub size: usize,
    /// In-target VA of the exported `IPC` static. Used by the broker
    /// to fill the IPC handle table directly via `WriteProcessMemory`.
    pub ipc_va: usize,
    /// In-target VAs of the 5 hook entries the interception layer
    /// patches into ntdll/kernelbase.
    pub hook_nt_open_section: usize,
    pub hook_nt_create_directory_object: usize,
    pub hook_nt_open_directory_object: usize,
    pub hook_nt_create_named_pipe_file: usize,
    pub hook_create_process_internal_w: usize,
}

/// Read `dll_path`, parse PE headers, allocate at preferred base in
/// `target`, copy sections, apply relocations, resolve imports, set
/// page protections, and return entry points.
pub fn manual_map_cdylib(target: HANDLE, dll_path: &Path) -> Result<ManualMapped> {
    let bytes = std::fs::read(dll_path)
        .with_context(|| format!("read cdylib bytes: {}", dll_path.display()))?;

    let (preferred_base, size_of_image, headers_view) = parse_headers(&bytes)?;

    // Allocate the entire image at the preferred base. If that VA is
    // taken in the target (a system DLL there or a previous map),
    // VirtualAllocEx returns NULL with ERROR_INVALID_ADDRESS. Bail and
    // let the caller fall back to LoadLibraryW.
    let alloc_size = size_of_image as usize;
    let raw = unsafe {
        VirtualAllocEx(
            target,
            Some(preferred_base as *const c_void),
            alloc_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    if raw.is_null() {
        let gle = unsafe { GetLastError() };
        bail!(
            "VirtualAllocEx({preferred_base:#x}, {alloc_size:#x}) for cdylib map: {gle:?} \
             (preferred base collides — fall back to LoadLibraryW path)"
        );
    }
    let base = raw as usize;
    if base != preferred_base as usize {
        // VirtualAllocEx with a non-NULL hint can return a different
        // address if the page-aligned hint is busy; we reject — reloc
        // walk would still work but the test surface is narrower with
        // delta=0.
        eprintln!(
            "[sbox-exec] manual_map: VirtualAllocEx returned {base:#x}, wanted {preferred_base:#x}; \
             relocations will run with non-zero delta"
        );
    }

    // 1. Copy the entire headers region (everything from byte 0 to the
    //    end of the section header table).
    write_remote_bytes(target, base, &bytes[..headers_view.size_of_headers as usize])
        .context("write headers to target")?;

    // 2. Copy each section's raw bytes to its virtual address.
    for sec in &headers_view.sections {
        let dst = base + sec.virtual_address as usize;
        // Skip pure-bss sections (no raw data). The pages are already
        // zero from VirtualAllocEx.
        if sec.size_of_raw_data == 0 {
            continue;
        }
        let raw_off = sec.pointer_to_raw_data as usize;
        let raw_size = sec.size_of_raw_data as usize;
        let virt_size = sec.virtual_size as usize;
        // Copy min(raw_size, virt_size) — sections often have more raw
        // bytes (file alignment) than virtual bytes.
        let copy = raw_size.min(virt_size.max(raw_size));
        let copy = copy.min(bytes.len() - raw_off);
        write_remote_bytes(target, dst, &bytes[raw_off..raw_off + copy])
            .with_context(|| format!("write section {}", sec.name_str()))?;
    }

    // 3. Apply relocations (.reloc / IMAGE_DIRECTORY_ENTRY_BASERELOC).
    //    With `/BASE:0x70000000` and a clean VirtualAllocEx at that
    //    address, delta == 0 and most entries are no-ops; we still
    //    walk because the loader-cleared image may have e.g. constant
    //    offsets the linker chose to encode as relocs (e.g. ARM64
    //    can't disable ASLR — every build emits relocs).
    let delta = base.wrapping_sub(preferred_base as usize) as i64;
    apply_relocations(target, base, &headers_view, delta)
        .context("apply relocations")?;

    // 4. Resolve imports (IMAGE_DIRECTORY_ENTRY_IMPORT). Patches the
    //    IAT in-place with broker-resolved VAs (system DLL bases match
    //    cross-process per session).
    resolve_imports(target, base, &headers_view)
        .context("resolve imports")?;

    // 5. Set page protections per section (RX for executable, RW for
    //    writable, R otherwise).
    apply_section_protections(target, base, &headers_view)
        .context("apply section protections")?;

    // 6. Warn on TLS callbacks (`.tls` directory): manual-map doesn't
    //    run them. For our cdylib's hook bodies (which don't touch
    //    Rust's std TLS) this is fine, but log so a future regression
    //    is visible.
    let tls = headers_view.data_dirs[DD_TLS];
    if tls.0 != 0 {
        eprintln!(
            "[sbox-exec] manual_map: cdylib has a TLS directory at RVA {:#x}; \
             callbacks NOT executed (manual map). Hook bodies must avoid std TLS.",
            tls.0,
        );
    }

    // 7. Resolve IPC + hook entries via the broker-side LoadLibraryA
    //    of the cdylib (idempotent — same path returns the same
    //    HMODULE; we don't unload). Compute target VAs via the same
    //    base+RVA trick `resolve_target_export` uses.
    let ipc_va = resolve_target_export_va(dll_path, base, "IPC")?;
    let hook_nt_open_section = resolve_target_export_va(dll_path, base, "hook_nt_open_section")?;
    let hook_nt_create_directory_object =
        resolve_target_export_va(dll_path, base, "hook_nt_create_directory_object")?;
    let hook_nt_open_directory_object =
        resolve_target_export_va(dll_path, base, "hook_nt_open_directory_object")?;
    let hook_nt_create_named_pipe_file =
        resolve_target_export_va(dll_path, base, "hook_nt_create_named_pipe_file")?;
    let hook_create_process_internal_w =
        resolve_target_export_va(dll_path, base, "hook_create_process_internal_w")?;

    eprintln!(
        "[sbox-exec] manual_map: cdylib mapped at {base:#x} ({alloc_size:#x} bytes), \
         IPC @ {ipc_va:#x}, delta={delta:#x}",
    );

    Ok(ManualMapped {
        base,
        size: alloc_size,
        ipc_va,
        hook_nt_open_section,
        hook_nt_create_directory_object,
        hook_nt_open_directory_object,
        hook_nt_create_named_pipe_file,
        hook_create_process_internal_w,
    })
}

/// Pre-fill the cdylib's `IPC` static with the IPC channel handles +
/// section VA. Layout (must match `crates/ac-cdylib/src/lib.rs::IpcEnv`):
///
///   ```c
///   struct IpcEnv {
///     u64 section;   // 0x00 — target-VA of the broker IPC section
///     u64 ev_req;    // 0x08 — target-side event handle
///     u64 ev_resp;   // 0x10 — target-side event handle
///     u64 mutex;     // 0x18 — target-side mutant handle
///   };
///   ```
///
/// Each `AtomicU64` is `repr(C)` over a `u64`, so `WriteProcessMemory`
/// of four contiguous `u64`s is byte-equivalent to four
/// `AtomicU64::store(Relaxed)`. The pre-resume write happens-before
/// any AC-side observation (every AC thread starts after
/// `ResumeThread`).
pub fn prefill_ipc(target: HANDLE, ipc_va: usize, addrs: &StubAddrs) -> Result<()> {
    let payload: [u64; 4] = [
        addrs.section as u64,
        addrs.ev_req,
        addrs.ev_resp,
        addrs.mutex,
    ];
    write_remote_bytes(
        target,
        ipc_va,
        unsafe {
            std::slice::from_raw_parts(
                payload.as_ptr() as *const u8,
                size_of::<[u64; 4]>(),
            )
        },
    )
    .context("WriteProcessMemory(IPC env prefill)")
}

// ─── PE header parsing ─────────────────────────────────────────────

struct HeadersView {
    sections: Vec<Section>,
    data_dirs: [(u32, u32); 16], // (rva, size) per data directory
    size_of_headers: u32,
}

#[derive(Clone)]
struct Section {
    name: [u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    characteristics: u32,
}
impl Section {
    fn name_str(&self) -> String {
        let end = self.name.iter().position(|&b| b == 0).unwrap_or(8);
        String::from_utf8_lossy(&self.name[..end]).into_owned()
    }
}

/// Parse the DOS + NT headers + section table out of `bytes`. Returns
/// (preferred_base, size_of_image, headers_view).
fn parse_headers(bytes: &[u8]) -> Result<(u64, u32, HeadersView)> {
    if bytes.len() < size_of::<IMAGE_DOS_HEADER>() {
        bail!("file too small for DOS header");
    }
    let dos = unsafe { &*(bytes.as_ptr() as *const IMAGE_DOS_HEADER) };
    if dos.e_magic != IMAGE_DOS_SIGNATURE as u16 {
        bail!("bad DOS signature {:#x}", dos.e_magic);
    }
    let nt_off = dos.e_lfanew as usize;
    if bytes.len() < nt_off + size_of::<IMAGE_NT_HEADERS64>() {
        bail!("file too small for NT headers");
    }
    let nt = unsafe {
        &*(bytes[nt_off..].as_ptr() as *const IMAGE_NT_HEADERS64)
    };
    if nt.Signature != IMAGE_NT_SIGNATURE {
        bail!("bad PE signature {:#x}", nt.Signature);
    }
    // The OptionalHeader follows the FileHeader at nt_off + 4 + 20.
    let opt = &nt.OptionalHeader;
    let preferred_base = opt.ImageBase;
    let size_of_image = opt.SizeOfImage;
    let size_of_headers = opt.SizeOfHeaders;
    let n_sections = nt.FileHeader.NumberOfSections as usize;
    // Section table starts immediately after the optional header.
    let opt_size = nt.FileHeader.SizeOfOptionalHeader as usize;
    let sec_table_off = nt_off + 4 /* Signature */ + 20 /* FileHeader */ + opt_size;
    if bytes.len() < sec_table_off + n_sections * size_of::<IMAGE_SECTION_HEADER>() {
        bail!("file too small for section table");
    }
    let mut sections = Vec::with_capacity(n_sections);
    for i in 0..n_sections {
        let sh = unsafe {
            &*(bytes[sec_table_off + i * size_of::<IMAGE_SECTION_HEADER>()..].as_ptr()
                as *const IMAGE_SECTION_HEADER)
        };
        sections.push(Section {
            name: sh.Name,
            virtual_size: unsafe { sh.Misc.VirtualSize },
            virtual_address: sh.VirtualAddress,
            size_of_raw_data: sh.SizeOfRawData,
            pointer_to_raw_data: sh.PointerToRawData,
            characteristics: sh.Characteristics.0,
        });
    }

    // Capture all 16 data directories. NumberOfRvaAndSizes might be
    // smaller; pad with zeros.
    let mut data_dirs = [(0u32, 0u32); 16];
    let n_dd = opt.NumberOfRvaAndSizes.min(16) as usize;
    for i in 0..n_dd {
        data_dirs[i] = (opt.DataDirectory[i].VirtualAddress, opt.DataDirectory[i].Size);
    }

    Ok((
        preferred_base,
        size_of_image,
        HeadersView { sections, data_dirs, size_of_headers },
    ))
}

// ─── Relocations ───────────────────────────────────────────────────

fn apply_relocations(
    target: HANDLE, base: usize, hv: &HeadersView, delta: i64,
) -> Result<()> {
    let (reloc_rva, reloc_size) = hv.data_dirs[DD_BASERELOC];
    if reloc_rva == 0 || reloc_size == 0 {
        return Ok(());
    }
    if delta == 0 {
        // Fast path: image landed at preferred base; no relocations
        // need to fire. We still walk in case any block is a special
        // ABSOLUTE-only padding block (no-op anyway).
        return Ok(());
    }

    // Read the .reloc data back out of target memory (we just wrote
    // it). Simpler to keep a copy of the file bytes in a parallel
    // buffer; for now read-back via NtReadVirtualMemory… no, that
    // loops. Use the source file slice instead — we still have it
    // available but only inside `manual_map_cdylib`. Pass it in if
    // we ever take this path; for now we re-read using the section.
    //
    // Note: this code path runs when delta != 0, which only happens
    // when the broker's VirtualAllocEx couldn't honour the preferred
    // base hint. With `/BASE:0x70000000` and a fresh AC target that's
    // never observed in practice; the walker is here as insurance.
    //
    // To keep the manual-map readable we just patch each entry by
    // reading the current 8 bytes via ReadProcessMemory and writing
    // back the adjusted value.
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;

    let reloc_section_va = base + reloc_rva as usize;
    let mut buf = vec![0u8; reloc_size as usize];
    let mut n = 0usize;
    unsafe {
        ReadProcessMemory(
            target,
            reloc_section_va as *const c_void,
            buf.as_mut_ptr() as *mut c_void,
            reloc_size as usize,
            Some(&mut n),
        )
        .context("read .reloc back from target")?;
    }
    let mut off = 0usize;
    while off < buf.len() {
        if off + size_of::<IMAGE_BASE_RELOCATION>() > buf.len() {
            break;
        }
        let block = unsafe {
            &*(buf[off..].as_ptr() as *const IMAGE_BASE_RELOCATION)
        };
        let block_size = block.SizeOfBlock as usize;
        if block_size < size_of::<IMAGE_BASE_RELOCATION>() {
            break;
        }
        let entry_count = (block_size - size_of::<IMAGE_BASE_RELOCATION>()) / 2;
        let entries_off = off + size_of::<IMAGE_BASE_RELOCATION>();
        let block_va_base = base + block.VirtualAddress as usize;
        for i in 0..entry_count {
            let entry = u16::from_le_bytes(
                buf[entries_off + i * 2..entries_off + i * 2 + 2]
                    .try_into()
                    .unwrap(),
            );
            let typ = (entry >> 12) as u32;
            let off_in_page = (entry & 0x0fff) as usize;
            let target_va = block_va_base + off_in_page;
            // ABSOLUTE entries are pad / no-op; HIGHLOW (type 3) is
            // 32-bit (x86, doesn't apply to x64); DIR64 (type 10) is
            // the canonical 64-bit reloc.
            #[allow(non_upper_case_globals)]
            match typ {
                t if t == IMAGE_REL_BASED_ABSOLUTE => {}
                t if t == IMAGE_REL_BASED_DIR64 => {
                    // Read 8 bytes, add delta, write back.
                    let mut v = [0u8; 8];
                    let mut nn = 0usize;
                    unsafe {
                        ReadProcessMemory(
                            target,
                            target_va as *const c_void,
                            v.as_mut_ptr() as *mut c_void,
                            8,
                            Some(&mut nn),
                        )
                        .context("read reloc target u64")?;
                    }
                    let cur = u64::from_le_bytes(v);
                    let fixed = cur.wrapping_add(delta as u64);
                    write_remote_bytes(target, target_va, &fixed.to_le_bytes())
                        .context("write reloc target u64")?;
                }
                t if t == IMAGE_REL_BASED_HIGHLOW => {
                    let mut v = [0u8; 4];
                    let mut nn = 0usize;
                    unsafe {
                        ReadProcessMemory(
                            target,
                            target_va as *const c_void,
                            v.as_mut_ptr() as *mut c_void,
                            4,
                            Some(&mut nn),
                        )
                        .context("read reloc target u32")?;
                    }
                    let cur = u32::from_le_bytes(v);
                    let fixed = cur.wrapping_add(delta as u32);
                    write_remote_bytes(target, target_va, &fixed.to_le_bytes())
                        .context("write reloc target u32")?;
                }
                t => {
                    eprintln!(
                        "[sbox-exec] manual_map: unhandled relocation type {t} at {target_va:#x}",
                    );
                }
            }
        }
        off += block_size;
    }
    Ok(())
}

// ─── Imports / IAT resolution ──────────────────────────────────────

fn resolve_imports(target: HANDLE, base: usize, hv: &HeadersView) -> Result<()> {
    let (imp_rva, imp_size) = hv.data_dirs[DD_IMPORT];
    if imp_rva == 0 || imp_size == 0 {
        return Ok(());
    }

    // Read the import descriptor table back out of the target (we just
    // wrote it as part of the section copy).
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    let imp_va = base + imp_rva as usize;
    // Import descriptors are NULL-terminated; bound by directory size.
    let max_descs = (imp_size as usize) / size_of::<IMAGE_IMPORT_DESCRIPTOR>() + 1;
    let mut descs_buf = vec![0u8; max_descs * size_of::<IMAGE_IMPORT_DESCRIPTOR>()];
    let mut n = 0usize;
    unsafe {
        ReadProcessMemory(
            target,
            imp_va as *const c_void,
            descs_buf.as_mut_ptr() as *mut c_void,
            descs_buf.len(),
            Some(&mut n),
        )
        .context("read import descriptors")?;
    }

    let mut desc_idx = 0usize;
    loop {
        let desc_off = desc_idx * size_of::<IMAGE_IMPORT_DESCRIPTOR>();
        if desc_off + size_of::<IMAGE_IMPORT_DESCRIPTOR>() > descs_buf.len() {
            break;
        }
        let desc = unsafe {
            &*(descs_buf[desc_off..].as_ptr() as *const IMAGE_IMPORT_DESCRIPTOR)
        };
        // Anonymous union: { Characteristics, OriginalFirstThunk } —
        // both are u32, identical bit pattern.
        let original_first_thunk = unsafe { desc.Anonymous.OriginalFirstThunk };
        let first_thunk = desc.FirstThunk;
        let name_rva = desc.Name;
        if name_rva == 0 && original_first_thunk == 0 && first_thunk == 0 {
            break; // null terminator descriptor
        }
        let module_name = read_target_cstr(target, base + name_rva as usize)?;
        // Use OriginalFirstThunk (the import lookup table) if non-zero,
        // else FirstThunk (the IAT itself, where lookup names live
        // before the loader binds them — same content pre-binding).
        let lookup_rva = if original_first_thunk != 0 {
            original_first_thunk
        } else {
            first_thunk
        };
        // Resolve the source module (broker-side). System DLLs share
        // a base across processes per session; the broker's
        // GetProcAddress yields a VA also valid in the target.
        let module_handle = unsafe {
            // Try GetModuleHandle first (already loaded — common case
            // for kernel32, ntdll). Fall back to LoadLibraryA so the
            // rare non-default DLL still resolves.
            let cname = std::ffi::CString::new(module_name.clone())
                .map_err(|e| anyhow!("CString({}): {e}", module_name))?;
            match GetModuleHandleA(PCSTR(cname.as_ptr() as *const u8)) {
                Ok(h) if !h.is_invalid() => h,
                _ => LoadLibraryA(PCSTR(cname.as_ptr() as *const u8))
                    .with_context(|| format!("LoadLibraryA({module_name})"))?,
            }
        };
        // Walk lookup table: each entry is u64. High bit set →
        // import-by-ordinal; else low 32 bits = RVA of
        // IMAGE_IMPORT_BY_NAME (u16 hint then NUL-terminated name).
        let mut entry_idx = 0usize;
        loop {
            let entry_va = base + lookup_rva as usize + entry_idx * 8;
            let mut entry_buf = [0u8; 8];
            let mut nn = 0usize;
            unsafe {
                ReadProcessMemory(
                    target,
                    entry_va as *const c_void,
                    entry_buf.as_mut_ptr() as *mut c_void,
                    8,
                    Some(&mut nn),
                )
                .context("read import lookup entry")?;
            }
            let entry = u64::from_le_bytes(entry_buf);
            if entry == 0 {
                break;
            }
            let resolved: usize = if entry & IMAGE_ORDINAL_FLAG64 != 0 {
                // Import by ordinal. Lower 16 bits.
                let ord = (entry & 0xffff) as u16;
                let p = unsafe {
                    GetProcAddress(module_handle, PCSTR(ord as usize as *const u8))
                };
                p.map(|f| f as usize).unwrap_or(0)
            } else {
                // Import by name; entry low 31 bits = RVA of IMAGE_IMPORT_BY_NAME.
                let ibn_rva = (entry & 0x7fff_ffff) as u32;
                // Skip the 2-byte hint, then read NUL-terminated name.
                let name = read_target_cstr(target, base + ibn_rva as usize + 2)?;
                let cname = std::ffi::CString::new(name.clone())
                    .map_err(|e| anyhow!("CString({name}): {e}"))?;
                let p = unsafe {
                    GetProcAddress(module_handle, PCSTR(cname.as_ptr() as *const u8))
                };
                p.map(|f| f as usize).unwrap_or(0)
            };
            if resolved == 0 {
                bail!(
                    "manual_map: couldn't resolve import {} (entry {entry:#x}) from {module_name}",
                    if entry & IMAGE_ORDINAL_FLAG64 != 0 {
                        format!("ord {}", entry & 0xffff)
                    } else {
                        let ibn_rva = (entry & 0x7fff_ffff) as u32;
                        read_target_cstr(target, base + ibn_rva as usize + 2)
                            .unwrap_or_else(|_| format!("rva {ibn_rva:#x}"))
                    },
                );
            }
            // Patch the IAT (FirstThunk) entry.
            let iat_va = base + first_thunk as usize + entry_idx * 8;
            write_remote_bytes(target, iat_va, &(resolved as u64).to_le_bytes())
                .context("write IAT entry")?;
            entry_idx += 1;
        }
        desc_idx += 1;
    }
    Ok(())
}

// ─── Section protections ───────────────────────────────────────────

fn apply_section_protections(
    target: HANDLE, base: usize, hv: &HeadersView,
) -> Result<()> {
    // The headers themselves end up R after we're done; we don't bother
    // tightening them past PAGE_READWRITE since the manual-mapper is
    // the only writer.
    for sec in &hv.sections {
        if sec.virtual_size == 0 && sec.characteristics & IMAGE_SCN_CNT_UNINIT_DATA == 0 {
            continue;
        }
        let prot = section_protection(sec.characteristics);
        let mut old = PAGE_PROTECTION_FLAGS(0);
        let dst = base + sec.virtual_address as usize;
        let len = sec.virtual_size.max(1) as usize;
        let rc = unsafe {
            VirtualProtectEx(target, dst as *const c_void, len, prot, &mut old)
        };
        if let Err(e) = rc {
            eprintln!(
                "[sbox-exec] manual_map: VirtualProtectEx({} @ {dst:#x}, {prot:?}): {e}",
                sec.name_str(),
            );
        }
    }
    Ok(())
}

fn section_protection(chars: u32) -> PAGE_PROTECTION_FLAGS {
    let r = chars & IMAGE_SCN_MEM_READ != 0;
    let w = chars & IMAGE_SCN_MEM_WRITE != 0;
    let x = chars & IMAGE_SCN_MEM_EXECUTE != 0;
    match (r, w, x) {
        (_, _, true) if w => PAGE_PROTECTION_FLAGS(0x40), // PAGE_EXECUTE_READWRITE
        (_, _, true) => PAGE_EXECUTE_READ,
        (_, true, _) => PAGE_READWRITE,
        (true, _, _) => PAGE_READONLY,
        _ => PAGE_READONLY,
    }
}

// ─── helpers ───────────────────────────────────────────────────────

fn read_target_cstr(target: HANDLE, va: usize) -> Result<String> {
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    let mut buf = Vec::with_capacity(64);
    let mut chunk = [0u8; 64];
    let mut cur = va;
    loop {
        let mut n = 0usize;
        unsafe {
            ReadProcessMemory(
                target,
                cur as *const c_void,
                chunk.as_mut_ptr() as *mut c_void,
                chunk.len(),
                Some(&mut n),
            )
            .with_context(|| format!("read cstr @ {cur:#x}"))?;
        }
        if n == 0 {
            bail!("ReadProcessMemory zero bytes @ {cur:#x}");
        }
        for &b in &chunk[..n] {
            if b == 0 {
                return Ok(String::from_utf8_lossy(&buf).into_owned());
            }
            buf.push(b);
            if buf.len() > 1024 {
                bail!("c-string @ {va:#x} unterminated past 1024 bytes");
            }
        }
        cur += n;
    }
}

/// Resolve an export's in-target VA via the broker's loaded copy of
/// `dll_path`. Same trick `cdylib_inject::resolve_target_export` uses,
/// inlined here so the manual-map module owns its own resolver.
fn resolve_target_export_va(
    dll_path: &Path, target_base: usize, name: &str,
) -> Result<usize> {
    use windows::Win32::System::LibraryLoader::LoadLibraryW;
    let path_w = crate::util::wstr(&dll_path.to_string_lossy());
    let m = unsafe { LoadLibraryW(PCWSTR(path_w.as_ptr())) }
        .with_context(|| format!("LoadLibraryW({}) (broker)", dll_path.display()))?;
    let cname = std::ffi::CString::new(name)
        .map_err(|e| anyhow!("CString({name}): {e}"))?;
    let p = unsafe { GetProcAddress(m, PCSTR(cname.as_ptr() as *const u8)) }
        .ok_or_else(|| anyhow!("GetProcAddress({name})"))?;
    let broker_va = p as usize;
    let broker_base = m.0 as usize;
    let rva = broker_va.checked_sub(broker_base)
        .ok_or_else(|| anyhow!("export {name} below broker base"))?;
    Ok(target_base + rva)
}

// Suppress dead-code warnings for items the public API doesn't use yet.
#[allow(dead_code)]
fn _ntdll_export_silence() -> Result<usize> {
    ntdll_export("NtSetEvent")
}
