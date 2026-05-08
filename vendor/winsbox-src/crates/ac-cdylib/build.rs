//! Phase E-1: pin a fixed preferred image base for the cdylib so the
//! broker's manual-mapper places sections at a known VA in target
//! memory. The broker still walks the relocation table because:
//!
//!   * On ARM64, `/DYNAMICBASE:NO` is rejected by the linker
//!     (`lld-link: /dynamicbase:no is not compatible with arm64` —
//!     ARM64 PEs are required to carry relocs since their RIP-relative
//!     equivalents have a smaller range than x64). The reloc walk
//!     still hits delta=0 when we map at the preferred base.
//!   * On x64 we can drop ASLR but the reloc walk is still robust
//!     against future ImageBase changes — emit it anyway.
//!
//! Base choice: a base of `0x70000000` (~1.75 GiB) was rejected by
//! the loader on ARM64 with `ERROR_BAD_EXE_FORMAT` — ARM64 PEs need a
//! base in the high-half user-address range. We use `0x190000000`
//! (just above the default DLL base of 0x180000000) on both archs;
//! it's in canonical user space, doesn't collide with system DLL
//! preferred bases (0x180000000 + a few MiB on most platforms), and
//! sits above where Cygwin's fork() remaps the parent's heap.

fn main() {
    if std::env::var("CARGO_CFG_WINDOWS").is_ok() {
        // /BASE:0x190000000 — preferred image base in hex. Picked to
        // sit above ntdll/kernelbase/kernel32 (clustered at the
        // 0x18xxxxxxx range on most Win10/11 builds) and below the
        // canonical Win64 user-mode top (0x7fff_ffff_ffff).
        println!("cargo:rustc-link-arg=/BASE:0x190000000");
        // /DYNAMICBASE:NO — only x64 honours it; ARM64 hard-rejects.
        // The manual-mapper compensates by walking relocs (delta=0
        // fast path).
        if std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("x86_64") {
            println!("cargo:rustc-link-arg=/DYNAMICBASE:NO");
        }
    }
}
