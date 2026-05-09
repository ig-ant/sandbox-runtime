//! `probe_schannel` — minimal SSPI/Schannel diagnostic probe.
//!
//! Phase N-4 follow-up. The N-4 agent observed curl HTTPS inside the AC
//! failing with `(35) schannel: AcquireCredentialsHandle failed:
//! SEC_E_NO_CREDENTIALS (0x8009030e)` and zero `[DENY]` syscalls between
//! cdylib injection and the error. Their conclusion ("structurally
//! LSA-internal") was based on curl's failure shape — not on a direct
//! probe. This binary settles the question by calling the SSPI surface
//! that curl uses, with no curl in the loop:
//!
//!   1. `QuerySecurityPackageInfoW(L"Schannel")` — does the SSP register?
//!   2. `AcquireCredentialsHandleW(NULL, "Schannel", OUTBOUND, NULL,
//!      NULL, ...)` — the default-creds path curl uses.
//!   3. If (2) returns SEC_E_NO_CREDENTIALS, retry with an explicit
//!      zeroed `SCHANNEL_CRED { dwVersion = SCHANNEL_CRED_VERSION }`.
//!   4. If (2) or (3) succeeded, call `InitializeSecurityContextW` with
//!      a sentinel target name and an output `SECBUFFER_TOKEN`. Expected:
//!      `SEC_I_CONTINUE_NEEDED` (Schannel produced ClientHello). We do
//!      NOT attempt a real handshake — a sentinel target is fine.
//!
//! Each step prints `STEP <N>: <description> -> <result>` where result
//! is `OK <details>` or `ERR <hex>: <SspiName>`. Final line is
//! `RESULT: PASS` or `RESULT: FAIL`. Exit 0 on PASS, 1 on FAIL.
//!
//! This probe deliberately uses a private `SCHANNEL_CRED` mirror rather
//! than the windows-rs `Win32_Security_Cryptography`-gated typed struct
//! so the workspace Cargo.toml feature list doesn't have to change for
//! one diagnostic binary.

#[cfg(not(windows))]
fn main() { eprintln!("probe_schannel: windows only"); std::process::exit(2); }

#[cfg(windows)]
fn main() {
    use std::ffi::c_void;
    use std::ptr;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{
        SEC_E_NO_CREDENTIALS, SEC_I_CONTINUE_NEEDED,
    };
    use windows::Win32::Security::Authentication::Identity::{
        AcquireCredentialsHandleW, DeleteSecurityContext, FreeContextBuffer,
        FreeCredentialsHandle, InitializeSecurityContextW,
        QuerySecurityPackageInfoW, SecBuffer, SecBufferDesc, SecPkgInfoW,
        ISC_REQ_ALLOCATE_MEMORY, ISC_REQ_CONFIDENTIALITY, ISC_REQ_FLAGS,
        ISC_REQ_REPLAY_DETECT, ISC_REQ_SEQUENCE_DETECT, ISC_REQ_STREAM,
        SECBUFFER_TOKEN, SECPKG_CRED_OUTBOUND, SECURITY_NATIVE_DREP,
    };
    use windows::Win32::Security::Credentials::SecHandle;

    // SCHANNEL_CRED is gated behind Win32_Security_Cryptography in the
    // typed bindings; mirror the layout locally so we don't have to add
    // the feature for one probe. Field order/types match wincrypt.h.
    #[repr(C)]
    struct SchannelCredMirror {
        dw_version: u32,
        c_creds: u32,
        pa_cred: *mut c_void,
        h_root_store: *mut c_void,
        c_mappers: u32,
        aph_mappers: *mut c_void,
        c_supported_algs: u32,
        palg_supported_algs: *mut c_void,
        grbit_enabled_protocols: u32,
        dw_minimum_cipher_strength: u32,
        dw_maximum_cipher_strength: u32,
        dw_session_lifespan: u32,
        dw_flags: u32,
        dw_cred_format: u32,
    }
    const SCHANNEL_CRED_VERSION: u32 = 4;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn fmt_hr(hr: windows::core::HRESULT) -> String {
        // Print as the canonical 0xXXXXXXXX form curl emits.
        format!("0x{:08x}", hr.0 as u32)
    }

    fn name_for(hr: windows::core::HRESULT) -> &'static str {
        // Friendly names for the codes we expect to see. Anything else
        // gets "OTHER".
        match hr.0 as u32 {
            0x00000000 => "S_OK",
            0x8009030e => "SEC_E_NO_CREDENTIALS",
            0x80090301 => "SEC_E_INVALID_HANDLE",
            0x80090304 => "SEC_E_INTERNAL_ERROR",
            0x80090322 => "SEC_E_WRONG_PRINCIPAL",
            0x8009030d => "SEC_E_UNKNOWN_CREDENTIALS",
            0x80090305 => "SEC_E_SECPKG_NOT_FOUND",
            0x80090308 => "SEC_E_INVALID_TOKEN",
            0x00090312 => "SEC_I_CONTINUE_NEEDED",
            0x00090313 => "SEC_I_COMPLETE_NEEDED",
            0x00090314 => "SEC_I_COMPLETE_AND_CONTINUE",
            _ => "OTHER",
        }
    }

    let mut step_results: Vec<String> = Vec::new();
    let mut overall_pass = true;

    macro_rules! emit {
        ($($a:tt)*) => {{
            let line = format!($($a)*);
            println!("{}", line);
            step_results.push(line);
        }};
    }

    // ── Step 1: QuerySecurityPackageInfoW("Schannel"). ──────────────
    let mut found_schannel = false;
    {
        let pkg = wide("Schannel");
        let mut info: *mut SecPkgInfoW = ptr::null_mut();
        let hr = unsafe {
            // Wrap the Result-returning shim — convert OK / Err.
            match QuerySecurityPackageInfoW(PCWSTR(pkg.as_ptr())) {
                Ok(p) => { info = p; windows::core::HRESULT(0) }
                Err(e) => e.code(),
            }
        };
        if hr.0 == 0 && !info.is_null() {
            let cb = unsafe { (*info).cbMaxToken };
            let rpc = unsafe { (*info).wRPCID };
            emit!(
                "STEP 1: QuerySecurityPackageInfoW(\"Schannel\") -> \
                 OK cbMaxToken={} wRPCID={}", cb, rpc,
            );
            found_schannel = true;
            unsafe { let _ = FreeContextBuffer(info as *mut c_void); }
        } else {
            emit!(
                "STEP 1: QuerySecurityPackageInfoW(\"Schannel\") -> \
                 ERR {}: {}", fmt_hr(hr), name_for(hr),
            );
            // Try the alias.
            let alt = wide("Microsoft Unified Security Protocol Provider");
            let mut info2: *mut SecPkgInfoW = ptr::null_mut();
            let hr2 = unsafe {
                match QuerySecurityPackageInfoW(PCWSTR(alt.as_ptr())) {
                    Ok(p) => { info2 = p; windows::core::HRESULT(0) }
                    Err(e) => e.code(),
                }
            };
            if hr2.0 == 0 && !info2.is_null() {
                let cb = unsafe { (*info2).cbMaxToken };
                emit!(
                    "STEP 1b: QuerySecurityPackageInfoW(\"Microsoft \
                     Unified Security Protocol Provider\") -> OK \
                     cbMaxToken={}", cb,
                );
                found_schannel = true;
                unsafe { let _ = FreeContextBuffer(info2 as *mut c_void); }
            } else {
                emit!(
                    "STEP 1b: alias QuerySecurityPackageInfoW -> \
                     ERR {}: {}", fmt_hr(hr2), name_for(hr2),
                );
                overall_pass = false;
            }
        }
    }

    // ── Step 2: AcquireCredentialsHandleW(NULL, "Schannel", OUT, NULL). ─
    let mut cred = SecHandle::default();
    let mut life: i64 = 0;
    let mut acquire_ok = false;
    let mut acquire_step2_hr = windows::core::HRESULT(0);
    if found_schannel {
        let pkg = wide("Schannel");
        let hr = unsafe {
            match AcquireCredentialsHandleW(
                PCWSTR::null(),
                PCWSTR(pkg.as_ptr()),
                SECPKG_CRED_OUTBOUND,
                None,
                None,
                None,
                None,
                &mut cred,
                Some(&mut life),
            ) {
                Ok(()) => windows::core::HRESULT(0),
                Err(e) => e.code(),
            }
        };
        acquire_step2_hr = hr;
        if hr.0 == 0 {
            emit!(
                "STEP 2: AcquireCredentialsHandleW(NULL, \"Schannel\", \
                 OUTBOUND, NULL pAuthData) -> OK cred={:#x}:{:#x}",
                cred.dwLower, cred.dwUpper,
            );
            acquire_ok = true;
        } else {
            emit!(
                "STEP 2: AcquireCredentialsHandleW(NULL, \"Schannel\", \
                 OUTBOUND, NULL pAuthData) -> ERR {}: {}",
                fmt_hr(hr), name_for(hr),
            );
        }
    } else {
        emit!("STEP 2: SKIPPED (Schannel SSP not registered)");
    }

    // ── Step 3: AcquireCredentialsHandleW with explicit SCHANNEL_CRED. ─
    let mut step3_attempted = false;
    if found_schannel
        && !acquire_ok
        && acquire_step2_hr == SEC_E_NO_CREDENTIALS
    {
        step3_attempted = true;
        let pkg = wide("Schannel");
        let sc = SchannelCredMirror {
            dw_version: SCHANNEL_CRED_VERSION,
            c_creds: 0,
            pa_cred: ptr::null_mut(),
            h_root_store: ptr::null_mut(),
            c_mappers: 0,
            aph_mappers: ptr::null_mut(),
            c_supported_algs: 0,
            palg_supported_algs: ptr::null_mut(),
            grbit_enabled_protocols: 0,
            dw_minimum_cipher_strength: 0,
            dw_maximum_cipher_strength: 0,
            dw_session_lifespan: 0,
            dw_flags: 0,
            dw_cred_format: 0,
        };
        let hr = unsafe {
            match AcquireCredentialsHandleW(
                PCWSTR::null(),
                PCWSTR(pkg.as_ptr()),
                SECPKG_CRED_OUTBOUND,
                None,
                Some(&sc as *const _ as *const c_void),
                None,
                None,
                &mut cred,
                Some(&mut life),
            ) {
                Ok(()) => windows::core::HRESULT(0),
                Err(e) => e.code(),
            }
        };
        if hr.0 == 0 {
            emit!(
                "STEP 3: AcquireCredentialsHandleW(NULL, \"Schannel\", \
                 OUTBOUND, &empty SCHANNEL_CRED) -> OK \
                 cred={:#x}:{:#x}", cred.dwLower, cred.dwUpper,
            );
            acquire_ok = true;
        } else {
            emit!(
                "STEP 3: AcquireCredentialsHandleW(NULL, \"Schannel\", \
                 OUTBOUND, &empty SCHANNEL_CRED) -> ERR {}: {}",
                fmt_hr(hr), name_for(hr),
            );
        }
    } else if found_schannel && !acquire_ok {
        emit!("STEP 3: SKIPPED (step 2 returned non-NO_CREDENTIALS)");
    } else if found_schannel {
        emit!("STEP 3: SKIPPED (step 2 succeeded)");
    } else {
        emit!("STEP 3: SKIPPED (Schannel SSP not registered)");
    }

    // ── Step 4: InitializeSecurityContextW (first call). ────────────
    let mut ctx = SecHandle::default();
    let mut ctx_valid = false;
    if acquire_ok {
        let target = wide("127.0.0.1");
        let req: ISC_REQ_FLAGS = ISC_REQ_REPLAY_DETECT
            | ISC_REQ_SEQUENCE_DETECT
            | ISC_REQ_CONFIDENTIALITY
            | ISC_REQ_ALLOCATE_MEMORY
            | ISC_REQ_STREAM;
        // Output buffer: one SECBUFFER_TOKEN, allocator-owned (NULL pv;
        // ISC_REQ_ALLOCATE_MEMORY tells Schannel to allocate, and we
        // FreeContextBuffer afterward).
        let mut out_buf = SecBuffer {
            cbBuffer: 0,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: ptr::null_mut(),
        };
        let mut out_desc = SecBufferDesc {
            ulVersion: 0,
            cBuffers: 1,
            pBuffers: &mut out_buf,
        };
        let mut attrs: u32 = 0;
        let hr = unsafe {
            InitializeSecurityContextW(
                Some(&cred),
                None,
                Some(target.as_ptr()),
                req,
                0,
                SECURITY_NATIVE_DREP,
                None,
                0,
                Some(&mut ctx),
                Some(&mut out_desc),
                &mut attrs,
                Some(&mut life),
            )
        };
        if hr == SEC_I_CONTINUE_NEEDED {
            emit!(
                "STEP 4: InitializeSecurityContextW(first call, target=\
                 \"127.0.0.1\") -> OK SEC_I_CONTINUE_NEEDED token_bytes={}",
                out_buf.cbBuffer,
            );
            ctx_valid = true;
        } else if hr.0 == 0 {
            emit!(
                "STEP 4: InitializeSecurityContextW -> OK S_OK \
                 token_bytes={} (unusual)", out_buf.cbBuffer,
            );
            ctx_valid = true;
        } else {
            emit!(
                "STEP 4: InitializeSecurityContextW -> ERR {}: {}",
                fmt_hr(hr), name_for(hr),
            );
            overall_pass = false;
        }
        // Clean up the output token if Schannel allocated one.
        if !out_buf.pvBuffer.is_null() {
            unsafe { let _ = FreeContextBuffer(out_buf.pvBuffer); }
        }
    } else {
        emit!("STEP 4: SKIPPED (no credential)");
        overall_pass = false;
    }

    // ── Cleanup. ────────────────────────────────────────────────────
    if ctx_valid {
        unsafe { let _ = DeleteSecurityContext(&ctx); }
    }
    if acquire_ok {
        unsafe { let _ = FreeCredentialsHandle(&cred); }
    }

    // ── Summary. ────────────────────────────────────────────────────
    println!(
        "SUMMARY: schannel_registered={} cred_acquired={} \
         cred_via_explicit={} ctx_initialized={}",
        found_schannel, acquire_ok, step3_attempted && acquire_ok,
        ctx_valid,
    );
    if overall_pass && acquire_ok && ctx_valid {
        println!("RESULT: PASS");
        std::process::exit(0);
    } else {
        println!("RESULT: FAIL");
        std::process::exit(1);
    }
}
