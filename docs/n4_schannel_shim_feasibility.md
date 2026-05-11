# N-4 follow-up: Schannel SSPI in-process shim — feasibility probe

**Status:** investigation only. No code changed.

**Question:** Can we sidestep the AC-Schannel LSA wall (see
`docs/n4_schannel_probe_findings.md`) by patching the SSPI dispatcher
exports inside the AC and redirecting Schannel/UNISP traffic to a
Rust TLS implementation, leaving Kerberos/NTLM/Negotiate to fall
through to the real LSA?

**TL;DR:**

* **Hookable: yes.** The Phase D-4 inline-hook machinery can patch
  any DLL export the same way it patches kernelbase!CreateProcessInternalW.
  But the right module to patch is `sspicli.dll`, not `secur32.dll` —
  every relevant Secur32 export is a forwarder. One small extension to
  `build_passthrough_thunk` is needed (saved-original + JMP-back; today
  the thunk is sized for self-contained ntdll syscall stubs).
* **Right architecture:** broker-mediated state. The cdylib's hooks
  marshal SSPI calls over the existing IPC `Wire` to the broker; a
  rustls-backed terminator on the broker side runs the TLS state
  machine. Cdylib stays `no_std`; per-context state lives in std-land
  on the broker.
* **Scope:** ~1100 LOC total (cdylib hooks ~250, broker SSPI handler
  ~450, rustls glue + cert store ~250, IPC wire extensions ~150).
  Plus one `rustls` + one `rcgen` (or `rustls-native-certs`) dep. **An
  honest day-of-work range is 3–6 days.**
* **Vs Phase O (broker MITM TLS proxy):** the Phase O sketch is
  ~300 LOC + rcgen + 1 trust-store install. It also gets us HTTPS but
  for **every** TLS client in the AC simultaneously, transparently —
  not just curl. Phase O wins on cost-per-coverage by ~3×.
* **Recommendation: go with Phase O.** This shim is feasible but
  strictly worse than Phase O on every axis except "stays in-process"
  (which we don't actually care about — curl is already
  network-mediated through the AF_UNIX bridge and the SRT proxy). The
  shim's only edge is *if* Phase O's per-user `certutil` install
  fails inside the AC, which we should verify before committing
  either way.

---

## Task 1 — SSPI surface inventory

The functions a curl-grade outbound HTTPS client touches, with their
exact prototypes from `windows-sys-0.61` (which mechanically generates
from the SDK headers, so these are authoritative):

| # | Export | Sig (abridged) | Used by curl |
|---|---|---|---|
| 1 | `QuerySecurityPackageInfoW` | `(pszPackageName: PCWSTR, pppPackageInfo: *mut *mut SecPkgInfoW) -> HRESULT` | yes (cap probe) |
| 2 | `AcquireCredentialsHandleW` | `(pszPrincipal, pszPackage, fCredentialUse, pvLogonId, pAuthData, pGetKeyFn, pvGetKeyArgument, phCredential, ptsExpiry) -> HRESULT` | yes |
| 3 | `FreeCredentialsHandle` | `(phCredential: *const SecHandle) -> HRESULT` | yes |
| 4 | `InitializeSecurityContextW` | `(phCredential, phContext, pszTargetName: *const u16, fContextReq: ISC_REQ_FLAGS, Reserved1: u32, TargetDataRep: u32, pInput: *const SecBufferDesc, Reserved2: u32, phNewContext: *mut SecHandle, pOutput: *mut SecBufferDesc, pfContextAttr: *mut u32, ptsExpiry: *mut i64) -> HRESULT` | yes (handshake) |
| 5 | `DeleteSecurityContext` | `(phContext: *const SecHandle) -> HRESULT` | yes |
| 6 | `QueryContextAttributesW` | `(phContext: *const SecHandle, ulAttribute: SECPKG_ATTR, pBuffer: *mut c_void) -> HRESULT` | yes (stream sizes, peer cert) |
| 7 | `EncryptMessage` | `(phContext: *const SecHandle, fQOP: u32, pMessage: *const SecBufferDesc, MessageSeqNo: u32) -> HRESULT` | yes (TLS write) |
| 8 | `DecryptMessage` | `(phContext: *const SecHandle, pMessage: *const SecBufferDesc, MessageSeqNo: u32, pfQOP: *mut u32) -> HRESULT` | yes (TLS read) |
| 9 | `ApplyControlToken` | `(phContext: *const SecHandle, pInput: *const SecBufferDesc) -> HRESULT` | yes (graceful close) |
| 10 | `FreeContextBuffer` | `(pvContextBuffer: *mut c_void) -> HRESULT` | yes (frees QSP allocations) |
| 11 | `EnumerateSecurityPackagesW` | `(pcPackages: *mut u32, ppPackageInfo: *mut *mut SecPkgInfoW) -> HRESULT` | maybe |
| 12 | `MakeSignature` / `VerifySignature` | n/a | no (TLS only — Schannel doesn't expose these meaningfully) |

**Package dispatch.** Items 1, 2, 11 take a `pszPackage` arg. Items
3–9 take a `phCredential` or `phContext` whose package was set at
acquire time; we cookie the handle (low slot = magic, upper = state
ptr) so the hook body can recognise our handles vs real LSA handles.
Items 10 (FreeContextBuffer) is package-agnostic — the buffer was
allocated by the SSP itself; we'd just route to the real impl always.

The "package names we'd intercept" are: `Schannel`, `Microsoft Unified
Security Protocol Provider`, `SChannel` (case-insensitive — SSPI
normalises). All other names (Kerberos, NTLM, Negotiate, CredSSP,
Digest, TSSSP) fall through to the real sspicli.

## Task 2 — Module loadability inside the AC

`Secur32.dll` and `sspicli.dll` both load cleanly inside the AC
target. Evidence:

* `docs/n4_schannel_probe_in_ac_default.log` shows
  `STEP 1: QuerySecurityPackageInfoW("Schannel") -> OK`. That call
  is implemented in `sspicli!QuerySecurityPackageInfoW` (Secur32 is a
  forwarder shell). It returns OK only after sspicli is mapped into
  the process and (for Schannel) reaches into the AC's per-AC LSA
  endpoint to fetch the package metadata. Both happen successfully —
  it's the **AcquireCredentials** call later that fails inside the
  per-AC LSA.
* The N-4 trace (`docs/n4_schannel_probe_in_ac_syscall_trace.log`)
  shows the probe runs to completion and prints the SUMMARY line.
  No `[DENY]` events from the probe pid pre-error. ntdll loader
  successfully maps both DLLs.

`Schannel.dll` proper loads on demand when a Schannel-specific code
path needs it. With the shim, **we never need Schannel.dll to load** —
the shim diverts before sspicli's first call into Schannel's
`InitContextW` plug-in fn-table. (sspicli doesn't load Schannel
during `QuerySecurityPackageInfoW`; it fetches package info via a
cached LSA RPC on first SSPI use. Schannel.dll only enters the
process once Acquire/InitContext call into the package's
`SpInitialize`.) So if the shim never lets sspicli touch Schannel,
that DLL never loads, which is fine.

## Task 3 — Hookability of sspicli exports

**Critical correction to the task brief:** `Secur32.dll` is **NOT**
the right patch target. Every SSPI export in Secur32 is a PE
**forwarder** to `SSPICLI.<same-name>`. Forwarders have no machine
code in Secur32 — the loader resolves the IAT entry directly to the
sspicli export at module load time. Patching the (nonexistent) bytes
in Secur32 is a no-op.

`dumpbin -exports C:\Windows\System32\Secur32.dll`:
```
3    2          AcquireCredentialsHandleW (forwarded to SSPICLI.AcquireCredentialsHandleW)
14   D          DecryptMessage           (forwarded to SSPICLI.DecryptMessage)
36   23          LsaCallAuthenticationPackage (forwarded to SSPICLI.LsaCallAuthenticationPackage)
... [98 of 98 SSPI exports are forwarders]
```

`sspicli.dll` is the right target. Its exports have real RVAs (e.g.
`AcquireCredentialsHandleW @ RVA 0xE3A0` on this Windows 11 ARM64
build) and real prologues:

```
000000018000E3A0: pacibsp                     ; ARM64 PAC prologue
000000018000E3A4: stp     fp,lr,[sp,#-0x10]!   ; standard frame setup
000000018000E3A8: mov     fp,sp
000000018000E3AC: sub     sp,sp,#0x10
000000018000E3B0: mov     w8,#1
... (regular function body, ~100s of bytes)
```

That's plain code, no PC-relative literal in the first 16 bytes — a
clean target for the existing `enc_abs_jmp` 16-byte ARM64 patch. On
x64 the same exports are typical 14-byte trampolines
(`mov rax,rsp; mov [rax+20h],rbx; push rbp; pop rbp; jmp <target>`)
which the existing 12-byte x64 ABS_JMP also handles cleanly.

**Existing machinery applies:**

* `manual_map::resolve_target_export_va` (lib.rs:867) already takes
  an arbitrary DLL path + export name and returns the in-target VA.
  Used today for `kernelbase!CreateProcessInternalW`; would be reused
  for `sspicli!*`. System DLLs share base across the session, so
  broker-side `LoadLibraryW("sspicli.dll") + GetProcAddress` returns
  a VA that's valid in the AC target.
* `interception::write_remote_bytes` flips the page RX→RWX→RX via
  `VirtualProtectEx`. Already the model used for ntdll patches; works
  on sspicli pages too (broker has `PROCESS_VM_OPERATION`).
* `interception_arm64::patch_with_abs_jmp` /
  `interception_x64::patch_with_abs_jmp` are the actual patch
  primitives. Untouched.

**One extension required:** `build_passthrough_thunk` today snapshots
32 bytes verbatim and relies on the snapshot being a self-contained
syscall stub (`svc; ret` or equivalent) — the snapshot's own `ret`
returns to the cdylib's caller. This is **not safe for regular
functions** like `AcquireCredentialsHandleW`: control falls off the
end of the 32-byte snapshot into uninitialised page bytes (zeros, i.e.
`udf #0` on ARM64).

For SSPI shimming we need a different thunk shape:

```
saved_original[0..16]      ; literal copy of the patched-over bytes
ABS_JMP <orig_va + 16>     ; 16-byte ABS_JMP back into the unpatched
                           ; remainder of the function
```

That's a 32-byte thunk (16 bytes saved + 16 bytes of ABS_JMP
template). One ~30-line addition to `interception_arm64.rs` /
`interception_x64.rs`.

**Aside — does the existing CPW passthrough have the same bug?**
Reading `vendor/winsbox-src/crates/ac-cdylib/src/lib.rs:572`:

```rust
if frame.r_status == FS_PASSTHROUGH {
    let pv = IPC.passthrough_create_process_internal_w.load(...);
    ... let f: FnCpw = core::mem::transmute(pv as usize);
    return f(...);
}
```

Yes, it would crash if the broker ever returned `FS_PASSTHROUGH` for
a CPW request. Surveying `launch.rs`'s `handle_cpw`, it doesn't —
the broker always either spawns the child and returns success/failure
or hard-fails with a non-passthrough status. So the CPW path is
de-facto correct because the bug branch is unreachable. For the SSPI
shim, the passthrough branch *is* reachable (any non-Schannel
package), so the new JMP-back thunk shape is mandatory.

**Hookability verdict: yes**, with one ~30-line addition to the thunk
emitter and a switch from "ntdll exports only" to "any DLL by path"
in the resolve helper (which is already generalisable — see CPW).

## Task 4 — Scope of the shim

### LOC by component

| Component | LOC | Notes |
|---|---|---|
| Cdylib hook bodies (10 hooks × ~25 LOC each) | ~250 | Mostly ABI-marshalling; SSPI args are pointer-heavy so we serialise (handle, package-name-hash, buffer-descriptor-array) into the existing 12-slot `args` array + a side-channel for >96 bytes of SecBuffer data. |
| Cdylib package dispatch + handle-cookie logic | ~80 | Pre-IPC: peek at `pszPackage` / `phCred` / `phContext`, decide intercept vs passthrough, call passthrough thunk on miss. |
| Broker SSPI handler (`launch.rs::handle_sspi_*`) | ~450 | Per-op handlers; per-context state map (`HashMap<u64, SspiContextState>`); rustls `ClientConnection` driver. |
| `rustls` glue (cert store, SNI, ALPN, fragment policy) | ~200 | `rustls::ClientConfig` + `rustls-native-certs::load_native_certs()`; SNI from `pszTargetName`. |
| IPC wire extensions (new `OP_SSPI_*` opcodes + buffer-descriptor passing) | ~150 | New Wire variants — variable-size; SSPI buffers are routinely 16KB+, well over the 96 bytes the current 12-slot args fit, so we add a side-buffer in the shared section (or chunk via repeated calls). |
| Tests | ~100 | Existing curl-https.test (currently `.skip`) + a unit test for the rustls driver state machine. |
| **Total** | **~1130** | |

### `no_std` dilemma

The cdylib is `no_std` since Phase E-5c (commit `c0209d1`) — that
saved 127 KB (manual-mapped binary went 138 KB → 11 KB) and removed
the TLS-callback hazard that was breaking Cygwin children.

`rustls` is std-using (it pulls `std::sync::Arc`, `std::io::Read`,
allocator). Two architectures:

**(a) Cdylib stays no_std; broker holds state.** The 10 SSPI hook
bodies in the cdylib are thin marshallers — 250 LOC of exactly the
same shape as the existing `hook_handle_op` (lib.rs:387). Per-hook
work is "fill `frame.args[]` + secbuffer side-data; `ipc_roundtrip`;
unpack reply into out-params; return `r_status`". Zero rustls or std
in the cdylib. **The cdylib stays at 11 KB.**

The broker keeps a `HashMap<SspiCookie, SspiState>` keyed by the
cookie we wrote into `cred->dwLower`/`ctx->dwLower`. Each
`SspiState` holds the `rustls::ClientConnection` and any pending
plaintext/ciphertext buffers. Calls into rustls happen entirely in
broker-land where std is available.

Latency cost: one IPC roundtrip per SSPI call. Curl HTTPS does ~6–8
SSPI calls per request (handshake + a few Encrypt/Decrypt). At 1–2µs
per IPC roundtrip on the existing Wire path, that's ~10µs of added
latency per request — invisible against 50–500 ms TCP+TLS RTTs.

**(b) Cdylib goes std again.** Rebloats binary, brings TLS-callbacks
back, puts us back into the manual-map landmine field that motivated
no_std. Strictly worse. Reject.

**Decision: (a).** All TLS state lives in the broker; cdylib hooks
are 250 LOC of straightforward IPC marshalling.

### Architecture diagram

```
┌───────────────── AC target (curl.exe) ─────────────────┐
│                                                         │
│   curl → schannel-vtt curl → sspicli!Acquire... ◄──┐   │
│                                                    │   │
│   [Patch site, 16 bytes]                           │   │
│   ABS_JMP cdylib!hook_acquire_creds_w  ────────┐   │   │
│                                                ▼   │   │
│   cdylib::hook_acquire_creds_w:                    │   │
│     if pszPackage NOT in {Schannel, UNISP}:        │   │
│       tail-call passthrough[acquire] ──────────┘   │   │
│     else:                                              │
│       Wire { op: OP_SSPI_ACQUIRE, args: [...] }       │
│       ipc_roundtrip(&mut wire)            ──┐         │
│       *phCred = SecHandle{lower=cookie};    │         │
│       return wire.r_status (SEC_E_OK)       │         │
│                                             │         │
└─────────────────────────────────────────────┼─────────┘
                                              │ shared section + ev_req/ev_resp
┌─────────────────────────── broker ──────────▼─────────┐
│   serve_ipc_loop():                                    │
│     OP_SSPI_ACQUIRE => handle_sspi_acquire(...)        │
│       config = rustls::ClientConfig::builder()...      │
│       state = SspiCredState { config }                 │
│       cookie = next_cookie(); state_map.insert(cookie) │
│       reply { r_status: SEC_E_OK, r0: cookie }         │
│                                                        │
│     OP_SSPI_INIT_CTX_W => handle_sspi_init_ctx(...)    │
│       state = state_map.get(cookie)                    │
│       conn = rustls::ClientConnection::new(...)        │
│       conn.read_tls(&inbuf)?  # process server reply   │
│       conn.write_tls(&mut outbuf)?  # outgoing token   │
│       reply { r_status: CONTINUE_NEEDED, sidebuf }     │
│                                                        │
│     OP_SSPI_ENCRYPT/DECRYPT => ... rustls per-call ... │
└────────────────────────────────────────────────────────┘
```

The "sidebuf" is the existing IPC shared-section memory — already
sized to 4096 B, but TLS records are up to 16 KB. We'd grow the
section to 32 KB (one-time alloc, no per-call cost) or chunk via
repeated round-trips. Easier to bump the section.

## Task 5 — Risks ranked by severity

### High

1. **Cert store access from inside the AC (vs in the broker).**
   `rustls-native-certs` reads `HKLM\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates`.
   In architecture (a), rustls runs in the broker (full user trust
   store access — works). But the AC user has restricted reg access
   and `RootCertCheck` may be ACL-stamped denied. Architecture (a)
   sidesteps this entirely. **Resolved by architecture choice.**
2. **`pszTargetName` is the SNI/peer-name source.** Curl passes the
   hostname here (e.g. `"example.com"`). We must marshal it through
   the IPC. Wire is fixed-size — we put the wstring in the
   shared-section sidebuf (offset 0x100 onward). Straightforward.
3. **rustls coverage gaps.** Modern TLS 1.2 + 1.3 only. No SSL 3.0,
   no RC4, no obscure ciphersuites. Curl on modern Windows defaults
   to TLS 1.2+ so this is fine for our test target. Document as a
   limitation.

### Medium

4. **Schannel-specific `QueryContextAttributes` codes.** Curl reads
   `SECPKG_ATTR_STREAM_SIZES` (cipher block/MAC/header sizes) and
   `SECPKG_ATTR_REMOTE_CERT_CONTEXT` (returns a `CERT_CONTEXT*`).
   The first is mechanical (pull from rustls `negotiated_cipher_suite()`).
   The second is gnarly: we'd have to synthesise a `CERT_CONTEXT`
   that points to a CryptoAPI-allocated cert, which means calling
   `CertCreateCertificateContext` in the broker and marshalling the
   pointer back. If curl uses it for cert pinning we have to handle;
   otherwise we can return `SEC_E_UNSUPPORTED_FUNCTION` and curl
   should fall back. **Audit needed.** (Curl does call it in default
   builds for verbose output and pinning.)
5. **Stream-vs-buffer impedance mismatch.** SSPI `EncryptMessage`
   takes 4 SecBuffers in a fixed roles: HEADER + DATA + TRAILER +
   PADDING. rustls is stream-oriented — `write_tls()` produces
   a contiguous TLS record. Mapping requires us to split the rustls
   output into the SECBUFFER_STREAM_HEADER / DATA / TRAILER slots
   curl provides. Doable but fiddly; one bug source.
6. **Curl Schannel-backend code paths.** Curl's libcurl-schannel.c
   has Schannel-specific behaviours (`SCH_USE_STRONG_CRYPTO`,
   ALPN via `SecApplicationProtocolNegotiationExt_*`, post-handshake
   re-acquire on cert prompts). Need to scrub the curl source to
   confirm we cover the codepath the test uses. The deferred test
   is `curl -sSI https://example.com/` which is the simplest
   possible request — handshake + 1 GET + close — so likely fine.

### Low

7. **System services using Schannel inside the AC.** None. AC
   processes are leaf user-mode; no Windows service runs inside
   our AC. Documented.
8. **Process injection ordering.** sspicli must be loaded before
   we patch it. It isn't in the loader's static dependency graph
   for `cmd.exe`, `bash.exe`, `node.exe`, etc. — it's pulled in
   only when SSPI is first called. So the patch can't be installed
   pre-resume. Two solutions: (a) `LoadLibraryEx(sspicli.dll)`
   from the cdylib's first hook entry (mirrors the kernelbase trick
   for CPW), or (b) hook `LdrLoadDll` for `sspicli.dll` and patch
   on demand. (a) is simpler.
9. **ALPN.** Curl HTTP/2 sets ALPN `["h2", "http/1.1"]`. rustls
   supports it natively. SSPI exposes ALPN via `SECPKG_ATTR_APPLICATION_PROTOCOL`
   query and `SecApplicationProtocolNegotiationExt`. ~20 LOC.
10. **Concurrency.** The IPC wire is mutex-serialised today.
    Multiple curl requests in flight (parallel connections) would
    serialise per-call but each call is short. Fine for our use case.

## Task 6 — Comparison with the other Phase O paths

The user's last message floated three architectures. Side-by-side:

|   | (1) Plain-HTTP-to-broker + URL rewrite | (2) OpenSSL-build of curl with `--cacert <broker-ca>` | (3) **This shim** (in-process Schannel intercept) | (Phase O) Broker-side TLS terminator |
|---|---|---|---|---|
| Coverage | curl-only, only when user manually rewrites URLs | curl-only (the swapped binary) | every TLS client in the AC | every TLS client in the AC |
| LOC | ~50 (URL rewrite in netbridge) | ~0 (just bundle a different curl.exe) | ~1100 | ~300 + rcgen dep |
| Surface | breaks any HTTPS-enforcing server | breaks any non-curl HTTPS user (node, python, git) | full SSPI compat (modulo rustls coverage) | full TLS compat — same as (3) |
| Cert validation | n/a (downgraded) | broker-CA (we control it) | rustls native-certs (broker-side) | broker-CA leaf, signed per-domain |
| Risks | server-side TLS-required policies break | breaks every non-curl client; binary swap is fragile | cdylib hook ordering; SSPI surface gaps; ~6 day build | cert-store-install in AC may fail (probe needed) |
| Maintenance | every URL needs rewriting | re-bundle curl on every Windows update | track Windows SSPI ABI drift; rustls upgrades | track rcgen/rustls upgrades only |
| Visibility | broker sees plaintext (good for audit) | broker sees TLS bytes (bad for audit) | broker sees plaintext (good) | broker sees plaintext (good) |

### Why Phase O wins over this shim

* **Same coverage** — both intercept all TLS traffic at the
  process boundary; (3) at the SSPI layer, (Phase O) at the TCP
  layer.
* **Same audit story** — broker sees plaintext in both.
* **3–4× less code** — Phase O is one rcgen-issuer, one TLS
  acceptor plumbed onto the existing netbridge AF_UNIX listener,
  one `certutil -user -addstore Root`. The shim needs hooks +
  IPC wire extensions + per-context state map + rustls glue +
  Schannel-cert-context emulation.
* **Less ABI surface to maintain.** Phase O depends on rustls'
  server API + rcgen. The shim depends on every SSPI export's
  exact ABI, plus all the per-package idioms curl exercises
  (cert ctx, stream sizes, ALPN, post-handshake messages, control
  tokens).

### Why someone might still pick the shim

The single scenario where the shim wins: **`certutil -user
-addstore Root` doesn't work inside (or for) the AC user.** If the
broker can't make the AC trust a synthetic root, Phase O is dead
and we fall back to the shim (which doesn't need cert-store cooperation
because rustls runs in the broker with the broker user's full cert
store).

**Action item before either path:** run `certutil -user -addstore
Root <broker.crt>` from broker context for the AC's user / package,
then check inside the AC whether `curl https://<broker-signed>` is
trusted. If yes, Phase O. If no, fall back to here.

## Recommendation

1. **Verify Phase O preconditions first** (1 day): can the broker
   install a per-user trust root the AC honours?
2. **If yes, ship Phase O** (~3 days for the rcgen + TLS terminator
   + netbridge integration).
3. **If no, ship the shim** (~5–6 days for the architecture above).
   At that point, spec out the SSPI wire ops, extend
   `build_passthrough_thunk` with a JMP-back variant, and plumb
   rustls into the broker.

Either way, **don't do (1) URL rewrite** (downgrade) or **(2) curl
binary swap** (breaks the rest of the toolchain).

---

## Appendix A — Concrete probes that would settle ambiguity

If we want to de-risk Phase O *now* without committing implementation:

* **Probe O-pre-1:** broker-side `rcgen` issues a self-signed CA;
  install it via `certutil -user -addstore Root` for the AC user;
  inside the AC, `curl -k https://localhost:<broker-https-port>`
  (broker presents a leaf signed by that CA). Pass = Phase O alive.
  Fail (cert store unreachable / RootCertCheck denial) = Phase O
  dead, fall back to shim.

* **Probe shim-pre-1:** patch `sspicli!QuerySecurityPackageInfoW`
  with a one-shot ABS_JMP into a 16-byte cdylib export that just
  returns `SEC_E_OK` and prints "intercepted" via the existing IPC
  log channel. Confirms the patch primitive works on sspicli pages
  end-to-end. (This is the minimum-viable hook smoke test, ~50 LOC
  + a follow-up commit to interception_arm64.rs / interception_x64.rs
  for the new "regular function" passthrough thunk shape — but
  for the smoke test we don't even need passthrough.)

## Appendix B — Files this probe inspected

* `vendor/winsbox-src/src/bin/probe_schannel.rs` — the N-4 SSPI probe
* `vendor/winsbox-src/src/interception.rs` — façade
* `vendor/winsbox-src/src/interception_arm64.rs` — ARM64 ABS_JMP +
  passthrough emitter
* `vendor/winsbox-src/src/interception_x64.rs` — x64 mirror
* `vendor/winsbox-src/src/manual_map.rs` —
  `resolve_target_export_va` is generic over module path
* `vendor/winsbox-src/src/entry_trampoline.rs` — `cpw_address` shows
  the kernelbase-export resolution pattern we'd reuse for sspicli
* `vendor/winsbox-src/crates/ac-cdylib/src/lib.rs` — IPC `Wire`,
  `ipc_roundtrip`, `hook_handle_op`, `hook_create_process_internal_w`
  (the latter shows the regular-function passthrough call shape;
  the bug noted in Task 3 is academic since CPW broker never returns
  `FS_PASSTHROUGH`)
* `vendor/winsbox-src/src/ipc.rs` — `Wire` layout, `OP_*` opcodes,
  `FS_PASSTHROUGH` sentinel, `TRACE_SYSCALL_NAMES`
* `vendor/winsbox-src/src/netbridge.rs` — the AF_UNIX bridge that
  Phase O would extend with TLS termination
* `docs/n4_schannel_probe_findings.md` — the underlying AC-Schannel
  failure analysis this builds on
* `docs/n4_schannel_probe_in_ac_*.log` — the probe outputs
* `dumpbin -exports C:\Windows\System32\Secur32.dll` — confirms all
  SSPI exports are PE forwarders to sspicli
* `dumpbin -disasm:nobytes C:\Windows\System32\sspicli.dll` —
  confirms sspicli SSPI exports are normal functions amenable to
  the existing 12-byte (x64) / 16-byte (ARM64) ABS_JMP shape

## Appendix C — One-line summary for plan-tracking

> Hookable yes (sspicli, not Secur32). Top hooks: AcquireCredentialsHandleW,
> InitializeSecurityContextW, EncryptMessage/DecryptMessage. ~1100 LOC,
> cdylib stays no_std with broker-mediated state. Worse than Phase O on
> all axes except "survives if Phase O cert install fails." Recommend
> Phase O after a 1-day cert-store-install probe.
