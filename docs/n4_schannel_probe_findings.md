# N-4 follow-up: Schannel-under-AppContainer probe — findings

## Summary

**Verdict: structurally broken.** A minimal SSPI probe that bypasses
curl reproduces the exact same `SEC_E_NO_CREDENTIALS (0x8009030e)`
failure on `AcquireCredentialsHandleW(OUTBOUND, "Schannel", NULL
pAuthData)` inside the AC. Passing an explicit zeroed `SCHANNEL_CRED
{ dwVersion = SCHANNEL_CRED_VERSION }` produces the **same** error,
ruling out the "curl is using the wrong calling convention" hypothesis
and confirming the N-4 agent's prior assumption: AC-Schannel is broken
end-to-end inside our lowbox token, with no user-mode workaround
available at the SSPI layer.

The N-4 agent's prior conclusion ("fundamentally LSA-internal, MITM
needed") stands. Phase O (broker-side TLS termination via rcgen-issued
session CA) is the right next step.

## Probe

Source: `vendor/winsbox-src/src/bin/probe_schannel.rs` (added by this
phase). It calls — directly, with no curl in the loop — the same SSPI
sequence curl uses:

1. `QuerySecurityPackageInfoW(L"Schannel")`
2. `AcquireCredentialsHandleW(NULL, "Schannel", SECPKG_CRED_OUTBOUND,
   NULL pAuthData)`
3. (only if step 2 returned `SEC_E_NO_CREDENTIALS`)
   `AcquireCredentialsHandleW(NULL, "Schannel", SECPKG_CRED_OUTBOUND,
   &SCHANNEL_CRED { dwVersion: 4, .. zeroed .. })`
4. (only if step 2 or 3 succeeded) `InitializeSecurityContextW`
   first-call with target=`"127.0.0.1"`, expecting
   `SEC_I_CONTINUE_NEEDED`.

The probe deliberately skips a real network handshake — step 4 just
verifies Schannel can produce a ClientHello, which is all curl needs
before it touches the wire.

## Results

### Outside AC (sanity baseline)

```
STEP 1: QuerySecurityPackageInfoW("Schannel") -> OK cbMaxToken=24576 wRPCID=14
STEP 2: AcquireCredentialsHandleW(NULL, "Schannel", OUTBOUND, NULL pAuthData) -> OK cred=...
STEP 3: SKIPPED (step 2 succeeded)
STEP 4: InitializeSecurityContextW(first call, target="127.0.0.1") -> OK SEC_I_CONTINUE_NEEDED token_bytes=147
RESULT: PASS
```

Schannel produced a 147-byte ClientHello. SSP works for the broker
user.

(Full log: `docs/n4_schannel_probe_outside_ac.log`.)

### Inside AC — variant: default

```
STEP 1: QuerySecurityPackageInfoW("Schannel") -> OK cbMaxToken=24576 wRPCID=14
STEP 2: AcquireCredentialsHandleW(NULL, "Schannel", OUTBOUND, NULL pAuthData) -> ERR 0x8009030e: SEC_E_NO_CREDENTIALS
STEP 3: AcquireCredentialsHandleW(NULL, "Schannel", OUTBOUND, &empty SCHANNEL_CRED) -> ERR 0x8009030e: SEC_E_NO_CREDENTIALS
STEP 4: SKIPPED (no credential)
RESULT: FAIL
```

Step 1 succeeds — the SSP itself is reachable; this rules out "Schannel
package isn't registered to the AC" as a hypothesis. Step 2 reproduces
the exact curl failure shape. Step 3 — the small-fix candidate — also
fails with `SEC_E_NO_CREDENTIALS`, killing the "curl needs to pass
explicit empty creds" theory.

(Full log: `docs/n4_schannel_probe_in_ac_default.log`.)

### Inside AC — variant: `WINSBOX_BROKER_OPEN=0`

Same `SEC_E_NO_CREDENTIALS` on both step 2 and step 3 with
broker-mediated NtCreateFile/NtOpenFile disabled. Disabling the broker
mediation produces a wave of `[denied-open]` lines for the path-walk
side of the probe's startup, but it still reaches the SSPI call and
still receives `NO_CREDENTIALS` — confirming the failure is inside the
LSA round trip, not the broker's FS path.

(Full log: `docs/n4_schannel_probe_in_ac_no_broker_open.log`.)

### Inside AC — variant: `WINSBOX_TRACE_SYSCALLS=1`

Same `SEC_E_NO_CREDENTIALS` outcome. Crucially, the trace span between
the probe-grandchild's cdylib injection (`grandchild cdylib injected:
pid=2504`) and the `STEP 2: ... ERR 0x8009030e` line on stdout contains
**zero `[DENY]` lines from pid=2504**. The few `[DENY]` lines visible
in the trace come from the parent cmd.exe wrapper's earlier path walk
(probing C:\Users\ig\AppData\Local\Temp\claude\ before broker-open
GRANTs settle), not from the grandchild that runs the SSPI calls.

This matches what the N-4 curl trace showed and disproves any
"hooked-syscall denial caused the credential lookup to fail" theory.
The failure is entirely inside the LSA ALPC round-trip — the call
reaches `lsasspirpc`, the AC-bound LSA endpoint replies
`STATUS_NO_CREDENTIALS`, and there is no user-mode hook surface to
mediate it. The AC's bound LSA endpoint is its own service-side state
machine; it doesn't share Schannel's per-user credential cache with
the broker user.

(Full log: `docs/n4_schannel_probe_in_ac_syscall_trace.log`.)

## Eliminated hypotheses

| Hypothesis | Verdict |
|---|---|
| Schannel SSP is not registered in AC | Rejected — step 1 succeeds. |
| Curl is calling AcquireCredentialsHandle wrong | Rejected — direct call has the same failure shape. |
| Curl needs to pass explicit `SCHANNEL_CRED` instead of NULL | Rejected — step 3 fails with the same code. |
| Broker-mediated FS opens are denying a credential-store file | Rejected — `WINSBOX_BROKER_OPEN=0` produces the same code, and trace mode shows zero DENYs from the SSPI process pre-error. |
| Some hooked syscall in our cdylib is intercepting an LSA-related call wrong | Rejected — same code with full 15-syscall trace coverage; no hooked path is implicated. |

## Recommended next step

Implement Phase O — broker-side TLS termination — as the N-4 agent
proposed.

- Broker generates a per-session CA (rcgen).
- Broker installs it as a per-user trust root (`certutil -user
  -addstore Root`) so AC-side curl trusts it.
- Broker's existing `netbridge.rs` HTTP CONNECT path becomes a TLS
  terminator that signs per-domain leaf certs on demand.
- AC-side curl sees plaintext upstream and never engages Schannel.

Estimated cost: ~300 LOC + rcgen dep. No further AC-Schannel work is
worth pursuing — the probe shows the failure is inside the LSA service,
unreachable from user-mode, and not contingent on any of our policy
knobs.

## Appendix: probe sources / harness

- Probe: `vendor/winsbox-src/src/bin/probe_schannel.rs`
- Cargo `[[bin]]` entry: `vendor/winsbox-src/Cargo.toml` (after
  `probe_priv`)
- AC harness: `docs/n4_probe_schannel.mjs` (Bun, mirrors `runSandboxed`
  from `test/helpers/windows.ts`)
- Logs:
  - `docs/n4_schannel_probe_outside_ac.log`
  - `docs/n4_schannel_probe_in_ac_default.log`
  - `docs/n4_schannel_probe_in_ac_no_broker_open.log`
  - `docs/n4_schannel_probe_in_ac_syscall_trace.log`
  - `docs/n4_schannel_probe_in_ac.log` (concatenation of all three
    inside-AC variants)

To reproduce:

```
# Build the probe.
CARGO_TARGET_DIR='C:\Users\ig\AppData\Local\Temp\winsbox-target' \
  cargo build --release --manifest-path vendor/winsbox-src/Cargo.toml \
  --bin probe_schannel
cp 'C:\Users\ig\AppData\Local\Temp\winsbox-target\release\probe_schannel.exe' \
  vendor/winsbox/arm64/

# Outside AC (sanity).
bun docs/n4_probe_schannel.mjs outside-ac

# Inside AC, default config.
bun docs/n4_probe_schannel.mjs default

# Inside AC, broker-open disabled.
bun docs/n4_probe_schannel.mjs no-broker-open

# Inside AC, full syscall trace.
bun docs/n4_probe_schannel.mjs syscall-trace
```
