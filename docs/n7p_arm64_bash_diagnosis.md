# N-7+ — ARM64 bash AV diagnosis: AC+Cygwin+Prism wall (not xtajit64-specific small fix)

**Branch**: `winsbox-msys2-iter`
**Date**: 2026-05-10
**Status**: **Investigation complete; no small-fix landed.** The bash
AV on ARM64 is the original Phase L Wall 1, not a new xtajit64 quirk
amenable to a 50-LOC patch.

## Question

The task hypothesised that the ARM64 bash test was hitting an
xtajit64-specific quirk (different syscall return values, missing
broker mediation for an emulator-injected device IOCTL, or similar)
that an x64 host on real silicon avoids. If true, a small targeted
fix should close the gap.

## TL;DR

The premise was wrong. The two traces we were diff'ing aren't testing
the **same scenario** on different platforms — they're testing
**different scenarios**:

- `bash_trace_x64_ci.txt` (x64 CI, passes): target = `cmd /d /s /c
  "<bash> -c echo hello"`. **cmd is the immediate target**; bash is a
  grandchild. cmd's CPW hook brokers the bash spawn; bash inherits
  cmd's job and AC via `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`.
- `n7p_bash_arm64_per_arch.log` (ARM64 local, fails): target =
  `<bash> -c echo hello` (via test-helper `directTargetExe`).
  **bash is the immediate target** — no cmd in the picture.

When you put the same scenario through both: bash-as-target with cmd
wrapper on ARM64-via-Prism still AVs. bash-as-target without cmd
wrapper on real x64 hardware reportedly works (see Phase L cycle
history). The variable that matters is **AC + Cygwin DllMain +
Prism emulation**, which is the wall N-6 step 2 (relocated bash)
already hit and partially documented in
`docs/n6_relocated_bash_findings.md`.

## What we ruled out (re-confirmed in this iteration)

Test matrix on this ARM64-via-Prism host (Win11 25H2, build 26200):

| Broker arch | Target shape                | cdylib | Result               |
|-------------|-----------------------------|--------|----------------------|
| x64 (xtajit64) | `cmd /c echo`           | x64    | exit=0 (PASS)        |
| x64 (xtajit64) | `cmd /c bash -c echo`   | x64    | exit=0xc0000005      |
| x64 (xtajit64) | `bash -c echo` (direct) | x64    | exit=0xc0000005      |
| x64 (xtajit64) | `bash -c echo` (direct) | none   | exit=0xc0000005      |
| x64 (xtajit64) | `bash -c echo` (direct) + `WINSBOX_BARE_AC=1` | x64 | exit=0xc0000005 |
| ARM64       | `cmd /c bash -c echo`        | arm64  | exit=0xc0000005 (cdylib graceful-degrade for x64 grandchild) |

Bash run **directly from PowerShell** (no broker, no AC) on this same
host: works fine, prints "hello", exits 0.

Conclusion: the AV is **AC + Cygwin's `cygwin1.dll/msys-2.0.dll`
DllMain + Prism JIT** on this host. It is NOT cdylib-induced, NOT
broker-arch-induced, NOT cross-arch-injection-induced.

## Where the AV happens

The trace stops at:
```
NtCreateSection name="" access=0xf0007 prot=0x4 attr=0x8000000 → 0
NtMapViewOfSection sect_h=0x158 prot=0x4 → 0
[AV — 0xc0000005, between syscalls]
```

This is inside `cygheap_user::init()` →
`NtQueryInformationToken(TokenUser)` → ksecdd → CNG/SSPI lazy init.
The 9 anonymous events + 2 anonymous SEC_COMMIT/PAGE_READWRITE
sections are the classic
`SspiInitializeSecurityContextW`/`LsaConnectUntrusted` ALPC handshake
prep on the AC's per-AC LSA endpoint
(`\Sessions\<n>\AppContainerNamedObjects\<sid>\LSARPC_ENDPOINT`).

The crash site is **between** trace-able syscalls — meaning it's in
**user-mode code** (likely
`sspicli!LsaConnectUntrusted_LegacyTrap` or a CNG init path)
dereferencing memory that was never initialised, never returned a
valid handle, or was returned in a layout Cygwin doesn't expect.

## Why a debugger would help (and why we can't run one here)

The minimum diagnostic is one debug-attach session over the AV to
recover RIP + module + instruction. The framework exists in
`vendor/winsbox-src/src/debug_attach.rs`, but `WaitForDebugEvent`
times out from inside this Claude Code parent-job
(`docs/n6_step3_debug_attach_findings.md`). The fix is environmental
— operator runs the broker from a plain PowerShell shell outside the
parent job and reads the resulting `[debug-attach]` log. Suggested in
`docs/n6_step3_debug_attach_findings.md` as N-6 step 4 / Option 1.

Without an RIP at the AV, every hypothesis is speculation. The shape
of the failure (between syscalls, deep inside CNG/SSPI lazy-init,
AC-only, this-host-only) suggests **Prism JIT translation of CNG's
ARM64-pre-translated x64 trap path** rather than something the broker
can mediate.

## Chromium analogue (negative finding)

`docs/xtajit64_chrome_research.md` exhaustively covered Chromium's
sandbox + xtajit64 history. They have **one** xtajit-aware carve-out
(crbug.com/977723: 32-bit ACG); the x64 path is arch-agnostic.
Chromium does NOT run Cygwin under their sandbox at scale, so the
specific failure mode here (Cygwin DllMain + AC + xtajit64/Prism)
is not a known-Chromium issue with a documented fix.

The `BTCpu*` ABI listed in the prior research is the right place to
look if we ever go deeper, but instrumenting xtajit64 itself is well
out of scope for this branch.

## Why the test stays skipped on ARM64

- `test/sandbox/windows.test.ts:142-143` already gates the bash test
  on `process.arch !== 'arm64'`. Correct.
- The cmd-wrapped path doesn't help on ARM64 — bash AVs as
  grandchild too (verified above).
- The `directTargetExe` test-helper is the right plumbing to pass
  bash directly through the per-arch broker picker on x64 hosts (a
  workload we may need to support if a future test runs without a cmd
  wrapper); it just doesn't unblock ARM64.

## Recommendations

1. **Keep the gate.** The 17p/5s/0f ARM64 baseline is correct as-is.
2. **If/when prioritising bash-on-ARM64**: run the broker from
   PowerShell-outside-Claude-Code with `WINSBOX_DEBUG_ATTACH=1` and
   capture the debug-attach RIP. Until we have that, no targeted fix
   can land with confidence.
3. **The "xtajit64 small quirk" hypothesis was wrong** in this
   instance, but the prior research is sound and the per-arch broker
   is correct architecture. The wall is downstream — Prism's
   interaction with AC + Cygwin's DllMain.
4. **Don't compound the misdiagnosis chain**. Phase L originally
   misattributed Wall 1 to "Cygwin DllMain in bare AC is broken
   forever". N-6 step 2 corrected: Wall 1 was cross-arch corruption
   on ARM64-broker-into-x64-target. N-7+ now corrects again: with
   arch parity Wall 1 is replaced by **the same downstream AV** in
   CNG/SSPI lazy-init that survives every change we've tried. That's
   the actual wall.

## Files referenced

- `Y:\bash_trace_x64_ci.txt` — x64 CI passing trace (cmd target)
- `Y:\docs\n7p_bash_arm64_per_arch.log` — ARM64 local failing trace
  (bash direct target, trace mode on)
- `Y:\docs\n6_x64broker_bash_trace.log` — x64 broker on ARM64 host,
  bash direct target — same AV, no per-arch issue
- `Y:\docs\n6_relocated_bash_findings.md` — H7-2 (cdylib base
  collision) ruled out
- `Y:\docs\n6_step3_debug_attach_findings.md` — debug-attach
  framework (blocked by parent job)
- `Y:\docs\xtajit64_chrome_research.md` — Chromium evidence (no
  applicable fix)
- `Y:\docs\cygwin_recovery_findings.md` — N-7's NtQueryAttributesFile
  + broker_pipes restoration (already landed in 4d26ef0)
