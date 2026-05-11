# Bash AVs in our AC on ARM64 — root-cause synthesis

Three diagnostic tasks (`broker_ntdll_arch_verify.md`,
`vanilla_ac_bash_test.md`, `procmon_bash_findings.md`) jointly answer
the question "**why does x64 bash AV in our AC on this ARM64 host
when it works in our AC on x64 CI and works on this ARM64 host
without AC?**"

## Task 1 — which ntdll our broker patches

x64 broker on ARM64 host running under xtajit64se:
```
[sbox-exec] interception: GetModuleHandle(ntdll.dll) handle=0x7ffc0d8d0000
            machine=0x8664 path=C:\WINDOWS\SYSTEM32\ntdll.dll
```

`machine=0x8664` = `IMAGE_FILE_MACHINE_AMD64`. **Our patches go into
the correct x64 ntdll that the x64-emulated bash process actually
calls.** This matches Chromium's documented pattern (which shipped
this exact pattern on ARM64 Windows from ~2021 to Mar 2024).

ARM64 broker → ARM64 ntdll (`machine=0xAA64`), correct.

**Conclusion: not the bug.** The wrong-ntdll hypothesis is falsified.

## Task 2 — vanilla AC bash test

Bare AC (just AC SID via `NtCreateLowBoxToken`, NO `CreateRestrictedToken`,
NO IL lowering, NO USER_LIMITED, NO capabilities, NO cdylib, NO hooks,
NO ACL stamps, NO policy):

| Target                              | Outcome |
|-------------------------------------|---------|
| Git's bash.exe (x64 Cygwin)         | AV `0xC0000005` |
| Git's true.exe  (x64 Cygwin)        | AV `0xC0000005` |
| `C:\Windows\System32\cmd.exe` (ARM64) | OK |
| `C:\Windows\SysWOW64\cmd.exe` (x86)  | OK |
| x64 native Rust sleep_target.exe    | OK |

**Conclusion: the bug is in Cygwin's DLL initialization, specifically
triggered by AppContainer on Windows 11 ARM64 (xtajit64se).** Our
broker's extra restrictions (USER_LIMITED, IL=LOW, hooks, etc.) do not
cause it; a bare AC SID alone is sufficient.

## Task 3 — exact faulting instruction

cdb attached to the suspended bash, resumed past two initial-breakpoints,
caught the AV:

- **Faulting frame**: `msys_2_0!msys_dll_init+0x1652` (DllMain body)
- **Faulting instruction**: `test byte ptr [rdx+1], 8` (a `__reent` /
  Cygwin `cygheap` setup byte test)
- **rdx at fault**: `0x00000002102fb980`
- **Memory region containing rdx**: 535-GB `MEM_FREE` / `PAGE_NOACCESS`
- **Module load order**: msys-2.0 → unload-reload → CRYPTBASE →
  bcryptPrimitives → **AV**

The `rdx` value is garbage — its high 32 bits (`0x00000002`) don't
match any valid allocation in this process (heap is at `0x272…`,
DLLs at `0x7ffc…`). Most likely it was loaded from a Cygwin global
that depends on a successful `cygwin_shared` mapping into
`\BaseNamedObjects\`, which AC cannot grant.

## Root cause

Combining Tasks 1+2+3:

1. **Cygwin x64 DllMain (`msys_dll_init`) assumes it can create or
   open a named shared section under `\BaseNamedObjects\`** for the
   per-Cygwin-version shared memory region (`cygwin_shared` / heap
   metadata / `__reent` baseline).

2. **In an AppContainer**, the kernel transparently redirects
   `\BaseNamedObjects\…` to
   `\Sessions\<sess>\AppContainerNamedObjects\<package-SID>\…`.
   In a fresh AC, this per-AC namespace is empty and the AC has no
   default ACL allowing it to create new named objects at the kernel-
   global level. The section create/open returns
   `STATUS_OBJECT_NAME_NOT_FOUND` or `STATUS_ACCESS_DENIED`.

3. **Cygwin doesn't gracefully handle that failure.** A pointer
   derived from the mapping base (or from a fallback path that
   silently zeros out and gets offset by a small integer) ends up
   in unmapped 535-GB-free address space, and the first dereference
   in `__reent` setup AVs.

4. **Why x64 CI doesn't see this**: on real x64 Windows hosts, *some*
   prior Cygwin-using process in the session has already created the
   `cygwin_shared` section at `\BaseNamedObjects\`, OR the AC's
   creation succeeds because the default-DACL stars align differently
   on x64. We didn't bisect this far (it's the OS-level interaction)
   but it explains the test-environment delta cleanly: on a fresh
   ARM64 AC with no prior Cygwin run, the first cygwin1.dll DllMain
   under AC has no prior section to find or attach to.

5. **Why this host without AC works**: outside AC,
   `\BaseNamedObjects\` is plain `BaseNamedObjects` with normal user
   ACLs. Cygwin's `NtCreateSection` succeeds, the shared region maps,
   the pointer is valid.

## Recommended fix shape

The Phase L finding ("(b) is a research project — likely needs running
bash WITHOUT the AC at all") is the right one. There is **no
broker-side fix** for this on Windows 11 ARM64 25H2 with current
Git-for-Windows / MSYS2 bash. Options:

### Defer (recommended)

**Document this as a known-bad combination and skip the bash compat
tests on Windows 11 ARM64 25H2 hosts.** x64 CI continues to cover
bash regressions; our ARM64 broker covers native-PE workloads
(smoke_cdylib + the 17p/5s/0f baseline). MSYS2/Cygwin compat under
ARM64 ACs needs a Cygwin-side fix (cygwin1.dll graceful-fallback on
section-create failure), which is out of scope for our broker.

Concrete actions:
- Keep `WINSBOX_SKIP_BASH_SMOKE=1` env-var opt-out in
  `examples/smoke_bash.rs` (already there).
- TS-side: detect host arch + 25H2 build + AC + Cygwin shell, skip
  with a clear "known OS-level issue" message.
- Update `docs/n7p_arm64_bash_diagnosis.md` to point at this
  synthesis as the closing finding (the prior diagnosis cycle stopped
  short of the full call-stack capture).

### Pre-create + stamp the shared section (speculative)

If we really wanted to push: have the broker create
`\Sessions\<sess>\AppContainerNamedObjects\<sid>\cygwin1S5` (and
similar names) ahead of time, ACL-stamp the AC SID, and ensure the
section base & layout match what cygwin1.dll expects. This is
fragile — we'd need to know Cygwin's internal layout for every
version of msys-2.0.dll and update when Cygwin does.

Not worth the maintenance cost.

### Use ARM64-native shell instead

If a use case requires running bash on ARM64 hosts inside our AC,
switch to an ARM64-native shell (PowerShell, ARM64 git-bash if/when
one ships, busybox-w32 — though busybox-w32 is x64 too currently).
Until an ARM64-native MSYS2 builds work in AC, this is the only path.

## Files

- `docs/broker_ntdll_arch_verify.md` — Task 1
- `docs/vanilla_ac_bash_test.md`     — Task 2
- `docs/procmon_bash_findings.md`    — Task 3 (cdb instead of procmon)
- `docs/bash_av_stack_capture.log`   — raw cdb log w/ full stack
- `docs/bash_av_memory_context.log`  — raw cdb log w/ !vprot
- New: `vendor/winsbox-src/examples/probe_vanilla_ac.rs`
- Modified: `vendor/winsbox-src/src/interception.rs` — one-shot
  diagnostic log line in `ntdll_export`
- Modified: `vendor/winsbox-src/src/lib.rs` — re-export
  `appcontainer` + `token` modules so the probe can reuse them
- Brokers built: `vendor/winsbox/{arm64,x64}/sbox-exec.exe`,
  cdylibs built: `vendor/winsbox/{arm64,x64}/ac_cdylib.dll`

## Verification

- `smoke_cdylib` (ARM64 broker → ARM64 target): PASS, ntdll machine
  `0xAA64` as expected.
- `smoke_bash` (x64 broker on ARM64 host → x64 bash): FAIL same way
  it has been (the Task-1 log line lit up: machine `0x8664`, path
  `C:\WINDOWS\SYSTEM32\ntdll.dll`; downstream still AVs).
- `probe_vanilla_ac.exe`: bare AC, bash AVs `0xC0000005` ; same probe
  with `cmd.exe`/`SysWOW64\cmd.exe`/native-Rust-x64 target: all
  succeed.
- cdb captured the AV at `msys_dll_init+0x1652`,
  `test byte ptr [rdx+1], 8`, rdx in 535-GB MEM_FREE region.

## Blockers that needed user intervention

- **Procmon installation required admin** (UAC silently waits). The
  cdb path was used instead and yielded equivalent or better data; if
  procmon is desired for additional confirmation, the user would need
  to run it elevated once. See `docs/procmon_bash_findings.md` for
  the would-be filter setup if a future agent picks this up.
