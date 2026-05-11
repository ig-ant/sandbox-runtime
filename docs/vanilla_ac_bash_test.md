# Task 2 — Vanilla AC bash test

## Hypothesis under test

Does x64 bash (a Cygwin binary) work in a *bare* AppContainer on
this Windows 11 ARM64 25H2 host? If yes → our sandbox adds something
extra (USER_LIMITED restricting SIDs / lowered IL / policy stamping /
hooks) that breaks bash. If no → the OS layer (AC + xtajit64se + Cygwin
x64) is broken and there is no fix possible at our level.

## Method

Minimum-viable AC sandbox (`examples/probe_vanilla_ac.rs`):

1. `CreateAppContainerProfile("srt.vanac.<hash>")`
2. `OpenProcessToken(self)` → `DuplicateTokenEx(...TokenPrimary)`
3. `NtCreateLowBoxToken` (`make_lowbox`) with:
   - empty capabilities (`capability_count=0`)
   - empty saved-handle list
   - empty restricting-SID list (no `CreateRestrictedToken` wrapping)
   - **no integrity-level lowering** (default IL retained)
4. `CreateProcessAsUserW` with `STARTF_USESTDHANDLES` + pipes for
   stdout/stderr capture. CWD = `%TEMP%`. ENV inherited.

That's it. No cdylib, no `CreateRestrictedToken`, no USER_LIMITED,
no IL=LOW, no ACL stamps, no hooks, no policy.

## Results

| Target binary                                                              | Arch  | Exit code   | Outcome |
|----------------------------------------------------------------------------|-------|-------------|---------|
| `C:\Program Files\Git\usr\bin\bash.exe` (Cygwin x64)                       | x64   | `0xC0000005` | AV  |
| `C:\Program Files\Git\usr\bin\true.exe`  (Cygwin x64)                      | x64   | `0xC0000005` | AV  |
| `C:\Windows\System32\cmd.exe` (native ARM64)                               | ARM64 | `0`          | OK  |
| `C:\Windows\SysWOW64\cmd.exe` (x86 32-bit, under WOW64)                    | x86   | `0`          | OK  |
| `sleep_target.exe` (x64 native Rust, built `x86_64-pc-windows-msvc`)       | x64   | `0`          | OK  |

## Implication

**The bug is OS-level and specifically affects Cygwin x64 binaries in
an AppContainer on Windows 11 ARM64 (xtajit64se).**

Note the cross-matrix:
- x64 native (Rust) in bare AC works.
- x64 Cygwin (bash/true/cygpath) in bare AC AVs.
- ARM64 native in bare AC works.
- x86 (32-bit) in bare AC works.
- x64 Cygwin **without** AC works fine on this host.

So the AV is a three-way interaction between:
- Cygwin's loader/DllMain initialization (cygwin1.dll / msys-2.0.dll)
- xtajit64se's x64 emulation on ARM64
- AppContainer's restricted access checks

The same x64 Cygwin binaries are reported to work in AppContainer on
**real x64** Windows (per the user, CI runs prove this), and they
work on this ARM64 host **without** AC. The combination is what's broken.

`0xC0000005` (access violation) tells us that during DLL_PROCESS_ATTACH,
some memory access traps. This matches the Phase L Wall 1 finding
already documented in `examples/smoke_bash.rs`. What this test newly
proves is that **dropping every additional restriction we add (lowbox
caps, USER_LIMITED restricting SIDs, IL=LOW, default DACL fiddling)
does NOT fix it.** A bare AC with the AC SID alone is enough to break
Cygwin x64 here.

## Verification — without AC, things work

For control:
```
$ 'C:\Program Files\Git\usr\bin\bash.exe' -c "echo hello"
hello
```
The same binary that AVs in `probe_vanilla_ac` runs fine outside AC
on the same host.

## Conclusion

This is not our bug to fix at the broker level. It's a Cygwin /
xtajit64se / AC interaction issue. Options going forward:

1. **Defer**: document as a known-bad combination; skip MSYS2/Cygwin
   bash tests on Windows 11 ARM64 25H2 hosts; rely on x64 CI for
   bash regression coverage.
2. **Workaround**: use a non-Cygwin shell on ARM64 hosts (busybox-w32,
   ARM64 native `pwsh`, ARM64 native git-bash if one ever ships).
3. **Investigate further**: get a procmon trace (Task 3) to pinpoint
   *which* memory access traps inside cygwin1.dll's DllMain. Even
   pinpointed, it's unlikely we can patch around it from outside the
   process (the AV happens before our hooks would run).

The Phase L `smoke_bash` file's recommendation — "(b) is a research
project — likely needs running bash WITHOUT the AC at all (use the
restricted token directly without AC capabilities)" — still applies.
Task 2 confirms it without ambiguity: the AC itself is incompatible
with Cygwin x64 on this host.

## Files

- New: `vendor/winsbox-src/examples/probe_vanilla_ac.rs` (200 LOC)
- Modified: `vendor/winsbox-src/src/lib.rs` (re-export
  `appcontainer` and `token` modules so the probe can use the same
  `make_lowbox` and `AppContainer::create` primitives the broker
  uses; pure re-export, no API surface change)
