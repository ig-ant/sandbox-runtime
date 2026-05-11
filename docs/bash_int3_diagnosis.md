# Diagnosis — `STATUS_BREAKPOINT` in `lldb_output.txt`

**Branch**: `winsbox-acl-stamping`
**Date**: 2026-05-10
**Status**: **Resolved as misdiagnosis.** The captured `0x80000003`
break is **not** the bash AV. It is the standard Windows loader's
*initial debugger break*, which **lldb on Windows ARM64 cannot
continue past** (a known LLDB bug). The actual production failure
remains `0xc0000005` in Cygwin DllMain, already documented in
`n7p_arm64_bash_diagnosis.md`.

## TL;DR

- ntdll+`0x2cbd8c` resolves to **`ntdll!#LdrpDoDebuggerBreak+0x34`**
  (the `#` prefix denotes the x64 view of an ARM64X PE function).
- The instruction at that address is `BRK #0xF000` (4 bytes; ARM64
  encoding of an x64 `int3`-equivalent). It fires `STATUS_BREAKPOINT`
  unconditionally for every debugged process on this host.
- This is the **expected** initial debugger break — its only purpose
  is to give the debugger a chance to set breakpoints before the
  target's main thread runs. Outside a debugger this code path is
  short-circuited because `ThreadHideFromDebugger` returns true.
- LLDB on Windows ARM64 enters a deadloop on `BRK #0xF000` because it
  fails to advance PC past the 4-byte BRK instruction
  ([llvm/llvm-project#56268](https://github.com/llvm/llvm-project/issues/56268)).
  After a `continue`, the process re-stops at the same address — which
  is exactly what the operator captured.
- **No fix is needed in our sandbox.** This is purely a debugger-tool
  limitation; the bash AV is a different, separate event that lldb
  never reaches under this host configuration. To make progress on the
  *actual* AV, attach with `cdb` instead of `lldb`.

## Identified function at ntdll+0x2cbd8c

Symbol resolution via `symchk` against the live build's PDB
(`51ABD10A0831CE1EA3597691D41F9DEE1`, downloaded from Microsoft Symbol
Server) and `cdb -c "ln ntdll+0x2cbd8c"` against a vanilla x64 process
on the same host:

```
(00007ffc`0db9bd58)   ntdll!#LdrpDoDebuggerBreak+0x34
                          # x64 view, +0x34 inside the function body
(00007ffc`0da2bfd0)   ntdll!LdrpDoDebuggerBreak
                          # native ARM64 view
```

Disassembly of the function (native ARM64 view, applies identically
because in an ARM64X PE the x64 view is a relocated alias of the same
code):

```text
ntdll!LdrpDoDebuggerBreak:
  pacibsp
  stp     fp,lr,[sp,#-0x20]!
  mov     fp,sp
  strb    wzr,[fp,#0x10]                  ; flag = 0
  mov     x4,#0
  mov     w3,#1                           ; ThreadInformationLength = 1
  add     x2,fp,#0x10                     ; &flag
  mov     w1,#0x11                        ; ThreadHideFromDebugger (0x11)
  mov     x0,#-2                          ; ThreadHandle = NtCurrentThread
  bl      ntdll!NtQueryInformationThread
  tbnz    x0,#0x1F, +0x3c                 ; if NT_ERROR -> skip
  ldrb    w8,[fp,#0x10]
  cbnz    w8, +0x3c                       ; if hidden -> skip
  brk     #0xF000                         ; <-- +0x34 == 0x2cbd8c
  b       +0x3c
  ldp     fp,lr,[sp],#0x20
  autibsp
  ret
```

Stack trace at the break (captured from a clean `sleep.exe` run under
cdb on this same Windows 11 26200 ARM64 host — every debugged x64
process hits this exactly once):

```
ntdll!#LdrpDoDebuggerBreak+0x34
ntdll!#LdrpInitializeProcess+0x1a6c
ntdll!#_LdrpInitialize+0x13c
ntdll!#LdrpInitializeInternal+0xd8
ntdll!#LdrpInitialize+0x34
ntdll!#LdrInitializeThunk+0x78
```

This is the **standard Windows loader hand-off to a debugger before
the target's `main()` runs**. The code is reached only when the
process has a debugger attached *and* the current thread is **not**
marked `ThreadHideFromDebugger`. With no debugger, the loader skips
the whole block.

## Why lldb gets stuck (the actual bug)

LLDB has a long-standing bug on AArch64: it does **not** advance PC
past `BRK #0xF000` (or any BRK) on continue. The user reports:

> The debugger stops at the instruction with "signal SIGTRAP" / Using
> the `cont` command resumes execution / The process immediately stops
> at the same instruction again / This cycle repeats indefinitely.

— [llvm/llvm-project#56268](https://github.com/llvm/llvm-project/issues/56268).

x86 debuggers handle `int3` automatically (the OS advances RIP past
the 1-byte trap before delivering `EXCEPTION_BREAKPOINT`). On ARM64,
`BRK` is a *synchronous abort* with PC pointing **at** the BRK; the
debugger must explicitly bump PC by 4. LLDB doesn't, so it loops.

This is **independent of our sandbox** — it would happen identically
to any x64 process on a Windows 11 ARM64 host attached with lldb. The
captured `lldb_output.txt` is therefore not evidence of an
xtajit64-specific quirk in our code; it's evidence that lldb is the
wrong tool for this host.

## Aside — why lldb's symbol attribution was misleading

`lldb_output.txt` shows the symbol as `EtwCheckCoverage + 75488`. That
is wrong: the closest **exported** symbol before `0x2cbd8c` is
`EtwCheckCoverage`; LLDB had a partial PDB and fell back to the
nearest export. Real PDB resolution against
`51ABD10A0831CE1EA3597691D41F9DEE1` gives
`#LdrpDoDebuggerBreak+0x34`. (See above for the full backtrace from
cdb.) `LdrpDoDebuggerBreak` is **not** exported, so any symbolicator
without the full PDB will miss it.

The disassembly LLDB printed (`addl %eax, (%rax)`, `addb %dl,
-0x573d85(,%rdi,8)`, …) is *also* wrong: LLDB decoded the bytes as
x64 instructions even though the ARM64X PE has been rewritten by the
ARM64X loader to native ARM64 code in this view. The actual bytes at
that address are `d4 3e 00 00` = `BRK #0xF000`.

## Likely category of integrity check

**None of A/B/C from the task brief.** This is **category D-adjacent
but not actually a check** — it is a deliberate, unconditional,
documented loader hand-off, not a violation detector:

- Not CFG (`LdrpDispatchUserCallTarget`).
- Not heap corruption (`RtlpHpAllocateHeap` family).
- Not PAC fail (would manifest with `STATUS_INVALID_IMAGE_HASH` or
  `STATUS_ILLEGAL_INSTRUCTION`, not `STATUS_BREAKPOINT`).
- Not xtajit64se integrity check (would not be at `LdrpDoDebuggerBreak`
  in ntdll proper; xtajit64se has its own CHPE-side guards).

The only Win11 25H2 / xtajit64se wrinkle is cosmetic: `xtajit64se` is
the "secure-enclave" successor to `xtajit64` (24H2's Prism). It does
*not* introduce new BRK-based checks at the ntdll layer that would be
relevant here. The function exists in every Windows ntdll for the
last decade.

## Recommended fix

**No code change is warranted from the lldb capture.** The capture
does not reflect a sandbox bug; it reflects the lldb-on-arm64-Windows
deadloop on `brk #0xF000`. If a fix is desired specifically for the
debug-attach UX, three small options exist (rough cost / risk):

1. **Use cdb instead of lldb for `WINSBOX_PAUSE_FOR_DEBUGGER=1`** —
   zero LOC. Update the operator hint in
   `vendor/winsbox-src/src/launch.rs:463` to recommend cdb first
   (cdb handles `BRK #0xF000` correctly: it advances PC, posts
   `EXCEPTION_BREAKPOINT`, and `g` continues normally as observed in
   our sleep-under-cdb experiment). This is a **doc-only** change.

2. **In `debug_attach.rs`**, when an `EXCEPTION_DEBUG_EVENT` arrives
   with `code == 0x80000003` (STATUS_BREAKPOINT) **at first chance**
   *and* `address == LdrpDoDebuggerBreak+0x34` (or simply: any
   first-chance `STATUS_BREAKPOINT` from `ntdll.dll`), respond with
   `DBG_CONTINUE` rather than `DBG_EXCEPTION_NOT_HANDLED`. That matches
   what cdb / WinDbg do by default. Currently
   `debug_attach.rs:69-72` uses `DBG_EXCEPTION_NOT_HANDLED` for *all*
   `EXCEPTION_DEBUG_EVENT`s, which would also fail to advance past the
   loader break. About 5 LOC. Improves debug-attach mode but
   debug-attach mode is already blocked on the parent-Job constraint
   per `n6_step3_debug_attach_findings.md`, so this is not on the
   critical path.

3. **Skip `LdrpDoDebuggerBreak` entirely** by setting
   `ThreadHideFromDebugger` (`NtSetInformationThread`,
   `ThreadInformationClass=0x11`) on the target's main thread before
   resuming. Strictly an anti-debug technique; not appropriate for our
   sandbox, listed only for completeness.

Recommended: **#1 (doc nudge to use cdb)**. This is the cheapest
change and unblocks the actual diagnostic the operator was trying to
do (capture the real bash AV rip), which is what
`n7p_arm64_bash_diagnosis.md` recommended as the next step anyway.

The deeper bash-AV question (`0xc0000005` in Cygwin DllMain → CNG/SSPI
lazy-init) is unchanged and unresolved. That remains an
AC + Cygwin + Prism interaction that has survived every targeted
change tried so far and which the prior diagnosis correctly tagged as
"not a small fix" (see `n7p_arm64_bash_diagnosis.md` §Recommendations).

## Implementation note (optional)

If we want #1, the patch is one-line:

```diff
--- a/vendor/winsbox-src/src/launch.rs
+++ b/vendor/winsbox-src/src/launch.rs
@@ -460,7 +460,11 @@
     if std::env::var("WINSBOX_PAUSE_FOR_DEBUGGER").as_deref() == Ok("1") {
         log!("WINSBOX_PAUSE_FOR_DEBUGGER=1: blocking until debugger attached to PID {}", pi.dwProcessId);
-        log!("  attach with: lldb -p {0}    OR    cdb -p {0}    OR    windbg -p {0}", pi.dwProcessId);
+        // On Windows ARM64, prefer cdb/windbg: lldb deadloops on the
+        // ntdll!LdrpDoDebuggerBreak BRK #0xF000 because it doesn't
+        // advance PC past it (llvm/llvm-project#56268). cdb / windbg
+        // handle this loader break correctly and let `g` continue.
+        log!("  attach with: cdb -p {0}    OR    windbg -p {0}    (avoid lldb on ARM64 — see llvm/llvm-project#56268)", pi.dwProcessId);
         loop {
```

## Sources

- LLDB AArch64 BRK deadloop —
  <https://github.com/llvm/llvm-project/issues/56268>
- LLDB Windows ARM64 hardware-breakpoint limitations (related, ditto
  general initial-stop weakness) —
  <https://github.com/llvm/llvm-project/issues/125054>
- `LdrpDoDebuggerBreak` is reached during loader init when a debugger
  is present and `ThreadHideFromDebugger` is unset — confirmed by:
  - cdb backtrace on this 26200 ARM64 host:
    `ntdll!#LdrpDoDebuggerBreak+0x34` ←
    `ntdll!#LdrpInitializeProcess+0x1a6c` ←
    `ntdll!#_LdrpInitialize+0x13c` ←
    `ntdll!#LdrpInitializeInternal+0xd8` ←
    `ntdll!#LdrpInitialize+0x34` ←
    `ntdll!#LdrInitializeThunk+0x78`
  - PDB resolution against
    `C:\tmp\symbols\ntdll.pdb\51ABD10A0831CE1EA3597691D41F9DEE11\ntdll.pdb`
- `BRK #0xF000` is the Windows loader's encoding of "x64 int3
  equivalent" in ARM64X PEs — disassembly above; comparable to the
  WinDbg / kiewic notes on `LdrpDoDebuggerBreak`
  (<https://kiewic.github.io/windbg>).
- ARM64X PE function aliasing (`ntdll!#LdrpDoDebuggerBreak` vs
  `ntdll!LdrpDoDebuggerBreak`) — FFRI Project Chameleon —
  <https://ffri.github.io/ProjectChameleon/new_reloc_chpev2/>.
- ARM64 BRK does not auto-advance PC; debugger must bump PC by 4 —
  Phabricator D91238 (`__builtin_debugtrap` on arm64) —
  <https://reviews.llvm.org/D91238>; LLDB discourse —
  <https://discourse.llvm.org/t/stepping-over-a-brk-instruction-on-arm64/69766>.
- The actual production AV (different event, not the lldb capture) —
  prior research in `Y:\docs\n7p_arm64_bash_diagnosis.md` and
  `Y:\docs\n6_relocated_bash_findings.md`.
- xtajit64 / xtajit64se architecture (general background; not the
  cause here) — `Y:\docs\xtajit64_chrome_research.md`.

## What was done in this investigation

- Read `lldb_output.txt`, prior n6/n7 docs, sandbox.md, xtajit64_chrome_research.md.
- Downloaded ntdll.pdb matching the live UUID from Microsoft Symbol Server.
- Resolved `ntdll+0x2cbd8c` via `cdb` against a clean x64 process on the
  same host. Same RVA, same RIP, same backtrace pattern → standard
  loader break.
- Disassembled `LdrpDoDebuggerBreak` to confirm the BRK is gated on
  `ThreadHideFromDebugger` (i.e. it only fires under a debugger).
- Verified the LLDB-on-ARM64 BRK deadloop is a known LLVM bug
  (#56268).
- Confirmed cdb continues past the same break correctly (`sleep 1`
  under `cdb -c "g; q"` exits cleanly).

## Hard-caveat compliance

- Read-only: no source files modified during investigation.
- The optional 5-line patch above is documented but not applied; it is
  cosmetic (operator hint) and the prior `n7p_arm64_bash_diagnosis.md`
  recommendations stand independently.
- ~1 hour elapsed.
