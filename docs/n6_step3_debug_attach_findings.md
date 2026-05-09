# N-6 step 3 — minimal Win32 debug-attach: framework landed, AV capture blocked by parent-job

**Branch**: `winsbox-msys2-iter`
**Date**: 2026-05-09
**Status**: **Framework wired, blocked by environmental constraint.** The
`WINSBOX_DEBUG_ATTACH=1` plumbing is in place and code-correct, but
`WaitForDebugEvent` returns `ERROR_SEM_TIMEOUT (0x80070079)` from
inside Claude Code's process tree because the broker is contained in
a parent Job object that suppresses debug-port delivery for
non-admin debuggers.

## TL;DR

- `vendor/winsbox-src/src/debug_attach.rs` (new, 286 LOC): minimal
  `DebugSession` with main-thread-only event drain, AV capture (RIP +
  module + access kind/addr + 8 stack quadwords + RBP-chain frame
  walk).
- `vendor/winsbox-src/src/launch.rs` integration: `WINSBOX_DEBUG_ATTACH=1`
  spawns target with `DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED`,
  drains initial event on the spawning thread, then runs to
  completion in the main loop.
- Default behaviour (no env var) is unchanged: `cargo test --lib`
  still 27/27, `smoke_cdylib` still `target exit=0x0`.
- With `WINSBOX_DEBUG_ATTACH=1`: `WaitForDebugEvent(initial)` times
  out (10 s), broker logs the failure, terminates the target, exits.
  Does **not** capture an AV.

## Why the timeout

We confirmed three combinations all fail:

| Spawn shape                                        | Result                |
|----------------------------------------------------|-----------------------|
| `CreateProcessAsUserW(lowbox, AC, DEBUG_ONLY_THIS_PROCESS)` | timeout |
| `CreateProcessAsUserW(no token, AC capabilities, DEBUG_ONLY_THIS_PROCESS)` | timeout |
| `CreateProcessW(no AC, no token, DEBUG_ONLY_THIS_PROCESS)` | timeout |

The third case rules out AppContainer / lowbox as the cause. We
also tried `CREATE_BREAKAWAY_FROM_JOB` to escape a parent Job; that
returned `ERROR_ACCESS_DENIED (0x80070005)`, telling us the broker's
parent Job has `JOB_OBJECT_LIMIT_BREAKAWAY_OK = 0`.

Putting the two together: the broker (`sbox-exec.exe`, spawned by
`smoke_cdylib.exe`, spawned by `cargo run`, spawned by Claude Code's
harness) sits inside a Job chain whose root job — likely Claude
Code's own — has the breakaway and silent-breakaway bits cleared.
Windows' debug subsystem refuses to attach a debug port for child
processes spawned from inside that Job by a non-admin caller. The
caller has no `SeDebugPrivilege` (we checked: standard-user privilege
list contains `SeChangeNotify`, `SeShutdown`, `SeUndock`,
`SeIncreaseWorkingSet`, `SeTimeZone` — no debug). Combined with the
Job containment, the kernel silently drops the DebugObject during
`NtCreateUserProcess` and `WaitForDebugEvent` therefore receives
nothing.

## What the framework delivers when the constraint isn't present

If `sbox-exec.exe` is launched directly from a PowerShell session
that's *not* inside a Job (e.g. an admin-elevated terminal, or a
plain PowerShell window outside Claude Code), the framework should
work as designed:

```
[debug-attach] CREATE_PROCESS pid=… tid=… image_base=… entry=… name=…
[debug-attach] LOAD_DLL base=… name="ntdll.dll"
[debug-attach] LOAD_DLL base=… name="kernelbase.dll"
…
[debug-attach] EXCEPTION first_chance=1 code=0xC0000005 address=…
[debug-attach] EXCEPTION first_chance=0 code=0xC0000005 address=…
[debug-attach] AV: RIP=… module=msys-2.0.dll+0x…
[debug-attach]     access_kind=0(read) access_addr=…
[debug-attach]     rsp=… rbp=…
[debug-attach]     stack[0]=… (msys-2.0.dll+0x…)
[debug-attach]     frame_1: rbp=… ret=… (msys-2.0.dll+0x…)
…
```

The main-thread-only event drain (the explicit fix from the previous
attempt's 562 LOC misadventure) is in `DebugSession::drain_initial`
and `DebugSession::run_to_completion` — both run on the same thread
that called `CreateProcessW`, satisfying `WaitForDebugEvent`'s
thread-affinity requirement. Cdylib injection is auto-disabled in
debug-attach mode to avoid the entry-rendezvous-vs-debug-drain
deadlock on the same broker thread; debug-attach also bypasses the
AppContainer entirely (the framework spawns into a plain CreateProcessW
with `DEBUG_ONLY_THIS_PROCESS` only) since `DEBUG_ONLY_THIS_PROCESS`
+ AC + no-`SeDebugPrivilege` is a separate kernel-policy denial.

## Path forward for actually capturing the bash AV

Three independent options, in increasing engineering cost:

1. **Run sbox-exec from outside Claude Code**, then read the captured
   logs back in. The framework is ready as-is; just needs:
   - A wrapper script the operator runs in PowerShell:
     `WINSBOX_DEBUG_ATTACH=1 sbox-exec.exe --policy bash-debug.json 2> debug.log`
   - The broker spawns *outside* AC (already done — see
     `spawn_for_debug` in launch.rs) so the AV-vs-AC question gets
     a clean answer too: if bash AVs without AC, the AV is
     Cygwin-internal; if it doesn't, the AV is purely AC-induced.
2. **Inject a vectored exception handler at process start.** We
   already have `entry_trampoline.rs` infrastructure that fires on
   the first thread before any user code runs. Modify the trampoline
   stub to call `RtlAddVectoredExceptionHandler` with a tiny handler
   in the cdylib that copies `ExceptionRecord` + `ContextRecord` into
   the IPC section and signals the broker. Cost: ~150 LOC extra in
   the cdylib (RtlAddVectoredExceptionHandler is in ntdll, mapped at
   process creation, so it's reachable from the trampoline). Bypasses
   the parent-Job constraint entirely because no debug port is
   involved. Caveat: the handler runs in the AV'ing thread's context,
   so it can't safely make IPC calls — needs to write to a fixed VA
   the broker polls.
3. **WER LocalDumps.** Set HKCU registry key for crash dumps for
   bash.exe; run smoke_bash; read the dump. Requires registry write
   (HKCU is OK for the user) + a minidump parser. ~300 LOC.

Option 1 is the cheapest unblock — the operator runs one PowerShell
command outside the Claude session and pastes the log back. Option 2
is the right long-term answer if the diagnostic is to live in the
broker.

## Files

- `vendor/winsbox-src/src/debug_attach.rs` — **new**, 286 LOC.
- `vendor/winsbox-src/src/main.rs` — `mod debug_attach;` declaration.
- `vendor/winsbox-src/src/launch.rs` — env-var gate + `spawn_for_debug`
  helper + drain-and-loop wiring.

## Verification gates

- `cargo build --release` (ARM64 + x64) — green.
- `cargo build --release -p ac-cdylib` (ARM64 + x64) — green.
- `cargo test --lib` — 27 / 27 (including 4 new tests from the
  parallel N-7 commit `3092e82`).
- `cargo run --example smoke_cdylib` (no env var) — `target exit=0x0`,
  `cdylib reported back` — **default path unchanged**.
- `WINSBOX_DEBUG_ATTACH=1 cargo run --example smoke_cdylib` —
  framework activates, `WaitForDebugEvent(initial)` times out at 10s,
  broker logs `parent-job blocks DebugObject delivery`, target
  terminated, broker exits cleanly. The AV-capture path itself is
  reached but produces no AV (sleep_target doesn't crash) — the
  blocker is environmental.

## Recommended N-6 step 4 scope

Implement option 1 above as a one-shot operator workflow:

- Add an `examples/smoke_bash_debug.rs` that wraps the regular
  smoke_bash policy with `WINSBOX_DEBUG_ATTACH=1` set in the broker's
  env, designed to be run by the operator in a PowerShell window
  *outside* Claude Code's process tree.
- The captured `debug.log` becomes the input to the actual N-6
  diagnostic: cross-referencing RIP+offset against `objdump -d` of
  the resolved `msys-2.0.dll` to identify the failing function.
