# N-6 step 2 — H7-2 (cdylib base VA collision) test results

**Branch**: `winsbox-msys2-iter`
**Date**: 2026-05-09
**Status**: **Outcome 3** — H7-2 was **wrong**. Relocating the cdylib
base does **not** affect bash's AV behavior. Reverted the relocation.

## Hypothesis

The N-6 step 1 trace showed bash AV'ing inside Cygwin DllMain after
two `NtCreateSection`+`NtMapViewOfSection` pairs. Per
`winsup/cygwin/local_includes/memory_layout.h`, Cygwin's
`memory_init()` maps shared regions at fixed VAs in
`SHARED_REGIONS_ADDRESS_LOW=0x1a0000000..SHARED_REGIONS_ADDRESS_HIGH=0x200000000`.
Our cdylib was preferred-based at `0x190000000` (16 MiB image), which
sits adjacent to but not inside that range.

H7-2: the proximity of the cdylib at `0x190000000` to Cygwin's
`SHARED_REGIONS` causes a collision (or expectation violation), and
moving the cdylib base well clear of Cygwin's reserved layout will
let bash continue past the AV point.

## Test

Relocated `crates/ac-cdylib/build.rs` from `/BASE:0x190000000` to
`/BASE:0x400000000` (4 GiB). Rebuilt both ARM64 and
`x86_64-pc-windows-msvc` cdylibs and brokers. Re-staged into
`vendor/winsbox/{arm64,x64}/`.

PE header verification confirmed both cdylibs had `ImageBase=0x400000000`.

## Verification gates (all pre-bash)

| Gate                                | Result   |
|-------------------------------------|----------|
| ARM64 sbox-exec build               | clean    |
| ARM64 ac-cdylib build               | clean    |
| x64 sbox-exec cross-build           | clean    |
| x64 ac-cdylib cross-build           | clean    |
| `cargo test --lib`                  | 23 / 23  |
| ARM64 `smoke_cdylib` (target exit)  | `0x0`    |
| ARM64 `smoke_trace` (trace lines)   | 149      |
| ARM64 `smoke_broker_open`           | soft-pass (unchanged) |
| `bun test test/sandbox/windows.test.ts` | 17p / 5s / 0f |

The `smoke_cdylib` log confirmed at-runtime: `cdylib mapped at
0x400000000 (0x9000 bytes), IPC @ 0x400006090, delta=0x0`. All
hook VAs landed in the new range, target exit clean. So the
relocation itself worked end-to-end for the native PE workload.

## Bash result

Run setup (mirroring N-6 step 1):
```
WINSBOX_TRACE_SYSCALLS=1
WINSBOX_SBOX=Y:\vendor\winsbox\x64\sbox-exec.exe
WINSBOX_CDYLIB=Y:\vendor\winsbox\x64\ac_cdylib.dll
cargo run --release --example smoke_bash --manifest-path vendor/winsbox-src/Cargo.toml
> docs/n6_relocated_bash_trace.log
```

Trace at `0x400000000`:
- 159 `[sbox-trace]` lines (vs N-6 step 1: 159).
- Final two syscalls: `NtCreateSection` + `NtMapViewOfSection`
  (twice), all returning `0x00000000` (success).
- Same `cdylib injection setup failed (entry rendezvous failed:
  target exited before signalling (exit=0xc0000005))`.
- Final `target exit=0xc0000005`.

Diff vs N-6 step 1 trace (handle-normalised): **only one line
differs** — an unrelated `NtUnmapViewOfSection` address that moved
~50 MiB in the system DLL load arena (line 86 in both runs;
`0x7ff35f880000` vs `0x7ff38d400000`). Every other syscall, return
status, and crash signature is byte-identical.

## Conclusion: H7-2 is wrong

Moving the cdylib base from `0x190000000` (just below Cygwin's
SHARED_REGIONS) to `0x400000000` (well clear, between SHARED_REGIONS
and cygheap) had **zero effect** on the AV. Same syscall trace, same
crash point, same exit code.

This rules out cdylib base proximity to `SHARED_REGIONS` as the
cause. The crash must be downstream of the second
`NtMapViewOfSection` and is something Cygwin does *internally*
without going through a hookable syscall (kernel-mode work, in-image
RW page accesses, RPC over an already-open ALPC handle, etc.).

## Followup: relocation reverted

Two reasons to revert:

1. **It doesn't help.** No measurable improvement.
2. **`0x400000000` lands inside Cygwin's `AUTOBASED_DLL_STORAGE`**
   range (`0x400000000..0x600000000` per `memory_layout.h`). This
   is where Cygwin's linker auto-bases rebased DLLs at runtime —
   so even if we wanted a fix-VA slot in this region, it would
   collide with Cygwin's loader on a different bash invocation that
   happens to drag in a rebased DLL.

The original `0x190000000` slot is, per Cygwin's layout map,
actually a *safer* pick than `0x400000000`: it falls in the gap
between `CYGWIN_DLL_ADDRESS+size=0x180040000+~10MiB` and
`SHARED_REGIONS_ADDRESS_LOW=0x1a0000000`, with no Cygwin-reserved
neighbours.

Per `memory_layout.h`, the only fully-Cygwin-safe slot for an
arbitrary-base 16 MiB DLL is at or above `0x10_00000000` (64 GiB —
above MMAP_STORAGE_LOW). Even this would only matter if/when
H7-2 were re-tested with that VA, which based on the
identical-trace evidence here is unlikely to make a difference.

## Files

- `vendor/winsbox-src/crates/ac-cdylib/build.rs` — **reverted**, base
  remains `0x190000000`.
- `vendor/winsbox-src/crates/ac-cdylib/Cargo.toml` — **reverted**.
- `vendor/winsbox-src/src/launch.rs` — **reverted** (doc comments
  only).
- `vendor/winsbox/{arm64,x64}/{sbox-exec.exe,ac_cdylib.dll}` —
  re-staged to match reverted source (`ImageBase=0x190000000`).
  Not committed (gitignored).
- `docs/n6_relocated_bash_trace.log` — committed; raw trace from the
  `0x400000000` test run.
- `docs/n6_relocated_bash_findings.md` — this file.

## What this leaves for next iteration

The bash AV is **not** a base-VA collision. Hypotheses to try next:

1. **Trace coverage gap.** Extend trace to cover more of Cygwin's
   loader-time syscall mix — particularly anything between the
   second `NtMapViewOfSection` and the AV. Candidates:
   `NtSetInformationProcess`, `NtSetInformationThread`,
   `NtAllocateVirtualMemory` (with base/size logged),
   `NtProtectVirtualMemory`, ALPC syscalls
   (`NtAlpcSendWaitReceivePort`).
2. **Attach a debugger.** Run bash under WinDbg with breakpoints on
   the broker exit + symbol load for cygwin1.dll/msys-2.0.dll, and
   inspect the AV exception record + stack at fault time. The two
   `NtCreateSection`+`NtMapViewOfSection` calls happen with empty
   names (anonymous shared sections — likely Cygwin's
   `cygwin_shared` and `user_shared`); the next code Cygwin runs
   after those is the actual crash site.
3. **Fork emulation.** Cygwin's `fork()` is well known to be
   fragile in restricted environments. Even though we're only
   running `echo hello`, Cygwin's DllMain may probe the fork
   infrastructure (parent-pid lookup, suspended-thread enumeration,
   etc.).
4. **AC-incompatible RPC.** The trace shows `OpenKey(...Lsa) ->
   0` succeeding pre-AV. If Cygwin then does an RPC to LSA over an
   open ALPC port, the call may hit
   `STATUS_ACCESS_DENIED`-after-auth-check inside LSA, returning a
   sentinel that Cygwin dereferences blindly.
