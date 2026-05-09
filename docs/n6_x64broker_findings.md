# N-6 — x64 broker on ARM64 host: bash diagnostic findings

**Branch**: `winsbox-msys2-iter`
**Date**: 2026-05-09
**Status**: Outcome 2 — bash AVs but trace fires extensively. **Phase L Wall 1 was H7-6** (cross-arch corruption) — settled.

## TL;DR

Cross-built `sbox-exec.exe` + `ac_cdylib.dll` for `x86_64-pc-windows-msvc`
landed cleanly on the ARM64 dev host. Running the x64 broker under
xtajit64 emulation against bash (also x64) gives broker-arch ==
target-arch, so manual-map + ntdll patching now operate within a
single architecture (xtajit64's view). Result: bash gets ~160 trace
lines into Cygwin DllMain before AV — vs. Phase L's **zero** trace
lines before AV.

This **conclusively confirms H7-6** from
`C:\Users\ig\.claude\plans\winsbox-cygwin-research.md`: the Phase L
"Wall 1" AV was caused by ARM64-broker-patching-x64-target writing
ARM64 ABS_JMP bytes into the wrong code pages of the x86_64 target's
ntdll. Cygwin's DllMain itself works under USER_LIMITED+AC; what
killed it before was *us*, not Cygwin.

The x64 broker run still ends in `0xC0000005`, but at a different
phase of Cygwin init — likely during `memory_init()` shared-region
mapping, well after DllMain entry. That's a separate, smaller
problem.

## Build verification

- `cargo build --release --target x86_64-pc-windows-msvc -p sbox-exec`
  → **clean**, 991 KB exe, `PE32+ x86-64`.
- `cargo build --release --target x86_64-pc-windows-msvc -p ac-cdylib`
  → **clean**, 22 KB DLL, `PE32+ x86-64`.
- ARM64 default build (`cargo build --release`) still works.
- `cargo test --lib` → 23/23.
- ARM64 `smoke_cdylib` → `target exit=0x0`.
- `bun test test/sandbox/windows.test.ts` → 17p / 5s / 0f preserved.

No code changes were needed for the cross-build to succeed. The
existing `#[cfg(target_arch = "x86_64")]` and
`#[cfg(target_arch = "aarch64")]` gates already select
`interception_x64.rs` / `entry_trampoline_x64.rs` correctly when
building for the x64 target.

## Run setup

```
WINSBOX_SBOX='Y:\vendor\winsbox\x64\sbox-exec.exe' \
WINSBOX_CDYLIB='Y:\vendor\winsbox\x64\ac_cdylib.dll' \
WINSBOX_TRACE_SYSCALLS=1 \
  smoke_bash.exe \
  > docs/n6_x64broker_bash_trace.log 2>&1
```

The smoke_bash example itself remains an ARM64 build — it's just a
launcher that spawns the broker via `WINSBOX_SBOX`. The broker
exec'd under xtajit64 emulation on this ARM64 host; from the x64
broker's view (and from the spawned x64 bash target's view), every
process involved is x64-on-x64.

## Trace evidence — Outcome 2

`docs/n6_x64broker_bash_trace.log` (236 lines total):

- **Lines 31–69**: cdylib reports back successfully
  (`init=0xACDC0001 (manual-map)`); 30 ntdll syscalls hooked at the
  x64 ntdll VAs (`0x7ffc0dbb*`) — these are now the **target's**
  ntdll VAs since broker == target arch.
- **Lines 71–229**: 160+ `[sbox-trace]` lines covering loader
  activity:
  - Initial CSRSS connect (NtCreateFile `\Connect`,
    NtDeviceIoControlFile ioctl 0x500023 / 0x500016).
  - Several denied `NtOpenThreadToken access=0x4 as_self=1`
    (returning `STATUS_ACCESS_DENIED 0xc0000022`) — token lookups
    AC denies, non-fatal.
  - AppCompat probing (`SdbUpdates` keys, `01DCDEACA1EDEDFD.sysmain.sdb`).
  - bash.exe re-opened, msys-2.0.dll loaded.
  - **Cygwin DllMain runs**: ucrtbase, msvcp_win, gdi32full, GDI32,
    USER32, msvcrt, sechost, RPCRT4, advapi32 all map cleanly.
  - Nls sorting key, CRYPTBASE.DLL, KsecDD device, bcryptPrimitives
    all reached.
  - LSA registry: `OpenKey "...Control\Lsa"` → 0; `QueryValueKey
    "LsaPid"` → 0 (success!).
  - 9× `NtCreateEvent` (Cygwin's `muto::init` and friends).
  - 2× `NtCreateSection access=0xf0007 attr=0x8000000 (SEC_COMMIT)`
    + `NtMapViewOfSection prot=0x4 (PAGE_READWRITE)` pairs.
- **Line 230**: `cdylib injection setup failed (entry rendezvous
  failed: target exited before signalling (exit=0xc0000005))`. The
  target died sometime after the second NtMapViewOfSection
  succeeded. The broker waits for the entry-trampoline rendezvous
  (set when the target reaches `RtlUserThreadStart` post-loader);
  the target died before reaching that, i.e. still inside the
  loader-driven DllMain chain.
- **Line 231**: `target exit=0xc0000005`.

The pattern of two `NtCreateSection` + `NtMapViewOfSection` pairs
right before the AV strongly suggests the crash site is
`memory_init()` in `mm/shared.cc:322-332` — Cygwin maps its
`cygwin_shared` and `user_shared` sections at the fixed VAs in the
`SHARED_REGIONS` range `0x1a0000000..0x200000000`. **Our cdylib is
mapped at `0x190000000`** — adjacent to but not overlapping that
range. If Cygwin's shared region request was for the address right
above us, and the kernel rounded somehow, there could still be a
collision. But the `MapViewOfSection` calls *succeeded* (returned
`0x00000000`), so the actual crash is downstream of those — perhaps
in subsequent code that dereferences the shared-region pointer at
its expected fixed offset.

Alternatively: the x64 cdylib at `0x190000000` may itself overlap
with msys-2.0.dll's preferred base `CYGWIN_DLL_ADDRESS = 0x180040000`
(unlikely — msys-2.0.dll is much smaller than `0x10000000`), or
with one of the MapViewOfSection mappings logged as `prot=0x80`
(PAGE_EXECUTE_WRITECOPY) earlier in the trace — those are image
mappings for system DLLs and our base `0x190000000` falls in the
"high" image region. **Need to log the requested base + length in
NtMapViewOfSection** to confirm.

## What to do next (not in scope for this commit)

1. **Extend trace** to log `BaseAddress`, `ViewSize`, and `Status`
   on NtMapViewOfSection so we can correlate the
   `0x1a0000000..0x200000000` Cygwin shared-region requests
   precisely.
2. **Move the cdylib base** to a region that doesn't conflict with
   Cygwin's fixed-VA layout. Per
   `winsup/cygwin/local_includes/memory_layout.h`, safe windows
   are: under `0x100000000` (the 32-bit half — risk: collides with
   loader-default DLLs), or above `0xa00000000` (above Cygwin's
   user heap). `0x800000000` is `CYGHEAP_STORAGE_LOW`, occupied.
   The mmap arena starts at `0x001000000000` (24 TB) — high enough
   to be safe. Re-cooking the cdylib with `/BASE:0x1000000000` is
   the obvious experiment.
3. **N-7 plan**: ship per-arch brokers. The cross-build is
   verified working (this commit). CI workflow update extends each
   Windows runner to cross-build the *other* arch too, producing
   `vendor/winsbox/{arm64,x64}/{sbox-exec.exe,ac_cdylib.dll}` for
   shipping. TS layer adds a target-arch detection pass
   (parse target binary's PE machine field, pick the matching
   broker).

## Files

- `vendor/winsbox/x64/sbox-exec.exe` — staged, **not** committed.
- `vendor/winsbox/x64/ac_cdylib.dll` — staged, **not** committed.
- `docs/n6_x64broker_bash_trace.log` — committed (raw trace).
- `docs/n6_x64broker_findings.md` — this doc.

## Verdict on Phase L walls

- **Wall 1 (Cygwin DllMain bare-AC)**: not actually a wall.
  H7-6 (broker/target arch mismatch) was the cause. With arch
  parity, Cygwin DllMain runs through the loader chain, msys-2.0.dll
  loads, registry/LSA reachable, NtCreateEvent + NtCreateSection
  all succeed. The Phase L conclusion that "cygwin1.dll's bare-AC
  DllMain crash is unfixable without dropping AC" was **wrong** —
  it was a misattribution caused by the cross-arch corruption.
- **Wall 2 (ARM64 cdylib into x64 target)**: confirmed real, but
  cross-arch by definition. The fix is per-arch brokers (this
  commit's foundation), not a cdylib re-engineering.

The remaining bash AV is a smaller problem — likely a
fixed-VA memory-layout issue between our cdylib base and Cygwin's
expected layout — addressable by relocating our cdylib's base or
parsing the target's PE machine field at broker startup to allow
late base selection.
