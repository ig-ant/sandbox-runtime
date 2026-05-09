# Phase N-5 — Cygwin DllMain trace-coverage findings

**Branch**: `winsbox-msys2-iter`
**Approach**: instead of debugger attach (two agents failed), broaden trace-syscall coverage from 15 → 30 hooks and re-run bash.exe to capture AV correlation.

## Trace coverage delta

| Phase | Hooks | Source |
|---|---|---|
| Phase K | 12 | original FS/IOCTL/ALPC/registry/sync |
| Phase L cycle 3 | 15 | + NtMapViewOfSection, NtCreateSection, NtAllocateVirtualMemory |
| **Phase N-5** | **30** | + NtOpenSection, NtQueryInformationProcess, NtOpenProcessToken, NtOpenThreadToken, NtQueryInformationToken, NtQuerySystemInformation, NtReadVirtualMemory, NtClose, NtCreateNamedPipeFile_trace, NtFsControlFile, NtSetInformationFile, NtQueryDirectoryFile, NtCreateKey, NtCreateMailslotFile, NtUnmapViewOfSection |

`CDYLIB_VERSION` bumped 6 → 7. `passthrough_nt_create_file_denylog` field offset shifted from `0xC0` to `0x138` (computed at runtime from `TRACE_SYSCALL_COUNT`).

## Hook-collision handling

Two of the new trace slots collide with existing proxy/namespace hooks:

- Slot 15 `NtOpenSection` — owned by `install_reg`'s namespace hook (Cygwin BNO redirect).
- Slot 23 `NtCreateNamedPipeFile` — owned by `install_fs`'s pipe broker.

`launch.rs` zeroes those entries in the `hook_trace` array before calling `install_trace`, so the proxy hooks survive. Result: **28/30 hooks install** at runtime; `[sbox-exec] interception(trace,arm64): cdylib export missing for NtOpenSection; skip` and the same for NtCreateNamedPipeFile are expected log lines.

## Verification gates (all green)

| Gate | Result |
|---|---|
| `cargo build --release` | green |
| `cargo build --release -p ac-cdylib` (and debug) | green |
| `cargo test --lib` | 23/23 pass |
| `cargo run --example smoke_cdylib` | target exit=0x0 |
| `WINSBOX_TRACE_SYSCALLS=1 cargo run --example smoke_trace` | 149 trace lines (up from 47), test PASS |
| `cargo run --example smoke_broker_open` | PASS |
| `bun test test/sandbox/windows.test.ts` | 17p/5s/0f |

## Bash run

`WINSBOX_TRACE_SYSCALLS=1 cargo run --example smoke_bash` → `docs/n5_bash_trace.log`:

```
[sbox-exec] cdylib trace hooks patched pre-resume (28/30 of TRACE_SYSCALL_NAMES)
[sbox-exec] cdylib serve_ipc thread spawned (pre-resume)
[sbox-exec] entry_trampoline: rtlstart=0x7ffc0daec3a0 → stub @ 0x7ff5b7a40000
[sbox-exec] cdylib injection setup failed (entry rendezvous failed: target exited before signalling (exit=0xc0000005)); resuming target without cdylib
[sbox-exec] target exit=0xc0000005
```

**Total `[sbox-trace]` lines emitted: 0.**

Variants (also zero trace lines, identical AV):

- `docs/n5_bash_no_gc.log` (`WINSBOX_GC_INJECT=0`)
- `docs/n5_bash_no_broker_open.log` (`WINSBOX_BROKER_OPEN=0`)

## Hypothesis match

The original ladder (H1–H6) does not fit. New finding **H7: pre-syscall AV**.

The entry trampoline at `RtlUserThreadStart` never fires (target dies between `ResumeThread` and the first instruction of `RtlUserThreadStart`). All 28 installed hooks cover the loader's documented pre-DllMain path:

- DLL loads: `NtMapViewOfSection`, `NtCreateSection`, `NtOpenSection`
- Heap/stack: `NtAllocateVirtualMemory`
- Token introspection: `NtOpenProcessToken`, `NtQueryInformationToken`
- Process introspection: `NtQueryInformationProcess`
- Handle lifetime: `NtClose`
- File access: `NtCreateFile`, `NtOpenFile`, `NtFsControlFile`
- Sync primitives: `NtCreateEvent`, `NtOpenEvent`, `NtCreateMutant`, `NtOpenMutant`
- Cross-process reads: `NtReadVirtualMemory`

The fact that bash.exe AVs without invoking ANY of these means the failure path bypasses the standard ntdll syscall stubs. Three plausible mechanisms:

1. **Inlined syscall instructions in the loader's bootstrap.** Some Windows ARM64 builds inline `NtAllocateVirtualMemory` via direct `svc` instructions in `_LdrpInitializeProcess` for the very first heap setup. Our hook patches the syscall stub but not the inlined call sites.
2. **Cdylib base collision.** The cdylib is mapped at `0x190000000` (its preferred base). If Cygwin's runtime expects that VA range to be free for `cygheap` allocation, the load itself would AV during DllMain's `mmap_alloc` step. The collision would manifest before any syscall.
3. **AV inside a TLS callback or static init that touches PEB/TEB fields AC zeroes.** TLS callbacks run before DllMain proper; AC restricts certain TEB reads. cygwin1.dll has TLS callbacks (we saw the manual_map TLS warning historically for cdylib but cygwin1.dll's own TLS isn't observed by us).

The strongest signal for distinguishing these is the AV instruction address — which is exactly what the abandoned debugger-attach approach would yield.

## N-6 scope

| Option | Estimate | Trade-off |
|---|---|---|
| **(1) Debugger attach with thread-affinity fix** | 4-6 cycles | Highest signal. Two prior agents failed at this; the second identified the root cause (`WaitForDebugEvent` thread-affinity). A targeted retry with that fix is the next step. |
| **(2) No-AC fallback for Cygwin** | 8-12 cycles | Ships now, surrenders AC isolation for Cygwin tools. Job-object + restricted token only. |
| **(3) Manual cygwin1.dll DllMain reimpl** | 12-20 cycles | Fragile against Cygwin updates; requires reverse-engineering. Not recommended. |

**Recommended**: option 1. Falls back to option 2 if debugger attach can't be made to work after one more attempt.
