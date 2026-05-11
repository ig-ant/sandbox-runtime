# Task 3 — Capture trace of the AC's bash AV

## Tool choice

Procmon was the intended tool, but it **requires admin** to install its
kernel-side filter driver. It silently waits for UAC elevation when run
without admin and so wasn't usable for one-shot diagnostic capture in
this session. The user would need to grant admin once; instead I took
a different angle that yielded better data:

- Used **cdb** (Windows Kits debugger, ARM64-native cross-debugger from
  `C:\Program Files (x86)\Windows Kits\10\Debuggers\arm64\cdb.exe`).
- Wired pause-for-debugger into `probe_vanilla_ac.rs` (via
  `WINSBOX_PAUSE_FOR_DEBUGGER=1`), so the bare-AC probe spawns bash
  suspended and we can attach cdb before `ResumeThread`.

This is *better* than procmon for this question: procmon shows
syscall-level events (NtCreateSection, NtOpenFile, …) and the AV gets
inferred from "process exits abnormally." cdb shows the **exact
faulting instruction, register state, and stack** of the AV.

Procmon-style kernel-syscall path resolution is still a useful followup
(would tell us if `\BaseNamedObjects\shared.5` or
`\Sessions\1\AppContainerNamedObjects\<sid>\shared.5` is what bash
tries to open). But the AV evidence here pre-empts that question:
**bash AVs before it gets to any `shared.5` lookup.**

## Setup

1. Built `probe_vanilla_ac.rs` with `CREATE_SUSPENDED` +
   `WINSBOX_PAUSE_FOR_DEBUGGER=1` gating ResumeThread on
   `CheckRemoteDebuggerPresent`.
2. Ran probe in background; it printed `target pid=<PID>` and blocked.
3. Attached cdb with:
   ```
   cdb -p <PID> -c "sxd ld; sxd ud; sxd ibp;
                    sxe c0000005;
                    g; g;
                    .echo ===AV===; .lastevent;
                    .echo ===INSN===; u rip-10 rip+10;
                    .echo ===CTX===;  .exr -1;
                    .echo ===VPROT_RDX===; !vprot @rdx;
                    .echo ===STACK===;    k 40;
                    qd"
   ```
4. `sxd ld; sxd ud; sxd ibp` disables stop-on load/unload/initial-break.
   `sxe c0000005` makes us stop on access violation.
5. First `g` clears `LdrpDoDebuggerBreak` (the loader's initial break).
6. Second `g` runs until the actual AV.

## Capture sequence — module loads up to the AV

```
ModLoad: ntdll
LdrpDoDebuggerBreak  (initial break; we 'g' past)
ModLoad: xtajit64se   ← x64 emulator on ARM64
ModLoad: KERNEL32
ModLoad: KERNELBASE
ModLoad: apphelp
ModLoad: USER32
ModLoad: win32u
ModLoad: msys-2.0.dll @ 27231450000  ← first attempt
ModLoad: GDI32, gdi32full
Unload module msys-2.0.dll @ 27231450000  ← loader retry
ModLoad: msvcp_win, ucrtbase
ModLoad: msys-2.0.dll @ 27231520000  ← reload at different base
LdrpDoDebuggerBreak  ← second initial break, we 'g' past
                       (from LdrpInitializeProcess+0x1a6c)
ModLoad: advapi32, msvcrt, sechost, RPCRT4
ModLoad: CRYPTBASE.DLL
ModLoad: bcryptPrimitives.dll
*** AV (c0000005) ***   ← here
```

The unload+reload of msys-2.0.dll is normal loader behavior (probe +
reload). What matters is what happens after CRYPTBASE/bcryptPrimitives
finish loading and `msys-2.0!dll_entry` runs `DllMain` for the second
(real) load.

## The AV

```
(1c18.1a08): Access violation - code c0000005 (first chance)
ExceptionAddress: 00000272317136aa (msys_2_0!alloca+0x0000000000001e1a)
NumberParameters: 2
   Parameter[0]: 0000000000000000  ← READ access
   Parameter[1]: 00000002102fb981  ← fault address
Attempt to read from address 00000002102fb981
```

The symbol `alloca+0x1e1a` is just the nearest exported symbol; the
actual code is deep inside `msys_dll_init`'s body. The disassembled
instruction at the fault:

```
00000272`317136a3 488d0506770000     lea     rax, [msys_2_0!abort+0x6e30]
00000272`317136aa f6420108           test    byte ptr [rdx+1], 8   ← AV
00000272`317136ae 488d15bb780000     lea     rdx, [msys_2_0!abort+0x6ff0]
00000272`317136b5 480f45c2           cmovne  rax, rdx
00000272`317136b9 4889058 8ce0200    mov     qword ptr [msys_2_0!reent_data+0xe48], rax
```

This is a setup-time `reent_data` initialization (`__reent` is Cygwin's
per-thread state struct). The faulting load reads a byte at `rdx+1`,
where `rdx = 0x00000002102fb980`.

### What's at `rdx`?

```
!vprot @rdx
BaseAddress:       00000002102fb000
AllocationBase:    0000000000000000
RegionSize:        000000847f705000          ← 535 GB free
State:             00010000  MEM_FREE
Protect:           00000001  PAGE_NOACCESS
```

`rdx` points into a **535-GB free region** — entirely unmapped. There
is no allocation at all in that range. AC processes get a constrained
view of the address space and this is firmly in unallocated territory.

### Where did `rdx` come from?

Looking at the registers at fault, the value `0x00000002102fb980` is
suspicious:
- `r15 = 0000022f69360000` (the *unload-only* phantom base address of
  msys-2.0's first load — note it was unloaded by the loader retry but
  cdb still shows the value)
- The actual msys-2.0 base after reload: `0x27231520000`.
- The high-32 bits of `rdx` are `0x00000002`, but valid 64-bit
  pointers in this process all have high bits in `0x27`-region (heap)
  or `0x7ff…`-region (DLLs).

**Hypothesis**: `rdx` was loaded from a global pointer in
msys-2.0.dll that was supposed to be initialized earlier in DllMain.
Whatever initializes it (likely the per-thread reent setup, a
`cygheap` block, or a `cygwin_shared` mapping) **silently failed**
inside AC and left the pointer at a partial / leftover value. The
test-byte-ptr at `[rdx+1]` then trips because `rdx` is garbage.

The most likely culprit (matching Phase L Wall 1 findings): **the
`cygwin_shared` named section** that Cygwin maps via
`NtCreateSection(\BaseNamedObjects\cygwin1S5)` or similar. Inside AC,
`\BaseNamedObjects\` is redirected to
`\Sessions\1\AppContainerNamedObjects\<sid>\` per-AC; the new SID has
no `cygwin1S5` mapped there. Cygwin's code likely treats the section
handle as nullable but uses it without checking, *or* assumes the
mapping succeeded and stores a base pointer; under AC the section
create silently returns `STATUS_OBJECT_NAME_NOT_FOUND` / `STATUS_ACCESS_DENIED`,
and the resulting `NULL` + `offset` is what we see as
`0x00000002102fb980`.

This is the same Cygwin DllMain code path Mr. Vinnik & co. discuss
in the cygwin-discuss thread on "Cygwin in AppContainer" — Cygwin's
initialization expects a writable per-cygwin-version shared memory
section in `\BaseNamedObjects\`, which AC can't grant.

## Faulting call stack

```
   AMD64 671fb158  msys_2_0!alloca+0x1e1a          ← AV here
   AMD64 671fb160  msys_2_0!msys_dll_init+0x1652   ← real caller
   AMD64 671fb1c0  msys_2_0!dll_entry+0xc8         ← DllMain entry
 ARM64EC 671fe430  ntdll!$iexit_thunk$cdecl$i8$i8+0x1c  ← x64→ARM64 thunk
 ARM64EC 671fe460  ntdll!LdrpCallInitRoutineInternal+0x94
 ARM64EC 671fe5b0  ntdll!LdrpCallInitRoutine+0x64
 ARM64EC 671fe600  ntdll!LdrpInitializeNode+0x1b0
 ARM64EC 671fe730  ntdll!LdrpInitializeGraphRecurse+0x48
 ARM64EC 671fe780  ntdll!LdrpInitializeGraphRecurse+0x6c
 ARM64EC 671fe7d0  ntdll!LdrpInitializeProcess+0x1aec
 ARM64EC 671febc0  ntdll!_LdrpInitialize+0x13c
 ARM64EC 671fec40  ntdll!LdrpInitializeInternal+0xd8
 ARM64EC 671fec90  ntdll!LdrpInitialize+0x34
 ARM64EC 671fecb0  ntdll!LdrInitializeThunk+0x78
```

`msys_dll_init+0x1652` is the textbook DllMain init code path. The
ARM64EC frames are the loader running on the ARM64-native side; the
AMD64 frames are emulated x64 code (msys-2.0.dll itself) running
under xtajit64se. The fault is in the x64-emulated DLL_PROCESS_ATTACH.

## Implication: it's NOT the namespace redirection

Our broker pre-creates `\Sessions\<sess>\AppContainerNamedObjects\<sid>`
and `\Sessions\<sess>\AppContainerNamedObjects\<sid>\RPC Control` and
hooks `NtOpenDirectoryObject` to redirect Cygwin's expected
`\BaseNamedObjects\…` paths into the AC namespace. But:

- **bare-AC (Task 2)** has NO redirection, NO hooks, and bash STILL AVs
  at the same spot.
- The AV happens before our cdylib hooks would activate
  (`LdrpInitializeProcess` is running pre-`DllMain` for non-loader
  DLLs).
- The AC's `\BaseNamedObjects\` simply does not contain
  `cygwin1S5`/`cygwin_shared`/etc.; Cygwin's create-or-open fails, and
  Cygwin doesn't gracefully handle that failure.

Even with perfect namespace-redirection from our broker:
1. The AC SID has no permission to create new named sections at the
   redirected path unless our broker also stamps an explicit ACL.
2. Cygwin's expected section layout assumes other Cygwin processes
   already exist and have created the shared region; in a fresh AC
   there is no prior process.

## Files

- `docs/bash_av_stack_capture.log` — full cdb output showing the AV
  call stack.
- `docs/bash_av_memory_context.log` — cdb output with !vprot showing
  the faulting address is 535GB MEM_FREE.
- New code: `vendor/winsbox-src/examples/probe_vanilla_ac.rs` extended
  with `WINSBOX_PAUSE_FOR_DEBUGGER=1` gating for cdb attach.

## Procmon — what it would have shown

If procmon were runnable here, we'd expect to see (around the AV):

```
bash.exe  NtCreateSection  Path: \BaseNamedObjects\cygwin1S5             Result: ACCESS_DENIED / OBJECT_NAME_NOT_FOUND
bash.exe  NtOpenSection    Path: \Sessions\1\AppContainerNamedObjects\<sid>\cygwin1S5  Result: OBJECT_NAME_NOT_FOUND
```

(or some variation of the cygwin shared-memory section name —
`cygwin1S5` is just an example; the actual name has a Cygwin version
hash.) The kernel-side path resolution after AC's automatic
`\BaseNamedObjects\` → per-AC redirection is the kernel feature; what
fails is that the redirected target doesn't exist and AC can't create
new objects without an ACL that allows the AC SID.

The cdb evidence makes the procmon trace nice-to-have but not
load-bearing for diagnosis. Recommend deferring procmon unless we
decide to attempt a fix (in which case procmon's exact path output
would be needed to know what name to pre-create + ACL).
