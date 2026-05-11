# Bash AV root cause — `cygwin_shared` NULL deref in `vapi_fatal` chain

**Branch**: `winsbox-msys2-iter`
**Date**: 2026-05-10
**Status**: **Root cause identified.** The AV is a recursive crash in
Cygwin's fatal-error handler, triggered when the *real* failure is
`CreateFileMappingW` returning NULL inside `shared_info::create()`.
**Recommended action**: investigate why `CreateFileMappingW` fails
under our sandbox (most likely AC + named-object-namespace ACL),
not the AV itself. The AV is a downstream secondary crash inside
upstream Cygwin's recursive fatal-error path — patching it would
just expose the underlying CreateFileMapping failure as a clean
`api_fatal` print before the process exits.

## Summary table

| Field                                | Value |
|--------------------------------------|-------|
| Faulting RIP                         | `0x1b04613ece1` (module-offset `0x2ece1`) |
| Faulting instruction                 | `mov r9d, dword ptr [rax + 0xE7B4]` |
| RAX                                  | `0` (NULL) |
| Function                             | `dll_list::cleanup_forkables()` |
| Source                               | `winsup/cygwin/forkable.cc:861` |
| Inlined call site                    | `dll_list::forkables_supported()` (`dll_init.h:84-87`) |
| Dereferenced global                  | `cygwin_shared` (`shared_info *`) at `.data` RVA `0x283d90` |
| Field at offset `0xE7B4`             | `shared_info::forkable_hardlink_support` (`LONG`, last field; `0x0=Unknown`, `1=Yes`, `-1=No`) |
| `sizeof (shared_info)`               | `0xE7B8` (matches `r9d=0xE7B8` literal at `shared_info::create` call site) |
| Trigger                              | `CreateFileMappingW` returning NULL inside `open_shared(L"shared", 5, ...)` from `shared_info::create()` |

## 1 — Identified function at module-offset `0x2ece1`

llvm-objdump'd `msys-2.0.dll` (image base `0x210040000`, function VMA
`0x21006ecd0`):

```
21006ecd0:  push  r14
21006ecd2:  push  rbp
21006ecd3:  push  rdi
21006ecd4:  push  rsi
21006ecd5:  push  rbx
21006ecd6:  sub   rsp, 0x20
21006ecda:  mov   rax, qword ptr [rip + 0x2550af]   # 0x2102c3d90 = &cygwin_shared
21006ece1:  mov   r9d, dword ptr [rax + 0xE7B4]     # FAULT — rax = NULL
21006ece8:  mov   rdi, rcx
21006eceb:  test  r9d, r9d
21006ecee:  js    0x21006ed91                       # if (... < 0) return;  ← `>= 0` test
```

cdb attributes this as `_feinitialise+0x8371` because `_feinitialise`
is the nearest exported symbol; the actual function is private.
Identification by source-pattern match:

- The function loads `cygwin_shared` (verified by tracing where the
  global is *written*: `shared_info::create()` at module-offset
  `0x15755b` — `mov [rip+...], rax` immediately after `call open_shared`,
  with the size-arg literal `r9d, 0xe7b8` matching `sizeof (shared_info)`).
- The `>= 0` test maps directly to:

  ```cpp
  bool dll_list::forkables_supported ()  // dll_init.h:84
  { return cygwin_shared->forkable_hardlink_support >= 0; }
  ```

  which is inlined into `dll_list::cleanup_forkables()` (`forkable.cc:861`):

  ```cpp
  void dll_list::cleanup_forkables () {
    if (!forkables_supported ())
      return;
    ...
  }
  ```

The five-pushed-register prologue + 0x20 stack frame matches the
`cleanup_forkables` IR shape (one bool branch into a path-name copy
that uses `wcpncpy`, exactly what `cleanup_forkables` does after the
guard).

## 2 — Identified struct field at offset `0xE7B4`

`shared_info` from `winsup/cygwin/local_includes/shared_info.h:43-61`:

```cpp
class shared_info {
  LONG version;                   //   +0x00, 4
  DWORD cb;                       //   +0x04, 4
public:
  tty_list tty;                   //   +0x08, large (NTTY=128 entries)
  HWND cons_hwnd[MAX_CONS_DEV];
  LONG last_used_bindresvport;
  DWORD obcaseinsensitive;
  mtinfo mt;
  loadavginfo loadavg;
  LONG pid_src;
  LONG forkable_hardlink_support; //   +0xE7B4, 4 (LAST field)
  ...
};
// sizeof (*this) == 0xE7B8 — matches the size argument `r9d, 0xE7B8`
// at the `shared_info::create()` call site (module-offset 0x15751b).
```

The faulting read is `cygwin_shared->forkable_hardlink_support`. The
JS (jump-if-signed) on the loaded value is the `>= 0` half of
`forkable_hardlink_support >= 0` (returns true for `0=Unknown` and
`1=Yes`, false only for `-1=No`).

## 3 — Why RAX is NULL: it's a recursive crash inside `vapi_fatal`

The cdb stack — frame attributions corrected from cdb's nearest-export
guesses:

| # | cdb attribution | Real function | Source |
|---|---|---|---|
| 0 | `feinitialise+0x8371` | `dll_list::cleanup_forkables` | `forkable.cc:861` |
| 1 | `dirname+0x78b` | `pinfo::exit` | `pinfo.cc:205` |
| 2 | `_main+0x4e9` | `vapi_fatal` (return from `myself.exit`) | `dcrt0.cc:1267` |
| 3 | `_main+0x512` | `api_fatal` (return from `vapi_fatal`) | `dcrt0.cc:1281` |
| 4 | `truncl+0xcb9c` | `open_shared` (return from `api_fatal`) | `shared.cc:154` |
| 5 | `truncl+0xd578` | `shared_info::create` (return from `open_shared`) | `shared.cc:280` |
| 6 | `msys_dll_init+0x17f2` | `dll_crt0_0`/`memory_init` chain (return from `shared_info::create`) | `dcrt0.cc:754`, `shared.cc:323-325` |
| 7 | `dll_entry+0xc8` | `dll_entry` (return from `dll_crt0_0`) | `init.cc:81` |
| 8+ | ntdll loader | LdrpCallInitRoutine etc. | n/a |

**The full call chain**:

```
LdrpCallInitRoutine → dll_entry(DLL_PROCESS_ATTACH)
  → dll_crt0_0()                                  // dcrt0.cc:725
    → setup_cygheap()      // succeeds, cygheap = &cygheap_dummy → real
    → memory_init()                               // dcrt0.cc:754
      → shared_info::create()                     // shared.cc:278
        → open_shared(L"shared", 5, &cygwin_shared_h, sizeof(shared_info)=0xE7B8, ...)
          → shared_h = CreateFileMappingW(...)    // ★ RETURNS NULL
          → api_fatal("CreateFileMapping %W, %E. Terminating.", mapname)
            → vapi_fatal(...)                     // dcrt0.cc:1267
              → strace.prntf(...)                 // emits "cYg..." debug line
              → myself.exit(__api_fatal_exit_val) // pinfo::exit, pinfo.cc:205
                → dlls.cleanup_forkables()        // pinfo.cc:235
                  → forkables_supported()         // INLINED, dll_init.h:84
                    → return cygwin_shared->forkable_hardlink_support >= 0;
                      ★★★ cygwin_shared is still NULL ★★★
                      ★★★ AV reading 0+0xE7B4 = 0xE7B4 ★★★
```

The NULL is **not** an emulator bug or a TEB-layout drift. `cygwin_shared`
is genuinely uninitialised at the moment of the faulting read because
its assignment (`cygwin_shared = (shared_info *) open_shared(...)`,
`shared.cc:280`) executes only after `open_shared` returns — which it
never does, because `open_shared` ran into `api_fatal` which is
declared `noreturn` and never unwinds.

This is a **recursive crash in upstream Cygwin's fatal-error path**:
`vapi_fatal` is reached only when something already failed; the path it
takes (`myself.exit → cleanup_forkables → forkables_supported`)
unconditionally dereferences `cygwin_shared`, which can be NULL exactly
when the original failure was inside `shared_info::create()`. There is
no upstream patch — the bug is latent because on real x64 with normal
permissions, `CreateFileMappingW` of an anonymous backed mapping with
a session-relative name never fails.

cdb's "First chance / second chance" pair plus the truncated
`cYgFFFFFFFF 1B0463934A0 0…ModLoad: …advapi32.dll` line is the strace
of the original `*** fatal error CreateFileMapping <name>, <error>.
Terminating.` getting clipped by intervening loader chatter (advapi32
is loaded lazily by `try_to_debug` / `api_fatal_debug`'s
`OutputDebugStringA`).

### Why on real x64 CI but not ARM64-via-xtajit64se

On x64 CI:
- Bash is launched as a **grandchild** via `cmd /c bash -c "echo hello"`.
  cmd.exe is the immediate AC target; bash inherits cmd's tokenised AC
  and (critically) any per-AC named-object subdirectory that cmd's
  startup primed.
- `bash_trace_x64_ci.txt` shows full passing run: cmd brokers the
  bash spawn via `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`, child gets
  the *same* named-object namespace, and bash's
  `CreateFileMappingW(L"shared.5")` resolves under
  `\Sessions\<n>\AppContainerNamedObjects\<sid>\` and succeeds.

On ARM64-via-xtajit64se in this repro:
- Bash is launched **directly as the AC target** (no cmd wrapper) per
  `n7p_bash_arm64_per_arch.log`. The session/per-AC named-object
  directory hierarchy isn't primed by an earlier process.
- Either the AC SID's own named-object directory hasn't been created,
  or AC's restrictions on `\Sessions\<n>\AppContainerNamedObjects\…`
  block `CreateFileMappingW` for a SEC_COMMIT mapping at this stage.
  Returning NULL → the recursive crash above.

The **architecture is incidental** — same bash binary AVs the same way
when launched directly under AC on x64 (per token.rs:33-43 comment
documenting the historical IL_LOW vs IL_UNTRUSTED differential, where
"NtCreateSection on anonymous shared regions for `cygwin_shared`/
`user_shared`" is named explicitly as the hit). What's different is:

- (a) **Launch shape** (cmd-wrapped vs direct), which controls who
  primes the AC named-object namespace.
- (b) **Token IL** (IL_LOW currently, was IL_UNTRUSTED for parts of
  Phases E/F — the same reachable-AV the comment in `token.rs` flags).

xtajit64se itself is an emulator on the syscall-syscall side; it does
not interpose on `CreateFileMappingW`'s access check, which runs in
ntoskrnl on the host CPU regardless of guest ISA.

## 4 — Recommended fix

**This is not a small fix.** The AV itself is upstream-Cygwin behaviour
recovering from an earlier failure, so the right intervention point is
**why does `CreateFileMappingW` fail in our sandbox** — not the AV.

Three orderings, by intrusiveness:

### 4.1 — Make the launch shape match x64 CI (cheapest)

Force bash launches through `cmd /c <bash> …` on every host (already
the x64 CI shape; just remove the `directTargetExe` codepath for bash
or wrap it). This is the lowest-risk: if it's only the cmd-wrapper
priming the AC named-object namespace, this restores the working
configuration without touching tokens or hooks. The ARM64 gate stays
because of unrelated cdylib cross-arch issues, but if/when that's
resolved, the bash test would then exercise the same shape that
already passes on x64.

### 4.2 — Broker the `\AppContainerNamedObjects\<sid>\…` priming

Have the broker pre-create the per-AC named-objects subdirectory
before spawning a Cygwin/MSYS2 binary. This is what cmd implicitly
provides on the grandchild path. Concretely: open / create
`\Sessions\<n>\AppContainerNamedObjects\<ac-sid>` with
`NtCreateDirectoryObject` and pass the handle in via a known mechanism,
or just ensure the directory exists before the bash spawn.
This is broker-mediation (well within the project's policy) and would
unblock direct-bash on every host, but verifying it's the *exact*
missing piece needs the strace log of the original `api_fatal`
(currently truncated in the cdb output) or a debug-attach run that
captures `CreateFileMappingW`'s `GetLastError` value.

### 4.3 — Skip the bash-direct test on this host shape (do nothing more)

The current state (test gated on `process.arch !== 'arm64'` already)
is already shipping. Updating Git for Windows ARM64 to a newer build
is unlikely to help: the cause isn't an outdated msys-2.0.dll
implementation (3006.7 → 3006.9 has no relevant patch — verified by
searching the upstream `msys2-runtime` for `cygwin_shared NULL` /
`api_fatal recursive`), so a newer DLL will hit the same recursive
crash if `CreateFileMappingW` fails.

### Not recommended

- **Patch upstream Cygwin for the NULL guard.** Adding
  `if (!cygwin_shared) return false;` to `forkables_supported()`
  would make the *recursive* AV silent but the original
  `*** fatal error CreateFileMapping shared.5, NTSTATUS=0x… `
  print would still appear, and the process would exit non-zero
  anyway. We'd be dressing the wound without removing the bullet.
- **Disable Win11 25H2 mitigations on bash.exe via IFEO.** Speculative;
  there's no concrete evidence a 25H2-specific mitigation is causing
  the CreateFileMapping failure.
- **Process-compat shim (ApplicationCompatibilityToolkit).**
  Heavyweight, distribution-hostile.

## 5 — Investigation artifacts

- `C:\Users\ig\AppData\Local\Temp\bash_cdb.txt` (UTF-16LE) — the cdb run.
- `C:\Program Files\Git\usr\bin\msys-2.0.dll` v3006.7.0.0 — the AV'ing
  binary.
- `C:\Users\ig\src\msys2-runtime` — upstream source corroborating the
  call-chain at every frame.
- `Y:\vendor\winsbox-src\src\token.rs:33-44` — pre-existing comment
  documenting "NtCreateSection on anonymous shared regions for
  `cygwin_shared`/`user_shared`" as the historically-known-fragile
  Cygwin DllMain code path. The cdb output is the first time we have
  module + offset + symbol-derived call-chain *confirming* that comment
  end-to-end.
- `Y:\docs\n7p_arm64_bash_diagnosis.md` — the prior agent's writeup
  that hypothesised "Prism + CNG/SSPI lazy-init" without RIP. The
  cdb output supersedes that hypothesis: the AV is not in CNG/SSPI;
  it is in Cygwin's own `cleanup_forkables` reading uninitialised
  `cygwin_shared`. CNG/SSPI may still be involved in the *original*
  `CreateFileMappingW` failure (e.g. via `everyone_sd`'s SD-build
  path), but it is not the AV site.

## 6 — Concrete next step

Run the broker once with `WINSBOX_DEBUG_ATTACH=1` from a PowerShell
shell **outside the Claude Code parent-job** (per `n6_step3` findings)
and capture the value of `GetLastError()` at the
`CreateFileMappingW` call site — i.e. set a breakpoint on
`msys-2.0.dll!truncl+0xd553` (module-offset `0x157553` — the
`call 0x21006ecd0` line of `shared_info::create`) which is right after
`open_shared` returns. The error code disambiguates 4.1 vs 4.2:

- `ERROR_ACCESS_DENIED` (5): the AC SID can't write into the named-object
  directory. **Fix path 4.2** (broker primes the directory).
- `ERROR_PATH_NOT_FOUND` (3) / `STATUS_OBJECT_PATH_NOT_FOUND`: the
  per-AC named-object subdirectory hasn't been created yet.
  **Fix path 4.2** (same).
- `ERROR_ALREADY_EXISTS` (183): inconsistency in our trace fakery —
  shouldn't happen.
- Anything else: cmd-wrapping (4.1) is still the cheap test.

No fix landed in this iteration — this branch was bound by the
"identify and report" half of the task and intentionally did **not**
modify code. The recommended hand-off is for the operator to (a) run
debug-attach for the GLE value as above, then (b) implement 4.2 if
the GLE indicates an ACL/namespace issue.
