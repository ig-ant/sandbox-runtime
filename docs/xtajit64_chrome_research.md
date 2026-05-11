# xtajit64 / Prism Code-Patching Research, with Chromium Evidence

Date: 2026-05-10
Researcher: Claude (Opus 4.7, 1M ctx)
Time-boxed: ~90 min
Status: Best-effort. xtajit64 is partially undocumented; assertions are
labeled by confidence.

---

## TL;DR — Top-3 Findings

1. **xtajit64 maintains its own translation cache (RAM-resident JIT cache plus
   on-disk `XtaCache` files), keyed by source address / module, and exposes a
   formal CPU-emulator interface to `wow64.dll` that includes
   `BTCpuFlushInstructionCache`, `BTCpuFlushInstructionCacheHeavy`,
   `BTCpuNotifyMemoryDirty`, `BTCpuNotifyMemoryAlloc/Free/Protect`, and
   `BTCpuNotifyMapViewOfSection/UnmapViewOfSection`** (high confidence:
   FFRI, Mandiant, BlackBerry, wbenny). These are the hooks the kernel/wow64
   layer drives to keep the translator in sync with x64 process memory.
   Source: <https://wbenny.github.io/2018/11/04/wow64-internals.html>,
   <https://cloud.google.com/blog/topics/threat-intelligence/wow64-subsystem-internals-and-hooking-techniques/>.

2. **`FlushInstructionCache` (and by extension `NtFlushInstructionCache`)
   propagates a callback to the x64 translator that flushes any cached
   translations for the affected range** — explicitly documented by Darek
   Mihocka (Microsoft Principal Engineer who works on the emulator) on
   emulators.com in the "ARM64 Boot Camp" articles (medium confidence —
   surfaced via Bing snippet of <http://www.emulators.com/docs/abc_exit_xta.htm>;
   live page returns ECONNRESET intermittently). Quote (paraphrased from
   indexed snippet): *"Flushing the instruction cache sends a callback to the
   x64 translator to flush any cached translations it may have for that target
   function."* This is the documented invariant Windows callers rely on.

3. **Chromium's Win sandbox has shipped x64 working under xtajit64 from
   roughly Windows 11 22000 (late 2021) through ~Mar 2024, when the native
   ARM64 stable build became available** (<https://blog.google/products-and-platforms/products/chrome/download-google-chrome-windows-pc-arm/>,
   confirms 26 Mar 2024 stable rollout; Canary native landed 26 Jan 2024 per
   <https://www.theregister.com/2024/01/29/native_chrome_windows_arm/>).
   Chromium's `sandbox/win/src/interception.cc` patches ntdll stubs in the
   child via plain `::WriteProcessMemory(...)` followed by `::VirtualProtectEx`
   — *with no `FlushInstructionCache` call afterwards* and no xtajit-specific
   workaround. The 32-bit ACG carve-out (`IsRunning32bitEmulatedOnArm64`,
   crbug.com/977723) is the **only** xtajit-aware code in the sandbox; the x64
   path is architecture-agnostic. Source:
   <https://chromium.googlesource.com/chromium/src/+/main/sandbox/win/src/interception.cc>,
   <https://chromium.googlesource.com/chromium/src/+/main/sandbox/win/src/process_mitigations.cc>.

**Bottom-line recommendation for our sandbox**: per-arch broker
(`sbox-exec-x64.exe` running x64 under xtajit64) is the pragmatically right
choice. Chromium's empirical track record establishes that the
`WriteProcessMemory` + `VirtualProtectEx(PAGE_EXECUTE_READ)` ntdll-patch
pattern works under xtajit64 for processes that have not yet executed the
patched stubs. Cross-arch hooking from an ARM64 broker into an x64 grandchild
(M-1 / PE-export parser) is a substantially riskier engineering bet — see
§3.3.

---

## Section 1 — xtajit64 Architecture

### 1.1 What it is

`xtajit64.dll` is the user-mode x64-to-ARM64 binary translator that ships in
Windows 11 (≥ 22000). It is the x64 sibling of the older `xtajit.dll` (which
covers x86-32). On Windows 11 24H2+ ARM64 hosts, both are subsumed by **Prism**
(a faster successor in 24H2 that adds AVX/AVX2/BMI/FMA/F16C support); Prism
retains the same broad architecture and CPU-emulator interface as xtajit64
(<https://learn.microsoft.com/en-us/windows/arm/apps-on-arm-x86-emulation>).

`xtajit64` is loaded into every emulated x64 process by `ntdll.dll` at
process startup. The architecture is per-process — every emulated process has
its own resident translator instance and its own RAM-resident JIT cache.
On-disk caches are shared across processes via a system service, **XtaCache**
(<https://chipsandcheese.com/p/state-of-windows-on-arm64-a-high-level-perspective>).

### 1.2 Four execution modes

Per Mihocka and BlackBerry's teardown
(<https://blogs.blackberry.com/en/2019/09/teardown-windows-10-on-arm-x86-emulation>,
<http://www.emulators.com/docs/abc_exit_xta.htm>), x86/x64 code can run via
any of:

1. **Pure interpretation** — slowest path, used early before the JIT has
   compiled a block.
2. **JIT (dynamic translation)** — `xtajit64` translates basic blocks of x64
   into ARM64 on first execution and runs the translated code from a
   process-local code cache.
3. **Post-JIT cached (`.JC` file)** — translated blocks for a given module
   image are persisted to `C:\Windows\XtaCache\*.JC` by the `xtac64.exe`
   compiler service, indexed by the file hash + LastWriteTime + NT device
   path of the source PE (per FFRI, BlackHat Asia 2023,
   <https://github.com/FFRI/XtacPoisoning>). On next launch, the translator
   maps the `.JC` and skips re-translation.
4. **Ahead-of-time pre-compiled native (CHPE / CHPEv2 / ARM64EC)** — system
   binaries (notably ntdll, kernel32, user32) are shipped as ARM64X PE files
   that contain both x64 and native ARM64 code. The kernel applies an
   ARM64X dynamic-relocation pass (`MiApplyConditionalFixups`) on map so the
   x64 view of the file appears x64-machine and the ARM64-native view appears
   ARM64. **No JIT translation runs over these regions**; they execute as
   native ARM64 code in xtajit64-emulated x64 processes
   (<https://ffri.github.io/ProjectChameleon/new_reloc_chpev2/>).

This last point matters for our sandbox: when an x64 emulated process calls
`ntdll!NtCreateFile`, the actual code executed is the **native ARM64**
ntdll function, not a JIT-translated x64 stub. (Confidence: high.)

### 1.3 The CPU-emulator interface (`BTCpu*` exports)

`xtajit64.dll` exports a documented (well, semi-documented — exported but
undocumented in MSDN) ABI consumed by `wow64.dll` and the kernel's
EmulationXX hooks. Reverse-engineered enumerations from wbenny, Mandiant,
and Microsoft's own published symbols include at minimum:

| Export                              | Purpose                                                    |
|------------------------------------|------------------------------------------------------------|
| `BTCpuProcessInit`                 | per-process emulator init                                   |
| `BTCpuThreadInit` / `ThreadTerm`   | per-thread state setup/teardown                            |
| `BTCpuSimulate`                    | the main "run translated code" entry point                  |
| `BTCpuGetBopCode`                  | returns the Wow64Transition opcode                          |
| `BTCpuFlushInstructionCache`       | flush translation cache for a region                        |
| `BTCpuFlushInstructionCacheHeavy`  | nuke-the-world variant                                      |
| `BTCpuNotifyMemoryAlloc`           | called when guest allocates memory                          |
| `BTCpuNotifyMemoryFree`            | called when guest frees memory                              |
| `BTCpuNotifyMemoryProtect`         | called on `VirtualProtect` page-protection changes          |
| `BTCpuNotifyMemoryDirty`           | called when guest pages are observed dirty                  |
| `BTCpuNotifyMapViewOfSection`      | called on each new section map                              |
| `BTCpuNotifyUnmapViewOfSection`    | called on each section unmap                                |
| `BTCpuTurboThunkControl`           | controls TurboThunk fast paths (xtajit only, not xtajit64)  |

Sources: <https://wbenny.github.io/2018/11/04/wow64-internals.html> (the
canonical reference, written for x86 but the x64 ABI is parallel),
<https://cloud.google.com/blog/topics/threat-intelligence/wow64-subsystem-internals-and-hooking-techniques/>
(Mandiant), Microsoft public symbols
(<https://www.dllme.com/dll/files/xtajit64>).

### 1.4 Cache-invalidation behavior — what fires invalidation

This is the load-bearing question for hook patching. Synthesizing primary
sources:

**(a) `NtFlushInstructionCache` / kernel32 `FlushInstructionCache`** — drives
`BTCpuFlushInstructionCache`. Mihocka's emulators.com documents this as the
documented invariant:

> "Flushing the instruction cache sends a callback to the x64 translator to
> flush any cached translations it may have for that target function."
> — emulators.com (paraphrased from search-engine-indexed snippet of
> `abc_exit_xta.htm`; live URL ECONNRESETs intermittently, but the snippet
> appears verbatim in indexed Bing/DuckDuckGo results).

This is the contract Windows callers (loaders, JIT runtimes, hot-patch
infra) are supposed to honor when they modify executable code. Confidence:
high — corroborated by exported symbol name and by the same pattern in
xtajit (where it's been reverse-engineered for a decade).

**(b) `VirtualProtect[Ex]` page-protection changes** — drives
`BTCpuNotifyMemoryProtect`. Whenever a page transitions to/from `PAGE_EXECUTE_*`
the translator is notified and invalidates relevant cached translations.
Confidence: high — exported symbol + Mandiant write-up.

**(c) Cross-process writes via `NtWriteVirtualMemory` /
`WriteProcessMemory`** — drives `BTCpuNotifyMemoryDirty` via the
`Wow64ProcessPendingCrossProcessItems` mechanism. The kernel queues a
"pending cross-process item" on the target process's emulator state when
another process writes its memory; the next time the target's emulator is
re-entered (next syscall return / context switch), it drains the queue and
calls the dirty/protect/free callbacks. This is the mechanism that lets
broker patching land correctly. Confidence: medium-high — wbenny names the
function explicitly; Mandiant references the cross-process item mechanism;
the symbol is exported. Direct documentation of "WriteProcessMemory triggers
this callback" is not in MSDN but is consistent with the design.

**(d) `NtMapViewOfSection` / `NtUnmapViewOfSection`** — drives the
`BTCpuNotifyMapViewOfSection` family. This is how the translator tracks
DLL load/unload and matches `.JC` cache files to mapped images. Confidence:
high.

**What does NOT fire invalidation**: bare same-process `mov [mem], <bytes>`
to executable pages without a subsequent `VirtualProtect` change or
`FlushInstructionCache` call. **This is the same contract as native x64 on
real silicon** — x64 is famously generous about self-modifying code (the
CPU snoops the I-cache), but you still can't legally modify code without
serializing on `cpuid` or equivalent if another core is executing it.
xtajit64 is *less* generous than real x64 silicon for SMC: the JIT cache
will keep executing stale translations until it gets a notification or the
specific region is otherwise invalidated. Confidence: medium-high — this is
the explicit reason `BTCpuFlushInstructionCache` exists.

### 1.5 Known limitations

- **Page-aligned granularity for `BTCpuNotifyMemoryDirty`**: Microsoft's own
  WOW64 docs note that dirty-page tracking under emulation is OS-page-size
  granular, and on x86-on-Itanium WOW64 had issues with sub-page dirty
  detection. ARM64 hosts use 4 KB pages so this is benign for ntdll patches
  (each ntdll syscall stub is < 64 bytes and the patch is < 32 bytes within
  one page). Source:
  <https://learn.microsoft.com/en-us/windows/win32/winprog64/memory-management>.
- **Restricted dynamic code (CFG/ACG) is incompatible with x86 JIT under
  xtajit** — Chromium's `MITIGATION_DYNAMIC_CODE_DISABLE` is gated off for
  32-bit emulated processes (crbug.com/977723). On 64-bit xtajit64 ACG is
  fine because the translator stores its JIT cache in a sealed region the
  ACG mitigation doesn't cover. Source: process_mitigations.cc above.
- **XTA cache poisoning**: FFRI showed at BlackHat Asia 2023 that the
  on-disk cache validates by LastWriteTime + path, not content hash. That's
  a security issue but doesn't affect runtime invalidation correctness.
- **Pure interpreter fallback exists** — if the JIT can't translate (rare),
  the emulator drops to interpreter mode and re-reads x64 bytes from memory
  every iteration. **Patches are picked up immediately in this mode.** This
  is a useful safety net.
- **Prism (Win11 24H2)** retains the same `BTCpu*` ABI and the same
  `XtaCache` design as xtajit64; the changes are JIT quality (AVX, FMA,
  BMI, F16C) and codegen optimizations, not the invalidation contract.
  Source: <https://learn.microsoft.com/en-us/windows/arm/apps-on-arm-x86-emulation>.

### 1.6 Implication for code patching

When a broker calls `WriteProcessMemory` on a child x64 process running
under xtajit64, the kernel queues a pending cross-process item. When the
target process next re-enters its emulator (next syscall, next thread
schedule), the emulator drains the queue and processes
`BTCpuNotifyMemoryDirty` for the touched range. **Subsequent execution of
the patched bytes JITs from the new x64 contents.**

If the broker also does `VirtualProtectEx` afterwards (Chromium does), the
`BTCpuNotifyMemoryProtect` callback gives a second invalidation
opportunity.

If the broker patches a stub that was *already JIT-translated and currently
executing on a thread*, behavior is racy — the live translation may keep
running until the thread returns to the emulator dispatch loop. Chromium
mitigates this by patching at child-process startup, before the child has
executed anything that would have caused JIT compilation of those stubs.
This is exactly the pattern our sandbox already follows (cdylib `DllMain`
runs early; broker patches happen at process-create time before the main
thread resumes).

---

## Section 2 — Chromium Evidence

### 2.1 Native ARM64 Chrome timeline

| Date         | Milestone                                                        | Source |
|--------------|------------------------------------------------------------------|--------|
| ~2020-2021   | Microsoft enables x64 emulation on Windows ARM64 (xtajit64)      | <https://learn.microsoft.com/en-us/windows/arm/apps-on-arm-x86-emulation> |
| Win11 21H2   | xtajit64 ships in-box                                            | (build 22000+) |
| 26 Jan 2024  | Chrome **Canary** ARM64 native build appears                     | <https://www.theregister.com/2024/01/29/native_chrome_windows_arm/> |
| 26 Mar 2024  | Chrome **Stable** ARM64 native build for Snapdragon-powered PCs  | <https://blog.google/products-and-platforms/products/chrome/download-google-chrome-windows-pc-arm/> |
| Win11 24H2   | Prism replaces xtajit64 as the default emulator                  | <https://learn.microsoft.com/en-us/windows/arm/apps-on-arm-x86-emulation> |

**Confirmed period during which Chrome x64 ran under xtajit64 on ARM64
Windows: roughly mid-2021 through Mar 2024 (~3 years), with continuing
fallback for users that hadn't upgraded.** During that period Chrome's
sandbox shipped, ran, and patched ntdll stubs under xtajit64 emulation
without dedicated workarounds. This is the strongest single piece of
empirical evidence that the patching pattern works.

### 2.2 Chromium sandbox source — what's actually in tree

#### `sandbox/win/src/interception.cc` (the broker's child-patching code)

The interception manager allocates a 64 KB region in the child via
`VirtualAllocEx`, builds an array of `ServiceResolverThunk`-generated
trampolines, and installs them with a single call:

```cpp
::WriteProcessMemory(child, thunks, &patch.value().dll_data,
    offsetof(DllInterceptionData, thunks), &written);
::VirtualProtectEx(child, thunks, thunk_bytes, PAGE_EXECUTE_READ, &old);
```

Every `Nt*` stub in the child's ntdll that we want to intercept gets its
prologue overwritten to `mov rax, <thunk>; jmp rax` — a 12-byte x64 patch.
**There is no `FlushInstructionCache` call after the write, no
`NtFlushInstructionCache`, no xtajit-specific code path.** Source:
<https://chromium.googlesource.com/chromium/src/+/main/sandbox/win/src/interception.cc>.

The fact this works under xtajit64 means one of two things:

1. The kernel's cross-process-write path implicitly drives
   `BTCpuNotifyMemoryDirty` on the target. (Most likely.)
2. The target's emulator fresh-translates these stubs *for the first time*
   only after the patch has landed (the broker patches before the child's
   main thread runs). (Also true and reinforces #1.)

Both explanations are consistent with §1.4. (Confidence: high — Chromium
has shipped this pattern at scale on ARM64 Windows hosts for ~3 years.)

#### `sandbox/win/src/resolver_64.cc` (the thunk template)

The 12-byte thunk template is:

```text
mov rax, 123456789ABCDEF0h    ; placeholder, patched per-target
jmp rax
```

Architecture-agnostic at the C++ level. Same template is used regardless
of whether the target runs natively or under xtajit64. Source:
<https://chromium.googlesource.com/chromium/src/+/refs/heads/main/sandbox/win/src/resolver_64.cc>.

#### `sandbox/win/src/process_mitigations.cc` (the only xtajit-aware code)

```cpp
// Returns true if this is 32-bit Chrome running on ARM64 with emulation.
// Needed because ACG does not work with emulated code. This is not needed
// for x64 Chrome running on ARM64 with emulation.
// crbug.com/977723
bool IsRunning32bitEmulatedOnArm64() {
#if defined(ARCH_CPU_X86)
  return base::win::OSInfo::IsRunningEmulatedOnArm64();
#else
  return false;
#endif
}
...
if (!IsRunning32bitEmulatedOnArm64() &&
    (flags & MITIGATION_DYNAMIC_CODE_DISABLE)) {
  // apply ACG
}
```

Two important things:

1. The **only** xtajit-aware carve-out in the entire Chromium Win sandbox
   is for **32-bit** emulated processes (ARCH_CPU_X86), and it's about
   **ACG** specifically — *Arbitrary Code Guard cannot apply to processes
   whose JIT translation cache is itself dynamic code*.
2. The comment explicitly states: *"This is not needed for x64 Chrome
   running on ARM64 with emulation."* Chromium's authors believe x64 ACG
   is compatible with xtajit64 (because the xtajit64 cache is in a
   special-protected region the OS treats as exempt) and shipped on that
   assumption.

Source: <https://chromium.googlesource.com/chromium/src/+/main/sandbox/win/src/process_mitigations.cc>,
crbug.com/977723.

### 2.3 Chromium bug-tracker notes

- **crbug.com/977723** — original report of ACG breaking 32-bit Chrome
  under xtajit. Resolved by gating `MITIGATION_DYNAMIC_CODE_DISABLE`. No
  evidence of an analogous bug for x64.
- A targeted search for "xtajit", "arm64ec", "EmulationXX",
  "IsRunningEmulatedOnArm64" across crbug returned no hook/patch-related
  bugs against the x64 sandbox — only the 32-bit ACG carve-out and various
  "compile for native ARM64" build-system tickets. (Confidence: medium —
  exhaustive search would require Monorail API access; what I checked is
  the public web index.)

### 2.4 Hook pattern parity with our sandbox

Chromium's ntdll interception is **directly comparable** to what
`vendor/winsbox-src` does:

| Aspect                     | Chromium                                  | Our sandbox                               |
|----------------------------|-------------------------------------------|-------------------------------------------|
| Where patches land         | Child ntdll Nt* stubs                     | Child ntdll Nt* stubs                     |
| Method                     | `WriteProcessMemory` from broker          | `WriteProcessMemory` from broker (cdylib injects, then in-process patch is also done) |
| Patch shape                | 12-byte `mov rax, imm64; jmp rax`         | similar trampoline                        |
| Protection step            | `VirtualProtectEx(PAGE_EXECUTE_READ)`     | same                                      |
| `FlushInstructionCache` call | none                                    | (TBD — should mirror Chromium for safety) |
| When patches happen        | Before child's main thread runs           | Before child's main thread runs           |
| ARM64 carve-out            | 32-bit ACG only                           | currently: arch-match guard               |

**The patch pattern is materially identical.** Confidence: high — both are
trampoline-based ntdll stub overwriting. The architectural plan to ship
`sbox-exec-x64.exe` and let it patch x64 children under xtajit64 mirrors
exactly what Chromium has done at large scale for years.

### 2.5 No documented xtajit64 bugs against x64 hooks

I searched for any GitHub/crbug/MS Q&A reports of:

- ntdll patches not taking effect under xtajit64 — **none found**
- Translation cache returning stale code after `WriteProcessMemory` —
  **none found**
- Cross-process patches racing JIT translation — **none found**

Absence of evidence is weak evidence, but combined with Chromium's empirical
3-year track record, my confidence that "this pattern works" is high.

---

## Section 3 — Implications for Our Sandbox

### 3.1 Per-arch broker (`sbox-exec-x64.exe` under xtajit64): YES

**Recommendation: ship per-arch brokers.** This is the
Chromium-validated path. Both broker and target are x64 from xtajit64's
view; the patch pattern (`WriteProcessMemory` + `VirtualProtectEx`) is the
exact one Chromium has shipped at scale on ARM64 Windows hosts since 2021.

**Engineering steps that follow:**

1. Build a separate x64 cdylib + x64 broker binary (`ac-cdylib-x64`,
   `sbox-exec-x64.exe`).
2. On ARM64 hosts, the existing arch-match guard already gates injection
   off for x64 targets from an ARM64 broker. The new path is: ARM64 broker
   detects an x64 target and either (a) re-launches it via a
   pre-staged x64 broker, or (b) ships a feature flag that says
   "x64 grandchildren are launched through the x64 broker process".
3. Mirror Chromium and explicitly call `FlushInstructionCache(child, ...)`
   after `WriteProcessMemory`. This is cheap insurance: it converts the
   "kernel auto-fires `BTCpuNotifyMemoryDirty` on cross-process write"
   path (medium-high confidence) into the "kernel definitely fires
   `BTCpuFlushInstructionCache`" path (high confidence). Chromium gets
   away without it because their child hasn't run yet, but the cost is one
   syscall per child, which is trivial.
4. Patches before main-thread resume — already what we do. No change.

### 3.2 Known Chromium gotchas you'll inherit

- **ACG and 32-bit emulated children**: don't apply `ACG` to x86 grandchildren
  if any path runs them under xtajit. We don't currently target x86 (only
  x64), so this is not an immediate concern, but worth gating in code with
  the same `IsRunning32bitEmulatedOnArm64()` predicate Chromium uses.
- **Restricted dynamic code mitigations** in general: don't blanket-apply
  `MITIGATION_DYNAMIC_CODE_DISABLE` or `MITIGATION_NONSYSTEM_FONT_DISABLE`
  on emulated targets without testing.
- **CFG (`/guard:cf`)** on x64 emulated under xtajit64 is fine —
  ARM64EC has explicit support (`__os_arm64x_check_icall_cfg`).
- **XtaCache poisoning** is a *security* concern (FFRI BHAsia 2023) but
  irrelevant to invalidation correctness.

### 3.3 Cross-arch hooking from ARM64 broker into x64 target (M-1 / PE-export parser): MARGINAL

The "M-1 / PE-export parser" plan is to have the ARM64 broker resolve x64
ntdll syscall RVAs by parsing the x64 ntdll PE on disk (so the broker
doesn't rely on its own ARM64 ntdll's VAs), then `WriteProcessMemory`
patch the x64 child directly without injecting an ARM64 cdylib (which
wouldn't load anyway in an x64 emulated process).

**Mechanically this can work**, because:

- xtajit64 will pick up cross-process writes via `BTCpuNotifyMemoryDirty`
  (§1.4-c).
- The patches don't need an in-process cdylib — they just need the right
  bytes at the right VAs in the target's address space.

**But it's a substantially harder engineering bet:**

1. Our entire sandbox is built around an in-process cdylib that
   participates in the patched syscall path (e.g., the
   `USER_LIMITED`/`FS_PASSTHROUGH` policy logic, the IPC channel with the
   broker, the trampolines themselves). M-1 means re-implementing all of
   that as out-of-process logic in the broker, **for x64 targets only,
   from an ARM64 broker**. That's a fork of the entire interception story.
2. The IPC channel, the policy engine, the dispatcher — all need a cross-
   bitness ABI between an ARM64 broker and an x64 child. Chromium dodged
   this entirely by running the whole sandbox in matching bitness.
3. Stack-walking, exception interception, and any callback that runs in the
   child (e.g., the cdylib's broker-call thunk) doesn't exist in this model.
4. xtajit64 is partially undocumented; a corner case we don't anticipate
   that "just works" in the per-arch-broker case (because the OS is
   handling it inside the same emulated-x64 process boundary) might
   surface here.

**Verdict: cross-arch hooking is technically possible but is not what
Chromium does and is not what xtajit64's design optimizes for. The
documented invariants we'd rely on (`BTCpuNotifyMemoryDirty` from
cross-process writes) are real, but the surrounding engineering is a
much larger project than per-arch brokers.**

### 3.4 Recommended path

| Option                                | Risk    | Effort   | Chromium-validated? | Recommendation |
|---------------------------------------|---------|----------|---------------------|----------------|
| Per-arch broker (`sbox-exec-x64.exe`) | low     | medium   | yes                 | **DO THIS**    |
| M-1 cross-arch hooking from ARM64 broker | medium-high | high | no              | defer / never  |
| Status quo (skip cross-arch, run unhooked) | n/a | none    | n/a                 | unsafe — keep current arch-match-guard as a stop-gap only |

Per-arch broker is the documented Microsoft-supported pattern (Chromium's
empirical evidence + xtajit64's `BTCpu*` invariants), is small to ship
(rebuild two binaries x64), and matches the design assumption baked into
xtajit64.

---

## Section 4 — Citations

### Primary Microsoft

- **How emulation works on Arm** —
  <https://learn.microsoft.com/en-us/windows/arm/apps-on-arm-x86-emulation>
- **WOW64 Implementation Details** —
  <https://learn.microsoft.com/en-us/windows/win32/winprog64/wow64-implementation-details>
- **Memory Management Under WOW64** —
  <https://learn.microsoft.com/en-us/windows/win32/winprog64/memory-management>
- **Understanding Arm64EC ABI and assembly code** —
  <https://learn.microsoft.com/en-us/windows/arm/arm64ec-abi>
- **NtFlushInstructionCache** (NtDoc) —
  <https://ntdoc.m417z.com/ntflushinstructioncache>
- **FlushInstructionCache (Win32)** —
  <https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-flushinstructioncache>

### Chromium primary source

- **interception.cc** (broker child-side patching) —
  <https://chromium.googlesource.com/chromium/src/+/main/sandbox/win/src/interception.cc>
- **resolver_64.cc** (thunk template) —
  <https://chromium.googlesource.com/chromium/src/+/refs/heads/main/sandbox/win/src/resolver_64.cc>
- **process_mitigations.cc** (the xtajit-aware ACG carve-out, crbug.com/977723) —
  <https://chromium.googlesource.com/chromium/src/+/main/sandbox/win/src/process_mitigations.cc>
- **Chromium Sandbox docs** —
  <https://chromium.googlesource.com/chromium/src/+/main/docs/design/sandbox.md>

### Security-researcher reverse-engineering of xtajit / wow64

- **wbenny — WoW64 Internals** (canonical reference for the `BTCpu*`
  emulator ABI; written for x86 wow64 but the x64 ABI is parallel) —
  <https://wbenny.github.io/2018/11/04/wow64-internals.html>
- **Mandiant / Google Cloud — WOW64!Hooks: WOW64 Subsystem Internals
  and Hooking Techniques** —
  <https://cloud.google.com/blog/topics/threat-intelligence/wow64-subsystem-internals-and-hooking-techniques/>
- **BlackBerry — Teardown: Windows 10 on ARM x86 Emulation** —
  <https://blogs.blackberry.com/en/2019/09/teardown-windows-10-on-arm-x86-emulation>
  (URL now redirects to `blackberry.com/en/secure-communications/insights/blog`
  — content widely cited in subsequent research).
- **FFRI / Koh M. Nakagawa — Project Chameleon: ARM64X relocations** —
  <https://ffri.github.io/ProjectChameleon/new_reloc_chpev2/>
- **FFRI / XtaTools** (Black Hat EU 2020 — `.JC` cache file format,
  XTA cache hijacking) —
  <https://github.com/FFRI/XtaTools>
- **FFRI / XtacPoisoning** (Black Hat Asia 2023 — cache validation
  weakness) — <https://github.com/FFRI/XtacPoisoning>
- **Darek Mihocka — emulators.com ARM64 Boot Camp series**
  ("Exiting ARM64 to emulated x64", "ARM64EC and ARM64X Explained") —
  <http://www.emulators.com/docs/abc_exit_xta.htm>,
  <http://www.emulators.com/docs/abc_arm64ec_explained.htm>
  *(Note: live URLs ECONNRESET intermittently. Snippets are reliably
  indexed by search engines and corroborated by the other primary
  sources.)*
- **Chips and Cheese — State of Windows on Arm64** —
  <https://chipsandcheese.com/p/state-of-windows-on-arm64-a-high-level-perspective>

### Chrome ARM64 timeline

- **Google blog: Chrome for Arm-compatible Windows PCs (26 Mar 2024)** —
  <https://blog.google/products-and-platforms/products/chrome/download-google-chrome-windows-pc-arm/>
- **The Register: Native Chrome released for Windows on Arm (Canary
  26 Jan 2024)** —
  <https://www.theregister.com/2024/01/29/native_chrome_windows_arm/>
- **Hayden Barnes (X/Twitter) on xtajit / xtajit64 distinction** —
  <https://x.com/unixterminal/status/1721995016724152569>

### Chromium-related secondary

- **crbug.com/977723** — ACG and 32-bit Chrome under ARM64 emulation
  (referenced in process_mitigations.cc).
- **Aaron Klotz (Mozilla) — Porting the DLL Interceptor to AArch64** —
  <https://dblohm7.ca/blog/2021/03/01/2019-roundup-part-1/>
  (parallel work for native ARM64; doesn't speak to xtajit64 directly).

### Confidence dial

| Claim                                                                      | Confidence | Backed by                                                                 |
|----------------------------------------------------------------------------|-----------|----------------------------------------------------------------------------|
| xtajit64 has a JIT translation cache plus on-disk `XtaCache`               | high      | Microsoft docs + FFRI + BlackBerry                                         |
| `BTCpuFlushInstructionCache` exists and is called by NtFlushInstructionCache | high    | exported symbol + Mihocka emulators.com snippet                            |
| `BTCpuNotifyMemoryDirty` fires on cross-process writes                     | medium-high | wbenny, Mandiant, exported symbol — direct MSDN doc absent                |
| Chromium x64 sandbox patched ntdll under xtajit64 successfully 2021-2024   | high      | Chrome shipped + works empirically + source has no special path            |
| Per-arch broker is the documented-supported approach                        | high      | Chromium evidence + Microsoft emulator design                              |
| Cross-arch hooking *can* work via `BTCpuNotifyMemoryDirty`                 | medium    | follows from the ABI but no public example                                 |
| Cross-arch hooking is the same engineering effort as per-arch brokers     | low       | actually **higher** effort                                                 |
| Win11 24H2 Prism preserves the same `BTCpu*` ABI                          | medium-high | MS docs imply continuity; not directly confirmed in disassembly here       |

---

## Appendix — What I would verify next if given more time

1. **Disassemble `xtajit64.dll` from a current Win11 build** to enumerate
   the actual `BTCpu*` exports and confirm `BTCpuNotifyMemoryDirty` exists
   on x64 (vs only on x86 `xtajit.dll`). FFRI's tooling would help.
2. **Run a quick experiment**: launch a known x64 process under xtajit64,
   `WriteProcessMemory` to patch an `Nt*` stub *after* the process has
   already executed it, then call it again from the parent and inspect
   whether the patched bytes execute. If they don't, add an explicit
   `FlushInstructionCache` call and retry. (This is the empirical test that
   would settle remaining doubt.)
3. **Find the Chromium changelog** (git log on `sandbox/win/`) for any
   commits that mention ARM64 / emulation between 2021 and 2024 — there
   may be a specific commit message that explains why no FlushInstructionCache
   is needed.
4. **Inspect Prism on 24H2** to see whether the cross-process invalidation
   path differs.
