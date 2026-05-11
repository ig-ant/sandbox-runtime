# Task 1 — Verify which ntdll our broker actually patches

## Hypothesis under test

x64 processes running under xtajit64se on ARM64 hosts have BOTH x64
and ARM64 ntdll modules mapped. If our broker's `GetModuleHandle("ntdll.dll")`
returns the ARM64 native ntdll (used by the emulator's actual syscalls)
rather than the x64 emulated ntdll, then our `WriteProcessMemory` patches
land at addresses the kernel side never sees — explaining the
post-resume `0xC0000005`.

## Method

Added diagnostic logging at the top of `interception::ntdll_export`
(only fires on first call; gated by `AtomicBool::swap`):

- Handle value
- `IMAGE_FILE_HEADER.Machine` field (read from DOS+NT header at handle base)
- Full module path via `GetModuleFileNameW`

Built brokers for both arches:

- `target/release/sbox-exec.exe` (ARM64, host build)
- `target/x86_64-pc-windows-msvc/release/sbox-exec.exe` (x64, cross)

Staged into `vendor/winsbox/{arm64,x64}/sbox-exec.exe`.

## Results

### x64 broker on ARM64 host (smoke_bash, runs under xtajit64se)

```
[sbox-exec] interception: GetModuleHandle(ntdll.dll) handle=0x7ffc0d8d0000 machine=0x8664 path=C:\WINDOWS\SYSTEM32\ntdll.dll
```

- `machine=0x8664` → `IMAGE_FILE_MACHINE_AMD64` (x64)
- Path `C:\WINDOWS\SYSTEM32\ntdll.dll` (the canonical SysWOW-style
  x64 ntdll path inside the WOW-on-ARM64 emulator; the ARM64 native
  ntdll lives under `\Windows\System32\arm64\` from the emulator's
  view but `GetModuleFileNameW` returns the **logical** path the
  x64-emulated process sees)

**Conclusion: our patches land in the x64 ntdll the emulated process actually executes.** This matches Chromium's verified pattern.

### ARM64 broker on ARM64 host (smoke_cdylib, native)

```
[sbox-exec] interception: GetModuleHandle(ntdll.dll) handle=0x7ffc0d8d0000 machine=0xaa64 path=C:\WINDOWS\SYSTEM32\ntdll.dll
```

- `machine=0xAA64` → `IMAGE_FILE_MACHINE_ARM64`
- Native ARM64 broker resolves native ARM64 ntdll (correct & expected).

## Implication

**This is NOT the bug.** Our patches go into the correct (x64) ntdll
the x64 emulator's syscall stubs actually invoke. The
`0xC0000005` cascade we observe is downstream of this — patches land
correctly, the emulator dispatches them correctly, and the AV happens
somewhere else (probably in Cygwin's DllMain or in xtajit64se's
own dispatch for some specific instruction sequence in our hooks).

The next hypothesis to test (Task 2) is whether vanilla AC also fails
on this host, in which case the OS layer is at fault, not our hooks.

## Files

- Modified: `vendor/winsbox-src/src/interception.rs` (lines 224–263) —
  one-shot diagnostic before the `GetProcAddress` call.
- Brokers built into `C:\Users\ig\AppData\Local\Temp\winsbox-target\{release,x86_64-pc-windows-msvc/release}\sbox-exec.exe`
  and staged into `vendor/winsbox/{arm64,x64}/sbox-exec.exe`.

Note: the same handle value `0x7ffc0d8d0000` appears for both x64
and ARM64 ntdll — this is a coincidence of how Windows maps both
arch's ntdlls at the same VA per session (KnownDlls + ASLR-per-session).
The `Machine` field is the unambiguous discriminant and confirms each
process sees its own arch's ntdll at this address.
