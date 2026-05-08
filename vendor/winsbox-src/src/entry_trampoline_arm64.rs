//! ARM64 entry-trampoline emitter (Phase H).
//!
//! Mirror of `entry_trampoline_x64.rs` for the ARM64 target. Captures
//! original `Pc`/`X0`/`X1` from `RtlUserThreadStart`'s suspended-thread
//! CONTEXT, allocates a remote RX page with a stub that signals
//! `ev_loaded`, blocks on `ev_go`, calls `NtSetInformationThread(
//! ThreadImpersonationToken, NULL)` (post-loader CPW patch settling
//! requires us to be running as the primary token, not impersonating),
//! optionally re-suspends, restores `X0`/`X1`, and tail-jumps to the
//! original entry point.
//!
//! ### ARM64-specific notes
//!
//! * **Argument registers**: ARM64 passes integer args in `X0..X7`
//!   (vs. x64 Microsoft ABI: `RCX`, `RDX`, `R8`, `R9`). The first two
//!   args at `RtlUserThreadStart` (entry pointer, parameter) live in
//!   `X0`/`X1` rather than `RCX`/`RDX`.
//! * **Indirect calls**: ARM64 has no `CALL imm64` form. We use the
//!   same literal-pool pattern as `interception_arm64.rs::enc_abs_jmp`:
//!   `LDR Xn, lit ; BLR Xn`. The literals live at the tail of the stub
//!   and are patched at install time.
//! * **Tail-jump to original Pc**: `LDR X16, lit ; BR X16` (B-not-link;
//!   the original `RtlUserThreadStart` doesn't expect to return to us).
//! * **Stack alignment**: ABI requires SP 16-byte aligned at every
//!   `BLR` boundary. We push `FP/LR` with `STP x29, x30, [sp, #-32]!`,
//!   which both saves them and reserves a 16-byte scratch slot at
//!   `[sp, #16]` for the `NtSetInformationThread` 3rd argument
//!   (a pointer to a `ULONG_PTR NULL`).
//! * **4-byte alignment**: ARM64 fetches instructions on 4-byte
//!   boundaries. The broker's `alloc_remote_rx` returns page-aligned
//!   memory, so the stub start is 4-byte aligned by construction.
//!
//! ### Stub layout (184 bytes)
//!
//! ```text
//!   offset  insn
//!   0x00    STP   x29, x30, [sp, #-32]!     ; allocate frame, save FP/LR
//!   0x04    MOV   x29, sp
//!   0x08    STR   xzr, [sp, #16]            ; *(scratch) = NULL
//!   0x0C    LDR   x0,  lit_t_loaded         ; arg0 = ev_loaded handle
//!   0x10    MOV   x1,  xzr                  ; arg1 = NULL
//!   0x14    LDR   x16, lit_nt_set_event
//!   0x18    BLR   x16                       ; NtSetEvent(ev_loaded, NULL)
//!   0x1C    LDR   x0,  lit_t_go             ; arg0 = ev_go handle
//!   0x20    MOV   x1,  xzr                  ; arg1 = FALSE (alertable)
//!   0x24    MOV   x2,  xzr                  ; arg2 = NULL  (timeout)
//!   0x28    LDR   x16, lit_nt_wait
//!   0x2C    BLR   x16                       ; NtWaitForSingleObject
//!   0x30    MOVN  x0,  #1                   ; arg0 = NtCurrentThread() = -2
//!   0x34    MOV   w1,  #5                   ; arg1 = ThreadImpersonationToken
//!   0x38    ADD   x2,  sp, #16              ; arg2 = &NULL on stack
//!   0x3C    MOV   w3,  #8                   ; arg3 = sizeof(HANDLE)
//!   0x40    LDR   x16, lit_nt_set_info
//!   0x44    BLR   x16                       ; NtSetInformationThread
//!   0x48    B     1f                        ; → no_suspend (skip suspend block)
//!                                           ;    patched to NOP if suspend_after
//!   0x4C    MOVN  x0,  #1
//!   0x50    MOV   x1,  xzr
//!   0x54    LDR   x16, lit_nt_suspend
//!   0x58    BLR   x16                       ; NtSuspendThread(self, NULL)
//!   0x5C  1:LDP   x29, x30, [sp], #32       ; restore FP/LR, free frame
//!   0x60    LDR   x0,  lit_orig_x0          ; restore original X0
//!   0x64    LDR   x1,  lit_orig_x1          ; restore original X1
//!   0x68    LDR   x16, lit_orig_pc
//!   0x6C    BR    x16                       ; tail-jump to RtlUserThreadStart
//!
//!   0x70    .quad  t_loaded                 ; literal pool
//!   0x78    .quad  t_go
//!   0x80    .quad  nt_set_event
//!   0x88    .quad  nt_wait
//!   0x90    .quad  nt_set_info_thread
//!   0x98    .quad  nt_suspend
//!   0xA0    .quad  orig_x0
//!   0xA8    .quad  orig_x1
//!   0xB0    .quad  orig_pc
//!   0xB8    end
//! ```

use anyhow::{Context, Result};
use std::mem::size_of;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::System::Diagnostics::Debug::{
    GetThreadContext, SetThreadContext, CONTEXT, CONTEXT_FULL_ARM64,
};
use windows::Win32::System::Threading::CreateEventW;

use crate::interception::{alloc_remote_rx, ntdll_export};
use crate::ipc::dup_into;

use crate::entry_trampoline::EntrySync;

// ─── Stub template (Phase H) ───────────────────────────────────────
//
// The stub is emitted via `global_asm!` and copied verbatim into the
// remote process; the literal pool at the tail is patched at install
// time with the actual handle/export VAs and original register values.
//
// Why a single template with a runtime-patched conditional branch:
// the `suspend_after` flag is a per-call decision, but emitting two
// global_asm! templates would either require two literal pools (drift
// risk) or shared labels (which `.L`-local labels don't support
// cleanly across blocks). A single template with one extra branch
// instruction is the cleanest expression.
//
// All `.L_entry_stub_*` labels use the GNU-AS convention for assembler-
// local symbols (not emitted into the binary's symbol table) so the
// literal-pool labels don't collide with anything else in the broker.

core::arch::global_asm!(
    ".section .text",
    ".p2align 4",
    ".global entry_stub_arm64_start",
    ".global entry_stub_arm64_end",
    "entry_stub_arm64_start:",
    "    stp     x29, x30, [sp, #-32]!",
    "    mov     x29, sp",
    "    str     xzr, [sp, #16]",
    "    ldr     x0,  .L_entry_stub_lit_t_loaded",
    "    mov     x1,  xzr",
    "    ldr     x16, .L_entry_stub_lit_nt_set_event",
    "    blr     x16",
    "    ldr     x0,  .L_entry_stub_lit_t_go",
    "    mov     x1,  xzr",
    "    mov     x2,  xzr",
    "    ldr     x16, .L_entry_stub_lit_nt_wait",
    "    blr     x16",
    "    movn    x0,  #1",                 // x0 = -2 = NtCurrentThread()
    "    mov     w1,  #5",                 // ThreadImpersonationToken
    "    add     x2,  sp, #16",            // &NULL
    "    mov     w3,  #8",                 // sizeof(HANDLE)
    "    ldr     x16, .L_entry_stub_lit_nt_set_info",
    "    blr     x16",
    "entry_stub_arm64_suspend_branch:",
    "    b       .L_entry_stub_no_suspend", // patched to NOP for suspend_after
    "    movn    x0,  #1",
    "    mov     x1,  xzr",
    "    ldr     x16, .L_entry_stub_lit_nt_suspend",
    "    blr     x16",
    ".L_entry_stub_no_suspend:",
    "    ldp     x29, x30, [sp], #32",
    "    ldr     x0,  .L_entry_stub_lit_orig_x0",
    "    ldr     x1,  .L_entry_stub_lit_orig_x1",
    "    ldr     x16, .L_entry_stub_lit_orig_pc",
    "    br      x16",
    ".p2align 3",
    ".L_entry_stub_lit_t_loaded:    .quad 0xCCCCCCCCCCCCCCCC",
    ".L_entry_stub_lit_t_go:        .quad 0xCCCCCCCCCCCCCCCC",
    ".L_entry_stub_lit_nt_set_event:.quad 0xCCCCCCCCCCCCCCCC",
    ".L_entry_stub_lit_nt_wait:     .quad 0xCCCCCCCCCCCCCCCC",
    ".L_entry_stub_lit_nt_set_info: .quad 0xCCCCCCCCCCCCCCCC",
    ".L_entry_stub_lit_nt_suspend:  .quad 0xCCCCCCCCCCCCCCCC",
    ".L_entry_stub_lit_orig_x0:     .quad 0xCCCCCCCCCCCCCCCC",
    ".L_entry_stub_lit_orig_x1:     .quad 0xCCCCCCCCCCCCCCCC",
    ".L_entry_stub_lit_orig_pc:     .quad 0xCCCCCCCCCCCCCCCC",
    "entry_stub_arm64_end:",
);

extern "C" {
    static entry_stub_arm64_start: u8;
    static entry_stub_arm64_end: u8;
}

// Total stub length in bytes; asserted at runtime against the linker-
// emitted `end - start` so toolchain drift is caught immediately.
const STUB_LEN: usize = 184;

// Offset of the `B .L_entry_stub_no_suspend` opcode (4 bytes) which
// gates the suspend block. In `suspend_after` mode we overwrite it
// with `NOP` so execution falls through into the suspend block.
//
// Layout (instruction-by-instruction):
//   0x00  STP x29,x30,[sp,#-32]!
//   0x04  MOV x29,sp
//   0x08  STR xzr,[sp,#16]
//   0x0C  LDR x0,lit_t_loaded
//   0x10  MOV x1,xzr
//   0x14  LDR x16,lit_nt_set_event
//   0x18  BLR x16
//   0x1C  LDR x0,lit_t_go
//   0x20  MOV x1,xzr
//   0x24  MOV x2,xzr
//   0x28  LDR x16,lit_nt_wait
//   0x2C  BLR x16
//   0x30  MOVN x0,#1
//   0x34  MOV w1,#5
//   0x38  ADD x2,sp,#16
//   0x3C  MOV w3,#8
//   0x40  LDR x16,lit_nt_set_info
//   0x44  BLR x16
//   0x48  B no_suspend           ← gate (this offset)
const SUSPEND_GATE_OFFSET: usize = 0x48;

// ARM64 NOP encoding (HINT #0): 0xD503201F. As little-endian bytes:
const NOP_BYTES: [u8; 4] = [0x1F, 0x20, 0x03, 0xD5];

// Literal-pool offsets (each `.quad`, 8 bytes). Pool starts at 0xB8 −
// 9*8 = 0x70 (offset 112). Asserted against actual layout via the
// `STUB_LEN` runtime check.
const LIT_T_LOADED_OFFSET:    usize = 0x70;
const LIT_T_GO_OFFSET:        usize = 0x78;
const LIT_NT_SET_EVENT_OFFSET:usize = 0x80;
const LIT_NT_WAIT_OFFSET:     usize = 0x88;
const LIT_NT_SET_INFO_OFFSET: usize = 0x90;
const LIT_NT_SUSPEND_OFFSET:  usize = 0x98;
const LIT_ORIG_X0_OFFSET:     usize = 0xA0;
const LIT_ORIG_X1_OFFSET:     usize = 0xA8;
const LIT_ORIG_PC_OFFSET:     usize = 0xB0;

pub fn install(
    target: HANDLE, thread: HANDLE, suspend_after: bool,
) -> Result<EntrySync> {
    unsafe {
        let sa = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: std::ptr::null_mut(),
            bInheritHandle: false.into(),
        };
        let ev_loaded = CreateEventW(Some(&sa), false, false, None)
            .context("CreateEventW(loaded)")?;
        let ev_go = CreateEventW(Some(&sa), false, false, None)
            .context("CreateEventW(go)")?;
        let t_loaded = dup_into(target, ev_loaded)?;
        let t_go = dup_into(target, ev_go)?;

        // CONTEXT must be 16-byte aligned; box it. The ARM64 CONTEXT
        // struct holds Pc/Sp/X0..X28/Fp/Lr in an anonymous union;
        // `Anonymous.Anonymous.X0` is the named-field path.
        let mut ctx: Box<CONTEXT> = Box::new(std::mem::zeroed());
        ctx.ContextFlags = CONTEXT_FULL_ARM64;
        GetThreadContext(thread, &mut *ctx).context("GetThreadContext")?;
        let orig_pc = ctx.Pc;
        let orig_x0 = ctx.Anonymous.Anonymous.X0;
        let orig_x1 = ctx.Anonymous.Anonymous.X1;

        let nt_set_event       = ntdll_export("NtSetEvent")?              as u64;
        let nt_wait            = ntdll_export("NtWaitForSingleObject")?   as u64;
        let nt_set_info_thread = ntdll_export("NtSetInformationThread")?  as u64;
        let nt_suspend         = ntdll_export("NtSuspendThread")?         as u64;

        let stub = emit_stub(
            t_loaded, t_go, nt_set_event, nt_wait, nt_set_info_thread,
            nt_suspend, suspend_after, orig_x0, orig_x1, orig_pc,
        );
        let stub_va = alloc_remote_rx(target, &stub)?;

        ctx.Pc = stub_va as u64;
        SetThreadContext(thread, &*ctx).context("SetThreadContext")?;
        eprintln!(
            "[sbox-exec] entry_trampoline: rtlstart={:#x} → stub @ {:#x}{}",
            orig_pc, stub_va,
            if suspend_after { " (suspend-after)" } else { "" },
        );
        Ok(EntrySync { ev_loaded, ev_go })
    }
}

#[allow(clippy::too_many_arguments)]
fn emit_stub(
    t_loaded: u64, t_go: u64,
    nt_set_event: u64, nt_wait: u64,
    nt_set_info_thread: u64, nt_suspend: u64, suspend_after: bool,
    orig_x0: u64, orig_x1: u64, orig_pc: u64,
) -> Vec<u8> {
    // SAFETY: `entry_stub_arm64_{start,end}` are linker-visible labels
    // emitted by the global_asm! block above. We only read their byte
    // representation here.
    let (start, end) = unsafe {
        (
            &entry_stub_arm64_start as *const u8,
            &entry_stub_arm64_end as *const u8,
        )
    };
    let len = unsafe { end.offset_from(start) as usize };
    debug_assert_eq!(
        len, STUB_LEN,
        "entry_trampoline_arm64 template length drift: expected {STUB_LEN} got {len}"
    );
    let mut v = unsafe { core::slice::from_raw_parts(start, len) }.to_vec();

    // Patch the literal pool with runtime values.
    let patch = |v: &mut Vec<u8>, off: usize, val: u64| {
        v[off..off + 8].copy_from_slice(&val.to_le_bytes());
    };
    patch(&mut v, LIT_T_LOADED_OFFSET,     t_loaded);
    patch(&mut v, LIT_T_GO_OFFSET,         t_go);
    patch(&mut v, LIT_NT_SET_EVENT_OFFSET, nt_set_event);
    patch(&mut v, LIT_NT_WAIT_OFFSET,      nt_wait);
    patch(&mut v, LIT_NT_SET_INFO_OFFSET,  nt_set_info_thread);
    patch(&mut v, LIT_NT_SUSPEND_OFFSET,   nt_suspend);
    patch(&mut v, LIT_ORIG_X0_OFFSET,      orig_x0);
    patch(&mut v, LIT_ORIG_X1_OFFSET,      orig_x1);
    patch(&mut v, LIT_ORIG_PC_OFFSET,      orig_pc);

    if suspend_after {
        // Patch the gating `B no_suspend` to a NOP so the suspend block
        // executes. The default template skips the suspend block; flip
        // it on by replacing the branch with a no-op.
        v[SUSPEND_GATE_OFFSET..SUSPEND_GATE_OFFSET + 4]
            .copy_from_slice(&NOP_BYTES);
    }

    v
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Template length must match `STUB_LEN`. Catches assembler/
    /// linker drift in the global_asm! block.
    #[test]
    fn entry_stub_template_len_matches_constant() {
        let (start, end) = unsafe {
            (
                &entry_stub_arm64_start as *const u8,
                &entry_stub_arm64_end as *const u8,
            )
        };
        let len = unsafe { end.offset_from(start) as usize };
        assert_eq!(
            len, STUB_LEN,
            "entry_trampoline_arm64 stub length changed: {len} bytes"
        );
    }

    /// Verify the literal pool starts at the expected offset by
    /// reading back a freshly emitted stub: each literal slot should
    /// hold the value we passed in.
    #[test]
    fn emit_stub_round_trips_literals() {
        let s = emit_stub(
            0x1111_1111_1111_1111, 0x2222_2222_2222_2222,
            0x3333_3333_3333_3333, 0x4444_4444_4444_4444,
            0x5555_5555_5555_5555, 0x6666_6666_6666_6666,
            false,
            0x7777_7777_7777_7777, 0x8888_8888_8888_8888,
            0x9999_9999_9999_9999,
        );
        assert_eq!(s.len(), STUB_LEN);
        let read_q = |off: usize| -> u64 {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&s[off..off + 8]);
            u64::from_le_bytes(buf)
        };
        assert_eq!(read_q(LIT_T_LOADED_OFFSET),     0x1111_1111_1111_1111);
        assert_eq!(read_q(LIT_T_GO_OFFSET),         0x2222_2222_2222_2222);
        assert_eq!(read_q(LIT_NT_SET_EVENT_OFFSET), 0x3333_3333_3333_3333);
        assert_eq!(read_q(LIT_NT_WAIT_OFFSET),      0x4444_4444_4444_4444);
        assert_eq!(read_q(LIT_NT_SET_INFO_OFFSET),  0x5555_5555_5555_5555);
        assert_eq!(read_q(LIT_NT_SUSPEND_OFFSET),   0x6666_6666_6666_6666);
        assert_eq!(read_q(LIT_ORIG_X0_OFFSET),      0x7777_7777_7777_7777);
        assert_eq!(read_q(LIT_ORIG_X1_OFFSET),      0x8888_8888_8888_8888);
        assert_eq!(read_q(LIT_ORIG_PC_OFFSET),      0x9999_9999_9999_9999);
    }

    /// Suspend-after mode must rewrite the gating B as a NOP so the
    /// suspend block executes instead of being branched over.
    #[test]
    fn emit_stub_suspend_after_nops_the_gate() {
        let s_no = emit_stub(0, 0, 0, 0, 0, 0, false, 0, 0, 0);
        let s_yes = emit_stub(0, 0, 0, 0, 0, 0, true,  0, 0, 0);
        // Default: gate is `B no_suspend` (forward 5 instructions).
        // Encoding: 0b000101_<imm26>; imm26 = (0x5C - 0x48)/4 = 5 →
        // opcode 0x14000005 → little-endian bytes 05 00 00 14.
        assert_eq!(
            &s_no[SUSPEND_GATE_OFFSET..SUSPEND_GATE_OFFSET + 4],
            &[0x05, 0x00, 0x00, 0x14],
            "B no_suspend opcode drift",
        );
        assert_eq!(
            &s_yes[SUSPEND_GATE_OFFSET..SUSPEND_GATE_OFFSET + 4],
            &NOP_BYTES,
            "suspend_after must NOP the gate",
        );
    }
}
