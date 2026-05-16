// entry.rs — Position-independent entry point
//
// Must be the first code in .text (enforced by link.x placing .text.loader_entry
// before all other .text sections).
//
// The CALL+POP gadget finds our runtime load address without any absolute
// symbol references.  Since link.x guarantees loader_entry is at offset 0
// of the extracted .text blob, rcx after the sub equals the blob base, which
// is also the address of the "THORNLDR" magic header.

use core::arch::naked_asm;

#[unsafe(naked)]
#[no_mangle]
#[link_section = ".text.loader_entry"]
pub unsafe extern "C" fn loader_entry() {
    naked_asm!(
        // ── CALL/POP base-finder ─────────────────────────────────────────────
        // 'call 2f' encodes as E8 00 00 00 00 (5 bytes, rel32 = 0).
        // After 'pop rcx', rcx = runtime address of label '2' = &loader_entry + 5.
        // Subtracting 5 gives &loader_entry = blob_base.
        "call 2f",
        "2:",
        "pop  rcx",
        "sub  rcx, 0x15",     // rcx = blob_base = &THORNLDR header
                              // 0x15 = 5 (CALL encoding) + 16 (header size before stub)

        // ── Stack alignment ──────────────────────────────────────────────────
        // On entry RSP = 16n-8 (CreateRemoteThread pushed a return address).
        // 'call 2f' pushed 8 more → RSP = 16n-16.
        // 'pop rcx'  popped 8    → RSP = 16n-8.
        // 'sub rsp, 0x28' (40 bytes) → RSP = 16n-48 = 16(n-3).  Aligned to 16.
        // 'call loader_main' pushes 8  → RSP = 16(n-3)-8 inside callee. Correct.
        "sub  rsp, 0x28",
        "call {main}",
        "add  rsp, 0x28",
        "ret",

        main = sym crate::loader::loader_main,
    );
}
