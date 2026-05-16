// entry.rs — Position-independent entry point for the COFF loader.
//
// Placed first in .text via link.x (.text.loader_entry section).
//
// Called as a CreateThread thread-proc: lpParameter = bundle_base (*mut u8).
// On x64 Windows, lpParameter arrives in RCX.

use core::arch::naked_asm;

#[unsafe(naked)]
#[no_mangle]
#[link_section = ".text.loader_entry"]
pub unsafe extern "system" fn loader_entry(bundle_base: *mut u8) -> u32 {
    naked_asm!(
        // RCX = bundle_base (lpParameter from CreateThread)
        // RSP = 16n-8 on entry (Windows thread proc: return addr pushed by OS)
        // sub rsp, 0x28 → RSP = 16n-8-40 = 16(n-3). Aligned for callee.
        "sub  rsp, 0x28",
        "call {main}",
        "add  rsp, 0x28",
        "xor  eax, eax",
        "ret",
        main = sym crate::loader::loader_main,
    );
}
