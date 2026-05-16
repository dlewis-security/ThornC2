//! thornldr — custom PIC PE loader (no_std, x86-64 Windows)
//!
//! Blob format written by builder/bab/loader.py:
//!   [0..8]  "THORNLDR" magic
//!   [8..12] pe_offset: u32 LE — byte offset from blob[0] to the PE MZ header
//!   [12..16] pe_size: u32 LE  — raw PE file size
//!   [16..]  loader stub machine code  (loader_entry at offset 16 = offset 0
//!           within the .text section, patched by the builder)
//!   [pe_offset..] raw PE bytes

#![no_std]
#![no_main]
#![allow(non_snake_case, non_camel_case_types, clippy::missing_safety_doc)]

pub mod api_hash;
pub mod entry;
pub mod loader;
pub mod peb_walk;

#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {
        unsafe { core::arch::asm!("pause", options(nostack, nomem)); }
    }
}
