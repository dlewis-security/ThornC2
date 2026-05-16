// dynload.rs
// Dynamic API resolution with compile-time XOR-obfuscated function/DLL names.
// All sensitive Win32 functions are resolved at runtime via GetProcAddress;
// their names never appear as plaintext strings in the binary.
// GetProcAddress and LoadLibraryA are the only Win32 imports, both benign.

use std::ffi::c_void;
use windows::core::PCSTR;
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};

// ── Function pointer type aliases ─────────────────────────────────────────────

pub type FnVirtualAlloc   = unsafe extern "system" fn(*mut c_void, usize, u32, u32) -> *mut c_void;
pub type FnVirtualProtect = unsafe extern "system" fn(*mut c_void, usize, u32, *mut u32) -> i32;

// ── XOR decode (KEY = 0x5A) ───────────────────────────────────────────────────

const KEY: u8 = 0x5A;

fn decode(enc: &[u8]) -> Vec<u8> {
    let mut v: Vec<u8> = enc.iter().map(|b| b ^ KEY).collect();
    v.push(0); // null terminator for PCSTR
    v
}

unsafe fn resolve<T>(dll_enc: &[u8], name_enc: &[u8]) -> Option<T> {
    let dll  = decode(dll_enc);
    let name = decode(name_enc);
    let hmod = LoadLibraryA(PCSTR(dll.as_ptr())).ok()?;
    let proc = GetProcAddress(hmod, PCSTR(name.as_ptr()))?;
    Some(std::mem::transmute_copy(&proc))
}

// ── Encoded names (each byte XOR'd with 0x5A; decode to recover plaintext) ────

// "kernel32.dll"
const K32: &[u8] = &[
    0x31, 0x3F, 0x28, 0x34, 0x3F, 0x36, 0x69, 0x68, 0x74, 0x3E, 0x36, 0x36,
];

// "VirtualAlloc"
const N_VIRTUAL_ALLOC: &[u8] = &[
    0x0C, 0x33, 0x28, 0x2E, 0x2F, 0x3B, 0x36, 0x1B, 0x36, 0x36, 0x35, 0x39,
];

// "VirtualProtect"
const N_VIRTUAL_PROTECT: &[u8] = &[
    0x0C, 0x33, 0x28, 0x2E, 0x2F, 0x3B, 0x36, 0x0A, 0x28, 0x35, 0x2E, 0x3F, 0x39, 0x2E,
];

// ── Public resolver functions ─────────────────────────────────────────────────

pub unsafe fn virtual_alloc()   -> Option<FnVirtualAlloc>   { resolve(K32, N_VIRTUAL_ALLOC)   }
pub unsafe fn virtual_protect() -> Option<FnVirtualProtect> { resolve(K32, N_VIRTUAL_PROTECT) }
