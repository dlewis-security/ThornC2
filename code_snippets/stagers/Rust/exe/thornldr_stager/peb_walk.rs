// peb_walk.rs — Find kernel32.dll / ntdll.dll base via PEB InLoadOrderModuleList.
//
// x64 offsets (stable since Windows Vista):
//   GS:[0x60]   → *PEB
//   PEB  + 0x18 → *PEB_LDR_DATA
//   LDR  + 0x10 → InLoadOrderModuleList LIST_ENTRY (head sentinel)
//   LDTE:
//     +0x00  InLoadOrderLinks.Flink   *mut LDTE
//     +0x30  DllBase                  *mut u8
//     +0x58  BaseDllName.Length       u16   (byte count, not char count)
//     +0x60  BaseDllName.Buffer       *const u16

use core::arch::asm;

#[inline(always)]
unsafe fn get_peb() -> *mut u8 {
    let peb: *mut u8;
    asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, nomem));
    peb
}

/// Case-insensitive compare of a UTF-16 buffer against an ASCII lowercase name.
#[inline(always)]
unsafe fn name_matches(buf: *const u16, chars: usize, want: &[u8]) -> bool {
    if chars != want.len() { return false; }
    let mut i = 0;
    while i < chars {
        let c  = *buf.add(i);
        let cl = if c >= b'A' as u16 && c <= b'Z' as u16 { c + 0x20 } else { c };
        if cl != want[i] as u16 { return false; }
        i += 1;
    }
    true
}

#[inline(always)]
unsafe fn find_module(want: &[u8]) -> *const u8 {
    let peb  = get_peb();
    let ldr  = (peb.add(0x18) as *const *mut u8).read();
    let head = ldr.add(0x10) as *mut *mut u8;

    let mut entry = (*head) as *mut u8;
    while entry as *mut *mut u8 != head {
        let name_bytes = (entry.add(0x58) as *const u16).read_unaligned() as usize;
        let name_buf   = (entry.add(0x60) as *const *const u16).read_unaligned();
        let dll_base   = (entry.add(0x30) as *const *const u8).read_unaligned();
        let name_chars = name_bytes / 2;
        if !name_buf.is_null() && name_matches(name_buf, name_chars, want) {
            return dll_base;
        }
        entry = (*( entry as *const *mut u8 )) as *mut u8;
    }
    core::ptr::null()
}

#[inline(always)]
pub unsafe fn find_kernel32() -> *const u8 {
    find_module(b"kernel32.dll")
}

// find_ntdll is not needed today — ntdll is resolved via the bootstrap
// LoadLibraryA("ntdll.dll") path in resolver::resolve. Left as a
// possible future shortcut if we want to skip one extra LL call.
#[allow(dead_code)]
#[inline(always)]
pub unsafe fn find_ntdll() -> *const u8 {
    find_module(b"ntdll.dll")
}
