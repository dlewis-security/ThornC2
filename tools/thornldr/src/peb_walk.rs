// peb_walk.rs — Find kernel32.dll base via PEB InLoadOrderModuleList.
//
// x64 offsets (stable since Windows Vista):
//   GS:[0x60]          → *PEB
//   PEB  + 0x18        → *PEB_LDR_DATA
//   LDR  + 0x10        → InLoadOrderModuleList LIST_ENTRY (head sentinel)
//   LDR_DATA_TABLE_ENTRY layout (InLoadOrderLinks at offset 0):
//     +0x00  InLoadOrderLinks.Flink  *mut LDTE
//     +0x30  DllBase                 *mut u8
//     +0x40  SizeOfImage             u32
//     +0x48  FullDllName.Length      u16   (byte count)
//     +0x50  FullDllName.Buffer      *const u16  (full path, e.g. C:\Windows\System32\foo.dll)
//     +0x58  BaseDllName.Length      u16   (byte count, not char count)
//     +0x60  BaseDllName.Buffer      *const u16

use core::arch::asm;

#[inline(always)]
unsafe fn get_peb() -> *mut u8 {
    let peb: *mut u8;
    asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, nomem));
    peb
}

/// Compare a UTF-16 buffer (length = `chars` UTF-16 code units)
/// against "kernel32.dll" case-insensitively.
#[inline(always)]
unsafe fn is_kernel32(buf: *const u16, chars: usize) -> bool {
    // "kernel32.dll" = 12 UTF-16 code units
    const NAME: [u16; 12] = [
        b'k' as u16, b'e' as u16, b'r' as u16, b'n' as u16,
        b'e' as u16, b'l' as u16, b'3' as u16, b'2' as u16,
        b'.'  as u16, b'd' as u16, b'l' as u16, b'l' as u16,
    ];
    if chars != 12 { return false; }
    let mut i = 0;
    while i < 12 {
        let c = *buf.add(i);
        // Lowercase the character (A-Z → a-z)
        let cl = if c >= b'A' as u16 && c <= b'Z' as u16 { c + 0x20 } else { c };
        if cl != NAME[i] { return false; }
        i += 1;
    }
    true
}

/// Return the base address of kernel32.dll, or null on failure.
#[inline(always)]
pub unsafe fn find_kernel32() -> *const u8 {
    let peb = get_peb();
    // PEB + 0x18 = *PEB_LDR_DATA
    let ldr = (peb.add(0x18) as *const *mut u8).read();
    // LDR + 0x10 = InLoadOrderModuleList head (LIST_ENTRY sentinel)
    let head = ldr.add(0x10) as *mut *mut u8;

    // Walk the circular doubly-linked list.  Each Flink points to the
    // InLoadOrderLinks field of the next LDR_DATA_TABLE_ENTRY, which is
    // at offset 0, so the Flink value IS the LDR_DATA_TABLE_ENTRY pointer.
    let mut entry = (*head) as *mut u8;

    while entry as *mut *mut u8 != head {
        // BaseDllName.Length (u16, in bytes) at entry + 0x58
        let name_bytes = (entry.add(0x58) as *const u16).read_unaligned() as usize;
        // BaseDllName.Buffer at entry + 0x60
        let name_buf   = (entry.add(0x60) as *const *const u16).read_unaligned();
        // DllBase at entry + 0x30
        let dll_base   = (entry.add(0x30) as *const *const u8).read_unaligned();

        // Length is in bytes; each UTF-16 char is 2 bytes
        let name_chars = name_bytes / 2;

        if !name_buf.is_null() && is_kernel32(name_buf, name_chars) {
            return dll_base;
        }

        // Advance: InLoadOrderLinks.Flink is at offset 0
        entry = (*( entry as *const *mut u8 )) as *mut u8;
    }

    core::ptr::null()
}
