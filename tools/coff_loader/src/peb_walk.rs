// peb_walk.rs — Find kernel32.dll base via PEB InLoadOrderModuleList.
//
// x64 offsets (stable since Windows Vista):
//   GS:[0x60]          → *PEB
//   PEB  + 0x18        → *PEB_LDR_DATA
//   LDR  + 0x10        → InLoadOrderModuleList LIST_ENTRY (head sentinel)
//   LDR_DATA_TABLE_ENTRY:
//     +0x00  InLoadOrderLinks.Flink
//     +0x30  DllBase
//     +0x58  BaseDllName.Length  (byte count)
//     +0x60  BaseDllName.Buffer  (*const u16)

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
    while i < chars {
        let c = *buf.add(i);
        let cl = if c >= b'A' as u16 && c <= b'Z' as u16 { c + 0x20 } else { c };
        if cl != target[i] { return false; }
        i += 1;
    }
    true
}

const KERNEL32: [u16; 12] = [
    b'k' as u16, b'e' as u16, b'r' as u16, b'n' as u16,
    b'e' as u16, b'l' as u16, b'3' as u16, b'2' as u16,
    b'.'  as u16, b'd' as u16, b'l' as u16, b'l' as u16,
];

/// Return the base address of kernel32.dll, or null on failure.
#[inline(always)]
pub unsafe fn find_kernel32() -> *const u8 {
    walk_ldr(&KERNEL32)
}

unsafe fn walk_ldr(target: &[u16]) -> *const u8 {
    let peb  = get_peb();
    let ldr  = (peb.add(0x18) as *const *mut u8).read();
    let head = ldr.add(0x10) as *mut *mut u8;
    let mut entry = (*head) as *mut u8;

    while entry as *mut *mut u8 != head {
        let name_bytes = (entry.add(0x58) as *const u16).read_unaligned() as usize;
        let name_buf   = (entry.add(0x60) as *const *const u16).read_unaligned();
        let dll_base   = (entry.add(0x30) as *const *const u8).read_unaligned();

        if !name_buf.is_null() && name_matches(name_buf, name_bytes / 2, target) {
            return dll_base;
        }
        entry = (*(entry as *const *mut u8)) as *mut u8;
    }
    core::ptr::null()
}
