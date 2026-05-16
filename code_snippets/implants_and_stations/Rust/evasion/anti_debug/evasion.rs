// evasion.rs — Anti-debug checks
//
// Three checks run at startup:
//   1. IsDebuggerPresent API
//   2. PEB BeingDebugged flag (catches some API-level spoofs)
//   3. Hardware breakpoint registers Dr0-Dr3 via GetThreadContext
//
// Any positive detection causes a clean silent exit. The sysinfo process-
// list approach was intentionally omitted — it adds a large dependency and
// is trivially bypassed by renaming the debugger binary.

use windows::Win32::System::Diagnostics::Debug::{
    GetThreadContext, IsDebuggerPresent, CONTEXT, CONTEXT_FLAGS,
};
use windows::Win32::System::Threading::GetCurrentThread;

// CONTEXT_AMD64 (0x00100000) | CONTEXT_DEBUG_REGISTERS (0x00000010).
// windows crate 0.58 does not export this combination as a named constant.
const CONTEXT_DEBUG_REGISTERS_AMD64: CONTEXT_FLAGS = CONTEXT_FLAGS(0x0010_0010);

pub fn evade() {
    if debugger_detected() {
        std::process::exit(0);
    }
}

fn debugger_detected() -> bool {
    unsafe {
        // Check 1: IsDebuggerPresent
        if IsDebuggerPresent().as_bool() {
            return true;
        }

        // Check 2: PEB BeingDebugged — read via gs:[0x60]+2 without importing
        // the PEB struct (avoids the Win32_System_Internals feature dependency).
        if peb_being_debugged() {
            return true;
        }

        // Check 3: Hardware breakpoints in Dr0-Dr3
        if hardware_breakpoints_set() {
            return true;
        }
    }
    false
}

#[inline(always)]
unsafe fn peb_being_debugged() -> bool {
    // BeingDebugged is at PEB+2 (x64). We read the raw pointer from gs:[0x60]
    // and index directly rather than importing the windows PEB struct.
    #[cfg(target_arch = "x86_64")]
    {
        let peb: u64;
        core::arch::asm!(
            "mov {}, gs:[0x60]",
            lateout(reg) peb,
            options(nostack, pure, readonly),
        );
        if peb == 0 { return false; }
        *(peb as *const u8).add(2) != 0
    }
    #[cfg(target_arch = "x86")]
    {
        let peb: u32;
        core::arch::asm!(
            "mov {:e}, fs:[0x30]",
            lateout(reg) peb,
            options(nostack, pure, readonly),
        );
        if peb == 0 { return false; }
        *(peb as *const u8).add(2) != 0
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    { false }
}

unsafe fn hardware_breakpoints_set() -> bool {
    let mut ctx = CONTEXT {
        ContextFlags: CONTEXT_DEBUG_REGISTERS_AMD64,
        ..Default::default()
    };
    if GetThreadContext(GetCurrentThread(), &mut ctx).is_err() {
        return false;
    }
    ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0
}
