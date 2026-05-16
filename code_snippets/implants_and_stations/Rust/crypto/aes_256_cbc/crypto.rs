// crypto.rs
// AES-256-CBC encrypt/decrypt matching station.py and payroll.ps1.
// Encrypt returns base64 ciphertext.
// Decrypt takes base64 ciphertext and returns plaintext string.

use aes::Aes256;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};

type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;

const BLOCK: usize = 16;

pub fn encrypt(plaintext: &str, key: &[u8; 32], iv: &[u8; 16]) -> String {
    let pt = plaintext.as_bytes();
    // PKCS7 always adds padding — allocate one extra block when already aligned
    let plen = pt.len() + (BLOCK - pt.len() % BLOCK);
    let mut buf = vec![0u8; plen];
    buf[..pt.len()].copy_from_slice(pt);
    let ct = Aes256CbcEnc::new(key.into(), iv.into())
        .encrypt_padded_mut::<Pkcs7>(&mut buf, pt.len())
        .expect("encrypt");
    B64.encode(ct)
}

/// Decrypt raw AES-256-CBC ciphertext bytes → raw plaintext bytes.
/// Used for binary payloads (shellcode) where base64 encoding is not desired.
pub fn decrypt_bytes(ct: &[u8], key: &[u8; 32], iv: &[u8; 16]) -> Result<Vec<u8>, String> {
    let mut buf = ct.to_vec();
    Aes256CbcDec::new(key.into(), iv.into())
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map(|pt| pt.to_vec())
        .map_err(|e| format!("decrypt: {e}"))
}

pub fn decrypt(b64_ct: &str, key: &[u8; 32], iv: &[u8; 16]) -> Result<String, String> {
    let ct      = B64.decode(b64_ct).map_err(|e| format!("base64: {e}"))?;
    let mut buf = ct.clone();
    let pt      = Aes256CbcDec::new(key.into(), iv.into())
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|e| format!("decrypt: {e}"))?;
    String::from_utf8(pt.to_vec()).map_err(|e| format!("utf8: {e}"))
}
