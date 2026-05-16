// crypto.rs — AES-256-CBC (PKCS7) variant of the stager_crypto component.
//
// Shared contract (every stager_crypto variant must expose this signature):
//
//     pub fn decrypt_in_place(key: &[u8], iv: &[u8], buf: &mut [u8]) -> Option<usize>
//
// - `key` and `iv` are passed raw; sizes are cipher-specific (this variant
//   requires 32-byte key, 16-byte IV).
// - Decryption happens in place on `buf`. On success the returned `usize` is
//   the plaintext length (PKCS7 padding stripped for block ciphers); the
//   caller slices `&buf[..len]` to get the plaintext.
// - Returns `None` on any failure (bad size, bad padding, bad ciphertext).
//
// Swapping this file for another variant (xor, chacha20, etc.) is the only
// source change required — main.rs calls `crate::crypto::decrypt_in_place`.

use aes::Aes256;
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};

type Aes256CbcDec = cbc::Decryptor<Aes256>;

pub fn decrypt_in_place(key: &[u8], iv: &[u8], buf: &mut [u8]) -> Option<usize> {
    if key.len() != 32 || iv.len() != 16 {
        return None;
    }
    // The cbc crate takes fixed-size arrays for key/iv; convert from slices.
    let k: &[u8; 32] = key.try_into().ok()?;
    let i: &[u8; 16] = iv.try_into().ok()?;
    let dec = Aes256CbcDec::new(k.into(), i.into());
    match dec.decrypt_padded_mut::<Pkcs7>(buf) {
        Ok(pt) => Some(pt.len()),
        Err(_) => None,
    }
}
