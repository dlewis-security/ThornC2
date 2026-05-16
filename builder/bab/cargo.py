# bab/cargo.py — shared cargo/subprocess utilities
#
# Extracted from build.py so that loader.py can import these without
# creating a circular dependency (build.py ↔ loader.py).

import os
import shutil
import subprocess
from pathlib import Path

CARGO_TARGET = "x86_64-pc-windows-gnu"
_cargo_bin   = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo")) / "bin"
CARGO_ENV    = {**os.environ, "PATH": f"{_cargo_bin}:{os.environ.get('PATH', '')}"}


def _find_cargo() -> str:
    """Return path to cargo, searching common install locations."""
    found = shutil.which("cargo")
    if found:
        return found
    candidate = _cargo_bin / ("cargo.exe" if os.name == "nt" else "cargo")
    if candidate.exists():
        return str(candidate)
    raise FileNotFoundError(
        "cargo not found.\n"
        "  Install Rust:  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh\n"
        "  Then add to PATH or restart your terminal."
    )


def run_cmd(args: list, cwd=None, env=None) -> bool:
    """Stream a subprocess, return True on success."""
    proc = subprocess.Popen(
        args, cwd=cwd, env=env or CARGO_ENV,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    for line in proc.stdout:
        print(f"    {line.rstrip()}")
    proc.wait()
    return proc.returncode == 0
