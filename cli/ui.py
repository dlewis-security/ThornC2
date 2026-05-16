"""ANSI colours, print helpers, and table/output renderers."""

import re
from datetime import datetime

RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[38;5;196m"
GREEN  = "\033[38;5;82m"
YELLOW = "\033[38;5;220m"
GREY   = "\033[38;5;245m"

ANSI_RE = re.compile(r"\033\[[0-9;]*m")

# ── Themes ────────────────────────────────────────────────────────────────────
# Each theme defines three roles:
#   primary   — banner and major chrome
#   accent    — section headers, sub-headers
#   highlight — command names, active rat in prompt

THEMES = {
    'default': {
        'primary':   "\033[38;5;196m",   # red
        'accent':    "\033[38;5;214m",   # orange
        'highlight': "\033[38;5;117m",   # cyan
    },
    'green': {
        'primary':   "\033[38;5;82m",    # bright green
        'accent':    "\033[38;5;213m",   # pink          (contrasts green)
        'highlight': "\033[38;5;82m",    # bright green
    },
    'blue': {
        'primary':   "\033[38;5;33m",    # medium blue
        'accent':    "\033[38;5;214m",   # orange        (contrasts blue)
        'highlight': "\033[38;5;75m",    # sky blue
    },
    'purple': {
        'primary':   "\033[38;5;129m",   # violet
        'accent':    "\033[38;5;220m",   # gold          (contrasts purple)
        'highlight': "\033[38;5;183m",   # lavender
    },
    'mono': {
        'primary':   "",
        'accent':    "",
        'highlight': "",
    },
}

_T = dict(THEMES['default'])   # active theme — mutated by set_theme()

def set_theme(name: str) -> bool:
    if name not in THEMES:
        return False
    _T.update(THEMES[name])
    return True

def get_themes() -> list:
    return list(THEMES.keys())

# ── Colour helpers ────────────────────────────────────────────────────────────

def strip_ansi(s): return ANSI_RE.sub("", str(s))
def vlen(s):       return len(strip_ansi(s))
def bold(s):       return f"{BOLD}{s}{RESET}"
def green(s):      return f"{GREEN}{s}{RESET}"
def yellow(s):     return f"{YELLOW}{s}{RESET}"
def grey(s):       return f"{GREY}{s}{RESET}"
# Themed helpers — read _T at call time so they update with set_theme()
def primary(s):    return f"{_T['primary']}{s}{RESET}"
def cyan(s):       return f"{_T['highlight']}{s}{RESET}"
def orange(s):     return f"{_T['accent']}{s}{RESET}"

def ok(msg):   print(f"  {GREEN}✓{RESET}  {msg}")
def err(msg):  print(f"  {RED}✗{RESET}  {msg}")
def info(msg): print(f"  {_T['highlight']}·{RESET}  {msg}")
def warn(msg): print(f"  {YELLOW}!{RESET}  {msg}")

# ── Time helpers ───────────────────────────────────────────────────────────────

def fmt_ts(ts_ms):
    if not ts_ms:
        return grey("—")
    return datetime.fromtimestamp(ts_ms / 1000).strftime("%Y-%m-%d %H:%M:%S")

def time_ago(ts_ms, ref_ms=None):
    if not ts_ms:
        return grey("—")
    now_ms = ref_ms if ref_ms is not None else datetime.now().timestamp() * 1000
    secs = (now_ms - ts_ms) / 1000
    if secs <  60:   return green(f"{int(secs)}s ago")
    if secs < 3600:  return green(f"{int(secs/60)}m ago")
    if secs < 86400: return yellow(f"{int(secs/3600)}h ago")
    return grey(f"{int(secs/86400)}d ago")

def rat_status(last_seen_ms, ref_ms=None):
    if not last_seen_ms:
        return grey("● unknown")
    now_ms = ref_ms if ref_ms is not None else datetime.now().timestamp() * 1000
    secs = (now_ms - last_seen_ms) / 1000
    if secs <  300:  return green("● active")
    if secs < 3600:  return yellow("◌ idle")
    return grey("○ stale")

def task_status(t):
    if t.get("completed_at", 0): return green("✓ done")
    if t.get("retrieved_at", 0): return yellow("⟳ running")
    return cyan("· pending")

# ── Table renderer ─────────────────────────────────────────────────────────────

def pad(cell, width):
    return cell + " " * max(0, width - vlen(cell))

def table(rows, headers, *, max_col=60, title=None):
    if not rows:
        print(f"  {grey('(none)')}\n")
        return

    col_w    = [vlen(h) for h in headers]
    str_rows = [[str(c) for c in row] for row in rows]

    for row in str_rows:
        for i, cell in enumerate(row):
            col_w[i] = min(max_col, max(col_w[i], vlen(cell)))

    sep = "  " + "  ".join("─" * w for w in col_w)
    hdr = "  " + "  ".join(pad(bold(cyan(h)), col_w[i]) for i, h in enumerate(headers))

    if title:
        print(f"\n  {bold(title)}")
    print(hdr)
    print(sep)
    for row in str_rows:
        cells = []
        for i, cell in enumerate(row):
            raw = strip_ansi(cell)
            if len(raw) > max_col:
                cell = cell[:max_col - 1] + grey("…")
            cells.append(pad(cell, col_w[i]))
        print("  " + "  ".join(cells))
    print()

def print_output(output):
    if not output:
        print(f"\n  {grey('(no output)')}\n")
        return
    print(f"\n  {bold('Output:')}")
    print(f"  {'─' * 60}")
    for line in str(output).splitlines():
        print(f"  {line}")
    print()
