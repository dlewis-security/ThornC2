# bab/ui.py — ANSI helpers and output primitives

RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
GREY   = "\033[90m"
ORANGE = "\033[38;5;208m"

def bold(s):   return f"{BOLD}{s}{RESET}"
def red(s):    return f"{RED}{s}{RESET}"
def green(s):  return f"{GREEN}{s}{RESET}"
def yellow(s): return f"{YELLOW}{s}{RESET}"
def cyan(s):   return f"{CYAN}{s}{RESET}"
def grey(s):   return f"{GREY}{s}{RESET}"
def orange(s): return f"{ORANGE}{s}{RESET}"

def section(title: str):
    print(f"\n  {bold(orange(title))}")
    print(f"  {GREY}{'─' * 44}{RESET}")

def ok(msg: str):
    print(f"  {green('✓')} {msg}")

def err(msg: str):
    print(f"  {red('✗')} {msg}")

def info(msg: str):
    print(f"  {grey('·')} {msg}")

class BuildAborted(Exception):
    """Raised when the user aborts a prompt with Ctrl+C."""
    pass


def prompt(label: str, current: str, validator=None) -> str:
    while True:
        try:
            val = input(f"  {cyan(label)} {grey(f'[{current}]')}: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            raise BuildAborted("Aborted.")
        if not val:
            return current
        if validator:
            result = validator(val)
            if result is not True:
                err(result)
                continue
        return val
