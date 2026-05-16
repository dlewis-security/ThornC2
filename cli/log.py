"""LogMixin — activity log and engagement report commands."""

from datetime import datetime
from pathlib import Path

from .ui import ok, err, info, warn, bold, cyan, grey, table, fmt_ts
from .api import rat_url, check

class LogMixin:

    def do_log(self, arg):
        """log [--rat <id>] [--imp <imp_id>] [--limit <n>]  —  Show activity log (newest first)"""
        s, url = self._session()
        if not s: return
        parts  = arg.split()
        params: dict = {'limit': 50}
        i = 0
        while i < len(parts):
            if parts[i] == '--limit' and i + 1 < len(parts):
                params['limit'] = parts[i + 1]; i += 2
            elif parts[i] == '--rat' and i + 1 < len(parts):
                params['rat_id'] = parts[i + 1]; i += 2
            elif parts[i] == '--imp' and i + 1 < len(parts):
                params['imp_id'] = parts[i + 1]; i += 2
            else:
                i += 1
        resp = check(s.get(f"{url}/api/logs", params=params))
        if not resp: return
        entries = resp.json()
        if not entries:
            info("No log entries yet.")
            return

        RESET = "\033[0m"
        _COLOR = {
            'RAT_NEW':       "\033[38;5;82m",
            'TASK_QUEUED':   "\033[38;5;117m",
            'TASK_COMPLETE': "\033[38;5;220m",
            'RAT_KILLED':    "\033[38;5;196m",
        }
        imp_filter   = params.get('imp_id', '')
        title_suffix = f"  {grey(f'imp={imp_filter}')}" if imp_filter else ''
        rows = []
        for e in reversed(entries):   # oldest → newest
            ev  = e.get('event', '?')
            col = _COLOR.get(ev, RESET)
            rows.append([
                grey(fmt_ts(e.get('ts'))),
                f"{col}{ev}{RESET}",
                e.get('msg', ''),
            ])
        table(rows, ["Timestamp", "Event", "Message"],
              title=f"Activity Log{title_suffix}  {grey(f'({len(entries)} entries)')}")

    def do_report(self, arg):
        """report [--imp <imp_id>] [filename]  —  Export engagement report as markdown"""
        s, url = self._session()
        if not s: return

        # Parse --imp flag; remaining tokens become filename
        parts    = arg.split()
        imp_id   = None
        filtered = []
        i = 0
        while i < len(parts):
            if parts[i] == '--imp' and i + 1 < len(parts):
                imp_id = parts[i + 1]; i += 2
            else:
                filtered.append(parts[i]); i += 1
        leftover = ' '.join(filtered).strip()

        rats_resp = check(s.get(f"{url}/api/rats"))
        if not rats_resp: return
        rats = rats_resp.json()
        if imp_id:
            rats = [r for r in rats if r.get('imp_id') == imp_id]
        if not rats:
            warn("No rats to include in report.")
            return

        rat_tasks: dict = {}
        for rat in rats:
            t_resp = check(s.get(rat_url(url, rat['id'], 'tasks')))
            rat_tasks[rat['id']] = t_resp.json() if t_resp else []

        now      = datetime.now()
        filename = leftover or f"thorn_report_{now.strftime('%Y%m%d_%H%M%S')}.md"
        out_dir  = Path("reports")
        out_dir.mkdir(exist_ok=True)
        out_path = out_dir / filename

        def _ts(ts_ms):
            if not ts_ms: return '—'
            return datetime.fromtimestamp(ts_ms / 1000).strftime('%Y-%m-%d %H:%M:%S')

        md: list = []
        md.append("# ThornC2 Engagement Report")
        md.append("")
        md.append(f"**Generated:** {now.strftime('%Y-%m-%d %H:%M:%S')}")
        if imp_id:
            md.append(f"**Implant ID:** `{imp_id}`")
        md.append("")

        total     = sum(len(v) for v in rat_tasks.values())
        completed = sum(sum(1 for t in v if t.get('completed_at', 0)) for v in rat_tasks.values())
        md.append("## Summary")
        md.append("")
        md.append("| | |")
        md.append("|---|---|")
        md.append(f"| Hosts compromised | {len(rats)} |")
        md.append(f"| Tasks dispatched  | {total} |")
        md.append(f"| Tasks completed   | {completed} |")
        md.append("")
        md.append("---")
        md.append("")
        md.append("## Hosts")
        md.append("")

        for rat in sorted(rats, key=lambda r: r.get('first_seen', 0)):
            user   = rat.get('user',   '?')
            host   = rat.get('host',   '?')
            domain = rat.get('domain', '?')
            md.append(f"### {host}")
            md.append("")
            md.append("| | |")
            md.append("|---|---|")
            md.append(f"| User          | `{user}@{domain}` |")
            md.append(f"| First contact | {_ts(rat.get('first_seen'))} |")
            md.append(f"| Last seen     | {_ts(rat.get('last_seen'))} |")
            md.append(f"| Rat ID        | `{rat['id']}` |")
            md.append("")

            done = sorted(
                [t for t in rat_tasks[rat['id']] if t.get('completed_at', 0)],
                key=lambda t: t.get('scheduled_at', 0)
            )
            if done:
                md.append(f"#### Tasks ({len(done)} completed)")
                md.append("")
                for t in done:
                    display = t.get('display') or t.get('id', '?')
                    output  = (t.get('output') or '').strip()
                    md.append(f"**{_ts(t.get('scheduled_at'))}** — {display}")
                    md.append("")
                    if output:
                        md.append("```")
                        md.append(output[:3000])
                        md.append("```")
                        md.append("")
            else:
                md.append("*No completed tasks.*")
                md.append("")

            md.append("---")
            md.append("")

        out_path.write_text("\n".join(md))
        ok(f"Report written  →  {cyan(str(out_path))}")
