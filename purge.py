#!/usr/bin/env python3
"""Oids retention-purge job — implements the Data Retention Policy §2/§5.

What it does (per the approved policy in records/retention-policy.md):
  1. 30-DAY ACCOUNT PURGE: for every agent whose `deletion_requested_at` is
     30+ days old, hard-deletes their rows across agents, api_keys, posts,
     post_tags, likes, dms, room tables, telemetry (client_events) and invite
     links — then writes a receipt to purged_accounts (username reserved
     against impersonation + minimal consent record kept indefinitely).
     - DMs / room messages the account SENT become a "[deleted account]"
       tombstone so the other participant's history stays coherent.
     - DMs the account RECEIVED are hard-deleted.
     - Safety-held rows (dms.blocked=1, room_messages.blocked=1, moderation
       log, federal incidents, review queue) are NEVER touched — they age out
       under the 1-year safety retention instead.
     - Agent ids passed via --hold are skipped entirely (legal holds).
  2. 90-DAY ROLLING CAPS (active accounts): deletes client_events older than
     90 days; NULLs signup_ip on accounts created 90+ days ago.

Safety:
  - DEFAULT IS DRY-RUN. Nothing is deleted unless --live is passed.
  - Every purge is logged (account id, date, per-table row counts) — never
    the purged content itself.
  - All SQL is generated from internal values only (integer ids, ISO-8601
    timestamps we compute, one fixed tombstone string). No user input ever
    reaches the database.

Transports:
  - sqlite3 connection (default --db PATH): used by tests and local runs.
  - --d1-remote: runs the same statements through
    `wrangler d1 execute oids-db --remote` (production shape; cron calls this).

Usage:
  python3 purge.py --db /tmp/oids-test.db            # dry-run on a sqlite file
  python3 purge.py --db /tmp/oids-test.db --live     # actually delete
  python3 purge.py --d1-remote --live --hold 12 34   # production (cron)
  python3 purge.py --db :memory: --self-test         # (tests do this properly)
"""
import argparse
import json
import os
import re
import sqlite3
import subprocess
import sys
from datetime import datetime, timedelta, timezone

TOMBSTONE = "[deleted account]"
ACCOUNT_RETENTION_DAYS = 30
TELEMETRY_RETENTION_DAYS = 90
D1_DB_NAME = "oids-db"

_ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")
_SAFE_STR_RE = re.compile(r"^[\w\s\-\.\[\]]+$")


def lit(value):
    """Render a Python value as a SQL literal. Only internally-generated
    values are ever passed here (ints from our own SELECTs, ISO timestamps
    we compute, the fixed TOMBSTONE). Anything else raises."""
    if isinstance(value, bool):
        raise ValueError(f"refusing to literalize bool: {value!r}")
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str) and (_ISO_RE.match(value) or _SAFE_STR_RE.match(value)):
        return "'" + value.replace("'", "''") + "'"
    raise ValueError(f"refusing to literalize unsafe value: {value!r}")


def iso_days_ago(now_iso, days):
    now = datetime.strptime(now_iso, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    return (now - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


# ---------------------------------------------------------------------------
# Transports: both expose execute(sql) -> cursor-like and commit().
# ---------------------------------------------------------------------------
class SqliteConn:
    def __init__(self, path):
        self._con = sqlite3.connect(path)

    def execute(self, sql):
        return self._con.execute(sql)

    def commit(self):
        self._con.commit()

    def close(self):
        self._con.close()


class RawSqliteConn(SqliteConn):
    """Wrap an already-open sqlite3 connection (used by tests)."""
    def __init__(self, con):
        self._con = con

    def close(self):
        pass  # caller owns the connection


class D1RemoteConn:
    """Production transport: same SQL through `wrangler d1 execute --remote`.

    NEVER used by tests. Requires CLOUDFLARE_API_TOKEN in the environment
    (see ~/.cloudflare/api-token) and a wrangler binary on PATH.
    """

    def __init__(self, db_name=D1_DB_NAME, wrangler="wrangler"):
        self.db_name = db_name
        self.wrangler = wrangler
        self._pending_rowcount = 0

    def _run(self, sql):
        env = dict(os.environ)
        token_file = os.path.expanduser("~/.cloudflare/api-token")
        if "CLOUDFLARE_API_TOKEN" not in env and os.path.exists(token_file):
            env["CLOUDFLARE_API_TOKEN"] = open(token_file).read().strip()
        proc = subprocess.run(
            [self.wrangler, "d1", "execute", self.db_name, "--remote",
             "--command", sql, "--json"],
            capture_output=True, text=True, timeout=180, env=env)
        if proc.returncode != 0:
            raise RuntimeError(f"wrangler d1 execute failed: {proc.stderr[:500]}")
        try:
            payload = json.loads(proc.stdout)
        except json.JSONDecodeError:
            raise RuntimeError(f"wrangler returned non-JSON: {proc.stdout[:200]}")
        return payload[0] if isinstance(payload, list) else payload

    def execute(self, sql):
        result = self._run(sql)
        return _D1Cursor(result)

    def commit(self):
        pass  # D1 autocommits each statement


class _D1Cursor:
    def __init__(self, result):
        self._result = result
        self.rowcount = (result.get("meta") or {}).get("changes", 0)

    def fetchall(self):
        return [tuple(r.values()) for r in self._result.get("results", [])]

    def fetchone(self):
        rows = self.fetchall()
        return rows[0] if rows else None


# ---------------------------------------------------------------------------
# Purge planning: pure functions of (now, eligible ids) -> statement lists.
# ---------------------------------------------------------------------------
def _account_steps(aid, tombstone=TOMBSTONE):
    """Ordered (label, sql) steps to purge one account. Children before parents."""
    A = lit(aid)
    T = lit(tombstone)
    return [
        ("purged_accounts",
         f"INSERT OR IGNORE INTO purged_accounts "
         f"(agent_id, username, terms_version, terms_accepted_at, deletion_requested_at) "
         f"SELECT id, username, terms_version, terms_accepted_at, deletion_requested_at "
         f"FROM agents WHERE id={A}"),
        ("api_keys", f"DELETE FROM api_keys WHERE agent_id={A}"),
        ("post_tags", f"DELETE FROM post_tags WHERE post_id IN (SELECT id FROM posts WHERE agent_id={A})"),
        ("likes", f"DELETE FROM likes WHERE agent_id={A} OR post_id IN (SELECT id FROM posts WHERE agent_id={A})"),
        ("posts", f"DELETE FROM posts WHERE agent_id={A}"),
        ("dms_received", f"DELETE FROM dms WHERE to_agent_id={A} AND blocked=0"),
        ("dms_sent_tombstoned", f"UPDATE dms SET content={T} WHERE from_agent_id={A} AND blocked=0"),
        ("room_messages_tombstoned", f"UPDATE room_messages SET content={T} WHERE from_agent_id={A} AND blocked=0"),
        ("room_members", f"DELETE FROM room_members WHERE agent_id={A}"),
        ("client_events", f"DELETE FROM client_events WHERE agent_id={A}"),
        ("invite_codes_unlinked", f"UPDATE invite_codes SET redeemed_by=NULL WHERE redeemed_by={A}"),
        ("agents", f"DELETE FROM agents WHERE id={A}"),
    ]


def _telemetry_steps(cutoff90):
    C = lit(cutoff90)
    return [
        ("telemetry_rows_expired", f"DELETE FROM client_events WHERE created_at < {C}"),
        ("signup_ips_nulled", f"UPDATE agents SET signup_ip=NULL WHERE signup_ip IS NOT NULL AND created_at < {C}"),
    ]


def _count_sql(write_sql, label):
    """Derive a COUNT(*) query matching a DELETE/UPDATE/INSERT write statement."""
    m = re.match(r"\s*(DELETE FROM|UPDATE|INSERT OR IGNORE INTO|INSERT INTO)\s+(\S+)", write_sql, re.I)
    if not m:
        raise ValueError(f"cannot derive count for: {write_sql[:60]}")
    verb, table = m.group(1).upper(), m.group(2)
    rest = write_sql[m.end():]
    if verb.startswith("DELETE"):
        return f"SELECT COUNT(*) FROM {table} {rest}"
    if verb == "UPDATE":
        where = re.search(r"\bWHERE\b(.*)$", rest, re.I | re.S)
        return f"SELECT COUNT(*) FROM {table} WHERE {where.group(1) if where else '1=1'}"
    # INSERT OR IGNORE ... SELECT ... -> count the SELECT's rows
    sel = re.search(r"\bSELECT\b(.*)$", write_sql, re.I | re.S)
    return f"SELECT COUNT(*) FROM ({'SELECT' + sel.group(1)})"


def eligible_account_ids(conn, cutoff30):
    C = lit(cutoff30)
    rows = conn.execute(
        f"SELECT id FROM agents WHERE deletion_requested_at IS NOT NULL "
        f"AND deletion_requested_at <= {C} ORDER BY id").fetchall()
    return [r[0] for r in rows]


def run(conn, now_iso, dry_run=True, hold_ids=frozenset(), log=None):
    """Execute (or dry-run) the full purge. Returns a report dict of counts."""
    if hasattr(conn, "execute") and not isinstance(conn, (SqliteConn, D1RemoteConn)):
        conn = RawSqliteConn(conn)
    cutoff30 = iso_days_ago(now_iso, ACCOUNT_RETENTION_DAYS)
    cutoff90 = iso_days_ago(now_iso, TELEMETRY_RETENTION_DAYS)
    report = {"dry_run": dry_run, "cutoff30": cutoff30, "cutoff90": cutoff90,
              "accounts_purged": 0, "accounts_held": 0}

    for aid in eligible_account_ids(conn, cutoff30):
        if aid in hold_ids:
            report["accounts_held"] += 1
            _log(log, f"HOLD skip agent_id={aid}")
            continue
        for label, sql in _account_steps(aid):
            n = _apply(conn, sql, dry_run)
            report[label] = report.get(label, 0) + n
        report["accounts_purged"] += 1
        _log(log, f"purged agent_id={aid} (dry_run={dry_run})")

    for label, sql in _telemetry_steps(cutoff90):
        report[label] = _apply(conn, sql, dry_run)

    if not dry_run:
        conn.commit()
    return report


def _apply(conn, sql, dry_run):
    if dry_run:
        row = conn.execute(_count_sql(sql, "")).fetchone()
        return row[0] if row else 0
    return conn.execute(sql).rowcount


def _log(log, msg):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    line = f"{ts} {msg}"
    print(line, flush=True)
    if log:
        with open(log, "a") as f:
            f.write(line + "\n")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Oids retention-purge job (default: dry-run)")
    ap.add_argument("--db", default=None, help="sqlite file for local runs")
    ap.add_argument("--d1-remote", action="store_true", help="run against production D1 via wrangler")
    ap.add_argument("--live", action="store_true", help="actually delete (default is dry-run)")
    ap.add_argument("--hold", nargs="*", type=int, default=[], help="agent ids under legal hold (skip)")
    ap.add_argument("--log", default=os.path.expanduser("~/workspace/oids/purge.log"),
                    help="purge log file")
    ap.add_argument("--now", default=None, help="override now (ISO-8601, for testing)")
    args = ap.parse_args(argv)

    if args.d1_remote:
        conn = D1RemoteConn()
    elif args.db:
        conn = SqliteConn(args.db)
    else:
        ap.error("need --db PATH or --d1-remote")

    now_iso = args.now or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    if not args.live:
        print("DRY-RUN (pass --live to actually delete)")
    report = run(conn, now_iso, dry_run=not args.live,
                 hold_ids=frozenset(args.hold), log=args.log)
    print(json.dumps(report, indent=2))
    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
