"""Tests for the Oids retention-purge job (purge.py).

Covers policy §2/§5: 30-day hard-delete of accounts past their deletion
window (with tombstone + safety-hold rules), and the rolling 90-day caps
on telemetry and IP history. Runs against a local sqlite DB built from
schema.sql + migrations/ — never touches production.
"""
import sys
import os
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.expanduser("~/workspace/oids"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from db import build_test_db
import purge

NOW = datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc)


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def days_ago(n, seconds=0):
    return iso(NOW - timedelta(days=n, seconds=seconds))


class PurgeTest(unittest.TestCase):
    def setUp(self):
        self.con = build_test_db()
        self.c = self.con.cursor()

    def tearDown(self):
        self.con.close()

    # ---- seeding helpers ----
    def add_agent(self, username, deletion_requested_at=None, created_days_ago=100,
                  signup_ip="9.9.9.9", terms_version="v1.5"):
        self.c.execute(
            """INSERT INTO agents (username, password_hash, created_at, terms_version,
               terms_accepted_at, signup_ip, deletion_requested_at)
               VALUES (?, 'hp', ?, ?, ?, ?, ?)""",
            (username, days_ago(created_days_ago), terms_version,
             days_ago(created_days_ago), signup_ip, deletion_requested_at))
        return self.c.lastrowid

    def seed_full_account(self, username, del_days_ago):
        """An account with data in every purged table. Returns agent id."""
        aid = self.add_agent(username, days_ago(del_days_ago) if del_days_ago else None)
        other = self.add_agent(username + "_peer")
        self.c.execute("INSERT INTO api_keys (agent_id, key_hash, revoked) VALUES (?, ?, 0)", (aid, 'k1_' + username))
        self.c.execute("INSERT INTO api_keys (agent_id, key_hash, revoked) VALUES (?, ?, 1)", (aid, 'k2_' + username))
        self.c.execute("INSERT INTO posts (agent_id, content) VALUES (?, 'hello')", (aid,))
        pid = self.c.lastrowid
        self.c.execute("INSERT INTO post_tags (post_id, tag) VALUES (?, 't')", (pid,))
        self.c.execute("INSERT INTO posts (agent_id, content) VALUES (?, 'peer post')", (other,))
        peer_pid = self.c.lastrowid
        self.c.execute("INSERT INTO likes (post_id, agent_id) VALUES (?, ?)", (peer_pid, aid))  # like given
        self.c.execute("INSERT INTO likes (post_id, agent_id) VALUES (?, ?)", (pid, other))     # like received
        # DMs: one sent (tombstone), one received (delete), one sent blocked (evidence: keep)
        self.c.execute("INSERT INTO dms (from_agent_id, to_agent_id, content, blocked) VALUES (?, ?, 'sent-msg', 0)",
                       (aid, other))
        self.sent_dm = self.c.lastrowid
        self.c.execute("INSERT INTO dms (from_agent_id, to_agent_id, content, blocked) VALUES (?, ?, 'recv-msg', 0)",
                       (other, aid))
        self.c.execute("INSERT INTO dms (from_agent_id, to_agent_id, content, blocked) VALUES (?, ?, 'EVIL', 1)",
                       (aid, other))
        self.blocked_dm = self.c.lastrowid
        # room messages: one sent (tombstone), one sent blocked (evidence: keep)
        self.c.execute("INSERT INTO rooms (name, created_by) VALUES ('r', ?)", (other,))
        rid = self.c.lastrowid
        self.c.execute("INSERT INTO room_members (room_id, agent_id) VALUES (?, ?)", (rid, aid))
        self.c.execute("INSERT INTO room_messages (room_id, from_agent_id, content, blocked) VALUES (?, ?, 'room-msg', 0)",
                       (rid, aid))
        self.c.execute("INSERT INTO room_messages (room_id, from_agent_id, content, blocked) VALUES (?, ?, 'EVIL2', 1)",
                       (rid, aid))
        self.c.execute("INSERT INTO client_events (agent_id, client_type, ip) VALUES (?, 'api', '1.1.1.1')", (aid,))
        self.c.execute("INSERT INTO invite_codes (code, created_by, redeemed_by, created_at) VALUES (?, ?, ?, ?)",
                       ('C_' + username, other, aid, days_ago(50)))
        self.con.commit()
        return aid

    def table_count(self, table, where="", params=()):
        return self.c.execute(f"SELECT COUNT(*) FROM {table} {where}", params).fetchone()[0]

    # ---- 30-day account purge ----
    def test_old_account_fully_purged(self):
        aid = self.seed_full_account("gone", 31)
        report = purge.run(self.con, iso(NOW), dry_run=False)
        self.assertEqual(self.table_count("agents", "WHERE id=?", (aid,)), 0)
        self.assertEqual(self.table_count("api_keys", "WHERE agent_id=?", (aid,)), 0)
        self.assertEqual(self.table_count("posts", "WHERE agent_id=?", (aid,)), 0)
        self.assertEqual(self.table_count("post_tags"), 0)
        self.assertEqual(self.table_count("likes", "WHERE agent_id=? OR post_id IN (SELECT id FROM posts WHERE agent_id=?)", (aid, aid)), 0)
        self.assertEqual(self.table_count("room_members", "WHERE agent_id=?", (aid,)), 0)
        self.assertEqual(self.table_count("client_events", "WHERE agent_id=?", (aid,)), 0)
        # receipt kept: username reserved + minimal consent record
        row = self.c.execute("SELECT username, terms_version, terms_accepted_at FROM purged_accounts WHERE agent_id=?",
                             (aid,)).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row[0], "gone")
        self.assertEqual(row[1], "v1.5")
        self.assertIsNotNone(row[2])
        self.assertGreater(report["accounts_purged"], 0)

    def test_tombstone_rules(self):
        aid = self.seed_full_account("gone2", 31)
        purge.run(self.con, iso(NOW), dry_run=False)
        # sent DM -> tombstone, content replaced, row kept for the peer
        content = self.c.execute("SELECT content FROM dms WHERE id=?", (self.sent_dm,)).fetchone()[0]
        self.assertEqual(content, purge.TOMBSTONE)
        # received DM -> hard deleted
        self.assertEqual(self.table_count("dms", "WHERE to_agent_id=? AND blocked=0", (aid,)), 0)
        # blocked (evidence) DM -> kept WITH original content
        row = self.c.execute("SELECT content, blocked FROM dms WHERE id=?", (self.blocked_dm,)).fetchone()
        self.assertEqual(row, ("EVIL", 1))
        # room message sent -> tombstone; blocked room message -> kept with content
        self.assertEqual(self.table_count("room_messages", "WHERE from_agent_id=? AND content=? AND blocked=0",
                                          (aid, purge.TOMBSTONE)), 1)
        self.assertEqual(self.table_count("room_messages", "WHERE content='EVIL2' AND blocked=1"), 1)

    def test_invite_link_severed(self):
        aid = self.seed_full_account("gone3", 31)
        purge.run(self.con, iso(NOW), dry_run=False)
        row = self.c.execute("SELECT redeemed_by FROM invite_codes WHERE code=?", ('C_gone3',)).fetchone()
        self.assertIsNone(row[0])  # link purged; the code row itself survives

    def test_boundary_exactly_30_days_purged(self):
        aid = self.add_agent("edge", days_ago(30))
        purge.run(self.con, iso(NOW), dry_run=False)
        self.assertEqual(self.table_count("agents", "WHERE id=?", (aid,)), 0)

    def test_just_under_30_days_kept(self):
        aid = self.add_agent("almost", days_ago(29, seconds=86399))  # 29d 23:59:59
        purge.run(self.con, iso(NOW), dry_run=False)
        self.assertEqual(self.table_count("agents", "WHERE id=?", (aid,)), 1)
        self.assertEqual(self.table_count("purged_accounts", "WHERE agent_id=?", (aid,)), 0)

    def test_fresh_deletion_request_kept(self):
        aid = self.seed_full_account("waiting", 10)
        report = purge.run(self.con, iso(NOW), dry_run=False)
        self.assertEqual(self.table_count("agents", "WHERE id=?", (aid,)), 1)
        self.assertEqual(report["accounts_purged"], 0)

    def test_active_account_untouched(self):
        aid = self.seed_full_account("active", None)
        purge.run(self.con, iso(NOW), dry_run=False)
        self.assertEqual(self.table_count("agents", "WHERE id=?", (aid,)), 1)
        self.assertEqual(self.table_count("posts", "WHERE agent_id=?", (aid,)), 1)

    def test_legal_hold_skipped(self):
        aid = self.seed_full_account("held", 40)
        report = purge.run(self.con, iso(NOW), dry_run=False, hold_ids={aid})
        self.assertEqual(self.table_count("agents", "WHERE id=?", (aid,)), 1)
        self.assertEqual(report.get("accounts_held", 0), 1)

    def test_multiple_accounts_one_run(self):
        a1 = self.seed_full_account("gone_a", 31)
        a2 = self.seed_full_account("gone_b", 60)
        a3 = self.seed_full_account("stay", 5)
        report = purge.run(self.con, iso(NOW), dry_run=False)
        self.assertEqual(report["accounts_purged"], 2)
        for aid in (a1, a2):
            self.assertEqual(self.table_count("agents", "WHERE id=?", (aid,)), 0)
        self.assertEqual(self.table_count("agents", "WHERE id=?", (a3,)), 1)

    def test_dry_run_changes_nothing_but_reports(self):
        aid = self.seed_full_account("dry", 31)
        report = purge.run(self.con, iso(NOW), dry_run=True)
        self.assertEqual(self.table_count("agents", "WHERE id=?", (aid,)), 1)
        self.assertEqual(self.table_count("purged_accounts"), 0)
        self.assertGreater(report["accounts_purged"], 0)  # would-be count

    # ---- rolling 90-day caps (policy §2: telemetry + IP history) ----
    def test_telemetry_90day_cap(self):
        aid = self.add_agent("tele", created_days_ago=10)
        self.c.execute("INSERT INTO client_events (agent_id, client_type, created_at) VALUES (?, 'api', ?)",
                       (aid, days_ago(100)))
        self.c.execute("INSERT INTO client_events (agent_id, client_type, created_at) VALUES (?, 'browser', ?)",
                       (aid, days_ago(10)))
        purge.run(self.con, iso(NOW), dry_run=False)
        rows = self.c.execute("SELECT client_type FROM client_events WHERE agent_id=?", (aid,)).fetchall()
        self.assertEqual([r[0] for r in rows], ["browser"])

    def test_signup_ip_90day_cap(self):
        old = self.add_agent("oldip", created_days_ago=100, signup_ip="9.9.9.9")
        new = self.add_agent("newip", created_days_ago=10, signup_ip="8.8.8.8")
        purge.run(self.con, iso(NOW), dry_run=False)
        self.assertIsNone(self.c.execute("SELECT signup_ip FROM agents WHERE id=?", (old,)).fetchone()[0])
        self.assertEqual(self.c.execute("SELECT signup_ip FROM agents WHERE id=?", (new,)).fetchone()[0], "8.8.8.8")

    def test_telemetry_dry_run(self):
        aid = self.add_agent("teledry", created_days_ago=10)
        self.c.execute("INSERT INTO client_events (agent_id, client_type, created_at) VALUES (?, 'api', ?)",
                       (aid, days_ago(100)))
        report = purge.run(self.con, iso(NOW), dry_run=True)
        self.assertEqual(self.table_count("client_events", "WHERE agent_id=?", (aid,)), 1)
        self.assertEqual(report["telemetry_rows_expired"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
