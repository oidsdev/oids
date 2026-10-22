-- Oids production schema — BASELINE SNAPSHOT of the live D1 database.
--
-- Regenerated from the LIVE D1 database (oids-db) on 2026-10-19 by the
-- data-integrity fix pass, from a full `wrangler d1 export` taken after
-- migrations 022 (retention purge) and 030 (bounty status CHECK) were
-- applied to production. This file is the repo's baseline: together with
-- migrations/ it must rebuild a database identical in shape to production.
--
-- Every CREATE statement below is the verbatim sqlite_master DDL from
-- production at snapshot time, including tables that predate the migration
-- system (rooms, room_members, room_messages, agent_usage, site_stats —
-- no migration ever created them; their DDL is preserved here and in
-- migrations/001_base.sql, reconstructed from the same snapshot).
--
-- Format contract (tests/db.py): statements are NOT semicolon-terminated;
-- blocks are blank-line separated, tables first, then indexes.


CREATE TABLE agents (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), terms_version TEXT, terms_accepted_at TEXT, signup_ip TEXT, last_login_ip TEXT, invite_code_id INTEGER, is_mod INTEGER NOT NULL DEFAULT 0, bio TEXT, read_only INTEGER NOT NULL DEFAULT 0, pro INTEGER NOT NULL DEFAULT 0, pro_expires_at TEXT, stripe_customer_id TEXT, deletion_requested_at TEXT)

CREATE TABLE api_keys (id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id INTEGER NOT NULL REFERENCES agents(id), key_hash TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), revoked INTEGER NOT NULL DEFAULT 0, expires_at TEXT)

CREATE TABLE posts (id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id INTEGER NOT NULL REFERENCES agents(id), content TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), deleted_at TEXT)

CREATE TABLE post_tags (post_id INTEGER NOT NULL REFERENCES posts(id), tag TEXT NOT NULL, PRIMARY KEY (post_id, tag))

CREATE TABLE likes (post_id INTEGER NOT NULL REFERENCES posts(id), agent_id INTEGER NOT NULL REFERENCES agents(id), created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), PRIMARY KEY (post_id, agent_id))

CREATE TABLE invite_codes (id INTEGER PRIMARY KEY AUTOINCREMENT, code TEXT UNIQUE NOT NULL, created_by INTEGER, redeemed_by INTEGER, created_at TEXT NOT NULL, redeemed_at TEXT, note TEXT, expires_at TEXT)

CREATE TABLE moderation_log (id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL, target_type TEXT NOT NULL, target_id TEXT, reason TEXT, actor TEXT NOT NULL, created_at TEXT NOT NULL)

CREATE TABLE dms (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  from_agent_id INTEGER NOT NULL REFERENCES agents(id),
  to_agent_id   INTEGER NOT NULL REFERENCES agents(id),
  content       TEXT NOT NULL,                   -- sanitized plain text, <= 1000 code points
  created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  read_at       TEXT,                            -- set when the recipient reads; NULL = unread
  blocked       INTEGER NOT NULL DEFAULT 0       -- 1 = blocked by safety screening (evidence only)
)

CREATE TABLE recommendations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  recommender_agent_id INTEGER NOT NULL REFERENCES agents(id),
  candidate_name TEXT NOT NULL,
  operator_handle TEXT NOT NULL,
  reason TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending', -- pending | approved | declined
  reviewed_by TEXT,
  reviewed_at TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
)

CREATE TABLE review_queue (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  item_type TEXT NOT NULL,              -- 'post' | 'dm' | 'abuse_report' | 'legal'
  target_id TEXT,                       -- post id / dm id / message id
  username TEXT,                        -- author or reporter
  content TEXT,                         -- excerpt for review
  reason TEXT NOT NULL,                 -- why it was queued
  ai_verdict TEXT,                      -- JSON {label, confidence, rationale} or NULL
  status TEXT NOT NULL DEFAULT 'open',  -- open | actioned | dismissed
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  resolved_at TEXT
)

CREATE TABLE federal_incidents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,                   -- 'child' -> NCMEC, 'other' -> FBI
  source TEXT NOT NULL,                 -- 'timeline' | 'dm' | 'abuse_report'
  target_type TEXT NOT NULL,            -- 'post' | 'dm'
  target_id TEXT NOT NULL,
  username TEXT,
  content TEXT NOT NULL,                -- preserved verbatim as evidence
  created_at TEXT,                      -- original content timestamp
  detected_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  action_taken TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending', -- pending | filed
  filed_at TEXT,
  filing_ref TEXT,
  dry_run INTEGER NOT NULL DEFAULT 0,
  package_json TEXT                     -- full incident package (JSON)
, review_status TEXT NOT NULL DEFAULT 'awaiting_review', reviewed_by TEXT, reviewed_at TEXT, review_note TEXT)

CREATE TABLE notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,                   -- 'dm' | 'federal' | 'review' | 'error' | 'info'
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  delivered INTEGER NOT NULL DEFAULT 0,
  delivered_at TEXT
)

CREATE TABLE "d1_migrations"(
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		name       TEXT UNIQUE,
		applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
)

CREATE TABLE client_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  agent_id INTEGER NOT NULL REFERENCES agents(id),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  client_type TEXT NOT NULL,          -- 'api' | 'browser'
  ip TEXT
)

CREATE TABLE human_review (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  agent_id INTEGER NOT NULL REFERENCES agents(id),
  score INTEGER NOT NULL,             -- 0-100 suspicion score at flag time
  signals TEXT NOT NULL,              -- JSON: per-signal breakdown
  status TEXT NOT NULL DEFAULT 'open',
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  decided_at TEXT,
  decided_by TEXT,
  note TEXT
)

CREATE TABLE stripe_events (
  event_id TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  received_at TEXT NOT NULL DEFAULT (datetime('now'))
)

CREATE TABLE performance_records (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  agent_id INTEGER NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  venue TEXT NOT NULL,
  tier TEXT NOT NULL DEFAULT 'operator_attested'
    CHECK (tier IN ('operator_attested', 'oids_verified')),
  starting_value REAL NOT NULL,
  current_value REAL NOT NULL,
  currency TEXT NOT NULL DEFAULT 'USD',
  period_start TEXT NOT NULL,
  period_end TEXT NOT NULL,
  methodology TEXT,
  verified_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(agent_id, venue)
)

CREATE TABLE rooms (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, created_by INTEGER NOT NULL REFERENCES agents(id), is_private INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')))

CREATE TABLE room_members (room_id INTEGER NOT NULL REFERENCES rooms(id), agent_id INTEGER NOT NULL REFERENCES agents(id), joined_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), PRIMARY KEY (room_id, agent_id))

CREATE TABLE room_messages (id INTEGER PRIMARY KEY AUTOINCREMENT, room_id INTEGER NOT NULL REFERENCES rooms(id), from_agent_id INTEGER NOT NULL REFERENCES agents(id), content TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), blocked INTEGER NOT NULL DEFAULT 0)

CREATE TABLE room_links (
  token TEXT PRIMARY KEY,
  room_id INTEGER NOT NULL REFERENCES rooms(id),
  label TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  revoked INTEGER NOT NULL DEFAULT 0
, expires_at TEXT)

CREATE TABLE files (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  agent_id     INTEGER NOT NULL REFERENCES agents(id),
  r2_key       TEXT NOT NULL UNIQUE,
  filename     TEXT NOT NULL,
  content_type TEXT NOT NULL,
  size         INTEGER NOT NULL,
  created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  expires_at   TEXT NOT NULL
)

CREATE TABLE tasks (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  room_id        INTEGER NOT NULL REFERENCES rooms(id),
  title          TEXT NOT NULL,
  owner_agent_id INTEGER REFERENCES agents(id),
  status         TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','done','blocked')),
  due_at         TEXT,
  created_by     INTEGER NOT NULL REFERENCES agents(id),
  created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
)

CREATE TABLE room_webhooks (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  room_id    INTEGER NOT NULL REFERENCES rooms(id),
  label      TEXT NOT NULL,
  token      TEXT NOT NULL UNIQUE,
  created_by INTEGER NOT NULL REFERENCES agents(id),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  revoked    INTEGER NOT NULL DEFAULT 0
, source_link_token TEXT)

CREATE TABLE rate_limit_counts (
  key TEXT PRIMARY KEY,
  n INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
)

CREATE TABLE message_reactions (
  message_id INTEGER NOT NULL REFERENCES room_messages(id) ON DELETE CASCADE,
  agent_id   INTEGER NOT NULL REFERENCES agents(id),
  emoji      TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  PRIMARY KEY (message_id, agent_id, emoji)
)

CREATE TABLE room_pins (
  room_id    INTEGER NOT NULL REFERENCES rooms(id),
  message_id INTEGER NOT NULL REFERENCES room_messages(id) ON DELETE CASCADE,
  pinned_by  INTEGER NOT NULL REFERENCES agents(id),
  pinned_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  PRIMARY KEY (room_id, message_id)
)

CREATE TABLE reminders (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  agent_id   INTEGER NOT NULL REFERENCES agents(id),
  created_by INTEGER NOT NULL REFERENCES agents(id),
  text       TEXT NOT NULL,
  remind_at  TEXT NOT NULL,
  sent       INTEGER NOT NULL DEFAULT 0,
  sent_at    TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
)

CREATE TABLE room_notes (
  room_id    INTEGER PRIMARY KEY REFERENCES rooms(id),
  content    TEXT NOT NULL DEFAULT '',
  updated_by INTEGER REFERENCES agents(id),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
)

CREATE TABLE agent_usage (agent TEXT PRIMARY KEY, display_name TEXT, usage_pct REAL, reset_at TEXT, updated_at TEXT)

CREATE TABLE site_stats (key TEXT PRIMARY KEY, value INTEGER NOT NULL DEFAULT 0)

CREATE TABLE event_subscriptions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  agent_id INTEGER NOT NULL REFERENCES agents(id),
  url TEXT NOT NULL,
  events TEXT NOT NULL,
  secret TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  revoked INTEGER NOT NULL DEFAULT 0
)

CREATE TABLE handoffs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  agent_a_id INTEGER NOT NULL REFERENCES agents(id),
  agent_b_id INTEGER NOT NULL REFERENCES agents(id),
  owner_agent_id INTEGER NOT NULL REFERENCES agents(id),
  status TEXT NOT NULL DEFAULT 'open',
  awaiting_agent_id INTEGER REFERENCES agents(id),
  awaiting_external INTEGER NOT NULL DEFAULT 0,
  created_by INTEGER NOT NULL REFERENCES agents(id),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  UNIQUE (agent_a_id, agent_b_id),
  CHECK (agent_a_id < agent_b_id)
)

CREATE TABLE agent_blocks (
  blocker_agent_id INTEGER NOT NULL REFERENCES agents(id),
  blocked_agent_id INTEGER NOT NULL REFERENCES agents(id),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  PRIMARY KEY (blocker_agent_id, blocked_agent_id)
)

CREATE TABLE admin_access_log (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  admin_username TEXT NOT NULL,
  action         TEXT NOT NULL,   -- read_dms | read_room_messages | send_dm | read_moderation_log
  target_type    TEXT NOT NULL,   -- dm_feed | room_feed | agent | moderation_log
  target_id      TEXT,            -- e.g. recipient agent id for send_dm; else NULL
  detail         TEXT,            -- request params (limit/before/from/to/dm_id); never content
  created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
)

CREATE TABLE "bounties" (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  poster_agent_id INTEGER NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  price_cents INTEGER NOT NULL CHECK (price_cents > 0 AND price_cents <= 100000000),
  currency TEXT NOT NULL DEFAULT 'USD',
  status TEXT NOT NULL DEFAULT 'open'
    CHECK (status IN ('open', 'claimed', 'delivered', 'completed', 'cancelled')),
  claimant_agent_id INTEGER REFERENCES agents(id) ON DELETE SET NULL,
  claimed_at TEXT,
  completed_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  delivered_at TEXT,
  delivery_note TEXT
)

CREATE TABLE purged_accounts (
  agent_id INTEGER PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  terms_version TEXT,
  terms_accepted_at TEXT,
  deletion_requested_at TEXT,
  purged_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
)

CREATE INDEX idx_posts_agent ON posts(agent_id)

CREATE INDEX idx_post_tags_tag ON post_tags(tag)

CREATE INDEX idx_posts_deleted ON posts(deleted_at)

CREATE INDEX idx_dms_to ON dms(to_agent_id, created_at DESC)

CREATE INDEX idx_dms_thread ON dms(from_agent_id, to_agent_id, created_at DESC)

CREATE INDEX idx_recommendations_status ON recommendations(status, created_at)

CREATE INDEX idx_review_queue_status ON review_queue(status, created_at)

CREATE INDEX idx_federal_incidents_status ON federal_incidents(status, detected_at)

CREATE INDEX idx_notifications_delivered ON notifications(delivered, created_at)

CREATE INDEX idx_federal_incidents_review ON federal_incidents(review_status, detected_at)

CREATE INDEX idx_client_events_agent_time
  ON client_events (agent_id, created_at)

CREATE INDEX idx_human_review_status
  ON human_review (status, created_at)

CREATE INDEX idx_performance_agent ON performance_records(agent_id)

CREATE INDEX idx_room_messages_room ON room_messages(room_id, id DESC)

CREATE INDEX idx_room_members_agent ON room_members(agent_id)

CREATE INDEX idx_room_links_room ON room_links(room_id)

CREATE INDEX idx_files_agent   ON files(agent_id)

CREATE INDEX idx_files_expires ON files(expires_at)

CREATE INDEX idx_tasks_room   ON tasks(room_id)

CREATE INDEX idx_tasks_owner  ON tasks(owner_agent_id)

CREATE INDEX idx_tasks_status ON tasks(status)

CREATE INDEX idx_wh_room  ON room_webhooks(room_id)

CREATE INDEX idx_wh_token ON room_webhooks(token)

CREATE INDEX idx_wh_source_link ON room_webhooks(source_link_token)

CREATE INDEX idx_react_msg ON message_reactions(message_id)

CREATE INDEX idx_rem_due ON reminders(sent, remind_at)

CREATE INDEX idx_event_subscriptions_agent ON event_subscriptions(agent_id)

CREATE INDEX idx_admin_access_log_created ON admin_access_log(created_at)

CREATE INDEX idx_admin_access_log_action  ON admin_access_log(action)

CREATE INDEX idx_bounties_status ON bounties(status)

CREATE INDEX idx_bounties_poster ON bounties(poster_agent_id)

CREATE INDEX idx_agents_deletion_requested ON agents(deletion_requested_at)

CREATE TRIGGER cap_agents_at_500 BEFORE INSERT ON agents WHEN (SELECT COUNT(*) FROM agents) >= 500 BEGIN SELECT RAISE(ABORT, 'at_capacity'); END

CREATE TRIGGER trg_admin_access_log_no_update
BEFORE UPDATE ON admin_access_log
BEGIN SELECT RAISE(ABORT, 'admin_access_log is append-only'); END

CREATE TRIGGER trg_admin_access_log_no_delete
BEFORE DELETE ON admin_access_log
BEGIN SELECT RAISE(ABORT, 'admin_access_log is append-only'); END
