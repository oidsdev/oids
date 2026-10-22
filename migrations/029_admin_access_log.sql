-- 029_admin_access_log.sql
-- Fix pass 2026-10-19 (sale-readiness audit H3/H4/H9):
-- 1. admin_access_log — append-only record of admin reads of DM/room content
--    and admin send-as actions. Metadata only: who, action, target, request
--    parameters. Message bodies are NEVER written here.
-- 2. room_links.expires_at — share links now expire. Existing live links get
--    a 7-day grace from this migration so the operator's Desk Chat windows
--    do not break today; links minted later must set expires_at at insert
--    (the worker also falls back to created_at + 7 days when it is NULL).

CREATE TABLE IF NOT EXISTS admin_access_log (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  admin_username TEXT NOT NULL,
  action         TEXT NOT NULL,   -- read_dms | read_room_messages | send_dm | read_moderation_log
  target_type    TEXT NOT NULL,   -- dm_feed | room_feed | agent | moderation_log
  target_id      TEXT,            -- e.g. recipient agent id for send_dm; else NULL
  detail         TEXT,            -- request params (limit/before/from/to/dm_id); never content
  created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_admin_access_log_created ON admin_access_log(created_at);
CREATE INDEX IF NOT EXISTS idx_admin_access_log_action  ON admin_access_log(action);

-- Append-only enforcement: the application only ever INSERTs. Anyone needing
-- to purge this table must deliberately drop these triggers first, which is
-- itself a visible, intentional act.
CREATE TRIGGER IF NOT EXISTS trg_admin_access_log_no_update
BEFORE UPDATE ON admin_access_log
BEGIN SELECT RAISE(ABORT, 'admin_access_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS trg_admin_access_log_no_delete
BEFORE DELETE ON admin_access_log
BEGIN SELECT RAISE(ABORT, 'admin_access_log is append-only'); END;

ALTER TABLE room_links ADD COLUMN expires_at TEXT;
UPDATE room_links
   SET expires_at = strftime('%Y-%m-%dT%H:%M:%fZ','now','+7 days')
 WHERE expires_at IS NULL;
