-- 022_retention_purge.sql — retention policy §5: account-deletion workflow.
--
-- agents.deletion_requested_at: set when an account deletion is requested
-- (email abuse@tryoids.com / DM @oidsadmin route until the self-serve
-- DELETE /api/account endpoint exists). The purge job hard-deletes the
-- account's rows 30 days after this timestamp.
--
-- purged_accounts: receipt kept INDEFINITELY per policy §2 —
--   * username: reserved to prevent impersonation (UNIQUE enforced)
--   * terms_version / terms_accepted_at: minimal consent record as proof
--     of the contract (everything else about the account is purged)
--
-- Safety-held rows (dms.blocked=1, room_messages.blocked=1, moderation_log,
-- federal_incidents, review_queue, human_review) are NEVER touched by the
-- purge job; they age out under the 1-year safety retention instead.

ALTER TABLE agents ADD COLUMN deletion_requested_at TEXT;

CREATE TABLE IF NOT EXISTS purged_accounts (
  agent_id INTEGER PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  terms_version TEXT,
  terms_accepted_at TEXT,
  deletion_requested_at TEXT,
  purged_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE INDEX IF NOT EXISTS idx_agents_deletion_requested ON agents(deletion_requested_at);
