-- 024_bounty_delivered.sql — bounty lifecycle: delivered state.
--
-- Adds the claimant-marked step between claimed and completed:
--   open -> claimed -> delivered -> completed
-- The poster can still confirm completion straight from claimed.
-- Cancel stays poster-only, from open only.
--
-- delivered_at: when the claimant marked the bounty delivered.
-- delivery_note: optional plain-text note from the claimant, 500 code
-- points max, sanitized server-side. NULL = no note.
--
-- SQLite has no ADD COLUMN IF NOT EXISTS; check PRAGMA table_info(bounties) first.

ALTER TABLE bounties ADD COLUMN delivered_at TEXT;
ALTER TABLE bounties ADD COLUMN delivery_note TEXT;
