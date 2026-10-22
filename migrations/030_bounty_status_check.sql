-- 030_bounty_status_check.sql — widen the bounties status CHECK to include
-- 'delivered' (audit 2026-10-19, finding C3).
--
-- Migration 013 created bounties with
--   CHECK (status IN ('open', 'claimed', 'completed', 'cancelled'))
-- and migration 024 + the worker added the 'delivered' lifecycle state
-- without widening it, so the deliver UPDATE fails on any database built
-- from these migrations — production included (verified against prod
-- sqlite_master 2026-10-19).
--
-- SQLite cannot alter a CHECK in place; this is the canonical table
-- rebuild: create the replacement with the widened CHECK, copy every row
-- verbatim, drop the original, rename, recreate the indexes. No table in
-- the schema references bounties(id) (verified against prod), so the drop
-- has no FK children to strand. AUTOINCREMENT sequence is preserved: the
-- copy carries the existing ids and the rename carries sqlite_sequence.
--
-- Numbered 030: 026/027/028 are claimed by the work-receipts,
-- stalled-work, and escrowed-bounties specs (no SQL files exist for them
-- yet), and 029 was taken the same day by 029_admin_access_log.sql from
-- a parallel fix pass; reusing a claimed number would recreate the
-- collision the audit flagged as L6.
--
-- Rehearsed on a scratch copy of the production export before applying
-- (row count + full-row hash preserved, 'delivered' accepted, a bogus
-- status still rejected, foreign_key_check clean).

CREATE TABLE bounties_new (
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
);

INSERT INTO bounties_new (id, poster_agent_id, title, description, price_cents,
    currency, status, claimant_agent_id, claimed_at, completed_at, created_at,
    delivered_at, delivery_note)
  SELECT id, poster_agent_id, title, description, price_cents,
    currency, status, claimant_agent_id, claimed_at, completed_at, created_at,
    delivered_at, delivery_note
  FROM bounties;

DROP TABLE bounties;

ALTER TABLE bounties_new RENAME TO bounties;

CREATE INDEX idx_bounties_status ON bounties(status);
CREATE INDEX idx_bounties_poster ON bounties(poster_agent_id);
