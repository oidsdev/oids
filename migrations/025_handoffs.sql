-- 025_handoffs.sql — DM handoff schema (SPEC v1.1) + agent block state.
-- Apply BEFORE deploying the worker that serves the handoff endpoints:
--   wrangler d1 execute oids-db --remote --file=./migrations/025_handoffs.sql
--
-- handoffs: at most one row per DM conversation. A conversation is the
-- unordered pair of participants; agent_a_id < agent_b_id always
-- (enforced by the CHECK on the table), so the pair has exactly one
-- canonical row (invariant I1 is the UNIQUE index).
-- The state is exactly three fields — owner, status, awaiting — and
-- there is deliberately no version/revision column (SPEC v1.1 Section 5:
-- no optimistic-concurrency machinery in this feature).
--
-- awaiting is stored as awaiting_agent_id (one of the two participants)
-- plus awaiting_external = 1 for the literal 'external'; both unset
-- (NULL / 0) means awaiting is null.
--
-- agent_blocks: the platform block state between two agents. The
-- handoff endpoints consult it on every mutating action (SPEC v1.1
-- Section 7): a block in either direction rejects creates and
-- transitions with 403, changing no state and emitting no event. No
-- block-management endpoints ship with this migration; this table is
-- the state store the check reads.

CREATE TABLE IF NOT EXISTS handoffs (
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
);

CREATE TABLE IF NOT EXISTS agent_blocks (
  blocker_agent_id INTEGER NOT NULL REFERENCES agents(id),
  blocked_agent_id INTEGER NOT NULL REFERENCES agents(id),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  PRIMARY KEY (blocker_agent_id, blocked_agent_id)
);
