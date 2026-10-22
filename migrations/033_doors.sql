-- 033_doors.sql — Oids Doors MVP (presentation + entry layer over the
-- Capability Exchange, Phase 1; migration 032).
--
-- A Door is an Exchange listing with door fields. There is NO parallel
-- registry: `doors.listing_id` is the primary key and points at
-- exchange_listings(id). Door visibility is derived from the listing
-- state (live + attested for its current revision + no moderation
-- lock), exactly as Exchange listings are read; there is no separate
-- door status column to drift out of sync.
--
-- Entry tokens (door_entries.token_hash): 256-bit random tokens,
-- SHA-256 hash only at rest; the plaintext is returned once at mint
-- and is never stored anywhere in this schema. Tokens are single-use
-- (consumed_at is set by the first successful validation), bound to
-- one door + one agent + (in grant mode) one grant, and expire
-- 5 minutes after mint (expires_at). Validation is fail-closed: it
-- re-checks listing eligibility, grant state, and blocks at
-- validation time, not at mint time.
--
-- Validate key (doors.validate_key_hash): a per-door key issued at
-- door registration, SHA-256 hash only at rest, plaintext shown once.
-- It can be used ONLY for that door's validate and exit calls. It is
-- not an agent API key and authorizes nothing else.
--
-- RETENTION RULE (Doors, defined for this build): a door_entries row
-- is kept for 90 days past the end of its recordable life, then the
-- doors sweep deletes it. "End of recordable life" is exited_at for
-- a validated entry (whether the exit came from the door or from
-- the session sweep), or expires_at for a token that was never
-- validated. The audit trail in exchange_audit (object_kind
-- 'listing', the door's listing as the object) is NOT deleted by
-- this rule; it follows the Exchange retention posture. Implemented
-- in doorsSweep() in worker/index.js.
--
-- Doors audit rows reuse exchange_audit with object_kind='listing'
-- (the door's listing is the object), so the audit CHECK in
-- migration 032 needs no change.

CREATE TABLE doors (
  listing_id INTEGER PRIMARY KEY REFERENCES exchange_listings(id),
  slug TEXT NOT NULL UNIQUE,            -- menu address, screened at registration
  entry_url TEXT NOT NULL,              -- https URL on the operator's own infrastructure
  entry_domain TEXT NOT NULL,           -- registrable domain of entry_url at last registration/change
  entry_mode TEXT NOT NULL DEFAULT 'grant' CHECK (entry_mode IN ('grant','open')),
  session_max_minutes INTEGER NOT NULL CHECK (session_max_minutes >= 1 AND session_max_minutes <= 1440),
  display_tag TEXT,                     -- menu browsing label, display only; not a taxonomy field
  validate_key_hash TEXT NOT NULL,      -- SHA-256 of the per-door validate-only key; plaintext shown once
  terms_ack_at TEXT,                    -- when the operator accepted the door terms at registration
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE door_entries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  public_ref TEXT NOT NULL UNIQUE,      -- the door-scoped session id; unrelated across doors/entries
  door_listing_id INTEGER NOT NULL REFERENCES exchange_listings(id),
  agent_id INTEGER NOT NULL REFERENCES agents(id),
  grant_id INTEGER REFERENCES exchange_grants(id),  -- set iff the door was in grant mode at mint
  token_hash TEXT NOT NULL UNIQUE,      -- SHA-256 of the entry token; the token itself is never stored
  consumed_at TEXT,                     -- set at first successful validation (single-use)
  issued_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,             -- presentation deadline: issued_at + 5 minutes
  session_expires_at TEXT,              -- consumed_at + the door's session_max_minutes; set at validation
  exited_at TEXT,                       -- set on door-reported exit or by the session sweep
  exit_source TEXT CHECK (exit_source IN ('door','sweep')),  -- NULL while the session record is open
  opt_in_visible INTEGER NOT NULL DEFAULT 0,  -- entering agent's opt-in to appear on the door's caller list
  created_at TEXT NOT NULL
);

CREATE INDEX idx_doors_entry_domain ON doors(entry_domain);
CREATE INDEX idx_door_entries_door ON door_entries(door_listing_id, consumed_at);
CREATE INDEX idx_door_entries_agent ON door_entries(agent_id, consumed_at);
CREATE INDEX idx_door_entries_retention ON door_entries(exited_at, expires_at);
