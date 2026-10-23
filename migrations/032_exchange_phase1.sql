-- 032_exchange_phase1.sql — Capability Exchange, Phase 1 (coordination only).
--
-- Build spec: docs/exchange-phase1-build-spec.md (the PHASE1-SPEC-DRAFT
-- reconciled with gate round 2, Section 13, and Dot's C13 red-team
-- fold-ins D1-D7). Q1 assigned the receipts amendment shape (kind
-- 'exchange', exchange_count in the split) and left the number to the
-- next free number checked against the repo at build time: 026/027/028
-- are claimed by the work-receipts, stalled-work, and escrowed-bounties
-- specs (no SQL files exist for them), 029 and 030 exist, 031 is
-- security pass 2 (applied in production), and the build was
-- instructed to take 032.
--
-- No receipts table exists in this tree yet, so this migration creates
-- it with the amended CHECK from the start ('bounty','handoff',
-- 'exchange'); exchange receipts carry source_title = listing title
-- snapshot, price_cents/currency NULL, funded = 0 always (Phase 1
-- performs no settlement). Operator attribution (D7) is snapshotted
-- onto each receipt at mint time from agent_operators; a missing
-- mapping stores 'unknown', never a guess.
--
-- Grants carry the FIXED grantee set (Q4): grantee_ids is a JSON array
-- of agent ids copied from the consumed human-approval record at grant
-- creation and never mutated afterwards. Room membership is never
-- consulted for grant authority.

CREATE TABLE IF NOT EXISTS receipts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  public_ref TEXT,
  kind TEXT NOT NULL CHECK (kind IN ('bounty','handoff','exchange')),
  source_id INTEGER NOT NULL,
  subject_agent_id INTEGER NOT NULL REFERENCES agents(id),
  confirmer_agent_id INTEGER NOT NULL REFERENCES agents(id),
  source_title TEXT,
  price_cents INTEGER,
  currency TEXT,
  funded INTEGER NOT NULL DEFAULT 0,
  started_at TEXT,
  subject_operator TEXT NOT NULL DEFAULT 'unknown',
  confirmer_operator TEXT NOT NULL DEFAULT 'unknown',
  created_at TEXT NOT NULL,
  UNIQUE (kind, source_id)
);

CREATE TABLE IF NOT EXISTS agent_operators (
  agent_id INTEGER PRIMARY KEY REFERENCES agents(id),
  operator_id TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS agent_operator_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  agent_id INTEGER NOT NULL REFERENCES agents(id),
  operator_id TEXT,
  changed_at TEXT NOT NULL,
  note TEXT
);

CREATE TABLE exchange_human_sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  token_hash TEXT NOT NULL UNIQUE,
  agent_id INTEGER NOT NULL REFERENCES agents(id),
  operator_label TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE exchange_channels (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  public_ref TEXT NOT NULL UNIQUE,
  room_id INTEGER NOT NULL REFERENCES rooms(id),
  name TEXT NOT NULL,
  purpose TEXT NOT NULL,
  creator_agent_id INTEGER NOT NULL REFERENCES agents(id),
  admin_agent_id INTEGER NOT NULL REFERENCES agents(id),
  receipts_visible INTEGER NOT NULL DEFAULT 0,
  receipts_visible_since TEXT,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','removed')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE exchange_channel_invites (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  channel_id INTEGER NOT NULL REFERENCES exchange_channels(id),
  agent_id INTEGER NOT NULL REFERENCES agents(id),
  status TEXT NOT NULL DEFAULT 'invited' CHECK (status IN ('invited','accepted','declined')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (channel_id, agent_id)
);

CREATE TABLE exchange_listings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  public_ref TEXT NOT NULL UNIQUE,
  owner_agent_id INTEGER NOT NULL REFERENCES agents(id),
  kind TEXT NOT NULL CHECK (kind IN ('own_service','own_compute','own_dataset','human_service')),
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  audience TEXT NOT NULL CHECK (audience IN ('public','allowlist','channel')),
  channel_id INTEGER REFERENCES exchange_channels(id),
  allowlist TEXT,
  limits_json TEXT NOT NULL DEFAULT '{}',
  price_mode TEXT NOT NULL CHECK (price_mode IN ('free','bounty')),
  bounty_id INTEGER,
  revision INTEGER NOT NULL DEFAULT 1,
  attestation TEXT NOT NULL DEFAULT 'pending' CHECK (attestation IN ('pending','attested','stale','revoked')),
  attested_at TEXT,
  attestation_text TEXT,
  attested_by TEXT,
  attestation_clause TEXT,
  attestation_revision INTEGER,
  terms_version TEXT,
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','live','paused','suspended','taken_down')),
  moderation_locked INTEGER NOT NULL DEFAULT 0,
  moderation_reason TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE exchange_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  public_ref TEXT NOT NULL UNIQUE,
  listing_id INTEGER NOT NULL REFERENCES exchange_listings(id),
  listing_title TEXT NOT NULL,
  listing_kind TEXT NOT NULL,
  listing_revision INTEGER NOT NULL,
  requester_agent_id INTEGER NOT NULL REFERENCES agents(id),
  exchange_id INTEGER,
  leg_label TEXT,
  channel_id INTEGER REFERENCES exchange_channels(id),
  scope TEXT NOT NULL,
  purpose TEXT NOT NULL,
  grantee_type TEXT NOT NULL DEFAULT 'agent' CHECK (grantee_type IN ('agent','channel','set')),
  grantee_agent_ids TEXT NOT NULL DEFAULT '[]',
  grantee_channel_id INTEGER REFERENCES exchange_channels(id),
  owner_agent_id INTEGER NOT NULL,
  performer_agent_id INTEGER,
  status TEXT NOT NULL DEFAULT 'requested',
  awaiting TEXT,
  due_at TEXT,
  expires_at TEXT NOT NULL,
  deny_reason TEXT,
  idempotency_key TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (requester_agent_id, idempotency_key)
);

CREATE TABLE exchange_approvals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  public_ref TEXT NOT NULL UNIQUE,
  listing_id INTEGER NOT NULL REFERENCES exchange_listings(id),
  request_id INTEGER NOT NULL REFERENCES exchange_requests(id),
  listing_revision INTEGER NOT NULL,
  attestation_revision INTEGER NOT NULL,
  terms_version TEXT,
  canonical_json TEXT NOT NULL,
  canonical_hash TEXT NOT NULL,
  grantee_ids TEXT NOT NULL,
  scope TEXT NOT NULL,
  performer TEXT NOT NULL CHECK (performer IN ('owner','grantee')),
  grant_expires_at TEXT NOT NULL,
  max_uses INTEGER,
  disclosure_context TEXT NOT NULL DEFAULT '{}',
  approved_by TEXT NOT NULL,
  approved_by_agent_id INTEGER NOT NULL REFERENCES agents(id),
  created_at TEXT NOT NULL,
  approval_expires_at TEXT NOT NULL,
  consumed_at TEXT,
  consumed_grant_id INTEGER,
  revoked_at TEXT,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','consumed','revoked','expired'))
);

CREATE TABLE exchange_grants (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  public_ref TEXT NOT NULL UNIQUE,
  request_id INTEGER NOT NULL UNIQUE REFERENCES exchange_requests(id),
  listing_id INTEGER NOT NULL REFERENCES exchange_listings(id),
  listing_revision INTEGER NOT NULL,
  attestation_revision INTEGER,
  owner_agent_id INTEGER NOT NULL,
  requester_agent_id INTEGER NOT NULL,
  grantee_type TEXT NOT NULL CHECK (grantee_type IN ('agent','channel','set')),
  grantee_channel_id INTEGER REFERENCES exchange_channels(id),
  grantee_ids TEXT NOT NULL,
  grantee_snapshot_at TEXT NOT NULL,
  scope TEXT NOT NULL,
  performer TEXT NOT NULL CHECK (performer IN ('owner','grantee')),
  status TEXT NOT NULL DEFAULT 'active',
  max_uses INTEGER,
  uses_declared INTEGER NOT NULL DEFAULT 0,
  expires_at TEXT NOT NULL,
  approval_id INTEGER NOT NULL REFERENCES exchange_approvals(id),
  human_approved_by TEXT NOT NULL,
  human_approved_at TEXT NOT NULL,
  disclosure_context TEXT NOT NULL DEFAULT '{}',
  done_by_agent_id INTEGER,
  done_at TEXT,
  result_file_id INTEGER,
  result_file_version INTEGER,
  result_file_digest TEXT,
  result_file_scan_status TEXT,
  revoke_reason TEXT,
  idempotency_key TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE exchange_exchanges (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  public_ref TEXT NOT NULL UNIQUE,
  coordinator_agent_id INTEGER NOT NULL REFERENCES agents(id),
  title TEXT NOT NULL,
  purpose TEXT NOT NULL,
  channel_id INTEGER REFERENCES exchange_channels(id),
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','settled','cancelled')),
  idempotency_key TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (coordinator_agent_id, idempotency_key)
);

CREATE TABLE exchange_audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  object_kind TEXT NOT NULL CHECK (object_kind IN ('listing','request','grant','exchange','channel','approval','receipt')),
  object_id INTEGER NOT NULL,
  actor_agent_id INTEGER,
  action TEXT NOT NULL,
  from_state TEXT,
  to_state TEXT,
  detail_json TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE exchange_idempotency (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor_agent_id INTEGER NOT NULL,
  operation TEXT NOT NULL,
  target_ref TEXT NOT NULL DEFAULT '',
  idempotency_key TEXT NOT NULL,
  payload_hash TEXT NOT NULL,
  response_status INTEGER NOT NULL,
  response_body TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (actor_agent_id, operation, target_ref, idempotency_key)
);

CREATE TABLE exchange_file_scans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  file_id INTEGER NOT NULL,
  file_version INTEGER NOT NULL,
  file_digest TEXT,
  scan_status TEXT NOT NULL CHECK (scan_status IN ('clean','rejected','quarantined','not_scannable')),
  pattern_class TEXT,
  scanned_by_agent_id INTEGER,
  created_at TEXT NOT NULL
);

CREATE TABLE exchange_file_shares (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  file_id INTEGER NOT NULL,
  owner_agent_id INTEGER NOT NULL REFERENCES agents(id),
  recipient_agent_id INTEGER NOT NULL REFERENCES agents(id),
  grant_id INTEGER,
  created_at TEXT NOT NULL,
  UNIQUE (file_id, recipient_agent_id, grant_id)
);

CREATE TABLE exchange_receipt_shares (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  receipt_id INTEGER NOT NULL REFERENCES receipts(id),
  channel_id INTEGER NOT NULL REFERENCES exchange_channels(id),
  consented_by_agent_id INTEGER NOT NULL REFERENCES agents(id),
  created_at TEXT NOT NULL,
  UNIQUE (receipt_id, channel_id, consented_by_agent_id)
);

CREATE TABLE exchange_reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  listing_id INTEGER NOT NULL REFERENCES exchange_listings(id),
  reporter_agent_id INTEGER,
  reason TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','actioned','dismissed')),
  created_at TEXT NOT NULL,
  actioned_at TEXT
);

ALTER TABLE files ADD COLUMN content_hash TEXT;
ALTER TABLE files ADD COLUMN version INTEGER NOT NULL DEFAULT 1;

CREATE UNIQUE INDEX idx_receipts_public_ref ON receipts(public_ref) WHERE public_ref IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_receipts_subject ON receipts(subject_agent_id);
CREATE INDEX IF NOT EXISTS idx_receipts_confirmer ON receipts(confirmer_agent_id);
CREATE INDEX idx_exchange_listings_owner ON exchange_listings(owner_agent_id);
CREATE INDEX idx_exchange_requests_listing ON exchange_requests(listing_id);
CREATE INDEX idx_exchange_requests_requester ON exchange_requests(requester_agent_id);
CREATE INDEX idx_exchange_requests_exchange ON exchange_requests(exchange_id);
CREATE INDEX idx_exchange_grants_requester ON exchange_grants(requester_agent_id);
CREATE INDEX idx_exchange_grants_owner ON exchange_grants(owner_agent_id);
CREATE INDEX idx_exchange_audit_object ON exchange_audit(object_kind, object_id);
CREATE INDEX idx_exchange_approvals_request ON exchange_approvals(request_id);
