-- 031_security_pass_2.sql
-- Security fix pass 2 (Claude sprint #8 review, findings 3, 5, 8).
-- Apply BEFORE deploying the pass-2 worker:
--   wrangler d1 execute oids-db --remote --file=./migrations/031_security_pass_2.sql
--
-- 1. rate_limit_counts (finding 5) — checkLimit's fixed-window counters
--    move from KV (cached reads let bursts slip past) to D1, mirroring
--    migration 023's auth_attempt_counts. The worker also creates this
--    table on demand; keep the statement in sync with
--    ensureRateLimitTable in worker/index.js. expires_at is epoch ms.
--
-- 2. room_webhooks.source_link_token (finding 3 residual) — tags a
--    webhook with the room link that created it, so revoking/expiring
--    the link revokes the webhooks made through it. NULL for webhooks
--    created with an API key. (Webhook tokens themselves are now stored
--    SHA-256 hashed in the existing token column by the worker; item 4
--    below adds the flag that marks which rows hold a hash.)
--
-- 3. api_keys expiry backfill (finding 8) — every key gets an expiry.
--    Existing keys with expires_at IS NULL (Pro / grandfathered / admin)
--    are given a generous now + 90 days so nobody is locked out by the
--    deploy; from the pass-2 worker on, every newly minted key carries
--    an expires_at.
--
-- 4. room_webhooks.token_is_hashed (gate S1) — 1 when the token column
--    holds a SHA-256 hash, 0 for a legacy plaintext row. Existing rows
--    take the DEFAULT 0, which is correct for them: every pre-031 row
--    holds plaintext. The worker matches a presented token against the
--    hash only on flagged rows and against plaintext only on unflagged
--    rows, and flips the flag when it upgrades a legacy row to its
--    hash — so a stored hash (itself a well-formed 64-hex string) can
--    never be presented as a working token. New rows are written by
--    the worker with the flag set.

CREATE TABLE IF NOT EXISTS rate_limit_counts (
  key TEXT PRIMARY KEY,
  n INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

ALTER TABLE room_webhooks ADD COLUMN source_link_token TEXT;
CREATE INDEX IF NOT EXISTS idx_wh_source_link ON room_webhooks(source_link_token);

ALTER TABLE room_webhooks ADD COLUMN token_is_hashed INTEGER NOT NULL DEFAULT 0;

UPDATE api_keys
   SET expires_at = strftime('%Y-%m-%dT%H:%M:%fZ','now','+90 days')
 WHERE expires_at IS NULL;
