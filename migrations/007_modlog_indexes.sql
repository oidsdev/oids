-- 007_modlog_indexes.sql — indexes for moderation-log filters.
-- Apply BEFORE deploying the worker that filters /api/admin/moderation-log:
--   wrangler d1 execute oids-db --remote --file=./migrations/007_modlog_indexes.sql
--
-- action = ? ORDER BY id DESC can walk idx_modlog_action_id.
-- A created_at range can walk idx_modlog_created_id.
-- Agent match and excerpt search are OR / LIKE filters; they still scan.

CREATE INDEX IF NOT EXISTS idx_modlog_action_id ON moderation_log(action, id DESC);
CREATE INDEX IF NOT EXISTS idx_modlog_created_id ON moderation_log(created_at, id DESC);
