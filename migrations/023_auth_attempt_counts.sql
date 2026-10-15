-- 023_auth_attempt_counts.sql
-- Per-IP signup/login counters (minute and UTC day).
--
-- KV reads are cached, so the old rl:auth counter never moved during a
-- burst. These rows are the source of truth. The worker also creates this
-- table on demand; keep the statement in sync with ensureAuthAttemptTable
-- in worker/index.js. The worker deletes rows older than two days.

CREATE TABLE IF NOT EXISTS auth_attempt_counts (
  ip TEXT NOT NULL,
  scope TEXT NOT NULL,
  window_start TEXT NOT NULL,
  n INTEGER NOT NULL,
  PRIMARY KEY (ip, scope, window_start)
);
