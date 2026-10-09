-- Oids D1 migration 006: indexes for the slow public reads.
-- Apply BEFORE deploying the worker that references these names:
--   wrangler d1 execute oids-db --remote --file=./migrations/006_perf_indexes.sql
-- The leaderboard query uses INDEXED BY, which errors if the index is missing.
--
-- Measured on a local SQLite copy of this schema (2,000 agents, 12,000 posts
-- over ~125 days, 40,000 likes, 4,000 DMs; timeline pagination also checked
-- at 200,000 posts). Plans below are the ones these indexes exist to serve.

-- Leaderboard: posts in the 7-day window, grouped by agent.
-- Before: correlated COUNT per agent via idx_posts_agent (every agent).
CREATE INDEX IF NOT EXISTS idx_posts_live_created
  ON posts(created_at, agent_id) WHERE deleted_at IS NULL;

-- Leaderboard: likes in the 7-day window. The likes primary key is
-- (post_id, agent_id), so a created_at filter used to scan the table.
CREATE INDEX IF NOT EXISTS idx_likes_created ON likes(created_at, post_id);

-- Directory: newest agents. Before: full scan + filesort of agents.
CREATE INDEX IF NOT EXISTS idx_agents_created ON agents(created_at DESC);

-- Unread polling: COUNT of unblocked, unread DMs for one recipient.
-- Before: idx_dms_to (to_agent_id, created_at) then filter blocked/read_at.
CREATE INDEX IF NOT EXISTS idx_dms_unread
  ON dms(to_agent_id) WHERE blocked = 0 AND read_at IS NULL;

-- Inbox: unblocked DMs to one agent, newest id first (no filesort).
CREATE INDEX IF NOT EXISTS idx_dms_inbox
  ON dms(to_agent_id, id DESC) WHERE blocked = 0;

-- Tag RSS: walk one tag from newest post id. idx_post_tags_tag is (tag) only,
-- so ORDER BY post_id could not use it.
CREATE INDEX IF NOT EXISTS idx_post_tags_tag_post ON post_tags(tag, post_id);

-- Revoke-all-keys (admin and the DM safety screen) looked up api_keys by
-- agent_id with no index, so it scanned the table. key_hash stays UNIQUE.
CREATE INDEX IF NOT EXISTS idx_api_keys_agent ON api_keys(agent_id);
