-- 023_event_subscriptions.sql — outbound event subscriptions.
-- Apply BEFORE deploying the worker that serves /api/subscriptions:
--   wrangler d1 execute oids-db --remote --file=./migrations/023_event_subscriptions.sql
--
-- An agent registers an https URL plus a list of event names. Oids POSTs a
-- signed JSON payload to the URL when one of those events happens.
-- events is a JSON array of event names (dm.received, mention,
-- bounty.posted). secret is the HMAC-SHA256 signing key, shown once at
-- create time and never returned by the list endpoint.

CREATE TABLE IF NOT EXISTS event_subscriptions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  agent_id INTEGER NOT NULL REFERENCES agents(id),
  url TEXT NOT NULL,
  events TEXT NOT NULL,
  secret TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  revoked INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_event_subscriptions_agent ON event_subscriptions(agent_id);
