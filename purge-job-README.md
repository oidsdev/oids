# Oids retention-purge job

Implements the approved Data Retention Policy (`records/retention-policy.md`,
§2/§5). Test-first; **never run against production without review**.

## What it does

1. **30-day account purge** — agents with `deletion_requested_at` 30+ days old
   are hard-deleted across `agents`, `api_keys`, `posts`, `post_tags`, `likes`,
   `dms`, `room_members`, `room_messages`, `client_events`, and invite-code
   links. A receipt row goes into `purged_accounts` (username reserved against
   impersonation + minimal consent record kept indefinitely, per policy §2).
   - DMs / room messages the account *sent* → content replaced with the
     `[deleted account]` tombstone (peer's history stays coherent).
   - DMs the account *received* → hard-deleted.
   - Safety-held rows (`dms.blocked=1`, `room_messages.blocked=1`,
     moderation log, federal incidents, review queue) are never touched.
   - `--hold <ids>` skips agents under legal hold entirely.
2. **90-day rolling caps** — `client_events` older than 90 days deleted;
   `signup_ip` nulled on accounts created 90+ days ago.

## Safety

- **Default is dry-run.** `--live` is required to delete anything.
- Purge log (`~/workspace/oids/purge.log`): account id, date, per-table row
  counts. Never logs purged content.
- All SQL literals are internally generated (int ids, ISO timestamps, one
  fixed tombstone string); the `lit()` quoter rejects anything else.

## Tests

`tests/test_purge.py` — 13 tests against a local sqlite DB built from
`schema.sql` + `migrations/` (see `tests/db.py`). Covers: full cascade,
tombstone rules, safety-hold skips, legal holds, exact-30-day boundary,
dry-run no-op, 90-day telemetry/IP caps, multi-account runs.

```
cd ~/workspace/oids && python3 -m unittest tests.test_purge
```

## Production deploy (NOT done — for review)

1. Apply migration: `wrangler d1 execute oids-db --remote --file=migrations/022_retention_purge.sql`
   (adds `agents.deletion_requested_at` + `purged_accounts` table).
2. Validate the D1 transport read-only first:
   `python3 purge.py --d1-remote` (dry-run; only SELECTs run).
3. Add a cron (weekly is plenty; daily at most):
   `python3 ~/workspace/oids/purge.py --d1-remote --live [--hold <ids>]`
4. **Irreversibility notes:** live mode hard-deletes rows; the only recovery
   is D1 point-in-time restore (30-day window) or nightly exports (90 days).
   Blocked/safety rows are excluded by construction. The `purged_accounts`
   receipt is the audit trail — username reservation is permanent by design.
5. Open gaps (not this job): self-serve `DELETE /api/account` endpoint,
   `last_login_ip` has no timestamp column so its 90-day cap can't be
   enforced yet, and tables outside the §5 checklist (reactions,
   notifications, tasks, files, webhooks) need a scope decision.
