# Oids Autonomous Moderation (`automod/`)

Cloudflare-native moderation for Oids: scheduled timeline sweeps, abuse-mail
processing, DM notifications, and a **billing hardstop** — all running inside
Cloudflare, off metered agent usage.

## Architecture: two workers, one billable

| Worker | Why Paid matters |
|---|---|
| `oids` (public API, `../worker/index.js`) | Metered under the account's Workers Paid plan. Protected by the hourly usage guard + cost circuit-breaker (full dark before overage). |
| `oids-automod` (`worker.js`, this dir) | Cron triggers + Workers AI require Paid. This is the worker that *needs* Paid; the plan itself is account-wide. |

Both workers bind to the **same D1 database and KV namespace**. The automod
worker has no public HTTP surface (`fetch` returns 404).

**Billing truth (verified 2026-09-27):** the Workers Paid plan ($5/mo base)
is per-**account**, not per-worker
([docs](https://developers.cloudflare.com/workers/platform/pricing/):
"a minimum charge of $5 USD per month for an account"). Once the account is
on Paid (required for the automod cron + Workers AI), **all** workers in the
account — including the public `oids` API worker — are metered against the
10M requests/month included quota (+$0.30/M over). An earlier version of this
doc claimed the public worker "stays on Free, rejected-not-billed"; that is
**wrong** and has been corrected. The enforced billing ceiling is the guard
below, not a plan tier.

**Do NOT add `[triggers]` or `[ai]` to the public worker's wrangler.toml.**
That would add cron/AI cost surface for no benefit.

## Billing hardstop (`guard.js`)

Cloudflare offers no native "never charge me more than $X" switch, so the
guard builds one. It runs **hourly** inside the 15-minute cron:

1. Queries the Cloudflare GraphQL Analytics API for Workers requests over the
   trailing 24h — **account total AND the `oids-automod` worker's own series**
   (per-script `scriptName` dimension). Whichever hits a tier first trips it.
2. **WARN tier — 250,000 requests/day** (tunable: `USAGE_WARN_THRESHOLD_PER_DAY`,
   override with the `USAGE_WARN_THRESHOLD` var): urgent notification so a human
   looks at the traffic. Once per day.
3. **KILL tier — 1,000,000 requests/day** (tunable: `USAGE_KILL_THRESHOLD_PER_DAY`,
   override with the `USAGE_KILL_THRESHOLD` var): **full dark** — flips BOTH
   shared KV flags (`oids:kill = "1"` and `oids:dark = "1"`). The API worker
   checks `oids:dark` first and returns **HTTP 404 on every route**. (Manual
   `../kill.sh` sets only `oids:kill` → 503 "temporarily unavailable"; that is
   the operator's explicit call, unchanged.)
4. On **any** API error (bad token, missing permission, schema change) the
   guard **never flips the switch** — unknown state fails safe, not armed.

**Cost circuit-breaker (primary, David 2026-09-27):** projects month-end
metered spend from month-to-date usage + trailing-24h rate and goes full dark
*before* any overage charge is incurred — trip when projected Workers
requests exceed 90% of the 10M/month included, or projected total overage
exceeds $1.00/month above the $5 base (tunable: `COST_KILL_USD`). **Two
consecutive hourly trips are required** before going dark (first trip only
arms a pending flag) — one-off anomalies never darken the site spuriously.
A healthy projection clears the pending flag. See `guard.js` header for the
full projection math and honest limits.

Why these numbers: legitimate Oids traffic is plausibly under 100k/day, so
1M/day is ~10x headroom. A sustained 1M/day flood is ~30M/month — roughly
**$10 over the 10M requests included on Workers Paid** (vs ~$70 at the old
5M/day threshold).

The guard needs a **narrow** API token as a worker secret (Account Analytics:
Read only — NOT the broad deploy token):

```bash
wrangler secret put CF_API_TOKEN --config automod/wrangler.toml
```

### AI spend cap (`claimAiCall` in `guard.js`)

Workers AI classification calls are hard-capped at **1,000/day**
(`AI_CALLS_PER_DAY_MAX`), tracked in KV per calendar day. Past the cap,
gray-area items go **straight to the human-review queue with no AI call** —
AI spend is structurally unable to spike. (KV is eventually consistent, so a
1–2 call overshoot under concurrency is possible; that is acceptable.)

### Honest limits — read this

- The guard reacts **hourly**. A fast flood can run for up to ~1 hour before
  the switch trips.
- The **$5/month Workers Paid base** for `oids-automod` is unavoidable
  (cron + Workers AI require Paid).
- L3/L4/L7 DDoS mitigation is **unmetered**, so the bill risk is floods that
  look legitimate — which is exactly what this guard covers.
- Worst case before the hourly guard trips is bounded by the **1M/day kill
  threshold** (~$10 overage/month equivalent at sustained flood levels).

## David's part: dashboard billing alerts (cannot be done via API)

The Cloudflare API does **not** expose usage/billing alert creation to this
account's token (alerting API returns authentication errors; there is no
`notification-policies` route), so this step needs David in the dashboard:

1. Go to **dash.cloudflare.com** and select the account
   (Mrdavesemailaddress@gmail.com's Account).
2. Top-right account menu → **Manage Account → Notifications** → create a
   **Budget alert**: set dollar thresholds (e.g. $10 and $25). These email
   when account-wide usage-based spend crosses the threshold.
3. In the same Notifications hub, optionally add a **Usage-based billing**
   alert for the **Workers** metric (e.g. 50% / 75% / 90% of a chosen
   requests threshold) — this reacts faster than the daily spend rollup.
4. Alternative path to the same: **Manage Account → Billing → Billable Usage
   → Set Budget Alert**.

These alerts are **informational only — they cap nothing**. The enforced
ceiling is the worker guard above. Exact dashboard labels may shift; if the
path differs, look under Manage Account → Billing.

## Scheduled sweep (`sweep.js`)

Every 15 minutes (dry-run until cutover: `AUTOMOD_DRY_RUN="1"`):

- **Federal tier first** — text-pattern screen (see `patterns.js`). Matches:
  post soft-deleted, all account keys revoked, and a **DRAFT** incident
  package written to D1 `federal_incidents`
  (`status='pending'`, `review_status='awaiting_review'`; dry-run: `dry_run=1`,
  nothing deleted/revoked).
  **Policy (David, 2026-09-27): NOTHING goes to an outside authority on the
  filter alone.** Filing the external report (NCMEC CyberTipline for
  `kind='child'`, FBI tips for `kind='other'`) requires a HUMAN REVIEW step
  first: Muse reviews the draft package (it contains everything needed for
  prompt filing — verbatim content, timestamps, account identifiers, the
  exact filing destination, and a review checklist), escalating to David when
  uncertain. A false positive must never mean reporting an innocent account.
  Filing itself is always done by a human through the official portal — never
  automated. Review workflow: `./review-federal.sh list|show|confirm|dismiss|filed`.
  Text-pattern screening only — never describe it as comprehensive semantic,
  image, or CSAM detection.
- **High-confidence abuse** (scam/pharma phrases, link spam, exact reposts of
  removed content): auto soft-delete + log. Destructive helpers respect the
  caller's dry-run decision (`db.js`).
- **Gray area** (threat patterns, piracy signals, phone/email): queued in
  `review_queue` with an optional Workers AI verdict (llama-3.1-8b-instruct).
  **AI alone never deletes.**
- **Blocked DMs**: DMs stopped by send-time federal screening are packaged
  as DRAFTs in `federal_incidents` for human review (same no-auto-filing
  policy as above).
- **DM watch**: new DMs to `@oidsadmin` → `notifications` (never marked read).
- **Dox patterns** load from KV `automod:dox-patterns` — private, never
  committed.

## Abuse email (`email.js`)

Cloudflare Email Worker for `abuse@tryoids.com` (route to `oids-automod` in
Email Routing). Minimal MIME parsing → post-ID / username extraction →
**delete-first, reversible soft-delete** policy → DMCA notices logged to the
review/legal queue. AI triage for abuse reports is still to be added (it must
respect the AI daily cap when it lands).

## Notifications (`notify.js`)

Always written to the D1 `notifications` table. Optional Resend fan-out when
`RESEND_API_KEY` + `NOTIFY_EMAIL` are set. Drain with:

```bash
python3 automod/drain-notifications.py   # exception-only; quiet when empty
```

## Privacy rules (standing)

- NOTHING public reveals AI generation. Public admin is `@oidsadmin`;
  public abuse contact is `abuse@tryoids.com`.
- Never expose David's real name, Gmail, phone, address, location, account
  IDs, or other PII — in code, logs, notifications, or UI copy.
- Preserve evidence via soft deletion. Synthetic federal incidents are never
  filed.
- User-facing text must pass the humanizer gate (no em-dash sentence glue,
  no press-release language).

## Files

- `worker.js` — automod worker entry (scheduled + email handlers)
- `wrangler.toml` — `oids-automod` config (Paid plan)
- `sweep.js` / `email.js` / `guard.js` / `patterns.js` / `db.js` / `notify.js`
- `drain-notifications.py` — exception-only notification drain cron
- `migrations/004_automod.sql` — D1 schema (copy of `../migrations/004_automod.sql`)
- `../migrations/004_automod.sql` — canonical migration source

## Docs

- `TEST-REPORT.md` — what was tested and the results
- `CUTOVER.md` — ordered cutover checklist (do not deploy before it is approved)
