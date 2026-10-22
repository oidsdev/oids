/**
 * automod/guard.js — hourly billing hardstop for Oids.
 *
 * Cloudflare offers no native "never charge me more than $X" switch, so this
 * guard builds one:
 *
 *   1. Once per hour (throttled inside the 15-min cron), it queries the
 *      Cloudflare GraphQL Analytics API for Workers requests over the
 *      trailing 24h — BOTH the account total AND the oids-automod worker's
 *      own series (per-script breakdown via the scriptName dimension).
 *      Whichever series hits a tier first trips it.
 *   2. WARN tier (USAGE_WARN_THRESHOLD_PER_DAY, default 250,000/day):
 *      urgent notification so a human looks at the traffic. Once per day.
 *   3. KILL tier (USAGE_KILL_THRESHOLD_PER_DAY, default 1,000,000/day):
 *      full dark — flips BOTH shared KV flags (oids:kill = "1" AND
 *      oids:dark = "1"). The API worker honors oids:dark with HTTP 404 on
 *      every route (dark is checked first). ../kill.sh stays manual-only and
 *      sets just oids:kill (503 "temporarily unavailable"). Recover with
 *      ../revive.sh (clears both flags) after reviewing the flood source.
 *   4. On any API error (bad token, missing permission, schema change) it
 *      NEVER flips the switch: unknown state fails safe, not armed.
 *
 * Why these numbers: legitimate Oids traffic is plausibly under 100k/day,
 * so 1M/day is ~10x headroom. A sustained 1M/day flood is ~30M/month, about
 * $10 over the 10M requests included on Workers Paid — vs ~$70 at the old
 * 5M/day threshold. Both thresholds are documented tunable constants and
 * can be overridden without a code change via the USAGE_WARN_THRESHOLD /
 * USAGE_KILL_THRESHOLD worker vars.
 *
 * Honest limits (do not oversell this):
 *   - The guard reacts hourly. A fast flood can run for up to ~1 hour before
 *     the switch trips. Pair it with the operator's account-level usage billing
 *     alerts in the Cloudflare dashboard (see README.md).
 *   - The $5/month Workers Paid base for the oids-automod worker is
 *     unavoidable (cron + Workers AI require Paid).
 *   - L3/L4/L7 DDoS mitigation is unmetered, so the bill risk is floods that
 *     look legitimate — which is exactly what this guard covers.
 *
 * Needs `wrangler secret put CF_API_TOKEN` on the oids-automod worker: a
 * narrow token with Account Analytics: Read permission (NOT the broad deploy
 * token). Optionally set CF_ACCOUNT_ID (var) to skip account auto-detection.
 */

import { logMod } from './db.js';
import { notify } from './notify.js';

/**
 * WARN tier: urgent notification. Default 250,000 Workers requests/day.
 * Override with the USAGE_WARN_THRESHOLD worker var.
 */
export const USAGE_WARN_THRESHOLD_PER_DAY = 250_000;

/**
 * KILL tier: flip KV oids:kill. Default 1,000,000 Workers requests/day.
 * Override with the USAGE_KILL_THRESHOLD worker var.
 */
export const USAGE_KILL_THRESHOLD_PER_DAY = 1_000_000;

/**
 * Hard daily cap on Workers AI classification calls. Beyond this, gray-area
 * items go straight to the human-review queue with NO AI call — AI spend is
 * structurally unable to spike. Overshoot of 1-2 calls is possible under
 * concurrency (KV is eventually consistent); that is acceptable.
 */
export const AI_CALLS_PER_DAY_MAX = 1_000;

const GUARD_INTERVAL_MS = 3_600_000; // hourly
const KV_LAST_RUN = 'automod:wm:guard';
const KV_UNCONFIGURED_FLAG = 'automod:guard-unconfigured-notified';
// Set when the cost circuit-breaker trips once but is awaiting a second
// consecutive hourly confirmation before going dark (2h TTL). Cleared on any
// healthy (non-tripped) projection; left alone when the usage query fails.
const COST_PENDING_KEY = 'automod:cost-trip-pending';
const KILL_KEY = 'oids:kill';
const DARK_KEY = 'oids:dark';
const DEFAULT_WORKER_NAME = 'oids-automod';

// ---------------------------------------------------------------------------
// COST CIRCUIT-BREAKER (the operator, 2026-09-27).
//
// The request-count tiers above react to floods. This layer projects
// MONTH-END Cloudflare spend from metered usage and goes FULL DARK
// (oids:kill + oids:dark -> the API worker returns 404 on every route) when
// the projection looks likely to exceed the $5/mo Workers Paid base. It
// fires BEFORE any overage charge is incurred, not after.
//
// Pricing verified 2026-09-27 against Cloudflare docs:
//   Workers Paid: 10M requests/mo + 30M CPU-ms/mo included; +$0.30/M req over.
//   Workers AI: 10,000 neurons/day free on Paid; +$0.011/1k neurons above that.
//   KV: 10M reads/mo included; +$0.50/M reads over. (writes: 1M/mo incl.)
//   D1: 25B rows read / 50M rows written per month included — structurally
//       unreachable at our scale (public worker is Free: 100k req/day hard
//       cap, rejected-not-billed), so D1 is not a separate trip term.
//   Pages static hosting: free, unlimited bandwidth — the frontend shell
//       costs $0 even while up, so it is not part of the spend projection.
//
// Projection math (documented estimates, all tunable via worker vars):
//   projRequests = month-to-date requests + trailing-24h rate x days left.
//   - TRIP if projRequests > 90% of the 10M included (COST_REQ_FRACTION).
//     The 10% headroom is what makes this fire BEFORE overage billing starts.
//   - reqOverageUsd = max(0, projRequests - 10M)/1M x $0.30.
//   KV reads ~= projRequests x 1.5 (kill-check + session/auth reads).
//   - kvOverageUsd = max(0, kvReads - 10M)/1M x $0.50; trip term at > $2.
//   Workers AI: our KV call counter is authoritative (we are the only AI
//   consumer). dailyUsd ~= calls x $0.00005 (llama-3.1-8b triage, conservative);
//   free allocation covers ~$0.11/day; monthly billable = max(0, daily-0.11)x30.
//   Our 1,000/day call cap bounds worst-case AI to ~$0 (usually) / $1.30;
//   the $2 trip term is a backstop against the cap breaking.
//   - TRIP if total projected overage > COST_KILL_USD (default $1.00).
// The $1.00 bar (not $0.00) exists because AI micro-usage and KV estimation
// noise would false-fire a $0 trigger; $1 is still far below any meaningful
// charge. Override with the COST_KILL_USD worker var.
//
// Anti-false-positive: a tripped projection does NOT go dark immediately.
// The first trip only arms a pending flag (2h TTL); the site goes dark when
// a SECOND consecutive hourly run also trips. One-off GraphQL anomalies or
// a spike that subsides never darken the site; a real slow-burn overage
// stays tripped hour after hour. A healthy projection clears the pending
// flag outright.
//
// Honest limits: projections extrapolate the trailing-24h rate, so a spike
// that stops will over-project (fail-safe direction: we go dark and a human
// revives with ./revive.sh). Like the request tiers, this reacts hourly.
// ---------------------------------------------------------------------------

/** Workers requests included per month on the Paid plan. */
export const WORKERS_REQ_INCLUDED_PER_MONTH = 10_000_000;
/** Overage price per million Workers requests. */
export const WORKERS_REQ_OVERAGE_USD_PER_M = 0.30;
/** Trip when projected monthly requests exceed this fraction of included. */
export const COST_REQ_FRACTION = 0.9;
/** KV reads included per month on the Paid plan. */
export const KV_READS_INCLUDED_PER_MONTH = 10_000_000;
/** Overage price per million KV reads. */
export const KV_READ_OVERAGE_USD_PER_M = 0.50;
/** Conservative KV reads per API request (kill-check + session/auth). */
export const KV_READS_PER_REQUEST_EST = 1.5;
/** Conservative USD per Workers AI triage call (llama-3.1-8b). */
export const AI_USD_PER_CALL_EST = 0.00005;
/** USD value of the free 10k-neurons/day AI allocation (~$0.011/1k). */
export const AI_FREE_USD_PER_DAY = 0.11;
/** Backstop trip terms (USD/month). */
export const AI_TRIP_USD_PER_MONTH = 2.0;
export const KV_TRIP_USD_PER_MONTH = 2.0;
/** Primary trip bar: projected total monthly overage above the $5 base. */
export const COST_KILL_OVERAGE_USD = 1.0;

/**
 * Pure month-end cost projection. All inputs are numbers; `now` is a Date.
 * Returns { projRequests, reqOverageUsd, kvOverageUsd, aiOverageUsd,
 *           totalOverageUsd, tripped, reasons[] }.
 */
export function projectMonthlyCost({ mtdRequests, rate24h, aiCallsToday }, costKillUsd, now) {
  const t = now || new Date();
  const monthStart = Date.UTC(t.getUTCFullYear(), t.getUTCMonth(), 1);
  const monthEnd = Date.UTC(t.getUTCFullYear(), t.getUTCMonth() + 1, 1);
  const daysInMonth = (monthEnd - monthStart) / 86400000;
  const daysElapsed = Math.max((t.getTime() - monthStart) / 86400000, 1 / 24);
  const daysLeft = Math.max(daysInMonth - daysElapsed, 0);

  const projRequests = Math.round(mtdRequests + rate24h * daysLeft);
  const reqOverageUsd =
    (Math.max(0, projRequests - WORKERS_REQ_INCLUDED_PER_MONTH) / 1e6) * WORKERS_REQ_OVERAGE_USD_PER_M;
  const kvOverageUsd =
    (Math.max(0, projRequests * KV_READS_PER_REQUEST_EST - KV_READS_INCLUDED_PER_MONTH) / 1e6) *
    KV_READ_OVERAGE_USD_PER_M;
  const aiOverageUsd = Math.max(0, aiCallsToday * AI_USD_PER_CALL_EST - AI_FREE_USD_PER_DAY) * 30;
  const totalOverageUsd = reqOverageUsd + kvOverageUsd + aiOverageUsd;

  const reasons = [];
  if (projRequests > WORKERS_REQ_INCLUDED_PER_MONTH * COST_REQ_FRACTION) {
    reasons.push(
      `projected ${projRequests.toLocaleString('en-US')} Workers requests this month exceeds 90% of the 10M included`
    );
  }
  if (aiOverageUsd > AI_TRIP_USD_PER_MONTH) {
    reasons.push(`projected Workers AI overage $${aiOverageUsd.toFixed(2)}/mo`);
  }
  if (kvOverageUsd > KV_TRIP_USD_PER_MONTH) {
    reasons.push(`projected KV read overage $${kvOverageUsd.toFixed(2)}/mo`);
  }
  if (reasons.length === 0 && totalOverageUsd > costKillUsd) {
    reasons.push(`projected total overage $${totalOverageUsd.toFixed(2)}/mo above the $5 base`);
  }
  return { projRequests, reqOverageUsd, kvOverageUsd, aiOverageUsd, totalOverageUsd, tripped: reasons.length > 0, reasons };
}

/**
 * Note about the Pages frontend when the cost breaker trips. The frontend
 * (tryoids.com) is static Pages hosting: free, unlimited bandwidth — it
 * cannot add a dollar to the bill, and it is fully non-functional while the
 * API is dark. A literal HTTP 404 on tryoids.com needs a Pages:Edit token
 * the API cannot mint; run ./dark-frontend.sh (or the dashboard) for that.
 * This keeps the automatic path honest about what it did and did not do.
 */
async function noteFrontendStatus(env, dry, detail) {
  const msg =
    `${detail} The API worker is now dark (404 on every route). The tryoids.com frontend ` +
    `is static Pages hosting (free, $0) and does nothing without the API. For a literal ` +
    `HTTP 404 on tryoids.com, run ./dark-frontend.sh from the repo (needs a Pages:Edit token) ` +
    `or pause the Pages project in the dashboard.`;
  await logMod(env, 'billing_guard', 'account', null, `${dry ? '[dry-run] ' : ''}${msg}`, 'automod');
  await notify(env, 'error', `${dry ? '[dry-run] ' : ''}Cost circuit-breaker: frontend note`, msg);
}

/** GraphQL Analytics API: POST /client/v4/graphql. Returns {data, errors} (no success wrapper). */
async function cfGraphQL(token, query, variables) {
  const r = await fetch('https://api.cloudflare.com/client/v4/graphql', {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ query, variables }),
  });
  const j = await r.json();
  if (j.errors && j.errors.length) {
    throw new Error('GraphQL: ' + j.errors.map((e) => e.message).join('; ').slice(0, 300));
  }
  return j.data;
}

async function cfRest(token, path) {
  const r = await fetch(`https://api.cloudflare.com/client/v4${path}`, {
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
  });
  const j = await r.json();
  if (!j.success) {
    throw new Error(`REST ${path}: ${(j.errors || []).map((e) => e.message).join('; ').slice(0, 200)}`);
  }
  return j.result;
}

const USAGE_QUERY = `query($accountTag: String!, $start: Time!, $end: Time!) {
  viewer {
    accounts(filter: {accountTag: $accountTag}) {
      workersInvocationsAdaptive(
        filter: {datetime_geq: $start, datetime_leq: $end}
        limit: 10000
      ) {
        sum { requests }
        dimensions { scriptName }
      }
    }
  }
}`;

/**
 * Workers request counts over an arbitrary window: { total, perWorker }.
 * perWorker is the series for the automod worker itself; total covers the
 * whole account (both workers). Query shape verified live 2026-09-27.
 */
export async function fetchWorkersUsage(token, accountTag, workerName, startIso, endIso) {
  const data = await cfGraphQL(token, USAGE_QUERY, {
    accountTag,
    start: startIso,
    end: endIso,
  });
  const rows = (((data || {}).viewer || {}).accounts || [])[0]?.workersInvocationsAdaptive || [];
  let total = 0;
  let perWorker = 0;
  for (const r of rows) {
    const n = ((r || {}).sum || {}).requests || 0;
    total += n;
    if (((r || {}).dimensions || {}).scriptName === workerName) perWorker += n;
  }
  return { total, perWorker };
}

/** Trailing-24h convenience wrapper (kept for the request-count tiers). */
export async function fetchDailyWorkersUsage(token, accountTag, workerName) {
  const end = new Date();
  const start = new Date(end.getTime() - 24 * 3_600_000);
  return fetchWorkersUsage(token, accountTag, workerName, start.toISOString(), end.toISOString());
}

/** Month-to-date (UTC) convenience wrapper for the cost circuit-breaker. */
export async function fetchMonthToDateWorkersUsage(token, accountTag, workerName, now) {
  const t = now || new Date();
  const start = new Date(Date.UTC(t.getUTCFullYear(), t.getUTCMonth(), 1));
  return fetchWorkersUsage(token, accountTag, workerName, start.toISOString(), t.toISOString());
}

function todayKey() {
  return new Date().toISOString().slice(0, 10);
}

/**
 * Claim one Workers AI call against the daily hard cap.
 * Returns true (and consumes the call) while budget remains, false when the
 * cap is hit — callers must then queue for human review WITHOUT an AI call.
 */
export async function claimAiCall(env) {
  const key = `automod:ai-calls:${todayKey()}`;
  const used = parseInt((await env.KV.get(key)) || '0', 10) || 0;
  if (used >= AI_CALLS_PER_DAY_MAX) {
    // One notification per day when the cap starts biting.
    const flagKey = `automod:ai-cap-notified:${todayKey()}`;
    if (!(await env.KV.get(flagKey))) {
      await notify(env, 'info', 'AI triage budget exhausted for today',
        `Workers AI classification hit its ${AI_CALLS_PER_DAY_MAX}/day hard cap. ` +
        `Gray-area items are going to the human-review queue with no AI verdict until the cap resets.`);
      await env.KV.put(flagKey, '1', { expirationTtl: 172800 });
    }
    return false;
  }
  await env.KV.put(key, String(used + 1), { expirationTtl: 172800 });
  return true;
}

/**
 * Run the hourly billing guard. Returns a summary object.
 * `dry` (AUTOMOD_DRY_RUN="1") logs what it WOULD do without flipping oids:kill.
 */
export async function runUsageGuard(env, dry) {
  // Hourly cadence (called from the 15-min cron).
  const last = parseInt((await env.KV.get(KV_LAST_RUN)) || '0', 10) || 0;
  if (Date.now() - last < GUARD_INTERVAL_MS) return { ran: false, reason: 'throttled' };
  await env.KV.put(KV_LAST_RUN, String(Date.now()));

  const warnThreshold = parseInt(env.USAGE_WARN_THRESHOLD || '', 10) || USAGE_WARN_THRESHOLD_PER_DAY;
  const killThreshold = parseInt(env.USAGE_KILL_THRESHOLD || '', 10) || USAGE_KILL_THRESHOLD_PER_DAY;
  const workerName = env.AUTOMOD_WORKER_NAME || DEFAULT_WORKER_NAME;

  const token = env.CF_API_TOKEN;
  if (!token) {
    // Notify once so the drain cron surfaces it, then stay quiet.
    if (!(await env.KV.get(KV_UNCONFIGURED_FLAG))) {
      await notify(env, 'error', 'Billing guard inert: CF_API_TOKEN missing',
        'The hourly usage guard has no API token, so the billing hardstop is OFF. ' +
        'Create a narrow Cloudflare token (Account -> Account Analytics: Read) and run ' +
        '`wrangler secret put CF_API_TOKEN` on the oids-automod worker, then clear ' +
        'KV key automod:guard-unconfigured-notified to re-arm this notice.');
      await env.KV.put(KV_UNCONFIGURED_FLAG, '1');
    }
    return { ran: false, reason: 'no-token' };
  }

  let accountTag;
  try {
    accountTag = env.CF_ACCOUNT_ID || (await cfRest(token, '/accounts'))[0]?.id;
    if (!accountTag) throw new Error('no accounts returned');
  } catch (e) {
    await logMod(env, 'billing_guard', 'account', null, `account lookup failed: ${String(e).slice(0, 200)}`, 'automod');
    await notify(env, 'error', 'Billing guard error: account lookup failed',
      `Could not resolve the Cloudflare account ID; guard did NOT flip the switch. ${String(e).slice(0, 200)}`);
    return { ran: true, tripped: false, reason: 'account-error' };
  }

  let usage;
  try {
    usage = await fetchDailyWorkersUsage(token, accountTag, workerName);
  } catch (e) {
    await logMod(env, 'billing_guard', 'account', null, `usage query failed: ${String(e).slice(0, 200)}`, 'automod');
    await notify(env, 'error', 'Billing guard error: usage query failed',
      `GraphQL usage query failed; guard did NOT flip the switch. ${String(e).slice(0, 200)}`);
    return { ran: true, tripped: false, reason: 'query-error' };
  }

  const { total, perWorker } = usage;
  const peak = Math.max(total, perWorker);
  const peakLabel = peak === perWorker && perWorker !== total ? `worker "${workerName}"` : 'account total';
  const detail =
    `Trailing 24h Workers requests: account total ${total.toLocaleString('en-US')}, ` +
    `"${workerName}" ${perWorker.toLocaleString('en-US')}. ` +
    `Warn tier ${warnThreshold.toLocaleString('en-US')}/day, kill tier ${killThreshold.toLocaleString('en-US')}/day.`;

  const result = { ran: true, tripped: false, warnTripped: false, killTripped: false, costTripped: false, total, perWorker, warnThreshold, killThreshold };

  // COST CIRCUIT-BREAKER (primary — the operator, 2026-09-27): project month-end
  // spend BEFORE any overage charge is incurred. Fires ahead of the
  // request-count tiers on slow-burn overages.
  const costKillUsd = parseFloat(env.COST_KILL_USD || '') || COST_KILL_OVERAGE_USD;
  // GUARD_NOW (ISO string) pins "now" for the projection — used by the unit
  // tests for determinism; unset in production (real clock).
  const nowOverride = env.GUARD_NOW ? new Date(env.GUARD_NOW) : undefined;
  try {
    const mtd = await fetchMonthToDateWorkersUsage(token, accountTag, workerName, nowOverride);
    const aiKey = `automod:ai-calls:${todayKey()}`;
    const aiCallsToday = parseInt((await env.KV.get(aiKey)) || '0', 10) || 0;
    const cost = projectMonthlyCost(
      { mtdRequests: mtd.total, rate24h: total, aiCallsToday },
      costKillUsd,
      nowOverride
    );
    result.cost = cost;
    if (cost.tripped) {
      result.costTripped = true;
      const detail =
        `Cost circuit-breaker tripped: ${cost.reasons.join('; ')}. ` +
        `Projected month: ${cost.projRequests.toLocaleString('en-US')} requests, ` +
        `overages req $${cost.reqOverageUsd.toFixed(2)} / KV $${cost.kvOverageUsd.toFixed(2)} / ` +
        `AI $${cost.aiOverageUsd.toFixed(2)} (total $${cost.totalOverageUsd.toFixed(2)}/mo above the $5 base).`;
      if (dry) {
        await logMod(env, 'billing_guard', 'account', null, `[dry-run] WOULD go full dark (${DARK_KEY}): ${detail}`, 'automod');
        await notify(env, 'error', '[dry-run] Cost circuit-breaker WOULD go full dark',
          `${detail} In live mode this sets KV ${KILL_KEY} AND ${DARK_KEY} to "1" — the API worker ` +
          `then returns 404 on every route. Recover with ./revive.sh (clears both flags) after review.`);
        await noteFrontendStatus(env, true, detail);
        return { ...result, dryRun: true };
      }
      // Already dark? Don't re-notify hourly; the switch is latched.
      if ((await env.KV.get(DARK_KEY)) === '1') return { ...result, alreadyTripped: true };
      // Confirmation hysteresis (anti-false-positive): a single tripped
      // projection only ARMS a pending flag. The site goes dark only when a
      // SECOND consecutive hourly run also trips — one-off GraphQL anomalies
      // or a spike that immediately subsides never take the site dark, while
      // a real slow-burn overage stays tripped hour after hour. The pending
      // flag self-expires (2h TTL); a healthy projection clears it outright.
      if ((await env.KV.get(COST_PENDING_KEY)) !== '1') {
        await env.KV.put(COST_PENDING_KEY, '1', { expirationTtl: 7200 });
        await logMod(env, 'billing_guard', 'account', null, `cost trip PENDING confirmation (1 of 2): ${detail}`, 'automod');
        await notify(env, 'error', 'Cost circuit-breaker: trip pending confirmation (site NOT dark)',
          `${detail} The site is NOT dark yet. If the next hourly check also trips, ` +
          `KV ${KILL_KEY} and ${DARK_KEY} go to "1" and the API returns 404 on every route. ` +
          `If this was a transient spike, no action is needed — the pending state clears itself on recovery.`);
        return { ...result, costPending: true };
      }
      await env.KV.delete(COST_PENDING_KEY);
      await env.KV.put(KILL_KEY, '1');
      await env.KV.put(DARK_KEY, '1');
      await logMod(env, 'billing_guard', 'account', null, `FULL DARK (${DARK_KEY}): ${detail}`, 'automod');
      await notify(env, 'error', 'URGENT: cost circuit-breaker went full dark',
        `${detail} KV ${KILL_KEY} and ${DARK_KEY} are now "1"; the API returns 404 on every route. ` +
        `Investigate the usage source, then recover with ./revive.sh (clears both flags).`);
      await noteFrontendStatus(env, false, detail);
      return result;
    }
  } catch (e) {
    // Cost projection failed: fail safe (no dark), keep the request tiers live.
    await logMod(env, 'billing_guard', 'account', null, `cost projection skipped: ${String(e).slice(0, 200)}`, 'automod');
    result.costSkipped = String(e).slice(0, 120);
  }

  // Healthy projection (query succeeded, no trip): stand down any
  // armed-but-unconfirmed cost trip. Not cleared when the query itself
  // failed — unknown state leaves the pending flag to its TTL.
  if (!result.costSkipped) await env.KV.delete(COST_PENDING_KEY);

  // KILL tier first (highest severity). Whichever series hits first trips.
  // Automated trips go FULL DARK (kill + dark -> API 404 on every route),
  // per the operator's rule: a flood at this tier (~$10/mo overage equivalent)
  // threatens charges above the $5 base. Manual ../kill.sh still sets only
  // oids:kill (503 "temporarily unavailable") — the operator's explicit call.
  if (peak >= killThreshold) {
    result.killTripped = true;
    if (dry) {
      await logMod(env, 'billing_guard', 'account', null, `[dry-run] WOULD go full dark (${DARK_KEY}) (${peakLabel} hit kill tier): ${detail}`, 'automod');
      await notify(env, 'error', '[dry-run] Billing guard WOULD go full dark (kill tier)',
        `${detail} In live mode this flips KV oids:kill AND oids:dark to "1" (API returns 404 on every route). ` +
        `Recover with ./revive.sh (clears both flags) after reviewing the flood source.`);
      await noteFrontendStatus(env, true, detail);
      return { ...result, dryRun: true };
    }
    // Already dark? Don't re-notify hourly; the switch is latched.
    if ((await env.KV.get(DARK_KEY)) === '1') return { ...result, alreadyTripped: true };
    await env.KV.put(KILL_KEY, '1');
    await env.KV.put(DARK_KEY, '1');
    await logMod(env, 'billing_guard', 'account', null, `FULL DARK (${DARK_KEY}) (${peakLabel} hit kill tier): ${detail}`, 'automod');
    await notify(env, 'error', 'URGENT: billing guard went full dark (flood tier)',
      `${detail} KV oids:kill and oids:dark are now "1"; the API is returning 404 on every route. ` +
      `Investigate the flood source, then recover with ./revive.sh (clears both flags).`);
    await noteFrontendStatus(env, false, detail);
    return result;
  }

  // WARN tier: urgent notification, once per day.
  if (peak >= warnThreshold) {
    result.warnTripped = true;
    const flagKey = `automod:guard-warned:${todayKey()}`;
    const prefix = dry ? '[dry-run] Billing guard WOULD warn' : 'Billing guard WARNING: usage above warn tier';
    if (!(await env.KV.get(flagKey))) {
      await logMod(env, 'billing_guard', 'account', null, `${dry ? '[dry-run] ' : ''}WARN tier hit (${peakLabel}): ${detail}`, 'automod');
      await notify(env, 'error', prefix,
        `${detail} This is the warn tier — no switch flipped. If usage keeps climbing toward the kill tier ` +
        `(${killThreshold.toLocaleString('en-US')}/day), the guard will flip KV oids:kill to "1".`);
      await env.KV.put(flagKey, '1', { expirationTtl: 172800 });
    }
    return { ...result, dryRun: dry || undefined };
  }

  return result;
}
