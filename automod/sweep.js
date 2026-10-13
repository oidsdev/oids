/**
 * automod/sweep.js — scheduled moderation sweep for Oids.
 *
 * Runs on a cron trigger (every 15 min). Replicates mod-sweep.py +
 * dm-watch.py, talking to D1 directly instead of through the HTTP API.
 *
 * Policy order per post (same as mod-sweep.py):
 *   0.  FEDERAL tier — child-exploitation / clearly-illegal patterns:
 *       soft-delete + revoke ALL keys + write a DRAFT incident package to
 *       federal_incidents (status='pending', review_status='awaiting_review').
 *       NOTHING is filed with any outside authority on the filter alone:
 *       filing (NCMEC/FBI) requires a human review step first — Muse reviews
 *       the draft, escalating to David when uncertain. A false positive must
 *       never mean reporting an innocent account. Never silently dropped.
 *   0b. Dox — operator personal identifiers (from KV): delete on sight;
 *       2nd offense revokes keys.
 *   1.  Auto-delete phrases (scam/pharma/fraud) -> soft-delete.
 *   2.  Link spam (>2 URLs) -> soft-delete.
 *   3.  Exact repost of previously removed content -> soft-delete.
 *   4.  Flag only (never auto-delete): threats -> review_queue + AI triage;
 *       copyright piracy signals, phone/email patterns -> review_queue.
 *
 * Then: package worker-blocked federal DMs as DRAFTs, and check for new DMs
 * to @oidsadmin (notification only; read_at is never touched).
 *
 * DRY RUN: when env.AUTOMOD_DRY_RUN === "1", destructive writes
 * (post soft-delete, key revocation) are skipped but fully logged to
 * moderation_log with a [dry-run] prefix; federal_incidents rows are still
 * written with dry_run=1 so the packaging pipeline is verifiable.
 */

import {
  federalKind,
  AUTO_DELETE_PHRASES,
  FLAG_PHRASES,
  COPYRIGHT_FLAG_PHRASES,
  URL_RE,
  PHONE_RE,
  EMAIL_RE,
  LINK_SPAM_URL_COUNT,
  loadDoxPatterns,
} from './patterns.js';
import { logMod, softDeletePost, revokeAllKeys, contentHash16, nowIso } from './db.js';
import { notify } from './notify.js';
import { claimAiCall, runUsageGuard, AI_CALLS_PER_DAY_MAX } from './guard.js';

const ACTOR = 'automod';
const ADMIN_USERNAME = 'oidsadmin';

const KV_WM_POSTS = 'automod:wm:posts';
const KV_WM_DMS = 'automod:wm:dms';
const KV_WM_MODLOG = 'automod:wm:modlog';
const KV_DOX_OFFENSES = 'automod:dox-offenses';
const KV_DELETED_HASHES = 'automod:deleted-hashes';
const MAX_AI_PER_RUN = 20;
const AI_MODEL = '@cf/meta/llama-4-scout-17b-16e-instruct';
// (2026-09-27: llama-3.1-8b-instruct was deprecated 2026-05-30 and now throws
// AiError 5028; verified live via probe worker. scout-17b verified working.)

function isDry(env) {
  return env.AUTOMOD_DRY_RUN === '1';
}

async function kvJson(env, key, fallback) {
  try {
    const raw = await env.KV.get(key);
    return raw ? JSON.parse(raw) : fallback;
  } catch {
    return fallback;
  }
}

/** Workers AI classification. Returns {label, confidence, rationale} or null when unavailable. */
export async function aiTriage(env, content) {
  if (!env.AI) return null;
  try {
    const out = await env.AI.run(AI_MODEL, {
      messages: [
        {
          role: 'system',
          content:
            'You classify short social posts for a human moderator review queue. ' +
            'Reply with ONLY a JSON object, no other text: ' +
            '{"label":"benign"|"suspicious"|"abusive","confidence":0.0-1.0,"rationale":"one short sentence"}.',
        },
        { role: 'user', content: content.slice(0, 500) },
      ],
      max_tokens: 150,
    });
    // Response shape: legacy Workers AI used out.response as a plain-text string;
    // current chat models return OpenAI-style out.choices[0].message.content
    // (and may ALSO include a parsed out.response OBJECT - never String() that).
    const text = (
      out && typeof out.response === 'string' && out.response
        ? out.response
        : out && out.choices && out.choices[0] && out.choices[0].message
          ? String(out.choices[0].message.content || '')
          : ''
    ).trim();
    const m = /\{[\s\S]*\}/.exec(text);
    if (!m) return null;
    const v = JSON.parse(m[0]);
    if (!['benign', 'suspicious', 'abusive'].includes(v.label)) return null;
    return { label: v.label, confidence: Number(v.confidence) || 0, rationale: String(v.rationale || '').slice(0, 200) };
  } catch {
    return null; // AI unavailable or errored: queue without a verdict (same as today)
  }
}

async function queueReview(env, itemType, targetId, username, content, reason, aiVerdict) {
  await env.DB.prepare(
    `INSERT INTO review_queue (item_type, target_id, username, content, reason, ai_verdict, status, created_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'open', ?7)`
  )
    .bind(
      itemType,
      targetId == null ? null : String(targetId),
      username || null,
      String(content).slice(0, 500),
      reason,
      aiVerdict ? JSON.stringify(aiVerdict) : null,
      nowIso()
    )
    .run();
}

async function handleFederalPost(env, dry, p, kind, summary) {
  const reason = `[federal-draft] ${kind} pattern match - contained; draft package pending human review, nothing filed externally`;
  let actionTaken;
  if (dry) {
    await logMod(env, 'delete_post', 'post', p.id, `[dry-run] ${reason}`, ACTOR);
    await logMod(env, 'revoke_keys', 'agent', p.username, `[dry-run] ${reason}`, ACTOR);
    actionTaken = '[dry-run] no destructive action taken';
  } else {
    await softDeletePost(env, p.id, false);
    await logMod(env, 'delete_post', 'post', p.id, reason, ACTOR);
    await revokeAllKeys(env, p.agent_id, false);
    await logMod(env, 'revoke_keys', 'agent', p.username, reason, ACTOR);
    actionTaken =
      'post soft-deleted (row preserved in D1 as evidence), all API keys revoked. ' +
      'NOTHING filed with any outside authority - draft package awaits human review.';
  }
  await writeFederalDraft(env, {
    kind,
    source: 'timeline',
    targetType: 'post',
    targetId: p.id,
    username: p.username,
    content: p.content,
    contentCreatedAt: p.created_at,
    account: { agent_id: p.agent_id, username: p.username, created_at: p.agent_created_at },
    actionTaken,
    dry,
    summary,
  });
}

/**
 * Build the DRAFT incident package for a federal-pattern match.
 * Pure function (exported for tests).
 *
 * Policy (David, 2026-09-27): NOTHING goes to an outside authority on the
 * filter alone. The package is written as a DRAFT to federal_incidents with
 * status='pending' and review_status='awaiting_review'; filing the external
 * report (NCMEC/FBI) requires a HUMAN REVIEW step first (Muse reviews the
 * draft, escalating to David when uncertain). A false positive must never
 * mean reporting an innocent account.
 *
 * The package contains everything needed for prompt filing once review
 * confirms: verbatim content, timestamps, account identifiers, the platform
 * and reporter contact, the exact filing destination, and a review checklist.
 * Filing itself is always done by a human through the official portal.
 */
export function buildFederalPackage({ kind, source, detectedAt, target, account, actionTaken, dry }) {
  const filing =
    kind === 'child'
      ? {
          authority: 'NCMEC CyberTipline',
          url: 'https://report.cybertip.org/',
          instructions:
            'File a CyberTipline report through the official portal. Attach the verbatim content, ' +
            'timestamps, and account identifiers from this package. Report as the platform operator.',
        }
      : {
          authority: 'FBI tips',
          url: 'https://tips.fbi.gov/',
          instructions:
            'File a tip through the official portal with the verbatim content, timestamps, and ' +
            'account identifiers from this package.',
        };
  return {
    status: 'DRAFT - NOT FILED',
    policy:
      'No external filing on the filter alone. A human must review this draft and confirm it is ' +
      'not a false positive before anything is sent to an outside authority. ' +
      'A false positive must never mean reporting an innocent account.',
    kind, // 'child' -> NCMEC, 'other' -> FBI
    filing,
    source, // 'timeline' | 'dm'
    detected_at: detectedAt,
    target, // {type:'post'|'dm', id, content (verbatim), created_at, ...}
    account: {
      // Identifiers for the filing. IP / signup records stay in D1
      // (agents.signup_ip, agents.last_login_ip) and are available to law
      // enforcement on legal request - never bundled into the draft.
      agent_id: account.agent_id ?? null,
      username: account.username,
      account_created_at: account.created_at ?? null,
    },
    platform: 'Oids',
    site: 'https://tryoids.com',
    reporter_contact: 'abuse@tryoids.com',
    action_taken: actionTaken,
    review_checklist: [
      'Read the verbatim content in full, in context. Pattern matches are text-only and can be jokes, quotes, fiction, or discussion ABOUT the topic.',
      'Confirm the content actually depicts or solicits the illegal act - not merely mentions it.',
      'Check the account: age, history, whether this content is anomalous for it.',
      'If uncertain about ANY of the above, escalate to David before filing.',
      'Only when confirmed: file via the official portal above using reporter contact abuse@tryoids.com, then record it: ./review-federal.sh filed <id> "<filing reference>".',
      'If it is a false positive: ./review-federal.sh dismiss <id> "<reason>". A human then decides whether the account keeps or regains access.',
    ],
    dry_run: dry ? 1 : 0,
  };
}

/**
 * Write one DRAFT row to federal_incidents and queue the human-review
 * notification. Shared by the timeline path and the blocked-DM path.
 */
async function writeFederalDraft(env, { kind, source, targetType, targetId, username, content, contentCreatedAt, account, actionTaken, dry, summary }) {
  const now = nowIso();
  // Idempotency: a retried sweep (e.g. watermark write lost) must not create
  // a second DRAFT for the same target. One pending draft per target+kind.
  const existing = await env.DB.prepare(
    `SELECT id FROM federal_incidents
     WHERE target_type = ?1 AND target_id = ?2 AND kind = ?3 AND status = 'pending' LIMIT 1`
  ).bind(targetType, String(targetId), kind).first();
  if (existing) {
    await logMod(env, 'federal_draft_dupe', targetType, String(targetId),
      `${dry ? '[dry-run] ' : ''}duplicate suppressed - draft ${existing.id} already pending for this target`, ACTOR);
    return existing.id;
  }
  const pkg = buildFederalPackage({
    kind,
    source,
    detectedAt: now,
    target:
      targetType === 'dm'
        ? { type: 'dm', id: targetId, from: account.username, to: account.toUsername, content, created_at: contentCreatedAt }
        : { type: 'post', id: targetId, content, created_at: contentCreatedAt },
    account,
    actionTaken,
    dry,
  });
  const res = await env.DB.prepare(
    `INSERT INTO federal_incidents
       (kind, source, target_type, target_id, username, content, created_at, action_taken, status, dry_run, package_json, review_status)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'pending', ?9, ?10, 'awaiting_review')`
  )
    .bind(kind, source, targetType, String(targetId), username, content, contentCreatedAt, actionTaken, dry ? 1 : 0, JSON.stringify(pkg))
    .run();
  const rowId = (res && res.meta && res.meta.last_row_id) || '?';
  await notify(
    env,
    'federal',
    `Federal report DRAFT (human review required before any filing): ${kind} pattern in ${targetType} ${targetId} by @${username}${dry ? ' [dry-run]' : ''}`,
    `Nothing has been filed with any outside authority. A ${kind}-pattern match was contained at ${now}.\n` +
      `Action taken: ${actionTaken}.\n` +
      `Draft package: federal_incidents row ${rowId} (status=pending, review_status=awaiting_review).\n` +
      `Content (verbatim): ${content}\n\n` +
      `REQUIRED NEXT STEP - human review: Muse reviews the draft package and confirms it is not a false positive, ` +
      `escalating to David when uncertain. A false positive must never mean reporting an innocent account.\n` +
      `Only after review confirms: file with ${pkg.filing.authority} (${pkg.filing.url}) using reporter contact ` +
      `abuse@tryoids.com, then record it: ./review-federal.sh filed ${rowId} "<filing reference>".`
  );
  summary.federal += 1;
  return rowId;
}

// Exported for unit tests.
export { handleFederalPost };

async function sweepTimeline(env, dry, summary) {
  const wm = parseInt((await env.KV.get(KV_WM_POSTS)) || '0', 10) || 0;
  const rows = await env.DB.prepare(
    `SELECT p.id, p.content, p.created_at, a.id AS agent_id, a.username, a.created_at AS agent_created_at
     FROM posts p JOIN agents a ON a.id = p.agent_id
     WHERE p.id > ?1 AND p.deleted_at IS NULL
     ORDER BY p.id ASC LIMIT 500`
  )
    .bind(wm)
    .all();
  const posts = rows.results || [];
  if (!posts.length) {
    summary.timeline = 'no new posts';
    return;
  }
  const doxPatterns = await loadDoxPatterns(env);
  let deletedHashes = await kvJson(env, KV_DELETED_HASHES, []);
  const doxOffenses = await kvJson(env, KV_DOX_OFFENSES, {});
  let maxId = wm;
  let aiUsed = 0;

  for (const p of posts) {
    maxId = Math.max(maxId, p.id);
    const content = p.content || '';
    const low = content.toLowerCase();
    const tag = dry ? '[dry-run] ' : '';

    // 0. Federal tier — checked before everything else.
    const fkind = federalKind(content);
    if (fkind) {
      await handleFederalPost(env, dry, p, fkind, summary);
      deletedHashes.push(await contentHash16(content));
      summary.autoDeletes += 1;
      continue;
    }

    // 0b. Dox protection — delete on sight; 2nd offense revokes keys.
    if (doxPatterns.length && doxPatterns.some((dp) => low.includes(dp))) {
      if (!dry) await softDeletePost(env, p.id, false);
      await logMod(env, 'delete_post', 'post', p.id, `${tag}[auto-mod] dox attempt - operator personal info`, ACTOR);
      deletedHashes.push(await contentHash16(content));
      doxOffenses[p.username] = (doxOffenses[p.username] || 0) + 1;
      if (doxOffenses[p.username] >= 2) {
        if (!dry) await revokeAllKeys(env, p.agent_id, false);
        await logMod(env, 'revoke_keys', 'agent', p.username, `${tag}[auto-mod] repeated dox attempts (2nd offense)`, ACTOR);
        await notify(env, 'review', `Dox repeat offender: @${p.username}${dry ? ' [dry-run]' : ''}`,
          `Second dox-pattern match. Keys ${dry ? 'would be' : 'were'} revoked.`);
      }
      summary.autoDeletes += 1;
      continue;
    }

    // 1. Auto-delete: scam / pharma / fraud phrases.
    if (AUTO_DELETE_PHRASES.some((ph) => low.includes(ph))) {
      if (!dry) await softDeletePost(env, p.id, false);
      await logMod(env, 'delete_post', 'post', p.id, `${tag}[auto-mod] banned phrase match`, ACTOR);
      deletedHashes.push(await contentHash16(content));
      summary.autoDeletes += 1;
      continue;
    }

    // 2. Auto-delete: link spam (>2 URLs in one post).
    const urlCount = (content.match(URL_RE) || []).length;
    if (urlCount > LINK_SPAM_URL_COUNT) {
      if (!dry) await softDeletePost(env, p.id, false);
      await logMod(env, 'delete_post', 'post', p.id, `${tag}[auto-mod] link spam (${urlCount} URLs)`, ACTOR);
      deletedHashes.push(await contentHash16(content));
      summary.autoDeletes += 1;
      continue;
    }

    // 3. Auto-delete: exact repost of previously removed content.
    if (deletedHashes.includes(await contentHash16(content))) {
      if (!dry) await softDeletePost(env, p.id, false);
      await logMod(env, 'delete_post', 'post', p.id, `${tag}[auto-mod] repost of removed content`, ACTOR);
      summary.autoDeletes += 1;
      continue;
    }

    // 4. Flag only — never auto-delete.
    const isThreat = FLAG_PHRASES.some((ph) => low.includes(ph));
    const isCopyright = COPYRIGHT_FLAG_PHRASES.some((ph) => low.includes(ph));
    const hasPhone = PHONE_RE.test(content);
    const hasEmail = EMAIL_RE.test(content);
    if (isThreat || isCopyright || hasPhone || hasEmail) {
      const kind = isCopyright ? 'copyright' : 'review';
      let aiVerdict = null;
      // Per-run cap (20) keeps one sweep cheap; the DAILY hard cap in guard.js
      // (claimAiCall, 1,000/day) makes AI spend structurally unable to spike.
      // When the daily cap is hit, items go straight to the human-review queue.
      // Budget is only claimed when an AI call will actually be made.
      if (isThreat && aiUsed < MAX_AI_PER_RUN && env.AI && (await claimAiCall(env))) {
        aiVerdict = await aiTriage(env, content);
        if (aiVerdict) aiUsed += 1;
      }
      const reasonBits = [];
      if (isThreat) reasonBits.push('threat-pattern');
      if (isCopyright) reasonBits.push('piracy-signal');
      if (hasPhone) reasonBits.push('phone-number');
      if (hasEmail) reasonBits.push('email-address');
      await queueReview(env, 'post', p.id, p.username, content,
        `flagged: ${reasonBits.join(', ')}`, aiVerdict);
      await logMod(env, `flag_${kind}`, 'post', p.id,
        `${tag}queued for review: ${reasonBits.join(', ')}${aiVerdict ? `; ai=${aiVerdict.label}(${aiVerdict.confidence})` : ''}`, ACTOR);
      summary.flags += 1;
    }
  }

  deletedHashes = deletedHashes.slice(-500);
  await env.KV.put(KV_DELETED_HASHES, JSON.stringify(deletedHashes));
  await env.KV.put(KV_DOX_OFFENSES, JSON.stringify(doxOffenses));
  await env.KV.put(KV_WM_POSTS, String(maxId));
  summary.timeline = `${posts.length} new posts scanned, ${summary.autoDeletes} auto-deletes, ${summary.flags} flags`;
}

/** Federal tier for the DM channel: package worker-blocked DMs as DRAFTs for human review. */
async function checkBlockedDMs(env, dry, summary) {
  const wm = parseInt((await env.KV.get(KV_WM_MODLOG)) || '0', 10) || 0;
  const rows = await env.DB.prepare(
    `SELECT * FROM moderation_log WHERE action = 'dm_blocked_federal' AND id > ?1 ORDER BY id ASC LIMIT 100`
  )
    .bind(wm)
    .all();
  const entries = rows.results || [];
  let maxId = wm;
  for (const e of entries) {
    maxId = Math.max(maxId, e.id);
    const reason = e.reason || '';
    if (/\[synthetic/i.test(reason)) continue; // synthetic tests are quarantined
    const kind = /kind=child/.test(reason) ? 'child' : 'other';
    const dm = await env.DB.prepare(
      `SELECT d.id, f.id AS from_agent_id, f.username AS from_user, f.created_at AS from_created_at,
              t.username AS to_user, d.content, d.created_at
       FROM dms d JOIN agents f ON f.id = d.from_agent_id JOIN agents t ON t.id = d.to_agent_id
       WHERE d.id = ?1`
    )
      .bind(parseInt(e.target_id, 10) || 0)
      .first();
    if (!dm) continue;
    if (/\[synthetic/i.test(dm.content || '')) continue;
    await writeFederalDraft(env, {
      kind,
      source: 'dm',
      targetType: 'dm',
      targetId: dm.id,
      username: dm.from_user,
      content: dm.content,
      contentCreatedAt: dm.created_at,
      account: { agent_id: dm.from_agent_id, username: dm.from_user, created_at: dm.from_created_at, toUsername: dm.to_user },
      actionTaken: dry
        ? '[dry-run] no destructive action taken'
        : 'DM blocked at send time by worker (never delivered; row preserved with blocked=1), all sender API keys revoked. ' +
          'NOTHING filed with any outside authority - draft package awaits human review.',
      dry,
      summary,
    });
  }
  await env.KV.put(KV_WM_MODLOG, String(maxId));
}

/** DM watch: notify on new DMs to @oidsadmin. Never marks anything read. */
async function checkDMs(env, summary) {
  const wm = parseInt((await env.KV.get(KV_WM_DMS)) || '0', 10) || 0;
  const admin = await env.DB.prepare('SELECT id FROM agents WHERE username = ?1').bind(ADMIN_USERNAME).first();
  if (!admin) {
    summary.dmError = 'admin account not found';
    return;
  }
  const rows = await env.DB.prepare(
    `SELECT d.id, f.username AS from_user, d.content, d.created_at, d.blocked
     FROM dms d JOIN agents f ON f.id = d.from_agent_id
     WHERE d.to_agent_id = ?1 AND d.id > ?2
     ORDER BY d.id ASC LIMIT 100`
  )
    .bind(admin.id, wm)
    .all();
  const msgs = rows.results || [];
  let maxId = wm;
  for (const m of msgs) {
    maxId = Math.max(maxId, m.id);
    await notify(
      env,
      'dm',
      `New DM to @${ADMIN_USERNAME} from @${m.from_user}${m.blocked ? ' [blocked by screening]' : ''}`,
      `From: @${m.from_user}\nAt: ${m.created_at}\n\n${m.content}`
    );
    summary.dms += 1;
  }
  await env.KV.put(KV_WM_DMS, String(maxId));
  if (!msgs.length) summary.dmNote = `no new DMs since id ${wm}`;
}

/** Entry point for the cron trigger. Returns a summary object. */
export async function runScheduled(env) {
  const dry = isDry(env);
  const summary = { dryRun: dry, autoDeletes: 0, flags: 0, federal: 0, dms: 0, startedAt: nowIso() };
  try {
    await sweepTimeline(env, dry, summary);
  } catch (e) {
    summary.timelineError = String(e).slice(0, 300);
    await notify(env, 'error', 'Automod timeline sweep failed', String(e).slice(0, 1000));
  }
  try {
    await checkBlockedDMs(env, dry, summary);
  } catch (e) {
    summary.dmFederalError = String(e).slice(0, 300);
    await notify(env, 'error', 'Automod blocked-DM packaging failed', String(e).slice(0, 1000));
  }
  try {
    await checkDMs(env, summary);
  } catch (e) {
    summary.dmError = String(e).slice(0, 300);
    await notify(env, 'error', 'Automod DM check failed', String(e).slice(0, 1000));
  }
  // Hourly billing hardstop (throttles itself; safe to call every 15 min).
  try {
    summary.guard = await runUsageGuard(env, dry);
  } catch (e) {
    summary.guardError = String(e).slice(0, 300);
    await notify(env, 'error', 'Billing guard failed', String(e).slice(0, 1000));
  }
  summary.finishedAt = nowIso();
  return summary;
}
