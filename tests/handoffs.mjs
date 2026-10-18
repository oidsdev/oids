/**
 * DM handoff schema (SPEC v1.1) + bounty claim-state events.
 *
 * Covers the SPEC v1.1 acceptance tests 1-5 and 7-10 (test 6 is the
 * pre-existing suites passing unchanged):
 *   1. Create fires handoff.created; PATCH fires handoff.updated with
 *      the correct changed-fields payload.
 *   2. Non-owner PATCH -> 403, including the awaiting party; a third
 *      agent cannot address the pair's conversation at all.
 *   3. Invalid status -> 400.
 *   4. Subscription validation accepts the four new event types and
 *      still rejects unknown ones.
 *   5. Bounty claim and poster-confirm each cause exactly one emission
 *      at the source (one event_id per transition, shared by every
 *      delivery of that emission).
 *   7. Invariants: second create creates nothing; done with a non-null
 *      awaiting is rejected and state is unchanged.
 *   8. event_id dedupe: a consumer processing the same delivery twice
 *      drives state once; distinct transitions have distinct event_ids.
 *   9. Block in either direction -> create/PATCH 403, state unchanged,
 *      no event; participant reads still work.
 *  10. Flag default OFF: with no HANDOFFS_ENABLED configured, the
 *      handoff endpoints 404, the new event types are rejected, and
 *      bounty claim emits nothing.
 * Plus Claude's v1.1 clearance nits (DM 3527): awaiting == owner is
 * rejected (nit 1), and a done handoff can only be reopened by its
 * owner (nit 2, behavior + API notes).
 * Plus Claude's PR 42 review conditions (DMs 3546-3548), tested as
 * lost races at the end: a bounty claim/confirm whose guarded UPDATE
 * matches no row emits nothing and answers as its read-time check
 * would (condition A); a handoff PATCH whose ownership moved
 * mid-flight writes nothing and emits nothing (condition B); and
 * migration 025's pair-ordering CHECK (agent_a_id < agent_b_id).
 * Plus Claude's PR 42 supplement condition D (DM 3554): a create
 * requires an existing DM thread between the pair (at least one
 * non-blocked DM in either direction, the dms representation the
 * worker reads); a create naming a partner with no DM thread is 404
 * and creates/emits nothing. The seed gives sender_bot DM threads
 * with both other agents; other_bot and third_bot have none.
 *
 * Runs the worker fetch handler against an in-memory SQLite database.
 * The handoffs / agent_blocks tables are created by exec'ing the real
 * migration 025, so the migration itself is under test.
 *   node tests/handoffs.mjs
 */
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';

// worker/index.js imports ./legal.js, which is not in this tree. These
// tests do not render legal pages, so a stub is enough to load the module.
const legalPath = new URL('../worker/legal.js', import.meta.url);
const createdLegalStub = !existsSync(legalPath);
if (createdLegalStub) {
  writeFileSync(legalPath, [
    'export const TERMS_BODY = "";',
    'export const PRIVACY_BODY = "";',
    'export const CONTENT_POLICY_BODY = "";',
    'export function legalPage(title, body) { return String(title) + String(body); }',
    '',
  ].join('\n'));
}
const { default: worker } = await import('../worker/index.js');

const KEYS = {
  sender_bot: 'oids_test_sender_key',
  other_bot: 'oids_test_other_key',
  third_bot: 'oids_test_third_key',
};
const ORIGIN = 'https://api.tryoids.com';
const HOOK_A = 'https://example.com/hook-a';
const HOOK_B = 'https://example.com/hook-b';
const HOOK_C = 'https://example.com/hook-c';
const HOOK_OFF = 'https://example.com/hook-off';
const NEW_EVENTS = ['handoff.created', 'handoff.updated', 'bounty.claimed', 'bounty.confirmed'];

const deliveries = [];
globalThis.fetch = async (url, opts = {}) => {
  deliveries.push({
    url: String(url),
    method: opts.method || 'GET',
    headers: opts.headers || {},
    body: typeof opts.body === 'string' ? opts.body : '',
  });
  return new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } });
};

function fail(msg) {
  console.error('FAIL', msg);
  process.exitCode = 1;
  throw new Error(msg);
}

function assert(cond, msg) {
  if (!cond) fail(msg);
}

function sha256hex(str) {
  return crypto.subtle.digest('SHA-256', new TextEncoder().encode(str)).then((digest) => {
    return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
  });
}

/** D1-shaped wrapper. Worker SQL uses ?1, ?2, …; node:sqlite wants `?`. */
function d1(db) {
  return {
    prepare(sql) {
      return {
        bind(...args) {
          const order = [];
          const rewritten = sql.replace(/\?(\d+)/g, (_, n) => {
            order.push(Number(n) - 1);
            return '?';
          });
          const positional = order.map((i) => args[i]);
          const stmt = db.prepare(rewritten);
          return {
            async first() {
              const row = stmt.get(...positional);
              return row || null;
            },
            async all() {
              return { results: stmt.all(...positional) };
            },
            async run() {
              const info = stmt.run(...positional);
              return { meta: { last_row_id: Number(info.lastInsertRowid), changes: info.changes } };
            },
          };
        },
      };
    },
    async batch(statements) {
      const out = [];
      for (const s of statements) out.push(await s.run());
      return out;
    },
  };
}

function kv() {
  const store = new Map();
  return {
    async get(key) {
      return store.has(key) ? store.get(key) : null;
    },
    async put(key, value) {
      store.set(key, String(value));
    },
  };
}

function seed(db, keyHashes) {
  db.exec(`
    CREATE TABLE agents (
      id INTEGER PRIMARY KEY,
      username TEXT NOT NULL,
      password_hash TEXT NOT NULL DEFAULT 'x',
      is_mod INTEGER NOT NULL DEFAULT 0,
      read_only INTEGER NOT NULL DEFAULT 0,
      pro INTEGER NOT NULL DEFAULT 0,
      pro_expires_at TEXT
    );
    CREATE TABLE api_keys (
      id INTEGER PRIMARY KEY,
      agent_id INTEGER NOT NULL,
      key_hash TEXT NOT NULL,
      revoked INTEGER NOT NULL DEFAULT 0,
      expires_at TEXT
    );
    CREATE TABLE client_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      agent_id INTEGER,
      client_type TEXT,
      ip TEXT
    );
    CREATE TABLE moderation_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      action TEXT NOT NULL,
      target_type TEXT NOT NULL,
      target_id TEXT,
      reason TEXT,
      actor TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE TABLE event_subscriptions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      agent_id INTEGER NOT NULL REFERENCES agents(id),
      url TEXT NOT NULL,
      events TEXT NOT NULL,
      secret TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      revoked INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE bounties (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      poster_agent_id INTEGER NOT NULL,
      claimant_agent_id INTEGER,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      price_cents INTEGER NOT NULL,
      currency TEXT NOT NULL DEFAULT 'USD',
      status TEXT NOT NULL DEFAULT 'open',
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      claimed_at TEXT,
      delivered_at TEXT,
      delivery_note TEXT,
      completed_at TEXT
    );
    CREATE TABLE dms (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      from_agent_id INTEGER NOT NULL REFERENCES agents(id),
      to_agent_id   INTEGER NOT NULL REFERENCES agents(id),
      content       TEXT NOT NULL,
      created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      read_at       TEXT,
      blocked       INTEGER NOT NULL DEFAULT 0
    );
    INSERT INTO agents (id, username) VALUES (1, 'sender_bot'), (2, 'other_bot'), (3, 'third_bot');
    INSERT INTO bounties (id, poster_agent_id, title, description, price_cents)
      VALUES (1, 1, 'Test bounty', 'A bounty for the handoff event tests.', 500);
    INSERT INTO dms (from_agent_id, to_agent_id, content) VALUES
      (1, 2, 'seed thread: sender_bot opens the thread with other_bot'),
      (2, 1, 'seed thread: other_bot replies, so the pair has both directions'),
      (1, 3, 'seed thread: a single one-direction DM with third_bot');
  `);
  // The tables this feature adds come from the real migration file.
  db.exec(readFileSync(new URL('../migrations/025_handoffs.sql', import.meta.url), 'utf8'));
  const insKey = db.prepare('INSERT INTO api_keys (agent_id, key_hash, revoked, expires_at) VALUES (?, ?, 0, NULL)');
  insKey.run(1, keyHashes.sender_bot);
  insKey.run(2, keyHashes.other_bot);
  insKey.run(3, keyHashes.third_bot);
}

async function makeWorld(flagValue) {
  const db = new DatabaseSync(':memory:');
  const keyHashes = {
    sender_bot: await sha256hex(KEYS.sender_bot),
    other_bot: await sha256hex(KEYS.other_bot),
    third_bot: await sha256hex(KEYS.third_bot),
  };
  seed(db, keyHashes);
  const env = { DB: d1(db), KV: kv() };
  if (flagValue !== undefined) env.HANDOFFS_ENABLED = flagValue;
  return { db, env };
}

async function call(env, method, path, { key, body } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (key) headers.Authorization = 'Bearer ' + key;
  const res = await worker.fetch(new Request(ORIGIN + path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  }), env);
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* plain text */ }
  return { status: res.status, json, text };
}

function deliveriesTo(url, event) {
  return deliveries.filter((d) => d.url === url && (!event || JSON.parse(d.body).event === event));
}

function lastPayload(url, event) {
  const list = deliveriesTo(url, event);
  assert(list.length > 0, `expected a ${event} delivery to ${url}`);
  return JSON.parse(list[list.length - 1].body);
}

const CONV_B = '/api/v1/conversations/other_bot/handoff';   // sender_bot <-> other_bot, from sender_bot
const CONV_C = '/api/v1/conversations/third_bot/handoff';   // sender_bot <-> third_bot, from sender_bot

async function main() {
  // =====================================================================
  // World OFF — Acceptance Test 10: flag defaults OFF with no config.
  // =====================================================================
  {
    const { env } = await makeWorld(undefined); // no HANDOFFS_ENABLED at all
    const before = deliveries.length;

    const post = await call(env, 'POST', CONV_B, {
      key: KEYS.sender_bot, body: { owner: 'sender_bot', status: 'open', awaiting: 'other_bot' },
    });
    assert(post.status === 404 && post.json.error === 'not_found',
      'flag off: POST handoff is the standard 404, got ' + post.status + ' ' + post.text);
    const get = await call(env, 'GET', CONV_B, { key: KEYS.sender_bot });
    assert(get.status === 404, 'flag off: GET handoff is 404, got ' + get.status);
    const patch = await call(env, 'PATCH', CONV_B, {
      key: KEYS.sender_bot, body: { status: 'in_progress' },
    });
    assert(patch.status === 404, 'flag off: PATCH handoff is 404, got ' + patch.status);

    // The new event types do not exist for subscription validation.
    const badSub = await call(env, 'POST', '/api/subscriptions', {
      key: KEYS.other_bot, body: { url: HOOK_OFF, events: ['handoff.created'] },
    });
    assert(badSub.status === 400, 'flag off: handoff event type rejected, got ' + badSub.status);
    // Pre-existing behavior is untouched.
    const goodSub = await call(env, 'POST', '/api/subscriptions', {
      key: KEYS.other_bot, body: { url: HOOK_OFF, events: ['dm.received'] },
    });
    assert(goodSub.status === 201, 'flag off: dm.received subscription still creates, got ' + goodSub.status);

    // Bounty claim works exactly as before and emits nothing.
    const claim = await call(env, 'POST', '/api/bounties/1/claim', { key: KEYS.other_bot });
    assert(claim.status === 200, 'flag off: claim still works, got ' + claim.status);
    assert(deliveries.length === before, 'flag off: claim emitted no event');
  }

  // =====================================================================
  // World ON — the feature itself.
  // =====================================================================
  const { db, env } = await makeWorld('1');
  const A = KEYS.sender_bot, B = KEYS.other_bot, C = KEYS.third_bot;

  // Unauthenticated access is 401 on all three verbs.
  for (const [method, body] of [['GET', undefined], ['POST', { owner: 'sender_bot', status: 'open', awaiting: null }], ['PATCH', { status: 'open' }]]) {
    const r = await call(env, method, CONV_B, { body });
    assert(r.status === 401, `no key: ${method} handoff is 401, got ` + r.status);
  }

  // Acceptance Test 4: the four new event types validate; unknown ones
  // are still rejected.
  const subA = await call(env, 'POST', '/api/subscriptions', { key: A, body: { url: HOOK_A, events: NEW_EVENTS } });
  assert(subA.status === 201, 'subscription with new event types creates, got ' + subA.status + ' ' + subA.text);
  assert(JSON.stringify(subA.json.events) === JSON.stringify(NEW_EVENTS), 'new events echoed on create');
  const subB = await call(env, 'POST', '/api/subscriptions', { key: B, body: { url: HOOK_B, events: NEW_EVENTS } });
  assert(subB.status === 201, 'participant B subscription creates');
  const subC = await call(env, 'POST', '/api/subscriptions', { key: C, body: { url: HOOK_C, events: NEW_EVENTS } });
  assert(subC.status === 201, 'third agent subscription creates');
  const badEvent = await call(env, 'POST', '/api/subscriptions', { key: A, body: { url: HOOK_A, events: ['post.liked'] } });
  assert(badEvent.status === 400, 'unknown event still rejected, got ' + badEvent.status);
  const listed = await call(env, 'GET', '/api/subscriptions', { key: A });
  assert(listed.json.subscriptions[0].events.length === 4, 'list returns the new event types while the flag is on');

  // No handoff yet: participant GET is 404.
  const noneYet = await call(env, 'GET', CONV_B, { key: A });
  assert(noneYet.status === 404, 'GET with no handoff is 404, got ' + noneYet.status);

  // Create-time validation (invariants + unknown fields + addressing).
  const badStatusCreate = await call(env, 'POST', CONV_C, { key: A, body: { owner: 'sender_bot', status: 'nope', awaiting: null } });
  assert(badStatusCreate.status === 400, 'create with invalid status is 400, got ' + badStatusCreate.status);
  const badOwnerCreate = await call(env, 'POST', CONV_C, { key: A, body: { owner: 'other_bot', status: 'open', awaiting: null } });
  assert(badOwnerCreate.status === 400, 'create with non-participant owner is 400 (I3), got ' + badOwnerCreate.status);
  const badAwaitCreate = await call(env, 'POST', CONV_C, { key: A, body: { owner: 'sender_bot', status: 'open', awaiting: 'other_bot' } });
  assert(badAwaitCreate.status === 400, 'create with non-participant awaiting is 400 (I4), got ' + badAwaitCreate.status);
  const selfAwaitCreate = await call(env, 'POST', CONV_C, { key: A, body: { owner: 'sender_bot', status: 'open', awaiting: 'sender_bot' } });
  assert(selfAwaitCreate.status === 400, 'create with awaiting == owner is 400 (DM 3527 nit 1), got ' + selfAwaitCreate.status);
  const extraField = await call(env, 'POST', CONV_C, { key: A, body: { owner: 'sender_bot', status: 'open', awaiting: null, note: 'x' } });
  assert(extraField.status === 400, 'create with unknown field is 400, got ' + extraField.status);
  const missingField = await call(env, 'POST', CONV_C, { key: A, body: { owner: 'sender_bot', status: 'open' } });
  assert(missingField.status === 400, 'create missing awaiting is 400, got ' + missingField.status);
  const selfConv = await call(env, 'POST', '/api/v1/conversations/sender_bot/handoff', { key: A, body: { owner: 'sender_bot', status: 'open', awaiting: null } });
  assert(selfConv.status === 400, 'conversation with yourself is 400, got ' + selfConv.status);
  const ghostConv = await call(env, 'POST', '/api/v1/conversations/ghost_bot/handoff', { key: A, body: { owner: 'sender_bot', status: 'open', awaiting: null } });
  assert(ghostConv.status === 404, 'conversation with a nonexistent agent is 404, got ' + ghostConv.status);
  assert(deliveriesTo(HOOK_C).length === 0, 'rejected creates emit nothing');

  // ---- Acceptance Test 1 (create) -------------------------------------
  const created = await call(env, 'POST', CONV_B, {
    key: A, body: { owner: 'sender_bot', status: 'open', awaiting: 'other_bot' },
  });
  assert(created.status === 201, 'create is 201, got ' + created.status + ' ' + created.text);
  const h = created.json.handoff;
  assert(h.owner === 'sender_bot' && h.status === 'open' && h.awaiting === 'other_bot', 'created state matches the body');
  assert(h.conversation_id === 'dm:other_bot:sender_bot', 'conversation_id is the canonical pair id, got ' + h.conversation_id);
  assert(!('version' in h) && !('revision' in h), 'handoff object carries no version field (SPEC Section 5)');
  assert(deliveriesTo(HOOK_A, 'handoff.created').length === 1, 'creator receives handoff.created');
  assert(deliveriesTo(HOOK_B, 'handoff.created').length === 1, 'other participant receives handoff.created');
  assert(deliveriesTo(HOOK_C).length === 0, 'third agent receives nothing');
  const createdPayloadB = lastPayload(HOOK_B, 'handoff.created');
  assert(createdPayloadB.data.actor === 'sender_bot', 'created actor is the creator');
  assert(createdPayloadB.data.handoff_id === h.id, 'created payload names the handoff id');
  assert(createdPayloadB.data.conversation_id === 'dm:other_bot:sender_bot', 'created payload names the conversation');
  assert(/^[0-9a-f]{32}$/.test(createdPayloadB.data.event_id), 'created payload carries an event_id');
  assert(createdPayloadB.data.changes.owner.from === null && createdPayloadB.data.changes.owner.to === 'sender_bot',
    'created changes carry owner from null');
  assert(createdPayloadB.data.changes.status.to === 'open' && createdPayloadB.data.changes.awaiting.to === 'other_bot',
    'created changes carry status and awaiting');
  const createdEventId = createdPayloadB.data.event_id;
  const createdBodyB = deliveriesTo(HOOK_B, 'handoff.created')[0].body;

  // The other participant reads the same state; a third agent cannot
  // address the pair's conversation (their conversations are their own).
  const readByB = await call(env, 'GET', '/api/v1/conversations/sender_bot/handoff', { key: B });
  assert(readByB.status === 200 && readByB.json.handoff.id === h.id, 'other participant reads the handoff');
  const readByC = await call(env, 'GET', CONV_B, { key: C });
  assert(readByC.status === 404, 'third agent addressing their own pair sees no handoff, got ' + readByC.status);

  // ---- Acceptance Test 7 (I1) ------------------------------------------
  const second = await call(env, 'POST', '/api/v1/conversations/sender_bot/handoff', {
    key: B, body: { owner: 'other_bot', status: 'open', awaiting: 'sender_bot' },
  });
  assert(second.status === 400 && second.json.error === 'handoff_exists',
    'second create is rejected (I1), got ' + second.status + ' ' + second.text);
  const afterSecond = await call(env, 'GET', CONV_B, { key: A });
  assert(afterSecond.json.handoff.owner === 'sender_bot' && afterSecond.json.handoff.status === 'open',
    'second create changed nothing');
  assert(deliveriesTo(HOOK_A, 'handoff.created').length === 1, 'second create emitted nothing');

  // ---- Acceptance Test 2 (owner-only; the awaiting party cannot act) ---
  const awaitingPatch = await call(env, 'PATCH', '/api/v1/conversations/sender_bot/handoff', { key: B, body: { status: 'in_progress' } });
  assert(awaitingPatch.status === 403, 'awaiting party PATCH is 403, got ' + awaitingPatch.status);
  const awaitingDone = await call(env, 'PATCH', '/api/v1/conversations/sender_bot/handoff', { key: B, body: { status: 'done', awaiting: null } });
  assert(awaitingDone.status === 403, 'awaiting party cannot mark done either, got ' + awaitingDone.status);

  // ---- Acceptance Test 3 + invariant rejections on PATCH ---------------
  const badStatus = await call(env, 'PATCH', CONV_B, { key: A, body: { status: 'doing' } });
  assert(badStatus.status === 400, 'PATCH invalid status is 400, got ' + badStatus.status);
  const doneWithAwaiting = await call(env, 'PATCH', CONV_B, { key: A, body: { status: 'done' } });
  assert(doneWithAwaiting.status === 400, 'done with non-null awaiting is 400 (I2), got ' + doneWithAwaiting.status);
  const selfAwait = await call(env, 'PATCH', CONV_B, { key: A, body: { awaiting: 'sender_bot' } });
  assert(selfAwait.status === 400, 'PATCH awaiting == owner is 400 (nit 1), got ' + selfAwait.status);
  const thirdAwait = await call(env, 'PATCH', CONV_B, { key: A, body: { awaiting: 'third_bot' } });
  assert(thirdAwait.status === 400, 'PATCH awaiting a non-participant is 400 (I4), got ' + thirdAwait.status);
  const thirdOwner = await call(env, 'PATCH', CONV_B, { key: A, body: { owner: 'third_bot' } });
  assert(thirdOwner.status === 400, 'PATCH owner to a non-participant is 400 (I3), got ' + thirdOwner.status);
  const unknownField = await call(env, 'PATCH', CONV_B, { key: A, body: { status: 'open', comment: 'hi' } });
  assert(unknownField.status === 400, 'PATCH with unknown field is 400, got ' + unknownField.status);
  const emptyPatch = await call(env, 'PATCH', CONV_B, { key: A, body: {} });
  assert(emptyPatch.status === 400, 'empty PATCH is 400, got ' + emptyPatch.status);
  const stateNow = await call(env, 'GET', CONV_B, { key: A });
  assert(stateNow.json.handoff.status === 'open' && stateNow.json.handoff.awaiting === 'other_bot',
    'every rejected PATCH left state unchanged (I6)');
  assert(deliveriesTo(HOOK_A, 'handoff.updated').length === 0, 'rejected PATCHes emitted nothing');

  // ---- Acceptance Test 1 (update) ---------------------------------------
  const upd = await call(env, 'PATCH', CONV_B, { key: A, body: { status: 'in_progress' } });
  assert(upd.status === 200 && upd.json.handoff.status === 'in_progress', 'owner PATCH transitions, got ' + upd.status);
  assert(deliveriesTo(HOOK_A, 'handoff.updated').length === 1, 'owner receives handoff.updated');
  assert(deliveriesTo(HOOK_B, 'handoff.updated').length === 1, 'other participant receives handoff.updated');
  const updPayload = lastPayload(HOOK_B, 'handoff.updated');
  assert(JSON.stringify(updPayload.data.changes) === JSON.stringify({ status: { from: 'open', to: 'in_progress' } }),
    'updated changes carry only the changed field, old -> new; got ' + JSON.stringify(updPayload.data.changes));
  assert(updPayload.data.actor === 'sender_bot', 'updated actor is the owner');
  const updatedEventId = updPayload.data.event_id;
  const updatedBodyB = deliveriesTo(HOOK_B, 'handoff.updated')[0].body;

  // A PATCH that changes nothing is not a transition: no emission.
  const noop = await call(env, 'PATCH', CONV_B, { key: A, body: { status: 'in_progress' } });
  assert(noop.status === 200, 'no-op PATCH still returns state, got ' + noop.status);
  assert(deliveriesTo(HOOK_B, 'handoff.updated').length === 1, 'no-op PATCH emitted nothing');

  // ---- Acceptance Test 8 (event_id dedupe) -------------------------------
  assert(createdEventId !== updatedEventId, 'distinct transitions carry distinct event_ids');
  const seen = new Set();
  let processed = 0;
  const consume = (bodyStr) => {
    const p = JSON.parse(bodyStr);
    if (seen.has(p.data.event_id)) return false; // duplicate delivery
    seen.add(p.data.event_id);
    processed += 1;
    return true;
  };
  assert(consume(updatedBodyB) === true && processed === 1, 'first delivery processes');
  assert(consume(updatedBodyB) === false && processed === 1, 'redelivery of the same event_id is a duplicate');
  assert(consume(createdBodyB) === true && processed === 2, 'a different emission processes');

  // ---- Transfer, done, reopen (owner-only throughout) --------------------
  const transfer = await call(env, 'PATCH', CONV_B, { key: A, body: { owner: 'other_bot', awaiting: 'sender_bot' } });
  assert(transfer.status === 200 && transfer.json.handoff.owner === 'other_bot' && transfer.json.handoff.awaiting === 'sender_bot',
    'owner transfers ownership, got ' + transfer.status + ' ' + transfer.text);
  const transferPayload = lastPayload(HOOK_B, 'handoff.updated');
  assert(transferPayload.data.changes.owner.from === 'sender_bot' && transferPayload.data.changes.owner.to === 'other_bot',
    'transfer changes carry owner old -> new');
  const oldOwnerPatch = await call(env, 'PATCH', CONV_B, { key: A, body: { status: 'blocked' } });
  assert(oldOwnerPatch.status === 403, 'after transfer the old owner (now the awaiting party) cannot act, got ' + oldOwnerPatch.status);
  const finish = await call(env, 'PATCH', '/api/v1/conversations/sender_bot/handoff', {
    key: B, body: { status: 'done', awaiting: null },
  });
  assert(finish.status === 200 && finish.json.handoff.status === 'done' && finish.json.handoff.awaiting === null,
    'new owner finishes with awaiting cleared in the same transition');
  // Nit 2: a done handoff can only be reopened by its owner.
  const reopenByOther = await call(env, 'PATCH', CONV_B, { key: A, body: { status: 'open' } });
  assert(reopenByOther.status === 403, 'non-owner cannot reopen a done handoff, got ' + reopenByOther.status);
  const reopen = await call(env, 'PATCH', '/api/v1/conversations/sender_bot/handoff', { key: B, body: { status: 'open' } });
  assert(reopen.status === 200 && reopen.json.handoff.status === 'open', 'owner reopens the done handoff');

  // ---- Acceptance Test 9 (block checks) ----------------------------------
  const countA = deliveriesTo(HOOK_A).length;
  const countB = deliveriesTo(HOOK_B).length;
  db.exec('INSERT INTO agent_blocks (blocker_agent_id, blocked_agent_id) VALUES (1, 2)');
  const blockedPatch = await call(env, 'PATCH', '/api/v1/conversations/sender_bot/handoff', { key: B, body: { status: 'blocked' } });
  assert(blockedPatch.status === 403 && blockedPatch.json.error === 'blocked',
    'PATCH under a block is 403, got ' + blockedPatch.status + ' ' + blockedPatch.text);
  const readUnderBlock = await call(env, 'GET', CONV_B, { key: A });
  assert(readUnderBlock.status === 200 && readUnderBlock.json.handoff.status === 'open',
    'participant read still works under a block and state is unchanged');
  assert(deliveriesTo(HOOK_A).length === countA && deliveriesTo(HOOK_B).length === countB,
    'blocked PATCH emitted nothing');
  db.exec('DELETE FROM agent_blocks');
  // Reverse direction blocks creates too.
  db.exec('INSERT INTO agent_blocks (blocker_agent_id, blocked_agent_id) VALUES (3, 1)');
  const blockedCreate = await call(env, 'POST', CONV_C, { key: A, body: { owner: 'sender_bot', status: 'open', awaiting: null } });
  assert(blockedCreate.status === 403 && blockedCreate.json.error === 'blocked',
    'create under a block (either direction) is 403, got ' + blockedCreate.status);
  const stillNone = await call(env, 'GET', CONV_C, { key: A });
  assert(stillNone.status === 404, 'blocked create created nothing');
  assert(deliveriesTo(HOOK_C).length === 0, 'blocked create emitted nothing');
  db.exec('DELETE FROM agent_blocks');
  // Unblocked, the same create succeeds; awaiting 'external' is storable.
  const externalCreate = await call(env, 'POST', CONV_C, { key: A, body: { owner: 'sender_bot', status: 'open', awaiting: 'external' } });
  assert(externalCreate.status === 201 && externalCreate.json.handoff.awaiting === 'external',
    "create with awaiting 'external' works once the block is lifted, got " + externalCreate.status);
  assert(deliveriesTo(HOOK_C, 'handoff.created').length === 1, 'the new participant receives handoff.created');

  // ---- Acceptance Test 5 (bounty claim / confirm: exactly one emission) --
  const claim = await call(env, 'POST', '/api/bounties/1/claim', { key: B });
  assert(claim.status === 200, 'claim works, got ' + claim.status);
  assert(deliveriesTo(HOOK_A, 'bounty.claimed').length === 1, 'poster receives exactly one bounty.claimed');
  assert(deliveriesTo(HOOK_B, 'bounty.claimed').length === 1, 'claimant receives exactly one bounty.claimed');
  assert(deliveriesTo(HOOK_C, 'bounty.claimed').length === 0, 'uninvolved agent receives no bounty.claimed');
  const claimedA = lastPayload(HOOK_A, 'bounty.claimed');
  const claimedB = lastPayload(HOOK_B, 'bounty.claimed');
  assert(claimedA.data.event_id === claimedB.data.event_id,
    'both deliveries of the claim carry the same event_id (one emission)');
  assert(claimedA.data.actor === 'other_bot' && claimedA.data.bounty_id === 1, 'claimed payload names actor and bounty');
  assert(JSON.stringify(claimedA.data.changes) === JSON.stringify({ status: { from: 'open', to: 'claimed' } }),
    'claimed changes carry status old -> new');
  const confirm = await call(env, 'POST', '/api/bounties/1/complete', { key: A });
  assert(confirm.status === 200, 'poster confirm works, got ' + confirm.status);
  assert(deliveriesTo(HOOK_A, 'bounty.confirmed').length === 1, 'poster receives exactly one bounty.confirmed');
  assert(deliveriesTo(HOOK_B, 'bounty.confirmed').length === 1, 'claimant receives exactly one bounty.confirmed');
  const confirmedPayload = lastPayload(HOOK_B, 'bounty.confirmed');
  assert(confirmedPayload.data.event_id !== claimedA.data.event_id, 'confirm emission has its own event_id');
  assert(JSON.stringify(confirmedPayload.data.changes) === JSON.stringify({ status: { from: 'claimed', to: 'completed' } }),
    'confirmed changes carry status old -> new');
  const reClaim = await call(env, 'POST', '/api/bounties/1/claim', { key: C });
  assert(reClaim.status === 400, 're-claim of a completed bounty is 400, got ' + reClaim.status);
  assert(deliveriesTo(HOOK_A, 'bounty.claimed').length === 1, 'failed claim emitted nothing');

  // ---- PR 42 supplement condition D (DM 3554): create needs a DM thread --
  // sender_bot has seeded DM threads with both other agents (the pairs
  // every create above used), but other_bot and third_bot have never
  // DM'd each other: a create between them must not exist as a door
  // for naming a stranger as owner/awaiting and firing events at them.
  {
    const beforeAll = deliveries.length;
    const noThread = await call(env, 'POST', '/api/v1/conversations/third_bot/handoff', {
      key: B, body: { owner: 'other_bot', status: 'open', awaiting: null },
    });
    assert(noThread.status === 404 && noThread.json.error === 'not_found',
      'create with no DM thread between the pair is 404, got ' + noThread.status + ' ' + noThread.text);
    const noThreadReverse = await call(env, 'POST', '/api/v1/conversations/other_bot/handoff', {
      key: C, body: { owner: 'third_bot', status: 'open', awaiting: null },
    });
    assert(noThreadReverse.status === 404 && noThreadReverse.json.error === 'not_found',
      'no-thread create is 404 in the other direction too, got ' + noThreadReverse.status);
    const bcRow = db.prepare('SELECT COUNT(*) AS n FROM handoffs WHERE agent_a_id = 2 AND agent_b_id = 3').get();
    assert(bcRow.n === 0, 'no-thread creates created no handoff row');
    const bcGet = await call(env, 'GET', '/api/v1/conversations/third_bot/handoff', { key: B });
    assert(bcGet.status === 404, 'GET confirms no handoff exists on the threadless pair, got ' + bcGet.status);
    assert(deliveries.length === beforeAll, 'no-thread creates emitted nothing to anyone');
    // And the contrast: a pair WITH a thread (sender_bot <-> other_bot
    // above, sender_bot <-> third_bot above) created successfully, and
    // a one-direction thread counts — the third_bot create succeeded
    // off a single sender_bot -> third_bot DM.
  }

  // ---- PR 42 conditions A + B: lost races emit nothing -------------------
  // A race is simulated by wrapping env.DB: the first run() of the
  // guarded UPDATE first lets a competing request complete through the
  // real API — exactly the interleaving a lost race produces (the
  // handler's read saw the old state; its write lands after the winner).
  {
    const { db: rdb, env: renv } = await makeWorld('1');
    const raceDB = renv.DB;
    const raceBase = deliveries.length;
    const raceEvents = (event, key, value) => deliveries.slice(raceBase).filter((d) => {
      const p = JSON.parse(d.body);
      return p.event === event && p.data[key] === value;
    });

    for (const [key, url] of [[A, HOOK_A], [B, HOOK_B], [C, HOOK_C]]) {
      const s = await call(renv, 'POST', '/api/subscriptions', { key, body: { url, events: NEW_EVENTS } });
      assert(s.status === 201, 'race world: subscription creates, got ' + s.status);
    }
    rdb.exec(`INSERT INTO bounties (id, poster_agent_id, title, description, price_cents)
      VALUES (2, 1, 'Claim race bounty', 'A bounty for the lost-claim-race test.', 700),
             (3, 1, 'Confirm race bounty', 'A bounty for the lost-confirm-race test.', 900)`);

    const armRace = (match, inject) => {
      let armed = true;
      renv.DB = {
        prepare(sql) {
          const stmt = raceDB.prepare(sql);
          if (!sql.includes(match)) return stmt;
          return {
            bind(...args) {
              const bound = stmt.bind(...args);
              return {
                first: bound.first,
                all: bound.all,
                async run() {
                  if (armed) {
                    armed = false; // the nested request shares this env
                    await inject();
                  }
                  return bound.run();
                },
              };
            },
          };
        },
        batch: (stmts) => raceDB.batch(stmts),
      };
    };

    // Migration nit: the pair-ordering CHECK rejects a reversed pair.
    let checkThrew = false;
    try {
      rdb.prepare("INSERT INTO handoffs (agent_a_id, agent_b_id, owner_agent_id, status, created_by) VALUES (2, 1, 1, 'open', 1)").run();
    } catch { checkThrew = true; }
    assert(checkThrew, 'migration 025 CHECK rejects agent_a_id > agent_b_id');

    // (A) Claim race: other_bot's claim reads the open bounty, but
    // third_bot's claim lands before other_bot's UPDATE runs.
    armRace("UPDATE bounties SET status = 'claimed'", async () => {
      const winner = await call(renv, 'POST', '/api/bounties/2/claim', { key: C });
      assert(winner.status === 200, 'claim race setup: the competing claim succeeds, got ' + winner.status);
    });
    const claimLoser = await call(renv, 'POST', '/api/bounties/2/claim', { key: B });
    renv.DB = raceDB;
    assert(claimLoser.status === 400 && claimLoser.json.error === 'bad_request',
      'lost claim race answers as the not-open 400, got ' + claimLoser.status + ' ' + claimLoser.text);
    const raceBounty = rdb.prepare('SELECT status, claimant_agent_id FROM bounties WHERE id = 2').get();
    assert(raceBounty.status === 'claimed' && raceBounty.claimant_agent_id === 3,
      'the winning claim owns the race bounty');
    const claimedRace = raceEvents('bounty.claimed', 'bounty_id', 2);
    assert(claimedRace.length === 2,
      'exactly one bounty.claimed emission for the raced claim (poster + winner deliveries), got ' + claimedRace.length);
    assert(new Set(claimedRace.map((d) => JSON.parse(d.body).data.event_id)).size === 1,
      'the single claim emission carries one event_id');
    assert(claimedRace.every((d) => d.url === HOOK_A || d.url === HOOK_C),
      'the claim emission went to the poster and the winner only');

    // (A) Confirm race: the poster's confirm reads 'claimed', but a
    // second confirm lands before the first one's UPDATE runs.
    const setupClaim = await call(renv, 'POST', '/api/bounties/3/claim', { key: B });
    assert(setupClaim.status === 200, 'confirm race setup: claim succeeds, got ' + setupClaim.status);
    armRace("UPDATE bounties SET status = 'completed'", async () => {
      const winner = await call(renv, 'POST', '/api/bounties/3/complete', { key: A });
      assert(winner.status === 200, 'confirm race setup: the competing confirm succeeds, got ' + winner.status);
    });
    const confirmLoser = await call(renv, 'POST', '/api/bounties/3/complete', { key: A });
    renv.DB = raceDB;
    assert(confirmLoser.status === 400 && confirmLoser.json.error === 'bad_request',
      'lost confirm race is 400, got ' + confirmLoser.status + ' ' + confirmLoser.text);
    const confirmedRace = raceEvents('bounty.confirmed', 'bounty_id', 3);
    assert(confirmedRace.length === 2,
      'exactly one bounty.confirmed emission for the raced confirm (poster + claimant deliveries), got ' + confirmedRace.length);
    assert(new Set(confirmedRace.map((d) => JSON.parse(d.body).data.event_id)).size === 1,
      'the single confirm emission carries one event_id');

    // (B) Stale-PATCH race: sender_bot's PATCH reads owner = sender_bot,
    // but a transfer to other_bot lands before its UPDATE runs.
    const raceCreate = await call(renv, 'POST', CONV_B, {
      key: A, body: { owner: 'sender_bot', status: 'open', awaiting: 'other_bot' },
    });
    assert(raceCreate.status === 201, 'race world: handoff creates, got ' + raceCreate.status);
    const raceHandoffId = raceCreate.json.handoff.id;
    armRace('UPDATE handoffs SET', async () => {
      const t = await call(renv, 'PATCH', CONV_B, { key: A, body: { owner: 'other_bot', awaiting: 'sender_bot' } });
      assert(t.status === 200, 'stale-PATCH race setup: the mid-flight transfer succeeds, got ' + t.status + ' ' + t.text);
    });
    const stale = await call(renv, 'PATCH', CONV_B, { key: A, body: { status: 'in_progress' } });
    renv.DB = raceDB;
    assert(stale.status === 403 && stale.json.error === 'forbidden',
      'stale PATCH after a mid-flight transfer is 403, got ' + stale.status + ' ' + stale.text);
    const afterRace = await call(renv, 'GET', CONV_B, { key: A });
    assert(afterRace.json.handoff.owner === 'other_bot' && afterRace.json.handoff.status === 'open'
      && afterRace.json.handoff.awaiting === 'sender_bot',
      'the stale PATCH wrote nothing: the transfer stands and status is untouched');
    const updatedRace = raceEvents('handoff.updated', 'handoff_id', raceHandoffId);
    assert(updatedRace.length === 2,
      'exactly one handoff.updated emission in the race (the transfer), got ' + updatedRace.length);
    assert(new Set(updatedRace.map((d) => JSON.parse(d.body).data.event_id)).size === 1,
      'the single update emission carries one event_id');
  }

  console.log('handoffs: all assertions passed');
}

main().catch((e) => {
  if (process.exitCode !== 1) {
    console.error('FAIL (unexpected)', e);
    process.exitCode = 1;
  }
});
