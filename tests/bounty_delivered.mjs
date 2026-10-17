/**
 * Bounty delivered state: create, claim, deliver, complete, plus the
 * permission and status guards around the new step.
 *
 * Lifecycle covered: open -> claimed -> delivered -> completed, and the
 * backward-compatible claimed -> completed path. Notes are rejected over
 * the 500 code point cap (413), not trimmed.
 *
 * Runs the worker fetch handler against an in-memory SQLite database.
 *   node tests/bounty_delivered.mjs
 */
import { readFileSync, existsSync, writeFileSync, unlinkSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';

// worker/index.js imports ./legal.js, which is not in this tree. The bounty
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

const POSTER_KEY = 'oids_test_bounty_poster_key';
const CLAIMANT_KEY = 'oids_test_bounty_claimant_key';
const THIRD_KEY = 'oids_test_bounty_third_key';
const ORIGIN = 'https://api.tryoids.com';

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
    CREATE TABLE client_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      agent_id INTEGER,
      client_type TEXT,
      ip TEXT
    );
    INSERT INTO agents (id, username) VALUES (1, 'poster_bot');
    INSERT INTO agents (id, username) VALUES (2, 'worker_bot');
    INSERT INTO agents (id, username) VALUES (3, 'third_bot');
  `);
  const insertKey = db.prepare('INSERT INTO api_keys (agent_id, key_hash, revoked, expires_at) VALUES (?, ?, 0, NULL)');
  insertKey.run(1, keyHashes[0]);
  insertKey.run(2, keyHashes[1]);
  insertKey.run(3, keyHashes[2]);
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

async function createBounty(env, title) {
  const created = await call(env, 'POST', '/api/bounties', {
    key: POSTER_KEY,
    body: { title, description: 'Do the work and report back in the room.', price_cents: 2500 },
  });
  assert(created.status === 200, 'create bounty is 200, got ' + created.status + ' ' + created.text);
  assert(Number.isInteger(created.json.id), 'create returns an integer id');
  return created.json.id;
}

async function listIds(env, status) {
  const listed = await call(env, 'GET', '/api/bounties?status=' + status);
  assert(listed.status === 200, 'list ?status=' + status + ' is 200, got ' + listed.status);
  return listed.json.bounties;
}

async function main() {
  const db = new DatabaseSync(':memory:');
  const keyHashes = [
    await sha256hex(POSTER_KEY),
    await sha256hex(CLAIMANT_KEY),
    await sha256hex(THIRD_KEY),
  ];
  seed(db, keyHashes);
  const env = { DB: d1(db), KV: kv() };

  // llms.txt copies stay in sync, and both name the deliver endpoint.
  const llms = await call(env, 'GET', '/llms.txt');
  assert(llms.status === 200, 'GET /llms.txt is 200');
  const fileLlms = readFileSync(new URL('../frontend/llms.txt', import.meta.url), 'utf8');
  assert(llms.text === fileLlms, 'worker /llms.txt matches frontend/llms.txt');
  assert(llms.text.includes('/:id/deliver'), 'llms.txt names the deliver endpoint');
  assert(llms.text.includes('delivered'), 'llms.txt names the delivered status');

  // Full lifecycle: create -> claim -> deliver -> complete.
  const id = await createBounty(env, 'Backtest this momentum rule');

  const openList = await listIds(env, 'open');
  const openRow = openList.find((b) => b.id === id);
  assert(openRow, 'new bounty is listed as open');
  assert(openRow.delivered_at === null, 'new bounty delivered_at is null');
  assert(openRow.delivery_note === null, 'new bounty delivery_note is null');
  assert(openRow.claimant === null, 'new bounty claimant is null');

  const earlyDeliver = await call(env, 'POST', '/api/bounties/' + id + '/deliver', { key: CLAIMANT_KEY, body: {} });
  assert(earlyDeliver.status === 400, 'deliver on an open bounty is 400, got ' + earlyDeliver.status);
  assert(earlyDeliver.json.error === 'bad_request', 'deliver on open error is bad_request');

  const earlyComplete = await call(env, 'POST', '/api/bounties/' + id + '/complete', { key: POSTER_KEY });
  assert(earlyComplete.status === 400, 'complete on an open bounty is 400, got ' + earlyComplete.status);
  assert(earlyComplete.json.message === 'Bounty must be claimed or delivered before it can be completed.', 'complete on open names claimed or delivered');

  const claimed = await call(env, 'POST', '/api/bounties/' + id + '/claim', { key: CLAIMANT_KEY });
  assert(claimed.status === 200 && claimed.json.status === 'claimed', 'claim is 200 claimed');

  const posterDeliver = await call(env, 'POST', '/api/bounties/' + id + '/deliver', { key: POSTER_KEY, body: {} });
  assert(posterDeliver.status === 403, 'deliver by poster is 403, got ' + posterDeliver.status);
  assert(posterDeliver.json.message === 'Only the claimant can mark a bounty delivered.', 'deliver by poster message names the claimant rule');

  const thirdDeliver = await call(env, 'POST', '/api/bounties/' + id + '/deliver', { key: THIRD_KEY, body: {} });
  assert(thirdDeliver.status === 403, 'deliver by third party is 403, got ' + thirdDeliver.status);
  assert(thirdDeliver.json.message === 'Only the claimant can mark a bounty delivered.', 'deliver by third party message names the claimant rule');

  const anonDeliver = await call(env, 'POST', '/api/bounties/' + id + '/deliver', { body: {} });
  assert(anonDeliver.status === 401, 'deliver without a key is 401, got ' + anonDeliver.status);

  const missingDeliver = await call(env, 'POST', '/api/bounties/999999/deliver', { key: CLAIMANT_KEY, body: {} });
  assert(missingDeliver.status === 404, 'deliver on a missing bounty is 404, got ' + missingDeliver.status);

  // Over the cap: rejected with 413, not trimmed, and the bounty stays claimed.
  const longNote = await call(env, 'POST', '/api/bounties/' + id + '/deliver', {
    key: CLAIMANT_KEY,
    body: { note: 'x'.repeat(501) },
  });
  assert(longNote.status === 413, 'note over 500 code points is 413, got ' + longNote.status);
  assert(longNote.json.error === 'content_too_long', 'long note error is content_too_long');
  const stillClaimed = await listIds(env, 'claimed');
  assert(stillClaimed.some((b) => b.id === id), 'bounty stays claimed after a rejected note');

  const delivered = await call(env, 'POST', '/api/bounties/' + id + '/deliver', {
    key: CLAIMANT_KEY,
    body: { note: 'Done. <b>Report</b> posted in the room.' },
  });
  assert(delivered.status === 200, 'deliver by claimant is 200, got ' + delivered.status + ' ' + delivered.text);
  assert(delivered.json.status === 'delivered', 'deliver response status is delivered');

  const deliveredList = await listIds(env, 'delivered');
  const deliveredRow = deliveredList.find((b) => b.id === id);
  assert(deliveredRow, '?status=delivered returns the delivered bounty');
  assert(typeof deliveredRow.delivered_at === 'string' && deliveredRow.delivered_at.length > 0, 'delivered_at is set');
  assert(deliveredRow.delivery_note === 'Done. Report posted in the room.', 'note is sanitized, stored, and returned, got ' + JSON.stringify(deliveredRow.delivery_note));
  assert(deliveredRow.poster === 'poster_bot' && deliveredRow.claimant === 'worker_bot', 'delivered row names poster and claimant');
  const stored = db.prepare('SELECT status, delivered_at, delivery_note FROM bounties WHERE id = ?').get(id);
  assert(stored.status === 'delivered' && stored.delivered_at === deliveredRow.delivered_at, 'stored row matches the listed delivered row');

  const claimedAfter = await listIds(env, 'claimed');
  assert(!claimedAfter.some((b) => b.id === id), 'delivered bounty no longer lists as claimed');

  const claimantComplete = await call(env, 'POST', '/api/bounties/' + id + '/complete', { key: CLAIMANT_KEY });
  assert(claimantComplete.status === 403, 'complete by claimant is 403, got ' + claimantComplete.status);

  const completed = await call(env, 'POST', '/api/bounties/' + id + '/complete', { key: POSTER_KEY });
  assert(completed.status === 200 && completed.json.status === 'completed', 'complete from delivered is 200 completed');
  const completedList = await listIds(env, 'completed');
  const completedRow = completedList.find((b) => b.id === id);
  assert(completedRow && completedRow.delivered_at === deliveredRow.delivered_at, 'completed row keeps delivered_at');

  // Backward compat: complete straight from claimed, no delivered step.
  const directId = await createBounty(env, 'Review this short report');
  const directClaim = await call(env, 'POST', '/api/bounties/' + directId + '/claim', { key: CLAIMANT_KEY });
  assert(directClaim.status === 200, 'second claim is 200');
  const directComplete = await call(env, 'POST', '/api/bounties/' + directId + '/complete', { key: POSTER_KEY });
  assert(directComplete.status === 200 && directComplete.json.status === 'completed', 'complete directly from claimed still works');

  // Deliver with no body at all: delivered, with a null note.
  const bareId = await createBounty(env, 'Check these three links');
  await call(env, 'POST', '/api/bounties/' + bareId + '/claim', { key: CLAIMANT_KEY });
  const bareDeliver = await call(env, 'POST', '/api/bounties/' + bareId + '/deliver', { key: CLAIMANT_KEY });
  assert(bareDeliver.status === 200, 'deliver with no body is 200, got ' + bareDeliver.status + ' ' + bareDeliver.text);
  const bareRow = (await listIds(env, 'delivered')).find((b) => b.id === bareId);
  assert(bareRow && bareRow.delivery_note === null && bareRow.delivered_at, 'no-body deliver sets delivered_at and a null note');

  // Cancel from open still works, and cancelled bounties are listable.
  const cancelId = await createBounty(env, 'Old task no longer needed');
  const cancelled = await call(env, 'POST', '/api/bounties/' + cancelId + '/cancel', { key: POSTER_KEY });
  assert(cancelled.status === 200 && cancelled.json.status === 'cancelled', 'cancel from open is 200 cancelled');
  const cancelledList = await listIds(env, 'cancelled');
  assert(cancelledList.some((b) => b.id === cancelId), '?status=cancelled returns the cancelled bounty');
  const allList = await listIds(env, 'all');
  assert(allList.some((b) => b.id === cancelId) && allList.some((b) => b.id === id), '?status=all returns cancelled and completed bounties');

  const badStatus = await call(env, 'GET', '/api/bounties?status=nope');
  assert(badStatus.status === 400, 'unknown status is still 400');
  assert(badStatus.json.message.includes('delivered') && badStatus.json.message.includes('cancelled'), 'status error message names delivered and cancelled');

  console.log('ok');
}

main().catch((err) => {
  if (!process.exitCode) {
    console.error(err);
    process.exitCode = 1;
  }
}).finally(() => {
  if (createdLegalStub) {
    try { unlinkSync(legalPath); } catch { /* already gone */ }
  }
});
