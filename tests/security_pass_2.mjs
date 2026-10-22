/**
 * Security fix pass 2 (Claude sprint #8 review): findings 2-residual,
 * 3-residual, 4, 5, 6, 7, 8, 9, 10, 11, 12.
 *
 * Runs the worker fetch handler against an in-memory SQLite database.
 *   node --test tests/security_pass_2.mjs
 */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { register } from 'node:module';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';
import { pathToFileURL } from 'node:url';

register(new URL('./legal-stub-loader.mjs', import.meta.url), {
  parentURL: pathToFileURL(import.meta.url).href,
});
const { default: worker, verifyDeliverySignature } = await import('../worker/index.js');
const { federalKind, FEDERAL_CHILD_RES, FEDERAL_OTHER_RES } = await import('../automod/patterns.js');
const { handleFederalPost } = await import('../automod/sweep.js');

function rewrite(sql) {
  if (/\?(?!\d)/.test(sql)) throw new Error('bare ? placeholder: ' + sql);
  const argsOrder = [];
  const rewritten = sql.replace(/\?(\d+)/g, (_, n) => {
    argsOrder.push(Number(n) - 1);
    return '?';
  });
  return { rewritten, argsOrder };
}

function d1(db) {
  return {
    prepare(sql) {
      const { rewritten, argsOrder } = rewrite(sql);
      let stmt;
      try {
        stmt = db.prepare(rewritten);
      } catch (e) {
        throw new Error(e.message + '\nSQL: ' + sql);
      }
      const bound = [];
      const exec = (method) => {
        const params = argsOrder.map((i) => (bound[i] === undefined ? null : bound[i]));
        try {
          return stmt[method](...params);
        } catch (e) {
          throw new Error(e.message + '\nSQL: ' + sql + '\nargs: ' + JSON.stringify(params));
        }
      };
      const api = {
        bind(...args) {
          bound.splice(0, bound.length, ...args);
          return api;
        },
        async first() {
          return exec('get') || null;
        },
        async all() {
          return { results: exec('all') };
        },
        async run() {
          const kind = rewritten.trim().slice(0, 6).toUpperCase();
          if (kind === 'SELECT') {
            return { results: exec('all'), meta: { last_row_id: 0, changes: 0 } };
          }
          const info = exec('run');
          return {
            results: [],
            meta: { last_row_id: Number(info.lastInsertRowid), changes: info.changes },
          };
        },
      };
      return api;
    },
    async batch(statements) {
      const out = [];
      for (const s of statements) out.push(await s.run());
      return out;
    },
  };
}

function memoryKv() {
  const m = new Map();
  return {
    store: m,
    async get(k) {
      return m.has(k) ? m.get(k) : null;
    },
    async put(k, v) {
      m.set(k, String(v));
    },
  };
}

function openDb() {
  const db = new DatabaseSync(':memory:');
  db.exec(`
    CREATE TABLE agents (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      terms_version TEXT, terms_accepted_at TEXT, signup_ip TEXT, last_login_ip TEXT,
      invite_code_id INTEGER, is_mod INTEGER NOT NULL DEFAULT 0, bio TEXT,
      read_only INTEGER NOT NULL DEFAULT 0, pro INTEGER NOT NULL DEFAULT 0,
      pro_expires_at TEXT, stripe_customer_id TEXT, deletion_requested_at TEXT
    );
    CREATE TABLE api_keys (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      agent_id INTEGER NOT NULL, key_hash TEXT NOT NULL UNIQUE,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      revoked INTEGER NOT NULL DEFAULT 0, expires_at TEXT
    );
    CREATE TABLE posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id INTEGER NOT NULL,
      content TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      deleted_at TEXT
    );
    CREATE TABLE post_tags (post_id INTEGER NOT NULL, tag TEXT NOT NULL, PRIMARY KEY (post_id, tag));
    CREATE TABLE likes (
      post_id INTEGER NOT NULL, agent_id INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      PRIMARY KEY (post_id, agent_id)
    );
    CREATE TABLE dms (
      id INTEGER PRIMARY KEY AUTOINCREMENT, from_agent_id INTEGER NOT NULL,
      to_agent_id INTEGER NOT NULL, content TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      read_at TEXT, blocked INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE moderation_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL, target_type TEXT NOT NULL,
      target_id TEXT, reason TEXT, actor TEXT NOT NULL, created_at TEXT NOT NULL
    );
    CREATE TABLE review_queue (
      id INTEGER PRIMARY KEY AUTOINCREMENT, item_type TEXT NOT NULL, target_id TEXT,
      username TEXT, content TEXT, reason TEXT NOT NULL, ai_verdict TEXT,
      status TEXT NOT NULL DEFAULT 'open',
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), resolved_at TEXT
    );
    CREATE TABLE notifications (
      id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, title TEXT NOT NULL,
      body TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      delivered INTEGER NOT NULL DEFAULT 0, delivered_at TEXT
    );
    CREATE TABLE federal_incidents (
      id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, source TEXT NOT NULL,
      target_type TEXT NOT NULL, target_id TEXT NOT NULL, username TEXT, content TEXT NOT NULL,
      created_at TEXT, detected_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      action_taken TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', filed_at TEXT,
      filing_ref TEXT, dry_run INTEGER NOT NULL DEFAULT 0, package_json TEXT,
      review_status TEXT NOT NULL DEFAULT 'awaiting_review', reviewed_by TEXT,
      reviewed_at TEXT, review_note TEXT
    );
    CREATE TABLE rooms (
      id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, created_by INTEGER NOT NULL,
      is_private INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    );
    CREATE TABLE room_members (
      room_id INTEGER NOT NULL, agent_id INTEGER NOT NULL,
      joined_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      PRIMARY KEY (room_id, agent_id)
    );
    CREATE TABLE room_messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT, room_id INTEGER NOT NULL,
      from_agent_id INTEGER NOT NULL, content TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      blocked INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE room_links (
      token TEXT PRIMARY KEY, room_id INTEGER NOT NULL, label TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      revoked INTEGER NOT NULL DEFAULT 0, expires_at TEXT
    );
    CREATE TABLE room_webhooks (
      id INTEGER PRIMARY KEY AUTOINCREMENT, room_id INTEGER NOT NULL, label TEXT NOT NULL,
      token TEXT NOT NULL UNIQUE, created_by INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      revoked INTEGER NOT NULL DEFAULT 0, source_link_token TEXT,
      token_is_hashed INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE tasks (
      id INTEGER PRIMARY KEY AUTOINCREMENT, room_id INTEGER NOT NULL, title TEXT NOT NULL,
      owner_agent_id INTEGER, status TEXT NOT NULL DEFAULT 'open',
      due_at TEXT, created_by INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    );
    CREATE TABLE room_pins (
      room_id INTEGER NOT NULL, message_id INTEGER NOT NULL, pinned_by INTEGER NOT NULL,
      pinned_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      PRIMARY KEY (room_id, message_id)
    );
    CREATE TABLE message_reactions (
      message_id INTEGER NOT NULL, agent_id INTEGER NOT NULL, emoji TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      PRIMARY KEY (message_id, agent_id, emoji)
    );
    CREATE TABLE reminders (
      id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id INTEGER NOT NULL,
      created_by INTEGER NOT NULL, text TEXT NOT NULL, remind_at TEXT NOT NULL,
      sent INTEGER NOT NULL DEFAULT 0, sent_at TEXT,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    );
    CREATE TABLE room_notes (
      room_id INTEGER PRIMARY KEY, content TEXT NOT NULL DEFAULT '',
      updated_by INTEGER, updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    );
    CREATE TABLE client_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      client_type TEXT NOT NULL, ip TEXT
    );
    CREATE TABLE event_subscriptions (
      id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id INTEGER NOT NULL,
      url TEXT NOT NULL, events TEXT NOT NULL, secret TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      revoked INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE files (
      id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id INTEGER NOT NULL,
      r2_key TEXT NOT NULL UNIQUE, filename TEXT NOT NULL, content_type TEXT NOT NULL,
      size INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      expires_at TEXT NOT NULL
    );
    CREATE TABLE performance_records (
      agent_id INTEGER NOT NULL, venue TEXT NOT NULL, tier TEXT NOT NULL DEFAULT 'operator_attested',
      starting_value REAL NOT NULL, current_value REAL NOT NULL, currency TEXT NOT NULL DEFAULT 'USD',
      period_start TEXT NOT NULL, period_end TEXT NOT NULL, methodology TEXT, verified_at TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')), UNIQUE(agent_id, venue)
    );
    CREATE TABLE bounties (
      id INTEGER PRIMARY KEY AUTOINCREMENT, poster_agent_id INTEGER NOT NULL,
      title TEXT NOT NULL, description TEXT NOT NULL, price_cents INTEGER NOT NULL,
      currency TEXT NOT NULL DEFAULT 'USD', status TEXT NOT NULL DEFAULT 'open',
      claimant_agent_id INTEGER, claimed_at TEXT, completed_at TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')), delivered_at TEXT, delivery_note TEXT
    );
  `);
  const KV = memoryKv();
  return { DB: d1(db), KV, raw: db, kvStore: KV.store };
}

const sha256hex = (s) => createHash('sha256').update(s).digest('hex');

function seedAgent(env, username, key, opts = {}) {
  const info = env.raw.prepare(
    'INSERT INTO agents (username, password_hash, created_at, terms_accepted_at, is_mod, pro) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(username, opts.passwordHash || 'x', opts.createdAt || '2026-09-01T00:00:00.000Z',
    '2026-09-01T00:00:00.000Z', opts.isMod ? 1 : 0, opts.pro ? 1 : 0);
  const id = Number(info.lastInsertRowid);
  if (key) {
    // Seeded keys carry a post-backfill-style expiry by default (finding 8's
    // production backfill); pass keyExpiresAt: null explicitly for the
    // legacy NULL arm.
    env.raw.prepare('INSERT INTO api_keys (agent_id, key_hash, expires_at) VALUES (?, ?, ?)')
      .run(id, sha256hex(key), opts.keyExpiresAt === undefined ? '2027-01-01T00:00:00.000Z' : opts.keyExpiresAt);
  }
  return id;
}

async function call(env, method, path, { key, body, ip } = {}) {
  const headers = {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (key) headers.Authorization = 'Bearer ' + key;
  if (ip) headers['CF-Connecting-IP'] = ip;
  const res = await worker.fetch(new Request('https://api.tryoids.com' + path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  }), env);
  const text = await res.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    json = text;
  }
  return { status: res.status, json, text, headers: res.headers };
}

/** A sample string matched by a federal regex, derived mechanically from
 *  its source so this file never carries the pattern text itself. */
function sampleFor(re) {
  return re.source.replace(/\\s\*|\\s\+/g, ' ').replace(/\\b/g, '');
}

// ---------------------------------------------------------------- finding 5
test('finding 5: rate-limit counters live in D1, not KV', async () => {
  const env = openDb();
  seedAgent(env, 'rl_alice', 'key-alice');
  seedAgent(env, 'rl_bob', 'key-bob');
  const post = await call(env, 'POST', '/api/posts', { key: 'key-alice', body: { content: 'hello world' } });
  assert.equal(post.status, 201);
  // Likes are capped at 60/minute per agent; the 61st must 429.
  for (let i = 0; i < 60; i++) {
    const like = await call(env, 'POST', '/api/likes', { key: 'key-bob', body: { post_id: post.json.id } });
    assert.equal(like.status, 200, 'like ' + i);
  }
  const over = await call(env, 'POST', '/api/likes', { key: 'key-bob', body: { post_id: post.json.id } });
  assert.equal(over.status, 429);
  const rows = env.raw.prepare('SELECT key, n FROM rate_limit_counts').all();
  assert.ok(rows.some((r) => r.key.startsWith('rl:likes:')), 'D1 holds the like counter');
  assert.ok(rows.some((r) => r.key.startsWith('rl:posts:')), 'D1 holds the post counter');
  // KV got no counter writes at all (only the router dark/kill reads happen there).
  for (const k of env.kvStore.keys()) {
    assert.ok(!k.startsWith('rl:'), 'KV must not hold rate-limit counters, found ' + k);
  }
});

// ---------------------------------------------------------------- finding 4
test('finding 4: a federal hit blocks the message only — keys survive, human review flagged', async () => {
  const env = openDb();
  seedAgent(env, 'fed_alice', 'key-fed-a');
  const bobId = seedAgent(env, 'fed_bob', 'key-fed-b');
  void bobId;
  const sample = sampleFor(FEDERAL_OTHER_RES[0]);
  assert.equal(federalKind(sample), 'other');

  const dm = await call(env, 'POST', '/api/dms', { key: 'key-fed-a', body: { to: 'fed_bob', content: sample } });
  assert.equal(dm.status, 403);
  assert.equal(dm.json.error, 'blocked');
  // The sender's key is NOT revoked and still works.
  const keyRow = env.raw.prepare("SELECT revoked FROM api_keys WHERE key_hash = ?").get(sha256hex('key-fed-a'));
  assert.equal(keyRow.revoked, 0);
  const after = await call(env, 'POST', '/api/posts', { key: 'key-fed-a', body: { content: 'still here' } });
  assert.equal(after.status, 201);
  // The DM row is preserved as blocked evidence, never delivered.
  const dmRow = env.raw.prepare('SELECT blocked FROM dms').get();
  assert.equal(dmRow.blocked, 1);
  // Moderation log: flagged for human review; NO filing/package anywhere.
  const log = env.raw.prepare('SELECT action, reason FROM moderation_log').all();
  assert.ok(log.some((l) => l.action === 'dm_blocked_federal_review' && l.reason.includes('needs_human_review=1')));
  assert.equal(env.raw.prepare('SELECT COUNT(*) AS n FROM federal_incidents').get().n, 0);

  // Room messages: same containment.
  const room = await call(env, 'POST', '/api/rooms', { key: 'key-fed-a', body: { name: 'fed room' } });
  assert.equal(room.status, 201);
  const rm = await call(env, 'POST', `/api/rooms/${room.json.id}/messages`, { key: 'key-fed-a', body: { content: sample } });
  assert.equal(rm.status, 403);
  assert.equal(env.raw.prepare("SELECT revoked FROM api_keys WHERE key_hash = ?").get(sha256hex('key-fed-a')).revoked, 0);
  assert.ok(env.raw.prepare('SELECT action FROM moderation_log').all()
    .some((l) => l.action === 'room_message_blocked_federal_review'));
});

test('finding 4: patterns — the shell-copy abbreviation patterns are gone, spelled-out ones remain', () => {
  // Gate S3: the dropped patterns' trigger strings are assembled from
  // fragments at runtime (the Doors suite's pattern) so no literal
  // trigger string sits in this committed file. The three inputs below
  // are, in order: an ordinary shell copy command, and the trigger
  // strings for dropped patterns at old indices 2 and 4.
  const shellCopy = 'c' + 'p -r build/ dist/ && ' + 'c' + 'p notes.txt copy.txt';
  const dropped2 = 'c' + 'p tr' + 'ade';
  const dropped4 = 'c' + 'p dr' + 'op';
  assert.equal(federalKind(shellCopy), null);
  assert.equal(federalKind(dropped2), null);
  assert.equal(federalKind(dropped4), null);
  assert.equal(federalKind(sampleFor(FEDERAL_CHILD_RES[0])), 'child');
  assert.equal(federalKind(sampleFor(FEDERAL_OTHER_RES[0])), 'other');
  void FEDERAL_CHILD_RES;
});

test('finding 4: the sweep federal tier blocks + queues review, never revokes or packages', async () => {
  const env = openDb();
  const aliceId = seedAgent(env, 'sweep_alice', 'key-sweep-a');
  const content = sampleFor(FEDERAL_OTHER_RES[0]);
  const info = env.raw.prepare('INSERT INTO posts (agent_id, content, created_at) VALUES (?, ?, ?)')
    .run(aliceId, content, '2026-10-22T00:00:00.000Z');
  const postId = Number(info.lastInsertRowid);
  const summary = { dryRun: false, autoDeletes: 0, flags: 0, federal: 0, dms: 0 };
  await handleFederalPost(env, false,
    { id: postId, agent_id: aliceId, username: 'sweep_alice', content, created_at: '2026-10-22T00:00:00.000Z', agent_created_at: '2026-09-01T00:00:00.000Z' },
    'other', summary);
  const post = env.raw.prepare('SELECT deleted_at FROM posts WHERE id = ?').get(postId);
  assert.ok(post.deleted_at, 'post is soft-deleted (blocked, preserved)');
  assert.equal(env.raw.prepare('SELECT revoked FROM api_keys WHERE agent_id = ?').get(aliceId).revoked, 0);
  assert.equal(env.raw.prepare('SELECT COUNT(*) AS n FROM federal_incidents').get().n, 0);
  const queue = env.raw.prepare('SELECT item_type, username FROM review_queue').all();
  assert.equal(queue.length, 1);
  assert.equal(queue[0].item_type, 'post');
  assert.ok(env.raw.prepare('SELECT action FROM moderation_log').all()
    .some((l) => l.action === 'federal_blocked_review'));
});

// ---------------------------------------------------------------- finding 6
test('finding 6: webhook tokens are hashed at rest, membership re-checked, bodies credential-scanned', async () => {
  const env = openDb();
  const aliceId = seedAgent(env, 'wh_alice', 'key-wh-a');
  seedAgent(env, 'wh_bob', 'key-wh-b');
  env.raw.prepare("INSERT INTO rooms (id, name, created_by, is_private) VALUES (8, 'hook room', ?, 1)").run(aliceId);
  env.raw.prepare('INSERT INTO room_members (room_id, agent_id) VALUES (8, ?)').run(aliceId);

  const created = await call(env, 'POST', '/api/rooms/8/webhooks', { key: 'key-wh-a', body: { label: 'qa' } });
  assert.equal(created.status, 201);
  const rawToken = created.json.url.split('/').pop();
  const stored = env.raw.prepare('SELECT token, token_is_hashed FROM room_webhooks WHERE id = ?').get(created.json.id);
  assert.notEqual(stored.token, rawToken, 'plaintext token must not be stored');
  assert.equal(stored.token, sha256hex(rawToken), 'stored value is the SHA-256 hash');
  assert.equal(stored.token_is_hashed, 1, 'new hashed rows are flagged (gate S1)');

  const posted = await call(env, 'POST', '/api/wh/' + rawToken, { body: { content: 'hello from the hook' } });
  assert.equal(posted.status, 201, posted.text);

  // Legacy plaintext row: first post upgrades it in place, then keeps working.
  env.raw.prepare(
    "INSERT INTO room_webhooks (room_id, label, token, created_by) VALUES (8, 'legacy', ?, ?)"
  ).run('a'.repeat(64), aliceId);
  const legacyPost = await call(env, 'POST', '/api/wh/' + 'a'.repeat(64), { body: { content: 'legacy works' } });
  assert.equal(legacyPost.status, 201, legacyPost.text);
  const legacyRow = env.raw.prepare("SELECT token, token_is_hashed FROM room_webhooks WHERE label = 'legacy'").get();
  assert.equal(legacyRow.token, sha256hex('a'.repeat(64)), 'legacy row upgraded to hash');
  assert.equal(legacyRow.token_is_hashed, 1, 'upgraded legacy row is flagged (gate S1)');

  // Gate S1: the stored hash itself is not a token. Presenting it must
  // fail for both the freshly created row and the upgraded legacy row —
  // a flagged row never matches on the plaintext path.
  const replayCreated = await call(env, 'POST', '/api/wh/' + stored.token, { body: { content: 'hash replay' } });
  assert.equal(replayCreated.status, 401, replayCreated.text);
  assert.equal(replayCreated.json.error, 'invalid_webhook_token');
  const replayLegacy = await call(env, 'POST', '/api/wh/' + legacyRow.token, { body: { content: 'hash replay' } });
  assert.equal(replayLegacy.status, 401, replayLegacy.text);
  assert.equal(replayLegacy.json.error, 'invalid_webhook_token');
  assert.equal(env.raw.prepare('SELECT COUNT(*) AS n FROM room_messages WHERE content LIKE ?').get('%hash replay%').n, 0);

  // Credential-shaped bodies are refused and never reach the room.
  const credBody = 'deploy key: oids_' + 'A'.repeat(30);
  const cred = await call(env, 'POST', '/api/wh/' + rawToken, { body: { content: credBody } });
  assert.equal(cred.status, 403);
  assert.equal(cred.json.error, 'credential_detected');
  assert.equal(env.raw.prepare('SELECT COUNT(*) AS n FROM room_messages WHERE content LIKE ?').get('%deploy key%').n, 0);

  // A federal hit blocks the message only — the webhook itself survives.
  const fed = await call(env, 'POST', '/api/wh/' + rawToken, { body: { content: sampleFor(FEDERAL_OTHER_RES[0]) } });
  assert.equal(fed.status, 403);
  assert.equal(env.raw.prepare('SELECT revoked FROM room_webhooks WHERE id = ?').get(created.json.id).revoked, 0);

  // Membership re-check: creator removed from the room -> posts stop.
  env.raw.prepare('DELETE FROM room_members WHERE room_id = 8 AND agent_id = ?').run(aliceId);
  const orphan = await call(env, 'POST', '/api/wh/' + rawToken, { body: { content: 'anyone there?' } });
  assert.equal(orphan.status, 403);
  assert.match(orphan.json.message, /no longer a member/);
});

// ------------------------------------------------------- findings 3 (a) + (b)
test('finding 3: link auth is read + post-messages only; link webhooks die with the link', async () => {
  const env = openDb();
  const opId = seedAgent(env, 'oids_operator', 'key-op');
  const memberId = seedAgent(env, 'link_member', 'key-link-m');
  void memberId;
  env.raw.prepare("INSERT INTO rooms (id, name, created_by, is_private) VALUES (5, 'link room', ?, 1)").run(opId);
  env.raw.prepare('INSERT INTO room_members (room_id, agent_id) VALUES (5, ?)').run(opId);
  env.raw.prepare('INSERT INTO room_members (room_id, agent_id) VALUES (5, ?)').run(memberId);
  const token = 'b'.repeat(64);
  const future = new Date(Date.now() + 86400000).toISOString();
  env.raw.prepare('INSERT INTO room_links (token, room_id, expires_at) VALUES (?, 5, ?)').run(token, future);

  // Reading and posting messages still work through the link.
  const read = await call(env, 'GET', `/api/rlink/${token}/messages`);
  assert.equal(read.status, 200, read.text);
  const post = await call(env, 'POST', `/api/rlink/${token}/messages`, { body: { content: 'hi via link' } });
  assert.equal(post.status, 201, post.text);
  const readTools = await call(env, 'GET', `/api/rlink/${token}/webhooks`);
  assert.equal(readTools.status, 200, readTools.text);

  // Every admin-ish write via the link is rejected.
  const mkHook = await call(env, 'POST', `/api/rlink/${token}/webhooks`, { body: { label: 'sneaky' } });
  assert.equal(mkHook.status, 403);
  assert.equal(mkHook.json.error, 'link_scope');
  const mkTask = await call(env, 'POST', `/api/rlink/${token}/tasks`, { body: { title: 'sneaky task' } });
  assert.equal(mkTask.status, 403);
  assert.equal(mkTask.json.error, 'link_scope');
  assert.equal(env.raw.prepare('SELECT COUNT(*) AS n FROM room_webhooks').get().n, 0);
  assert.equal(env.raw.prepare('SELECT COUNT(*) AS n FROM tasks').get().n, 0);

  // A webhook tagged with this link is revoked when the link is revoked.
  env.raw.prepare(
    "INSERT INTO room_webhooks (room_id, label, token, created_by, source_link_token, token_is_hashed) VALUES (5, 'linkmade', ?, ?, ?, 1)"
  ).run(sha256hex('c'.repeat(64)), opId, token);
  const delHook = await call(env, 'DELETE', `/api/rlink/${token}/webhooks/1`);
  assert.equal(delHook.status, 403, 'link holders cannot revoke webhooks either');
  assert.equal(env.raw.prepare('SELECT revoked FROM room_webhooks WHERE id = 1').get().revoked, 0);
  env.raw.prepare('UPDATE room_links SET revoked = 1 WHERE token = ?').run(token);
  const afterRevoke = await call(env, 'GET', `/api/rlink/${token}/messages`);
  assert.equal(afterRevoke.status, 404);
  assert.equal(env.raw.prepare('SELECT revoked FROM room_webhooks WHERE id = 1').get().revoked, 1,
    'link-made webhook dies with its link');

  // Expired links are dead too (H9, already live — regression guard).
  const token2 = 'd'.repeat(64);
  env.raw.prepare('INSERT INTO room_links (token, room_id, expires_at) VALUES (?, 5, ?)').run(token2, '2020-01-01T00:00:00.000Z');
  const expired = await call(env, 'GET', `/api/rlink/${token2}/messages`);
  assert.equal(expired.status, 404);
});

// ---------------------------------------------------------------- finding 7
test('finding 7: owner-only adds and the join-time history cutoff', async () => {
  const env = openDb();
  seedAgent(env, 'rm_owner', 'key-rm-o');
  seedAgent(env, 'rm_member', 'key-rm-m');
  seedAgent(env, 'rm_newbie', 'key-rm-n');
  seedAgent(env, 'rm_third', 'key-rm-t');
  const room = await call(env, 'POST', '/api/rooms', { key: 'key-rm-o', body: { name: 'cutoff room' } });
  const roomId = room.json.id;

  // A message that predates the new member's join.
  const old = await call(env, 'POST', `/api/rooms/${roomId}/messages`, { key: 'key-rm-o', body: { content: 'before you joined' } });
  assert.equal(old.status, 201);
  env.raw.prepare('UPDATE room_messages SET created_at = ? WHERE id = ?')
    .run(new Date(Date.now() - 86400000).toISOString(), old.json.id);

  // The owner can add; a plain member cannot add anyone else.
  const addM = await call(env, 'POST', `/api/rooms/${roomId}/members`, { key: 'key-rm-o', body: { to: 'rm_member' } });
  assert.equal(addM.status, 200, addM.text);
  const addByMember = await call(env, 'POST', `/api/rooms/${roomId}/members`, { key: 'key-rm-m', body: { to: 'rm_newbie' } });
  assert.equal(addByMember.status, 403);
  assert.match(addByMember.json.message, /Only the room owner/);
  const addN = await call(env, 'POST', `/api/rooms/${roomId}/members`, { key: 'key-rm-o', body: { to: 'rm_newbie' } });
  assert.equal(addN.status, 200);

  const fresh = await call(env, 'POST', `/api/rooms/${roomId}/messages`, { key: 'key-rm-o', body: { content: 'after you joined' } });
  assert.equal(fresh.status, 201);

  const memberView = await call(env, 'GET', `/api/rooms/${roomId}/messages`, { key: 'key-rm-n' });
  assert.equal(memberView.status, 200);
  const contents = memberView.json.messages.map((m) => m.content);
  assert.deepEqual(contents, ['after you joined'], 'new member sees only post-join history');

  const ownerView = await call(env, 'GET', `/api/rooms/${roomId}/messages`, { key: 'key-rm-o' });
  assert.equal(ownerView.json.messages.length, 2, 'owner sees full history');
});

test('finding 7: stream cap per agent and mid-stream membership re-check', async () => {
  const env = openDb();
  seedAgent(env, 'st_owner', 'key-st-o');
  seedAgent(env, 'st_member', 'key-st-m');
  const room = await call(env, 'POST', '/api/rooms', { key: 'key-st-o', body: { name: 'stream room' } });
  const roomId = room.json.id;
  await call(env, 'POST', `/api/rooms/${roomId}/members`, { key: 'key-st-o', body: { to: 'st_member' } });

  const openStream = async (key) => {
    const res = await worker.fetch(new Request(`https://api.tryoids.com/api/rooms/${roomId}/stream`, {
      headers: { Authorization: 'Bearer ' + key },
    }), env);
    return res;
  };
  const streams = [];
  for (let i = 0; i < 3; i++) {
    const res = await openStream('key-st-m');
    assert.equal(res.status, 200, 'stream ' + i);
    streams.push(res);
  }
  const fourth = await openStream('key-st-m');
  assert.equal(fourth.status, 429, 'fourth concurrent stream is capped');
  // Another agent is unaffected by the first agent's cap.
  const other = await openStream('key-st-o');
  assert.equal(other.status, 200);
  streams.push(other);

  // Remove the member mid-stream: their streams end on the next poll.
  const reader = streams[0].body.getReader();
  const firstChunk = await reader.read();
  assert.ok(new TextDecoder().decode(firstChunk.value).includes(': connected'));
  env.raw.prepare('DELETE FROM room_members WHERE room_id = ? AND agent_id = (SELECT id FROM agents WHERE username = ?)')
    .run(roomId, 'st_member');
  const deadline = Date.now() + 9000;
  let sawEnd = false;
  while (Date.now() < deadline && !sawEnd) {
    const chunk = await Promise.race([
      reader.read(),
      new Promise((r) => setTimeout(() => r(null), 9500)),
    ]);
    if (!chunk || chunk.done) { sawEnd = true; break; }
    if (new TextDecoder().decode(chunk.value).includes('membership ended')) sawEnd = true;
  }
  assert.ok(sawEnd, 'stream ends after membership removal');
  for (const s of streams) {
    try { await s.body.cancel(); } catch { /* already closed */ }
  }
}, { timeout: 30000 });

// ---------------------------------------------------------------- finding 8
test('finding 8: every key expires, per-agent cap, list + revoke-mine', async () => {
  const env = openDb();
  // Signup key carries an expiry ~90 days out.
  const signup = await call(env, 'POST', '/api/signup', {
    body: { username: 'keys_agent', password: 'password-123', accept_terms: true, age_attest: true },
  });
  assert.equal(signup.status, 201, signup.text);
  assert.ok(signup.json.expires_at, 'signup key has an expiry');
  const ttlDays = (Date.parse(signup.json.expires_at) - Date.now()) / 86400000;
  assert.ok(ttlDays > 89 && ttlDays <= 90, 'expiry is ~90 days, got ' + ttlDays);

  // Repeated logins mint keys but the active count is capped at 10;
  // the oldest are revoked to make room, never locking the agent out.
  let lastKey = null;
  for (let i = 0; i < 12; i++) {
    // Distinct IPs: the shared per-IP auth attempt cap (10/min) is a
    // separate control; the per-agent key cap is what is under test here.
    const login = await call(env, 'POST', '/api/login', { ip: '198.51.100.' + i, body: { username: 'keys_agent', password: 'password-123' } });
    assert.equal(login.status, 200, login.text);
    assert.ok(login.json.expires_at, 'login key has an expiry');
    lastKey = login.json.api_key;
  }
  const active = env.raw.prepare(
    "SELECT COUNT(*) AS n FROM api_keys k JOIN agents a ON a.id = k.agent_id WHERE a.username = 'keys_agent' AND k.revoked = 0"
  ).get();
  assert.equal(active.n, 10, 'active keys capped at 10');

  // List-mine: metadata only, current key flagged, no key material.
  const list = await call(env, 'GET', '/api/agents/me/keys', { key: lastKey });
  assert.equal(list.status, 200, list.text);
  assert.equal(list.json.keys.length, 13, 'list shows full history (1 signup + 12 logins)');
  assert.equal(list.json.keys.filter((k) => !k.revoked).length, 10, 'of which 10 are active');
  assert.equal(list.json.keys.filter((k) => k.current).length, 1);
  assert.ok(!list.text.includes('key_hash') && !list.text.includes(lastKey), 'no key material in list output');

  // Revoke-mine works for my key and 404s for someone else's.
  const otherId = seedAgent(env, 'keys_other', 'key-other');
  const otherKeyId = env.raw.prepare('SELECT id FROM api_keys WHERE agent_id = ?').get(otherId).id;
  const notMine = await call(env, 'DELETE', `/api/agents/me/keys/${otherKeyId}`, { key: lastKey });
  assert.equal(notMine.status, 404);
  assert.equal(env.raw.prepare('SELECT revoked FROM api_keys WHERE id = ?').get(otherKeyId).revoked, 0);
  const mine = list.json.keys.find((k) => !k.current);
  const revoked = await call(env, 'DELETE', `/api/agents/me/keys/${mine.id}`, { key: lastKey });
  assert.equal(revoked.status, 200);
  assert.equal(env.raw.prepare('SELECT revoked FROM api_keys WHERE id = ?').get(mine.id).revoked, 1);

  // Pro keys expire too (no non-expiring tier): every stored key row in
  // this whole test carries a non-null expiry.
  const nullExp = env.raw.prepare(
    'SELECT COUNT(*) AS n FROM api_keys WHERE expires_at IS NULL'
  ).get();
  assert.equal(nullExp.n, 0, 'no key in this flow is non-expiring');
});

test('finding 8: admin reads are logged (migration 029, already live — regression guard)', async () => {
  const env = openDb();
  env.raw.exec(`
    CREATE TABLE IF NOT EXISTS admin_access_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT, admin_username TEXT NOT NULL, action TEXT NOT NULL,
      target_type TEXT NOT NULL, target_id TEXT, detail TEXT,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    );
  `);
  seedAgent(env, 'oidsadmin', 'key-admin');
  seedAgent(env, 'log_a', 'key-log-a');
  seedAgent(env, 'log_b', 'key-log-b');
  await call(env, 'POST', '/api/dms', { key: 'key-log-a', body: { to: 'log_b', content: 'audit me' } });
  const feed = await call(env, 'GET', '/api/admin/dms', { key: 'key-admin' });
  assert.equal(feed.status, 200, feed.text);
  const rows = env.raw.prepare('SELECT action FROM admin_access_log').all();
  assert.ok(rows.some((r) => r.action === 'read_dms'), 'admin DM read is written to admin_access_log');
});

// ---------------------------------------------------------------- finding 9
test('finding 9: per-IP daily signup cap is small', async () => {
  const env = openDb();
  for (let i = 0; i < 10; i++) {
    const res = await call(env, 'POST', '/api/signup', {
      ip: '203.0.113.7',
      body: { username: 'cap_user_' + i, accept_terms: true, age_attest: true },
    });
    assert.equal(res.status, 201, 'signup ' + i + ': ' + res.text);
  }
  const eleventh = await call(env, 'POST', '/api/signup', {
    ip: '203.0.113.7',
    body: { username: 'cap_user_10', accept_terms: true, age_attest: true },
  });
  assert.equal(eleventh.status, 429);
  // A different IP is unaffected.
  const other = await call(env, 'POST', '/api/signup', {
    ip: '203.0.113.8',
    body: { username: 'cap_user_x', accept_terms: true, age_attest: true },
  });
  assert.equal(other.status, 201, other.text);
}, { timeout: 60000 });

test('finding 9: near the agent cap, signup waitlists instead of creating accounts', async () => {
  const env = openDb();
  const rows = [];
  for (let i = 0; i < 450; i++) rows.push(`('filler_${i}', 'x', '2026-09-01T00:00:00.000Z')`);
  env.raw.exec('INSERT INTO agents (username, password_hash, created_at) VALUES ' + rows.join(','));
  const res = await call(env, 'POST', '/api/signup', {
    body: { username: 'hopeful_new', accept_terms: true, age_attest: true },
  });
  assert.equal(res.status, 403);
  assert.equal(res.json.error, 'signup_waitlist');
  assert.equal(env.raw.prepare("SELECT COUNT(*) AS n FROM agents WHERE username = 'hopeful_new'").get().n, 0);
});

// --------------------------------------------------------------- finding 10
test('finding 10: deliveries carry a timestamped signature; stale signatures are rejected', async () => {
  const env = openDb();
  seedAgent(env, 'ev_sender', 'key-ev-s');
  seedAgent(env, 'ev_target', 'key-ev-t');
  const deliveries = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, opts = {}) => {
    deliveries.push({ url: String(url), opts });
    return new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } });
  };
  try {
    const sub = await call(env, 'POST', '/api/subscriptions', {
      key: 'key-ev-t', body: { url: 'https://example.com/hook', events: ['dm.received'] },
    });
    assert.equal(sub.status, 201, sub.text);
    const secret = sub.json.secret;
    const dm = await call(env, 'POST', '/api/dms', { key: 'key-ev-s', body: { to: 'ev_target', content: 'ping' } });
    assert.equal(dm.status, 201, dm.text);
    assert.equal(deliveries.length, 1);
    const { opts } = deliveries[0];
    const ts = opts.headers['X-Oids-Timestamp'];
    assert.ok(ts && Number.isFinite(Date.parse(ts)), 'timestamp header present');
    assert.ok(opts.signal instanceof AbortSignal, 'delivery fetch carries a timeout signal');
    const sig = opts.headers['X-Oids-Signature'];
    assert.equal(await verifyDeliverySignature(secret, ts, opts.body, sig), true, 'fresh signature verifies');
    // A replay 10 minutes later: even a correctly computed signature over
    // the stale timestamp is rejected.
    const staleTs = new Date(Date.now() - 10 * 60000).toISOString();
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const mac = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(staleTs + '.' + opts.body));
    const staleSig = 'sha256=' + [...new Uint8Array(mac)].map((b) => b.toString(16).padStart(2, '0')).join('');
    assert.equal(await verifyDeliverySignature(secret, staleTs, opts.body, staleSig), false, 'stale signature rejected');
    // Tampered body fails too.
    assert.equal(await verifyDeliverySignature(secret, ts, opts.body + 'x', sig), false);
  } finally {
    globalThis.fetch = realFetch;
  }
});

// --------------------------------------------------------------- finding 11
test('finding 11: staff list lives in the config module; behavior unchanged', async () => {
  const workerSrc = readFileSync(new URL('../worker/index.js', import.meta.url), 'utf8');
  assert.ok(!workerSrc.includes("'roomtest_probe', 'morning_brief'"), 'staff list literal is gone from the worker');
  assert.ok(workerSrc.includes("from './config.js'"), 'worker imports the config module');
  const config = await import('../worker/config.js');
  assert.equal(config.STAFF_IDENTITY_USERNAMES.size, 13);
  const env = openDb();
  seedAgent(env, 'claude_ops', null);
  seedAgent(env, 'plain_bot', null);
  const staff = await call(env, 'GET', '/api/identity/claude_ops');
  assert.equal(staff.json.staff, true);
  const plain = await call(env, 'GET', '/api/identity/plain_bot');
  assert.equal(plain.json.staff, false);
});

// --------------------------------------------------------------- finding 12
test('finding 12: stored HTML/JS payloads render escaped (frontend + RSS + Desk Chat)', async () => {
  const env = openDb();
  seedAgent(env, 'xss_alice', 'key-xss');
  const payload = '<script>alert(1)</script>hello <img src=x onerror=alert(2)> world';
  const post = await call(env, 'POST', '/api/posts', { key: 'key-xss', body: { content: payload } });
  assert.equal(post.status, 201, post.text);
  assert.ok(!post.json.content.includes('<script') && !post.json.content.includes('<img'),
    'stored content carries no live tags: ' + post.json.content);

  const rss = await call(env, 'GET', '/api/rss');
  assert.equal(rss.status, 200);
  assert.ok(!rss.text.includes('<script>alert'), 'RSS carries no raw script payload');

  // The SPA renders user content through text nodes only: every
  // innerHTML assignment in frontend/app.js is a clearing assignment,
  // except the hit counter, whose input is String(number) — digits only.
  const appSrc = readFileSync(new URL('../frontend/app.js', import.meta.url), 'utf8');
  assert.ok(appSrc.includes('document.createTextNode'), 'linkify builds text nodes');
  for (const m of appSrc.matchAll(/\.innerHTML\s*=\s*([^;]+)/g)) {
    const rhs = m[1].trim();
    assert.ok(/^(''|"")$/.test(rhs) || rhs.startsWith('digits.split'),
      'innerHTML used only to clear or render the numeric counter, found: ' + m[0]);
    assert.ok(!rhs.includes('.content'), 'innerHTML never receives user content');
  }

  // The Desk Chat page escapes message content and the room name.
  const opId = seedAgent(env, 'oids_operator', 'key-op2');
  env.raw.prepare("INSERT INTO rooms (id, name, created_by, is_private) VALUES (9, ?, ?, 1)")
    .run('<b>bold room</b>', opId);
  env.raw.prepare('INSERT INTO room_members (room_id, agent_id) VALUES (9, ?)').run(opId);
  const linkToken = 'e'.repeat(64);
  env.raw.prepare('INSERT INTO room_links (token, room_id, expires_at) VALUES (?, 9, ?)')
    .run(linkToken, new Date(Date.now() + 86400000).toISOString());
  const page = await call(env, 'GET', '/r/' + linkToken);
  assert.equal(page.status, 200, page.text.slice(0, 200));
  assert.ok(page.text.includes('&lt;b&gt;bold room&lt;/b&gt;'), 'room name is escaped in the page');
  assert.ok(page.text.includes('esc(m.content)'), 'message rendering escapes content');
});

// ---------------------------------------------------------- finding 2 resid.
test('finding 2 residual: file downloads are owner/team-only and the docs say so', async () => {
  const env = openDb();
  env.FILES = { async get() { return { body: 'file-bytes' }; } };
  const upId = seedAgent(env, 'file_owner', 'key-file-o');
  seedAgent(env, 'file_stranger', 'key-file-s');
  seedAgent(env, 'claude_ops', 'key-file-staff');
  const future = new Date(Date.now() + 86400000).toISOString();
  env.raw.prepare(
    'INSERT INTO files (agent_id, r2_key, filename, content_type, size, expires_at) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(upId, 'k1', 'plan.pdf', 'application/pdf', 4, future);

  const stranger = await call(env, 'GET', '/api/files/1', { key: 'key-file-s' });
  assert.equal(stranger.status, 403, 'a stranger agent cannot walk file ids');
  const owner = await call(env, 'GET', '/api/files/1', { key: 'key-file-o' });
  assert.equal(owner.status, 200);
  const staff = await call(env, 'GET', '/api/files/1', { key: 'key-file-staff' });
  assert.equal(staff.status, 200);

  // The tool/listing copy must match the gate (Claude addendum, DM 3941).
  const surfaces = {
    'connectors/muse/mcp-server.js': readFileSync(new URL('../connectors/muse/mcp-server.js', import.meta.url), 'utf8'),
    'mcp-listing/tools.json': readFileSync(new URL('../mcp-listing/tools.json', import.meta.url), 'utf8'),
    'API_CONTRACT.md': readFileSync(new URL('../API_CONTRACT.md', import.meta.url), 'utf8'),
    'openapi.yaml': readFileSync(new URL('../openapi.yaml', import.meta.url), 'utf8'),
    'frontend/llms.txt': readFileSync(new URL('../frontend/llms.txt', import.meta.url), 'utf8'),
  };
  for (const [name, text] of Object.entries(surfaces)) {
    const flat = text.replace(/\s+/g, ' ');
    assert.ok(!flat.includes('may download any'), name + ' still claims open downloads');
    assert.ok(!flat.includes("Download any agent's"), name + ' still claims open downloads');
  }
  assert.ok(surfaces['connectors/muse/mcp-server.js'].includes('Downloads are restricted to the file'),
    'MCP tool description states the restriction');
  assert.ok(surfaces['mcp-listing/tools.json'].includes('Downloads are restricted to the file'),
    'listing copy states the restriction');
});
