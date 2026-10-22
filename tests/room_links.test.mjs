/**
 * Admin room-link API (Desk Chat mint endpoint):
 *   POST /api/admin/room-links          mint
 *   POST /api/admin/room-links/extend   extend (from now; revoked -> 409)
 *   POST /api/admin/room-links/revoke   revoke
 *   GET  /api/admin/room-links          list (token_prefix only)
 *
 * Acceptance groups (spec-desk-chat-mint-endpoint.md):
 *   1. Mint happy path + defaults/bounds.
 *   2. Mint validation matrix: exact status/code, no row inserted on failure.
 *   3. Minted token works against the link consumers; refused after expiry.
 *   4. Extend semantics: expired revives, revoked 409, unknown 404.
 *   5. List visibility: default hides expired + revoked; include_expired=1
 *      shows them marked; prefix-only (full token nowhere in the response).
 *   6. Audit: mint/extend/revoke write moderation_log AND admin_access_log;
 *      list writes admin_access_log only; no full token in any log row.
 *   7. Auth: router gate 403s (no header / non-admin key / malformed Bearer)
 *      and the handlers' internal M16 admin assert via direct calls.
 *
 * Runs the worker against an in-memory SQLite database (node:sqlite).
 *   node --test tests/room_links.test.mjs
 */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { register } from 'node:module';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';

register(new URL('./helpers/legal-resolve-hook.mjs', import.meta.url));

const {
  default: worker,
  handleAdminMintRoomLink,
  handleAdminListRoomLinks,
} = await import('../worker/index.js');

const ADMIN_KEY = 'oids_test_admin_key';
const AGENT_KEY = 'oids_test_agent_key';
const sha256 = (s) => createHash('sha256').update(s).digest('hex');

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
      created_at TEXT NOT NULL,
      is_mod INTEGER NOT NULL DEFAULT 0,
      read_only INTEGER NOT NULL DEFAULT 0,
      pro INTEGER NOT NULL DEFAULT 0,
      pro_expires_at TEXT
    );
    CREATE TABLE api_keys (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      agent_id INTEGER NOT NULL,
      key_hash TEXT NOT NULL UNIQUE,
      created_at TEXT NOT NULL,
      revoked INTEGER NOT NULL DEFAULT 0,
      expires_at TEXT
    );
    CREATE TABLE rooms (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      created_by INTEGER NOT NULL,
      is_private INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    );
    CREATE TABLE room_members (
      room_id INTEGER NOT NULL,
      agent_id INTEGER NOT NULL,
      joined_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      PRIMARY KEY (room_id, agent_id)
    );
    CREATE TABLE room_messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      room_id INTEGER NOT NULL,
      from_agent_id INTEGER NOT NULL,
      content TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      blocked INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE room_links (
      token TEXT PRIMARY KEY,
      room_id INTEGER NOT NULL REFERENCES rooms(id),
      label TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      revoked INTEGER NOT NULL DEFAULT 0,
      expires_at TEXT
    );
    CREATE TABLE dms (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      from_agent_id INTEGER NOT NULL,
      to_agent_id INTEGER NOT NULL,
      content TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      blocked INTEGER NOT NULL DEFAULT 0
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
    CREATE TABLE admin_access_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      admin_username TEXT NOT NULL,
      action TEXT NOT NULL,
      target_type TEXT NOT NULL,
      target_id TEXT,
      detail TEXT,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    );
    CREATE TABLE client_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      agent_id INTEGER,
      client_type TEXT,
      ip TEXT
    );
  `);
  db.prepare("INSERT INTO agents (id, username, password_hash, created_at) VALUES (1, 'oidsadmin', 'x', '2026-09-01T00:00:00.000Z')").run();
  db.prepare("INSERT INTO agents (id, username, password_hash, created_at) VALUES (2, 'plain_agent', 'x', '2026-09-01T00:00:00.000Z')").run();
  db.prepare("INSERT INTO agents (id, username, password_hash, created_at) VALUES (3, 'oids_operator', 'x', '2026-09-01T00:00:00.000Z')").run();
  db.prepare("INSERT INTO api_keys (agent_id, key_hash, created_at) VALUES (1, ?, '2026-09-01T00:00:00.000Z')").run(sha256(ADMIN_KEY));
  db.prepare("INSERT INTO api_keys (agent_id, key_hash, created_at) VALUES (2, ?, '2026-09-01T00:00:00.000Z')").run(sha256(AGENT_KEY));
  db.prepare("INSERT INTO rooms (id, name, created_by) VALUES (1, 'desk-chat', 1)").run();
  db.prepare("INSERT INTO rooms (id, name, created_by) VALUES (2, 'second-room', 1)").run();
  return { DB: d1(db), KV: memoryKv(), raw: db };
}

async function call(env, method, path, { key, body, rawBody, auth } = {}) {
  const headers = {};
  if (body !== undefined || rawBody !== undefined) headers['Content-Type'] = 'application/json';
  if (auth !== undefined) headers.Authorization = auth;
  else if (key) headers.Authorization = 'Bearer ' + key;
  const res = await worker.fetch(new Request('https://api.tryoids.com' + path, {
    method,
    headers,
    body: rawBody !== undefined ? rawBody : body === undefined ? undefined : JSON.stringify(body),
  }), env);
  const text = await res.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    json = text;
  }
  return { status: res.status, json, text };
}

const mint = (env, body = {}) =>
  call(env, 'POST', '/api/admin/room-links', { key: ADMIN_KEY, body: { room_id: 1, ...body } });
const linkCount = (env) => env.raw.prepare('SELECT COUNT(*) AS n FROM room_links').get().n;
const PAST = '2020-01-01T00:00:00.000Z';

// ---------------------------------------------------------------------------
// 1. Mint happy path
// ---------------------------------------------------------------------------
test('mint happy path: 201 shape, row stored, expires_at ~ now + ttl', async () => {
  const env = openDb();
  const before = Date.now();
  const res = await mint(env, { label: 'David desktop live window', ttl_days: 7 });
  const after = Date.now();
  assert.equal(res.status, 201, JSON.stringify(res.json));
  assert.match(res.json.token, /^[0-9a-f]{64}$/);
  assert.equal(res.json.url, 'https://tryoids.com/r/' + res.json.token);
  assert.equal(res.json.room_id, 1);
  assert.equal(res.json.room_name, 'desk-chat');
  assert.equal(res.json.label, 'David desktop live window');
  const exp = Date.parse(res.json.expires_at);
  assert.ok(exp >= before + 7 * 86400000 - 5000 && exp <= after + 7 * 86400000 + 5000,
    `expires_at ${res.json.expires_at} not within 5s of now + 7d`);

  const row = env.raw.prepare('SELECT * FROM room_links WHERE token = ?').get(res.json.token);
  assert.ok(row, 'minted row exists');
  assert.equal(row.room_id, 1);
  assert.equal(row.label, 'David desktop live window');
  assert.equal(row.expires_at, res.json.expires_at);
  assert.equal(row.revoked, 0);
});

test('mint defaults: ttl 7 and empty label; bounds 1 and 30 accepted; label trimmed', async () => {
  const env = openDb();
  const before = Date.now();
  const def = await mint(env, {});
  assert.equal(def.status, 201, JSON.stringify(def.json));
  assert.equal(def.json.label, '');
  const exp = Date.parse(def.json.expires_at);
  assert.ok(Math.abs(exp - (before + 7 * 86400000)) < 10000, 'default ttl is 7 days');

  const one = await mint(env, { ttl_days: 1 });
  assert.equal(one.status, 201);
  assert.ok(Math.abs(Date.parse(one.json.expires_at) - (Date.now() + 1 * 86400000)) < 10000);

  const thirty = await mint(env, { ttl_days: 30 });
  assert.equal(thirty.status, 201);
  assert.ok(Math.abs(Date.parse(thirty.json.expires_at) - (Date.now() + 30 * 86400000)) < 10000);

  const trimmed = await mint(env, { label: '  padded label  ' });
  assert.equal(trimmed.status, 201);
  assert.equal(trimmed.json.label, 'padded label');

  const maxLabel = await mint(env, { label: 'x'.repeat(120) });
  assert.equal(maxLabel.status, 201);
});

// ---------------------------------------------------------------------------
// 2. Mint validation matrix
// ---------------------------------------------------------------------------
test('mint validation matrix: exact status/code and no row inserted on failure', async () => {
  const env = openDb();
  const cases = [
    { name: 'body not JSON', rawBody: '{not json', status: 400, error: 'invalid_json' },
    { name: 'missing room_id', body: { label: 'x' }, status: 400, error: 'invalid_room_id' },
    { name: 'room_id string', body: { room_id: '1' }, status: 400, error: 'invalid_room_id' },
    { name: 'room_id fractional', body: { room_id: 1.5 }, status: 400, error: 'invalid_room_id' },
    { name: 'room_id null', body: { room_id: null }, status: 400, error: 'invalid_room_id' },
    { name: 'ttl 0', body: { room_id: 1, ttl_days: 0 }, status: 400, error: 'invalid_ttl' },
    { name: 'ttl 31', body: { room_id: 1, ttl_days: 31 }, status: 400, error: 'invalid_ttl' },
    { name: 'ttl negative', body: { room_id: 1, ttl_days: -3 }, status: 400, error: 'invalid_ttl' },
    { name: 'ttl fractional', body: { room_id: 1, ttl_days: 7.5 }, status: 400, error: 'invalid_ttl' },
    { name: 'ttl string', body: { room_id: 1, ttl_days: '7' }, status: 400, error: 'invalid_ttl' },
    { name: 'label 121 chars', body: { room_id: 1, label: 'x'.repeat(121) }, status: 400, error: 'invalid_label' },
    { name: 'label non-string', body: { room_id: 1, label: 42 }, status: 400, error: 'invalid_label' },
    { name: 'room does not exist', body: { room_id: 999 }, status: 404, error: 'room_not_found' },
  ];
  for (const c of cases) {
    const res = c.rawBody !== undefined
      ? await call(env, 'POST', '/api/admin/room-links', { key: ADMIN_KEY, rawBody: c.rawBody })
      : await call(env, 'POST', '/api/admin/room-links', { key: ADMIN_KEY, body: c.body });
    assert.equal(res.status, c.status, `${c.name}: got ${res.status} ${JSON.stringify(res.json)}`);
    assert.equal(res.json.error, c.error, `${c.name}: got ${JSON.stringify(res.json)}`);
  }
  assert.equal(linkCount(env), 0, 'no row inserted on any validation failure');
  // Validation failures write no audit rows either.
  assert.equal(env.raw.prepare('SELECT COUNT(*) AS n FROM moderation_log').get().n, 0);
  assert.equal(env.raw.prepare('SELECT COUNT(*) AS n FROM admin_access_log').get().n, 0);
});

// ---------------------------------------------------------------------------
// 3. Minted token against the link consumers, before and after expiry
// ---------------------------------------------------------------------------
test('minted token works end-to-end, then consumers refuse it after forced expiry', async () => {
  const env = openDb();
  const res = await mint(env, { label: 'consumer check' });
  assert.equal(res.status, 201);
  const token = res.json.token;

  const page = await call(env, 'GET', '/r/' + token);
  assert.equal(page.status, 200, page.text.slice(0, 200));
  assert.match(page.text, /desk-chat/);

  const msgs = await call(env, 'GET', '/api/rlink/' + token + '/messages');
  assert.equal(msgs.status, 200, JSON.stringify(msgs.json));
  assert.equal(msgs.json.room_id, 1);
  assert.deepEqual(msgs.json.messages, []);

  env.raw.prepare('UPDATE room_links SET expires_at = ? WHERE token = ?').run(PAST, token);

  const deadPage = await call(env, 'GET', '/r/' + token);
  assert.equal(deadPage.status, 410, 'expired page is 410');
  const deadMsgs = await call(env, 'GET', '/api/rlink/' + token + '/messages');
  assert.equal(deadMsgs.status, 404, 'expired messages are 404');
  assert.equal(deadMsgs.json.error, 'not_found');
});

// ---------------------------------------------------------------------------
// 4. Extend semantics
// ---------------------------------------------------------------------------
test('extend: expired link revives with expiry from now; revoked 409; unknown 404', async () => {
  const env = openDb();
  const res = await mint(env, { label: 'extend me', ttl_days: 7 });
  const token = res.json.token;
  env.raw.prepare('UPDATE room_links SET expires_at = ? WHERE token = ?').run(PAST, token);
  const dead = await call(env, 'GET', '/api/rlink/' + token + '/messages');
  assert.equal(dead.status, 404);

  const before = Date.now();
  const ext = await call(env, 'POST', '/api/admin/room-links/extend', {
    key: ADMIN_KEY, body: { token, ttl_days: 14 },
  });
  const after = Date.now();
  assert.equal(ext.status, 200, JSON.stringify(ext.json));
  assert.equal(ext.json.token, token, 'extend keeps the same token/URL');
  assert.equal(ext.json.url, 'https://tryoids.com/r/' + token);
  assert.equal(ext.json.room_id, 1);
  assert.equal(ext.json.room_name, 'desk-chat');
  assert.equal(ext.json.label, 'extend me');
  const exp = Date.parse(ext.json.expires_at);
  assert.ok(exp >= before + 14 * 86400000 - 5000 && exp <= after + 14 * 86400000 + 5000,
    'new expiry is from now, not from the old expiry');
  const row = env.raw.prepare('SELECT expires_at FROM room_links WHERE token = ?').get(token);
  assert.equal(row.expires_at, ext.json.expires_at);

  const alive = await call(env, 'GET', '/api/rlink/' + token + '/messages');
  assert.equal(alive.status, 200, 'revived link works again');

  // Default ttl on extend is 7 days.
  const def = await call(env, 'POST', '/api/admin/room-links/extend', {
    key: ADMIN_KEY, body: { token },
  });
  assert.equal(def.status, 200);
  assert.ok(Math.abs(Date.parse(def.json.expires_at) - (Date.now() + 7 * 86400000)) < 10000);

  // Invalid ttl: 400 and the stored expiry is untouched.
  const badTtl = await call(env, 'POST', '/api/admin/room-links/extend', {
    key: ADMIN_KEY, body: { token, ttl_days: 2.5 },
  });
  assert.equal(badTtl.status, 400);
  assert.equal(badTtl.json.error, 'invalid_ttl');
  assert.equal(
    env.raw.prepare('SELECT expires_at FROM room_links WHERE token = ?').get(token).expires_at,
    def.json.expires_at
  );

  // Unknown token (well-formed and malformed) -> 404 link_not_found.
  for (const unknown of ['f'.repeat(64), 'not-a-token', '']) {
    const unk = await call(env, 'POST', '/api/admin/room-links/extend', {
      key: ADMIN_KEY, body: { token: unknown },
    });
    assert.equal(unk.status, 404, `token=${unknown}`);
    assert.equal(unk.json.error, 'link_not_found');
  }

  // Revoked link -> 409, and extend does not resurrect it.
  const rv = await call(env, 'POST', '/api/admin/room-links/revoke', {
    key: ADMIN_KEY, body: { token },
  });
  assert.equal(rv.status, 200);
  assert.deepEqual(rv.json, { revoked: true });
  const conflict = await call(env, 'POST', '/api/admin/room-links/extend', {
    key: ADMIN_KEY, body: { token, ttl_days: 7 },
  });
  assert.equal(conflict.status, 409);
  assert.equal(conflict.json.error, 'link_revoked');
  const stillDead = await call(env, 'GET', '/api/rlink/' + token + '/messages');
  assert.equal(stillDead.status, 404);

  // Revoke of an unknown token -> 404 link_not_found.
  const rvUnk = await call(env, 'POST', '/api/admin/room-links/revoke', {
    key: ADMIN_KEY, body: { token: 'e'.repeat(64) },
  });
  assert.equal(rvUnk.status, 404);
  assert.equal(rvUnk.json.error, 'link_not_found');
});

// ---------------------------------------------------------------------------
// 5. List visibility + prefix-only
// ---------------------------------------------------------------------------
test('list: default hides expired + revoked, include_expired shows them marked, prefix only', async () => {
  const env = openDb();
  const a = await mint(env, { label: 'live one' });
  const b = await mint(env, { label: 'expired one' });
  const c = await mint(env, { label: 'revoked one' });
  const d = await mint(env, { room_id: 2, label: 'other room' });
  assert.equal(a.status + b.status + c.status + d.status, 201 * 4);
  env.raw.prepare('UPDATE room_links SET expires_at = ? WHERE token = ?').run(PAST, b.json.token);
  env.raw.prepare('UPDATE room_links SET revoked = 1 WHERE token = ?').run(c.json.token);
  // Deterministic created_at ordering: a < d < b < c (descending: c, b, d, a).
  env.raw.prepare('UPDATE room_links SET created_at = ? WHERE token = ?').run('2026-10-01T00:00:00.000Z', a.json.token);
  env.raw.prepare('UPDATE room_links SET created_at = ? WHERE token = ?').run('2026-10-02T00:00:00.000Z', d.json.token);
  env.raw.prepare('UPDATE room_links SET created_at = ? WHERE token = ?').run('2026-10-03T00:00:00.000Z', b.json.token);
  env.raw.prepare('UPDATE room_links SET created_at = ? WHERE token = ?').run('2026-10-04T00:00:00.000Z', c.json.token);

  const live = await call(env, 'GET', '/api/admin/room-links', { key: ADMIN_KEY });
  assert.equal(live.status, 200, JSON.stringify(live.json));
  assert.deepEqual(live.json.links.map((l) => l.label), ['other room', 'live one'],
    'default list: live only, created_at descending');
  for (const row of live.json.links) {
    assert.equal(row.token_prefix.length, 8);
    assert.equal('token' in row, false);
    assert.equal(row.expired, false);
    assert.equal(row.revoked, 0);
  }
  assert.equal(live.json.links.find((l) => l.label === 'live one').token_prefix, a.json.token.slice(0, 8));
  assert.equal(live.json.links.find((l) => l.label === 'other room').room_id, 2);
  assert.equal(live.json.links.find((l) => l.label === 'other room').room_name, 'second-room');

  const all = await call(env, 'GET', '/api/admin/room-links?include_expired=1', { key: ADMIN_KEY });
  assert.equal(all.status, 200);
  assert.deepEqual(all.json.links.map((l) => l.label),
    ['revoked one', 'expired one', 'other room', 'live one']);
  const byLabel = Object.fromEntries(all.json.links.map((l) => [l.label, l]));
  assert.equal(byLabel['expired one'].expired, true);
  assert.equal(byLabel['expired one'].revoked, 0);
  assert.equal(byLabel['revoked one'].revoked, 1);
  assert.equal(byLabel['revoked one'].expired, false);
  assert.equal(byLabel['revoked one'].token_prefix, c.json.token.slice(0, 8));

  // room_id filter, both modes.
  const room2 = await call(env, 'GET', '/api/admin/room-links?room_id=2', { key: ADMIN_KEY });
  assert.deepEqual(room2.json.links.map((l) => l.label), ['other room']);
  const room1All = await call(env, 'GET', '/api/admin/room-links?room_id=1&include_expired=1', { key: ADMIN_KEY });
  assert.deepEqual(room1All.json.links.map((l) => l.label), ['revoked one', 'expired one', 'live one']);
  const badRoom = await call(env, 'GET', '/api/admin/room-links?room_id=nope', { key: ADMIN_KEY });
  assert.equal(badRoom.status, 400);
  assert.equal(badRoom.json.error, 'invalid_room_id');

  // The full token appears nowhere in any list response.
  for (const res of [live, all, room2, room1All]) {
    for (const t of [a, b, c, d]) {
      assert.equal(res.text.includes(t.json.token), false, 'full token leaked into a list response');
    }
  }
});

// ---------------------------------------------------------------------------
// 6. Audit logging
// ---------------------------------------------------------------------------
test('audit: mint + list + extend write exactly the expected rows, prefix only', async () => {
  const env = openDb();
  const m = await mint(env, { label: 'audit link', ttl_days: 7 });
  assert.equal(m.status, 201);
  const token = m.json.token;
  const list = await call(env, 'GET', '/api/admin/room-links', { key: ADMIN_KEY });
  assert.equal(list.status, 200);
  const ext = await call(env, 'POST', '/api/admin/room-links/extend', {
    key: ADMIN_KEY, body: { token, ttl_days: 10 },
  });
  assert.equal(ext.status, 200);

  const access = env.raw.prepare('SELECT * FROM admin_access_log ORDER BY id ASC').all();
  assert.equal(access.length, 3, 'exactly three admin_access_log rows');
  assert.deepEqual(access.map((r) => r.action), ['mint_room_link', 'list_room_links', 'extend_room_link']);
  for (const row of access) {
    assert.equal(row.admin_username, 'oidsadmin');
    assert.equal(row.target_type, 'room');
    assert.equal(JSON.stringify(row).includes(token), false, 'full token in admin_access_log');
  }
  assert.equal(access[0].target_id, '1');
  assert.equal(access[2].target_id, '1');
  const mintDetail = JSON.parse(access[0].detail);
  assert.deepEqual(Object.keys(mintDetail).sort(), ['expires_at', 'label', 'token_prefix', 'ttl_days']);
  assert.equal(mintDetail.label, 'audit link');
  assert.equal(mintDetail.ttl_days, 7);
  assert.equal(mintDetail.expires_at, m.json.expires_at);
  assert.equal(mintDetail.token_prefix, token.slice(0, 8));
  const extDetail = JSON.parse(access[2].detail);
  assert.equal(extDetail.ttl_days, 10);
  assert.equal(extDetail.expires_at, ext.json.expires_at);
  assert.equal(extDetail.token_prefix, token.slice(0, 8));

  const mod = env.raw.prepare('SELECT * FROM moderation_log ORDER BY id ASC').all();
  assert.deepEqual(mod.map((r) => r.action), ['mint_room_link', 'extend_room_link'],
    'moderation_log holds the two writes, not the list read');
  for (const row of mod) {
    assert.equal(row.actor, 'admin:oidsadmin');
    assert.equal(row.target_type, 'room');
    assert.equal(row.target_id, '1');
    assert.equal(JSON.stringify(row).includes(token), false, 'full token in moderation_log');
    assert.ok(row.reason.includes(token.slice(0, 8)), 'mod log reason carries the prefix');
  }
});

test('audit: revoke writes both logs, prefix only', async () => {
  const env = openDb();
  const m = await mint(env, { label: 'revoke audit' });
  const token = m.json.token;
  const rv = await call(env, 'POST', '/api/admin/room-links/revoke', {
    key: ADMIN_KEY, body: { token },
  });
  assert.equal(rv.status, 200);
  const access = env.raw.prepare('SELECT * FROM admin_access_log ORDER BY id ASC').all();
  assert.deepEqual(access.map((r) => r.action), ['mint_room_link', 'revoke_room_link']);
  const mod = env.raw.prepare('SELECT * FROM moderation_log ORDER BY id ASC').all();
  assert.deepEqual(mod.map((r) => r.action), ['mint_room_link', 'revoke_room_link']);
  for (const row of [...access, ...mod]) {
    assert.equal(JSON.stringify(row).includes(token), false, 'full token in a log row');
  }
  assert.equal(JSON.parse(access[1].detail).token_prefix, token.slice(0, 8));
});

// ---------------------------------------------------------------------------
// 7. Auth gate + internal M16 assert
// ---------------------------------------------------------------------------
test('auth: router gate 403s no header, non-admin key, and malformed Bearer', async () => {
  const env = openDb();
  const attempts = [
    { name: 'no header', opts: {} },
    { name: 'non-admin agent key', opts: { key: AGENT_KEY } },
    { name: 'malformed scheme', opts: { auth: 'Token abc123' } },
    { name: 'unknown bearer key', opts: { auth: 'Bearer oids_not_a_real_key' } },
    { name: 'empty bearer', opts: { auth: 'Bearer ' } },
  ];
  for (const a of attempts) {
    const res = await call(env, 'POST', '/api/admin/room-links', { ...a.opts, body: { room_id: 1 } });
    assert.equal(res.status, 403, `${a.name}: got ${res.status}`);
    assert.equal(res.json.error, 'forbidden', a.name);
    const list = await call(env, 'GET', '/api/admin/room-links', a.opts);
    assert.equal(list.status, 403, `${a.name} (list)`);
    const ext = await call(env, 'POST', '/api/admin/room-links/extend', {
      ...a.opts, body: { token: 'f'.repeat(64) },
    });
    assert.equal(ext.status, 403, `${a.name} (extend)`);
  }
  assert.equal(linkCount(env), 0, 'no link minted by any rejected caller');

  // Unknown admin route still falls through to the block's 404.
  const unknown = await call(env, 'POST', '/api/admin/bogus', { key: ADMIN_KEY, body: {} });
  assert.equal(unknown.status, 404);
  assert.equal(unknown.json.error, 'not_found');
});

test('auth: direct handler calls enforce the internal M16 admin assert', async () => {
  const env = openDb();
  const mkReq = () => new Request('https://api.tryoids.com/api/admin/room-links', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ room_id: 1, label: 'direct call' }),
  });
  for (const badAdmin of [null, undefined, { username: 'plain_agent' }, { username: 'other' }]) {
    const res = await handleAdminMintRoomLink(mkReq(), env, badAdmin);
    assert.equal(res.status, 403, `admin=${JSON.stringify(badAdmin)}`);
    const body = await res.json();
    assert.equal(body.error, 'forbidden');
  }
  assert.equal(linkCount(env), 0);

  const ok = await handleAdminMintRoomLink(mkReq(), env, { username: 'oidsadmin', agent_id: 1 });
  assert.equal(ok.status, 201, 'the real admin passes the internal assert without the router');
  const okBody = await ok.json();
  assert.match(okBody.token, /^[0-9a-f]{64}$/);
  assert.equal(linkCount(env), 1);

  const listReq = new Request('https://api.tryoids.com/api/admin/room-links', { method: 'GET' });
  const badList = await handleAdminListRoomLinks(listReq, env, { username: 'plain_agent' });
  assert.equal(badList.status, 403);
  const goodList = await handleAdminListRoomLinks(listReq, env, { username: 'oidsadmin', agent_id: 1 });
  assert.equal(goodList.status, 200);
});
