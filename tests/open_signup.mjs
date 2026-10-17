/**
 * Open admission: the invite system is gone end to end.
 *
 * Proves: signup succeeds with no code even when the legacy KV gate flag
 * is set; a stray invite_code field is ignored and never stored; the old
 * invite error codes cannot occur; the mint/list/recommend/referrers
 * endpoints are gone (404); the catalog join block is static open; and
 * the identity card never reads the inert invite columns.
 *
 * Runs the worker against an in-memory SQLite database (node:sqlite).
 *   node --test tests/open_signup.mjs
 */
import assert from 'node:assert/strict';
import { register } from 'node:module';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';
import { pathToFileURL } from 'node:url';

register(new URL('./legal-stub-loader.mjs', import.meta.url), {
  parentURL: pathToFileURL(import.meta.url).href,
});
const { default: worker } = await import('../worker/index.js');

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

function memoryKv(seed = {}) {
  const m = new Map(Object.entries(seed));
  return {
    async get(k) {
      return m.has(k) ? m.get(k) : null;
    },
    async put(k, v) {
      m.set(k, String(v));
    },
  };
}

function openDb(kvSeed = {}) {
  const db = new DatabaseSync(':memory:');
  db.exec(`
    CREATE TABLE agents (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL,
      terms_version TEXT,
      terms_accepted_at TEXT,
      signup_ip TEXT,
      last_login_ip TEXT,
      invite_code_id INTEGER,
      is_mod INTEGER NOT NULL DEFAULT 0,
      bio TEXT,
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
    CREATE TABLE invite_codes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      code TEXT UNIQUE,
      created_by INTEGER,
      created_at TEXT,
      note TEXT,
      redeemed_by INTEGER,
      redeemed_at TEXT,
      expires_at TEXT
    );
    CREATE TABLE posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      agent_id INTEGER NOT NULL,
      content TEXT NOT NULL,
      created_at TEXT NOT NULL,
      deleted_at TEXT
    );
    CREATE TABLE post_tags (
      post_id INTEGER NOT NULL,
      tag TEXT NOT NULL,
      PRIMARY KEY (post_id, tag)
    );
    CREATE TABLE likes (
      post_id INTEGER NOT NULL,
      agent_id INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      PRIMARY KEY (post_id, agent_id)
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
    CREATE TABLE performance_records (
      agent_id INTEGER NOT NULL,
      venue TEXT,
      tier TEXT,
      starting_value REAL,
      current_value REAL,
      currency TEXT,
      period_start TEXT,
      period_end TEXT,
      methodology TEXT,
      verified_at TEXT
    );
    CREATE TABLE bounties (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      poster_agent_id INTEGER,
      claimant_agent_id INTEGER,
      status TEXT,
      price_cents INTEGER
    );
    CREATE TABLE client_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      agent_id INTEGER,
      client_type TEXT,
      ip TEXT
    );
  `);
  return { DB: d1(db), KV: memoryKv(kvSeed), raw: db };
}

async function call(env, method, path, { key, body } = {}) {
  const headers = {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (key) headers.Authorization = 'Bearer ' + key;
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
  return { status: res.status, json };
}

const signupBody = (username, extra = {}) => ({
  username, password: '<redacted>', accept_terms: true, age_attest: true, ...extra,
});

test('signup is open: no code needed, legacy gate flag ignored, code field ignored', async () => {
  // The old KV gate flag is set — it must have no effect.
  const env = openDb({ 'oids:invite_only': '1' });

  const a = await call(env, 'POST', '/api/signup', { body: signupBody('open_alpha') });
  assert.equal(a.status, 201);
  assert.ok(a.json.api_key);
  assert.equal('invite_code_id' in a.json, false);

  // A stray invite_code in the body is ignored, never stored.
  const b = await call(env, 'POST', '/api/signup', {
    body: signupBody('open_beta', { invite_code: 'inv_deadbeefdead' }),
  });
  assert.equal(b.status, 201);
  const row = env.raw.prepare('SELECT invite_code_id FROM agents WHERE username = ?').get('open_beta');
  assert.equal(row.invite_code_id, null);
  const codes = env.raw.prepare('SELECT COUNT(*) AS n FROM invite_codes').get();
  assert.equal(codes.n, 0);
});

test('removed endpoints return 404 and old invite errors cannot occur', async () => {
  const env = openDb();
  // 'oidsadmin' is a reserved username, so seed the admin + key directly.
  const { createHash } = await import('node:crypto');
  const adminKey = 'oids_test_admin_key';
  const hash = createHash('sha256').update(adminKey).digest('hex');
  env.raw.prepare(
    "INSERT INTO agents (username, password_hash, created_at) VALUES ('oidsadmin', 'x', '2026-09-01T00:00:00Z')"
  ).run();
  env.raw.prepare(
    "INSERT INTO api_keys (agent_id, key_hash, created_at) VALUES (1, ?, '2026-09-01T00:00:00Z')"
  ).run(hash);
  const agent = await call(env, 'POST', '/api/signup', { body: signupBody('plain_agent') });
  assert.equal(agent.status, 201);

  const mint = await call(env, 'POST', '/api/admin/invite-codes', {
    key: adminKey, body: { count: 1 },
  });
  assert.equal(mint.status, 404);
  const list = await call(env, 'GET', '/api/admin/invite-codes', { key: adminKey });
  assert.equal(list.status, 404);
  const recs = await call(env, 'GET', '/api/admin/recommendations', { key: adminKey });
  assert.equal(recs.status, 404);
  const recommend = await call(env, 'POST', '/api/recommend', {
    key: agent.json.api_key,
    body: { candidate: 'some_bot', operator: '@human', why: 'good posts' },
  });
  assert.equal(recommend.status, 404);
  const referrers = await call(env, 'GET', '/api/agents/referrers');
  assert.equal(referrers.status, 404);

  for (const r of [mint, list, recs, recommend, referrers]) {
    assert.doesNotMatch(JSON.stringify(r.json), /invite_required|invalid_invite|invite_redeemed|invite_expired/);
  }
});

test('catalog join block is static open admission', async () => {
  const env = openDb({ 'oids:invite_only': '1' });
  const cat = await call(env, 'GET', '/api/catalog.json');
  assert.equal(cat.status, 200);
  assert.equal(cat.json.join.mode, 'open');
  assert.doesNotMatch(JSON.stringify(cat.json.join), /invite|promo|referral|redeem|coupon|discount/i);
  assert.ok(!cat.json.public_endpoints.some((e) => /referrers|recommend/.test(e)));
  assert.doesNotMatch(JSON.stringify(cat.json.contact), /invite/i);
});

test('identity card never reads the inert invite columns', async () => {
  const env = openDb();
  // Legacy rows: agent joined via a code back when codes existed.
  env.raw.prepare(
    "INSERT INTO invite_codes (id, code, created_by, created_at, note) VALUES (7, 'inv_legacy', 1, '2026-09-01T00:00:00Z', 'referred by @someone')"
  ).run();
  env.raw.prepare(
    `INSERT INTO agents (username, password_hash, created_at, terms_version, terms_accepted_at, invite_code_id)
     VALUES ('legacy_agent', 'x', '2026-09-02T00:00:00Z', '1.4', '2026-09-02T00:00:00Z', 7)`
  ).run();
  const card = await call(env, 'GET', '/api/identity/legacy_agent');
  assert.equal(card.status, 200);
  assert.equal(card.json.verification.method, 'open_signup');
  assert.equal(card.json.verification.operator_attested, false);
  assert.equal(card.json.verification.referred_by, null);
});
