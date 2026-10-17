/**
 * Profile + directory trust fields: GET /api/agents/:username returns
 * bio and verified, GET /api/agents/directory returns verified per agent.
 * verified is true exactly when terms_accepted_at is set.
 *
 * Runs the worker against an in-memory SQLite database (node:sqlite).
 *   node --test tests/profile_verified.test.mjs
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
      note TEXT,
      redeemed_by INTEGER,
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
  return { DB: d1(db), KV: memoryKv(), raw: db };
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

test('profile returns bio and verified; directory returns verified', async () => {
  const env = openDb();

  const a = await call(env, 'POST', '/api/signup', {
    body: { username: 'profile_a', accept_terms: true, age_attest: true, bio: 'automated QA bot' },
  });
  assert.equal(a.status, 201, JSON.stringify(a.json));

  // An agent row with no terms acceptance and no bio (legacy / unset).
  env.raw.prepare(
    'INSERT INTO agents (username, password_hash, created_at, terms_accepted_at, bio) VALUES (?, ?, ?, ?, ?)'
  ).run('profile_b', 'unused', '2026-01-01T00:00:00.000Z', null, null);

  const profA = await call(env, 'GET', '/api/agents/profile_a');
  assert.equal(profA.status, 200, JSON.stringify(profA.json));
  assert.equal(profA.json.bio, 'automated QA bot');
  assert.equal(profA.json.verified, true);

  const profB = await call(env, 'GET', '/api/agents/profile_b');
  assert.equal(profB.status, 200, JSON.stringify(profB.json));
  assert.equal(profB.json.bio, null);
  assert.equal(profB.json.verified, false);

  const missing = await call(env, 'GET', '/api/agents/no_such_agent');
  assert.equal(missing.status, 404);

  const dir = await call(env, 'GET', '/api/agents/directory');
  assert.equal(dir.status, 200, JSON.stringify(dir.json));
  const rowA = dir.json.agents.find((r) => r.username === 'profile_a');
  const rowB = dir.json.agents.find((r) => r.username === 'profile_b');
  assert.ok(rowA);
  assert.ok(rowB);
  assert.equal(rowA.verified, true);
  assert.equal(rowA.bio, 'automated QA bot');
  assert.equal(rowB.verified, false);
  assert.equal(rowB.bio, null);
});
