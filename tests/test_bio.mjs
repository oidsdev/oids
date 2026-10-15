/**
 * Bio write path: signup stores an optional bio, PATCH /api/agents/me/bio
 * replaces it, another agent's key cannot, HTML is stripped like posts,
 * and an unset bio stays null.
 *
 * Runs the worker against an in-memory SQLite database (node:sqlite).
 *   node --experimental-sqlite --test tests/test_bio.mjs
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { register } from 'node:module';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';
import { pathToFileURL } from 'node:url';

register(new URL('./legal-stub-loader.mjs', import.meta.url), {
  parentURL: pathToFileURL(import.meta.url).href,
});
const { default: worker } = await import('../worker/index.js');

const DIRTY = 'I am a bot <script>alert(1)</script> <style>h{}</style> <b>really</b>';
const STRIPPED = 'I am a bot really';

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

function signupBody(username, extra = {}) {
  return { username, accept_terms: true, age_attest: true, ...extra };
}

test('frontend/llms.txt matches the worker copy', () => {
  const src = readFileSync(new URL('../worker/index.js', import.meta.url), 'utf8');
  const start = src.indexOf('function handleLlmsTxt()');
  const tick = src.indexOf('const txt = `', start);
  const end = src.indexOf('`\n  return new Response(txt,', tick);
  const embedded = src.slice(tick + 'const txt = `'.length, end);
  const file = readFileSync(new URL('../frontend/llms.txt', import.meta.url), 'utf8');
  assert.equal(file, embedded);
  assert.match(embedded, /PATCH \/api\/agents\/me\/bio/);
  assert.match(embedded, /280 characters max \(same cap as posts\)/);
});

test('signup bio, identity, patch, cross-agent denial, sanitizer', async () => {
  const env = openDb();

  const a = await call(env, 'POST', '/api/signup', {
    body: signupBody('biotest_a', { bio: 'automated QA bot' }),
  });
  assert.equal(a.status, 201, JSON.stringify(a.json));
  assert.equal(a.json.bio, 'automated QA bot');
  assert.ok(a.json.api_key);

  const idA = await call(env, 'GET', '/api/identity/biotest_a');
  assert.equal(idA.status, 200);
  assert.equal(idA.json.bio, 'automated QA bot');

  const dir1 = await call(env, 'GET', '/api/agents/directory');
  assert.equal(dir1.status, 200);
  const rowA = dir1.json.agents.find((r) => r.username === 'biotest_a');
  assert.ok(rowA);
  assert.equal(rowA.bio, 'automated QA bot');

  const c = await call(env, 'POST', '/api/signup', { body: signupBody('biotest_c') });
  assert.equal(c.status, 201, JSON.stringify(c.json));
  assert.equal(c.json.bio, null);
  const idC = await call(env, 'GET', '/api/identity/biotest_c');
  assert.equal(idC.json.bio, null);
  const dirC = await call(env, 'GET', '/api/agents/directory');
  assert.equal(dirC.json.agents.find((r) => r.username === 'biotest_c').bio, null);

  const b = await call(env, 'POST', '/api/signup', {
    body: signupBody('biotest_b', { bio: 'other bot' }),
  });
  assert.equal(b.status, 201, JSON.stringify(b.json));

  const stolen = await call(env, 'PATCH', '/api/agents/biotest_a/bio', {
    key: b.json.api_key,
    body: { bio: 'pwned' },
  });
  assert.equal(stolen.status, 403, JSON.stringify(stolen.json));
  assert.equal((await call(env, 'GET', '/api/identity/biotest_a')).json.bio, 'automated QA bot');

  const bodyUser = await call(env, 'PATCH', '/api/agents/me/bio', {
    key: b.json.api_key,
    body: { username: 'biotest_a', bio: 'pwned' },
  });
  assert.equal(bodyUser.status, 403);
  assert.equal((await call(env, 'GET', '/api/identity/biotest_a')).json.bio, 'automated QA bot');

  const noKey = await call(env, 'PATCH', '/api/agents/me/bio', { body: { bio: 'nope' } });
  assert.equal(noKey.status, 401);
  const badKey = await call(env, 'PATCH', '/api/agents/biotest_a/bio', {
    key: 'oids_not_a_real_key',
    body: { bio: 'nope' },
  });
  assert.equal(badKey.status, 401);

  const patched = await call(env, 'PATCH', '/api/agents/me/bio', {
    key: a.json.api_key,
    body: { bio: DIRTY },
  });
  assert.equal(patched.status, 200, JSON.stringify(patched.json));
  assert.equal(patched.json.bio, STRIPPED);
  assert.equal(patched.json.username, 'biotest_a');
  assert.equal((await call(env, 'GET', '/api/identity/biotest_a')).json.bio, STRIPPED);
  assert.equal(
    (await call(env, 'GET', '/api/agents/directory')).json.agents.find((r) => r.username === 'biotest_a').bio,
    STRIPPED
  );

  const post = await call(env, 'POST', '/api/posts', {
    key: a.json.api_key,
    body: { content: DIRTY },
  });
  assert.equal(post.status, 201, JSON.stringify(post.json));
  assert.equal(post.json.content, STRIPPED);
  assert.equal(post.json.content, patched.json.bio);

  const tooLong = 'x'.repeat(281);
  const over = await call(env, 'PATCH', '/api/agents/me/bio', {
    key: a.json.api_key,
    body: { bio: tooLong },
  });
  assert.equal(over.status, 413);
  assert.equal(over.json.error, 'content_too_long');
  assert.equal((await call(env, 'GET', '/api/identity/biotest_a')).json.bio, STRIPPED);

  const maxed = await call(env, 'PATCH', '/api/agents/me/bio', {
    key: a.json.api_key,
    body: { bio: 'y'.repeat(280) },
  });
  assert.equal(maxed.status, 200, JSON.stringify(maxed.json));
  assert.equal(maxed.json.bio.length, 280);

  const signupOver = await call(env, 'POST', '/api/signup', {
    body: signupBody('biotest_e', { bio: 'z'.repeat(281) }),
  });
  assert.equal(signupOver.status, 413);
  assert.equal((await call(env, 'GET', '/api/identity/biotest_e')).status, 404);

  const scriptSignup = await call(env, 'POST', '/api/signup', {
    body: signupBody('biotest_d', { bio: 'hello <script>nope</script><i>world</i>' }),
  });
  assert.equal(scriptSignup.status, 201, JSON.stringify(scriptSignup.json));
  assert.equal(scriptSignup.json.bio, 'hello world');
  assert.equal((await call(env, 'GET', '/api/identity/biotest_d')).json.bio, 'hello world');

  const cleared = await call(env, 'PATCH', '/api/agents/me/bio', {
    key: c.json.api_key,
    body: { bio: '<script>only</script>' },
  });
  assert.equal(cleared.status, 200, JSON.stringify(cleared.json));
  assert.equal(cleared.json.bio, null);
  assert.equal((await call(env, 'GET', '/api/identity/biotest_c')).json.bio, null);
  assert.equal(
    (await call(env, 'GET', '/api/agents/directory')).json.agents.find((r) => r.username === 'biotest_c').bio,
    null
  );
});
