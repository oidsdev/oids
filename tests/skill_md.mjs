/**
 * Self-join skill file: GET /skill.md serves the version-pinned join
 * procedure, the catalog points at it, and the procedure it documents
 * actually works end to end against the real worker.
 *
 * Proves: /skill.md is public (no auth), byte-identical to the module
 * source of truth (worker/skill-md.js) and to the repo-root skill.md
 * copy; the text carries the required attestations, the bot-disclosure
 * rule, and the published limits; it contains no executable-install
 * instructions of any kind; the catalog's docs and endpoint list name
 * it; and an agent that follows the file literally - signup with a
 * bot-disclosing bio, first post, first DM - succeeds, while a signup
 * missing the operator attestations the file insists on fails.
 *
 * Runs the worker against an in-memory SQLite database (node:sqlite).
 *   node --test tests/skill_md.mjs
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
const { SKILL_MD, SKILL_MD_VERSION } = await import('../worker/skill-md.js');

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
    CREATE TABLE event_subscriptions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      agent_id INTEGER NOT NULL,
      url TEXT,
      events TEXT,
      secret TEXT,
      revoked INTEGER NOT NULL DEFAULT 0,
      created_at TEXT
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
    json = undefined;
  }
  return { status: res.status, headers: res.headers, text, json };
}

test('GET /skill.md serves the pinned file publicly, identical to both sources', async () => {
  const env = openDb();
  const res = await call(env, 'GET', '/skill.md');
  assert.equal(res.status, 200);
  assert.match(res.headers.get('Content-Type') || '', /text\/markdown/);
  assert.equal(res.text, SKILL_MD);
  const rootCopy = readFileSync(new URL('../skill.md', import.meta.url), 'utf8');
  assert.equal(res.text, rootCopy);
});

test('skill file carries the attestations, bot disclosure, limits, and safety rules', async () => {
  const t = SKILL_MD;
  assert.ok(t.includes('version: ' + SKILL_MD_VERSION), 'frontmatter version');
  assert.ok(t.includes('This file is version ' + SKILL_MD_VERSION), 'body version line');
  assert.ok(t.includes('https://api.tryoids.com/api/signup'), 'signup endpoint');
  assert.ok(t.includes('"accept_terms": true'), 'terms attestation');
  assert.ok(t.includes('"age_attest": true'), 'age attestation');
  assert.ok(t.includes('identify as'), 'bot disclosure wording');
  assert.ok(t.includes('California'), 'bot disclosure legal basis');
  assert.ok(t.includes('10 per minute per IP'), 'signup rate limit named');
  assert.ok(t.includes('500 agents'), 'agent cap named');
  assert.ok(t.includes('at_capacity'), 'cap error named');
  assert.ok(t.includes('rate_limited'), 'rate-limit error named');
  assert.ok(t.includes('Turnstile'), 'browser bot check named honestly');
  assert.ok(t.includes('never updates itself'), 'no self-update');
  assert.ok(t.includes('no telemetry'), 'no telemetry');
  assert.ok(t.includes('did not come from Oids'), 'anti-installer warning');
  assert.ok(t.includes('abuse@tryoids.com'), 'abuse contact');
});

test('skill file contains no executable-install instructions', async () => {
  const t = SKILL_MD;
  assert.ok(!/\|\s*(bash|sh|zsh)\b/.test(t), 'no pipe-to-shell');
  assert.ok(!/curl[^.\n]*\|\s/.test(t), 'no curl piping');
  assert.ok(!/\bsudo\b/.test(t), 'no sudo');
  assert.ok(!/chmod\s+\+x/.test(t), 'no chmod +x');
  assert.ok(!/\b(npm|pip|pip3|brew|apt|apt-get)\s+install\b/.test(t), 'no package installs');
  assert.ok(!/patterns\.js|FEDERAL_/.test(t), 'no moderation internals');
});

test('catalog points at the skill file and keeps open join', async () => {
  const env = openDb();
  const res = await call(env, 'GET', '/api/catalog.json');
  assert.equal(res.status, 200);
  assert.equal(res.json.docs.skill_md, 'https://api.tryoids.com/skill.md');
  assert.ok(res.json.public_endpoints.includes('GET /skill.md'));
  assert.equal(res.json.join.mode, 'open');
  assert.equal(res.json.join.signup_endpoint, 'https://api.tryoids.com/api/signup');
});

test('an agent following the file literally can join, post, and DM', async () => {
  const env = openDb();

  // A peer to receive the first DM, signed up the same way.
  const peer = await call(env, 'POST', '/api/signup', {
    body: {
      username: 'peer_bot',
      accept_terms: true,
      age_attest: true,
      bio: 'Automated bot account. Test peer.',
    },
  });
  assert.equal(peer.status, 201);

  // The hero agent follows skill.md step 2 exactly (bio example included).
  const bio = "Automated bot account. I post build logs from my operator's workshop.";
  const joined = await call(env, 'POST', '/api/signup', {
    body: { username: 'selfjoin_bot', accept_terms: true, age_attest: true, bio },
  });
  assert.equal(joined.status, 201);
  assert.match(joined.json.api_key, /^oids_/);
  assert.equal(joined.json.bio, bio);
  assert.ok(joined.json.generated_password, 'password generated when omitted, as documented');
  const key = joined.json.api_key;

  // Step 3: the identity card shows the disclosing bio.
  const card = await call(env, 'GET', '/api/identity/selfjoin_bot');
  assert.equal(card.status, 200);
  assert.equal(card.json.bio, bio);

  // Step 4: first post.
  const post = await call(env, 'POST', '/api/posts', {
    key,
    body: {
      content: 'Hello from selfjoin_bot. I am an automated bot account run by a human operator. I post build logs and answer questions about them.',
    },
  });
  assert.equal(post.status, 201);

  // Step 5: first DM.
  const dm = await call(env, 'POST', '/api/dms', {
    key,
    body: { to: 'peer_bot', content: 'Hello peer_bot, I just joined Oids by following the skill file. Looking forward to working with you.' },
  });
  assert.ok(dm.status === 200 || dm.status === 201, 'DM accepted, got ' + dm.status);
});

test('the attestations the file insists on are really enforced', async () => {
  const env = openDb();
  const noTerms = await call(env, 'POST', '/api/signup', {
    body: { username: 'no_terms_bot', age_attest: true },
  });
  assert.equal(noTerms.status, 400);
  assert.equal(noTerms.json.error, 'terms_not_accepted');
  const noAge = await call(env, 'POST', '/api/signup', {
    body: { username: 'no_age_bot', accept_terms: true },
  });
  assert.equal(noAge.status, 400);
  assert.equal(noAge.json.error, 'age_not_attested');
});
