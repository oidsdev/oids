/**
 * POST /api/signup, open mode and invite-gate mode.
 *
 * Terms v1.4 section 3: signup is open unless KV `oids:invite_only` is
 * exactly "1". Open mode must keep the responses the handler returns
 * today (a bad code is ignored; a taken name is username_taken). Gate
 * mode must return the documented invite errors, and must do so before
 * it will say username_taken. A bad code must not tell a caller whether
 * the username exists.
 *
 * Run: node --test tests/signup_invite.test.js
 */
import { register } from 'node:module';
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';

// worker/index.js imports ./legal.js, which is not in this tree. Signup does
// not read it. Register the stub before the worker module is evaluated.
await register(new URL('./signup_invite_hook.js', import.meta.url));
const worker = (await import('../worker/index.js')).default;

const FUTURE = '2099-01-01T00:00:00.000Z';
const PAST = '2020-01-01T00:00:00.000Z';
const NOW_SEED = '2026-01-01T00:00:00.000Z';

const INVITE_REQUIRED = 'Oids is invite-only right now. A valid invite code is required to sign up.';
const INVALID_INVITE = 'That invite code is not valid.';
const INVITE_REDEEMED = 'That invite code has already been used.';
const INVITE_EXPIRED = 'That invite code has expired.';
const USERNAME_TAKEN = 'That username is taken.';

const SCHEMA = `
CREATE TABLE agents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  terms_version TEXT,
  terms_accepted_at TEXT,
  signup_ip TEXT,
  last_login_ip TEXT,
  invite_code_id INTEGER,
  is_mod INTEGER NOT NULL DEFAULT 0,
  bio TEXT,
  deletion_requested_at TEXT
);
CREATE TABLE api_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  agent_id INTEGER NOT NULL,
  key_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  revoked INTEGER NOT NULL DEFAULT 0,
  expires_at TEXT
);
CREATE TABLE invite_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT UNIQUE NOT NULL,
  created_by INTEGER,
  redeemed_by INTEGER,
  created_at TEXT NOT NULL,
  redeemed_at TEXT,
  note TEXT,
  expires_at TEXT
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
`;

/** D1-shaped wrapper. The worker binds ?1, ?2, … which node:sqlite wants as {1: v, 2: v}.
 *  Some statements (the agent-count read) call first() with no bind(). */
function d1(db) {
  return {
    prepare(sql) {
      const stmt = db.prepare(sql);
      function bound(params) {
        const named = {};
        params.forEach((v, i) => {
          named[i + 1] = v === undefined ? null : v;
        });
        return {
          bind(...next) {
            return bound(next);
          },
          async first() {
            const row = params.length ? stmt.get(named) : stmt.get();
            return row === undefined ? null : row;
          },
          async run() {
            const info = params.length ? stmt.run(named) : stmt.run();
            return {
              meta: {
                last_row_id: Number(info.lastInsertRowid),
                changes: info.changes,
              },
            };
          },
        };
      }
      return bound([]);
    },
  };
}

function kv(initial) {
  const store = new Map(Object.entries(initial || {}));
  return {
    async get(key) {
      return store.has(key) ? store.get(key) : null;
    },
    async put(key, value) {
      store.set(key, String(value));
    },
  };
}

let ipSeq = 0;

function makeEnv(inviteOnly) {
  const db = new DatabaseSync(':memory:');
  db.exec(SCHEMA);
  db.prepare(
    'INSERT INTO agents (username, password_hash, created_at) VALUES (?, ?, ?)'
  ).run('scribe', 'hp', NOW_SEED);
  const scribeId = Number(db.prepare('SELECT id FROM agents WHERE username = ?').get('scribe').id);
  const insertCode = db.prepare(
    'INSERT INTO invite_codes (code, created_at, redeemed_by, redeemed_at, expires_at) VALUES (?, ?, ?, ?, ?)'
  );
  insertCode.run('inv_valid_code', NOW_SEED, null, null, FUTURE);
  insertCode.run('inv_used_code', NOW_SEED, scribeId, NOW_SEED, FUTURE);
  insertCode.run('inv_old_code', NOW_SEED, null, null, PAST);
  insertCode.run('inv_used_and_old', NOW_SEED, scribeId, NOW_SEED, PAST);
  const initial = {};
  if (inviteOnly !== undefined) initial['oids:invite_only'] = inviteOnly;
  return { env: { DB: d1(db), KV: kv(initial) }, db, scribeId };
}

async function postSignup(env, body) {
  ipSeq += 1;
  const raw = typeof body === 'string';
  const res = await worker.fetch(
    new Request('https://api.tryoids.com/api/signup', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'CF-Connecting-IP': `203.0.113.${ipSeq}`,
      },
      body: raw ? body : JSON.stringify(body),
    }),
    env
  );
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }
  return { status: res.status, json };
}

function baseBody(username, extra) {
  return Object.assign(
    { username, accept_terms: true, age_attest: true, password: 'long-enough-password' },
    extra || {}
  );
}

function assertError(res, status, code, message) {
  assert.equal(res.status, status);
  assert.ok(res.json, 'response was not JSON');
  assert.equal(res.json.error, code);
  if (message !== undefined) assert.equal(res.json.message, message);
  assert.equal(res.json.api_key, undefined);
}

function agentCount(db) {
  return db.prepare('SELECT COUNT(*) AS n FROM agents').get().n;
}

function codeRow(db, code) {
  return db.prepare(
    'SELECT id, redeemed_by, redeemed_at FROM invite_codes WHERE code = ?'
  ).get(code);
}

describe('POST /api/signup open mode (oids:invite_only unset)', () => {
  it('registers without an invite code', async () => {
    const { env, db } = makeEnv();
    const res = await postSignup(env, {
      username: 'fresh_bot',
      accept_terms: true,
      age_attest: true,
    });
    assert.equal(res.status, 201);
    assert.equal(res.json.username, 'fresh_bot');
    assert.match(res.json.api_key, /^oids_/);
    assert.equal(typeof res.json.generated_password, 'string');
    assert.ok(res.json.generated_password.length >= 8);
    assert.equal(typeof res.json.created_at, 'string');
    assert.equal(typeof res.json.expires_at, 'string');
    const row = db.prepare(
      'SELECT terms_version, invite_code_id FROM agents WHERE username = ?'
    ).get('fresh_bot');
    assert.equal(row.terms_version, '1.4');
    assert.equal(row.invite_code_id, null);
    assert.equal(agentCount(db), 2);
  });

  it('accepts a fake invite code and does not redeem a real one', async () => {
    const { env, db } = makeEnv();
    const res = await postSignup(env, baseBody('fresh_bot', { invite_code: 'inv_not_a_real_code' }));
    assert.equal(res.status, 201);
    assert.equal(res.json.username, 'fresh_bot');
    assert.equal(res.json.generated_password, undefined);
    assert.equal(codeRow(db, 'inv_valid_code').redeemed_by, null);
    const row = db.prepare('SELECT invite_code_id FROM agents WHERE username = ?').get('fresh_bot');
    assert.equal(row.invite_code_id, null);
  });

  it('reports username_taken for a taken name no matter the invite presented', async () => {
    const { env, db } = makeEnv();
    const before = agentCount(db);
    const cases = [
      { invite_code: 'inv_not_a_real_code' },
      {},
      { invite_code: '' },
      { invite_code: '   ' },
      { invite_code: null },
      { invite_code: 'inv_valid_code' },
      { invite_code: 'inv_used_code' },
      { invite_code: 'inv_old_code' },
    ];
    for (const extra of cases) {
      const res = await postSignup(env, baseBody('scribe', extra));
      assertError(res, 409, 'username_taken', USERNAME_TAKEN);
    }
    assert.equal(agentCount(db), before);
    assert.equal(codeRow(db, 'inv_valid_code').redeemed_by, null);
  });

  it('reports a short password before username_taken, and does not create an account', async () => {
    const { env, db } = makeEnv();
    const taken = await postSignup(env, baseBody('scribe', {
      password: 'short',
      invite_code: 'inv_not_a_real_code',
    }));
    const free = await postSignup(env, baseBody('fresh_bot', {
      password: 'short',
      invite_code: 'inv_not_a_real_code',
    }));
    assertError(taken, 400, 'invalid_password', 'Password must be 8-128 characters.');
    assertError(free, 400, 'invalid_password', 'Password must be 8-128 characters.');
    assert.equal(agentCount(db), 1);
  });

  it('keeps the terms and age checks ahead of the taken-name response', async () => {
    const { env } = makeEnv();
    const noAge = await postSignup(env, {
      username: 'scribe',
      accept_terms: true,
      invite_code: 'inv_not_a_real_code',
    });
    assertError(noAge, 400, 'age_not_attested');

    const ageString = await postSignup(env, baseBody('scribe', {
      age_attest: 'true',
      invite_code: 'inv_not_a_real_code',
    }));
    assertError(ageString, 400, 'age_not_attested');

    const termsString = await postSignup(env, baseBody('scribe', {
      accept_terms: 'true',
      invite_code: 'inv_not_a_real_code',
    }));
    assertError(termsString, 400, 'terms_not_accepted');
  });

  it('rejects a non-JSON body', async () => {
    const { env } = makeEnv();
    const res = await postSignup(env, '{not json');
    assertError(res, 400, 'invalid_json', 'Request body must be JSON.');
  });

  it('stays open when the flag is present but not exactly "1"', async () => {
    for (const flag of ['0', 'true', 'yes', '']) {
      const { env } = makeEnv(flag);
      const res = await postSignup(env, baseBody('scribe', { invite_code: 'inv_not_a_real_code' }));
      assertError(res, 409, 'username_taken', USERNAME_TAKEN);
    }
  });
});

describe('POST /api/signup gate mode (oids:invite_only = "1")', () => {
  async function pair(extra) {
    const { env, db } = makeEnv('1');
    const free = await postSignup(env, baseBody('fresh_bot', extra));
    const taken = await postSignup(env, baseBody('scribe', extra));
    return { env, db, free, taken };
  }

  it('rejects a missing code with invite_required, taken name or not', async () => {
    const missing = await pair({});
    assertError(missing.free, 403, 'invite_required', INVITE_REQUIRED);
    assertError(missing.taken, 403, 'invite_required', INVITE_REQUIRED);
    assert.deepEqual(missing.free.json, missing.taken.json);
    assert.equal(agentCount(missing.db), 1);

    for (const invite_code of ['', '   ', null]) {
      const { db, free, taken } = await pair({ invite_code });
      assertError(free, 403, 'invite_required', INVITE_REQUIRED);
      assertError(taken, 403, 'invite_required', INVITE_REQUIRED);
      assert.deepEqual(free.json, taken.json);
      assert.equal(agentCount(db), 1);
    }
  });

  it('rejects an unknown code with invalid_invite, taken name or not', async () => {
    const { db, free, taken } = await pair({ invite_code: 'inv_not_a_real_code' });
    assertError(free, 403, 'invalid_invite', INVALID_INVITE);
    assertError(taken, 403, 'invalid_invite', INVALID_INVITE);
    assert.deepEqual(free.json, taken.json);
    assert.equal(agentCount(db), 1);
    assert.equal(codeRow(db, 'inv_valid_code').redeemed_by, null);
  });

  it('rejects a redeemed code with invite_redeemed, taken name or not', async () => {
    const { db, free, taken } = await pair({ invite_code: 'inv_used_code' });
    assertError(free, 403, 'invite_redeemed', INVITE_REDEEMED);
    assertError(taken, 403, 'invite_redeemed', INVITE_REDEEMED);
    assert.deepEqual(free.json, taken.json);
    assert.equal(agentCount(db), 1);

    const both = await pair({ invite_code: 'inv_used_and_old' });
    assertError(both.free, 403, 'invite_redeemed', INVITE_REDEEMED);
    assertError(both.taken, 403, 'invite_redeemed', INVITE_REDEEMED);
  });

  it('rejects an expired code with invite_expired, taken name or not', async () => {
    const { db, free, taken } = await pair({ invite_code: 'inv_old_code' });
    assertError(free, 403, 'invite_expired', INVITE_EXPIRED);
    assertError(taken, 403, 'invite_expired', INVITE_EXPIRED);
    assert.deepEqual(free.json, taken.json);
    assert.equal(agentCount(db), 1);
  });

  it('reveals username_taken only after the code is valid, and does not redeem it', async () => {
    const { env, db } = makeEnv('1');
    const res = await postSignup(env, baseBody('scribe', { invite_code: '  inv_valid_code  ' }));
    assertError(res, 409, 'username_taken', USERNAME_TAKEN);
    assert.equal(codeRow(db, 'inv_valid_code').redeemed_by, null);
    assert.equal(agentCount(db), 1);
  });

  it('registers with a valid code and then rejects that code as redeemed', async () => {
    const { env, db } = makeEnv('1');
    const res = await postSignup(env, {
      username: 'Fresh_Bot',
      accept_terms: true,
      age_attest: true,
      invite_code: ' inv_valid_code ',
    });
    assert.equal(res.status, 201);
    assert.equal(res.json.username, 'fresh_bot');
    assert.match(res.json.api_key, /^oids_/);
    const agent = db.prepare(
      'SELECT id, invite_code_id, terms_version FROM agents WHERE username = ?'
    ).get('fresh_bot');
    const code = codeRow(db, 'inv_valid_code');
    assert.equal(agent.terms_version, '1.4');
    assert.equal(agent.invite_code_id, code.id);
    assert.equal(code.redeemed_by, agent.id);
    assert.equal(typeof code.redeemed_at, 'string');

    const again = await postSignup(env, baseBody('other_bot', { invite_code: 'inv_valid_code' }));
    assertError(again, 403, 'invite_redeemed', INVITE_REDEEMED);
    assert.equal(db.prepare('SELECT id FROM agents WHERE username = ?').get('other_bot'), undefined);
  });

  it('still reports a short password before any invite error, for a free or taken name', async () => {
    const { db, free, taken } = await pair({
      password: 'short',
      invite_code: 'inv_not_a_real_code',
    });
    assertError(free, 400, 'invalid_password', 'Password must be 8-128 characters.');
    assertError(taken, 400, 'invalid_password', 'Password must be 8-128 characters.');
    assert.deepEqual(free.json, taken.json);
    assert.equal(agentCount(db), 1);
    assert.equal(codeRow(db, 'inv_valid_code').redeemed_by, null);
  });
});
