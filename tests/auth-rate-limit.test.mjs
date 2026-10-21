/**
 * Signup/login rate limit, against the worker fetch handler.
 *
 * Storage is an in-memory D1 stand-in (node:sqlite) plus a KV map.
 * Nothing here talks to production.
 *
 * Attempts 1-10 of a parsed body go through to the normal handler.
 * Attempt 11 in the same minute is 429 with Retry-After. A second IP
 * is not affected. A body that is not JSON does not count.
 *
 * Run: node --import ./tests/register-legal-stub.mjs --test tests/auth-rate-limit.test.mjs
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import worker from '../worker/index.js';

const SIGNUP_BODY = { username: 'scribe', accept_terms: true, age_attest: true };
const LOGIN_BODY = { username: 'scribe', password: 'not-the-password' };

function secondsToUtcMidnight() {
  const now = Date.now();
  const d = new Date(now);
  const next = Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate() + 1);
  return Math.max(1, Math.ceil((next - now) / 1000));
}

function makeEnv() {
  const sqlite = new DatabaseSync(':memory:');
  const kv = new Map();
  const counts = { agentLookups: 0 };
  function statement(sql, args) {
    if (!/auth_attempt_counts/i.test(sql)) {
      return {
        async first() {
          if (/SELECT id FROM agents WHERE username/i.test(sql)) {
            counts.agentLookups += 1;
            return { id: 1 };
          }
          if (/SELECT id, password_hash FROM agents/i.test(sql)) {
            counts.agentLookups += 1;
            return null;
          }
          throw new Error('unexpected SQL: ' + sql);
        },
        async run() {
          return { success: true, meta: { changes: 0 } };
        },
        async all() {
          return { results: [] };
        },
      };
    }
    const positional = sql.replace(/\?(\d+)/g, '?');
    const stmt = sqlite.prepare(positional);
    return {
      async first() {
        const row = args.length ? stmt.get(...args) : stmt.get();
        return row ?? null;
      },
      async run() {
        const info = args.length ? stmt.run(...args) : stmt.run();
        return { success: true, meta: { changes: info.changes } };
      },
      async all() {
        const rows = args.length ? stmt.all(...args) : stmt.all();
        return { results: rows };
      },
    };
  }
  const db = {
    prepare(sql) {
      const stmt = statement(sql, []);
      stmt.bind = (...args) => statement(sql, args);
      return stmt;
    },
  };
  return {
    sqlite,
    counts,
    DB: db,
    KV: {
      async get(key) {
        return kv.has(key) ? kv.get(key) : null;
      },
      async put(key, value) {
        kv.set(key, String(value));
      },
    },
  };
}

async function post(env, path, ip, body) {
  const res = await worker.fetch(new Request('https://api.tryoids.com' + path, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'CF-Connecting-IP': ip,
    },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  }), env);
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }
  return { status: res.status, headers: res.headers, json, text };
}

function assertRateLimited(res, message) {
  assert.equal(res.status, 429);
  assert.ok(res.json, '429 body was not JSON: ' + res.text);
  assert.deepEqual(Object.keys(res.json).sort(), ['error', 'message']);
  assert.equal(res.json.error, 'rate_limited');
  assert.equal(res.json.message, message);
  const retry = res.headers.get('Retry-After');
  assert.match(retry, /^\d+$/);
  return Number(retry);
}

function minuteCount(env, ip) {
  const table = env.sqlite.prepare(
    `SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'auth_attempt_counts'`
  ).get();
  if (!table) return 0;
  const row = env.sqlite.prepare(
    `SELECT n FROM auth_attempt_counts WHERE ip = ? AND scope = 'm'`
  ).get(ip);
  return row ? row.n : 0;
}

describe('POST /api/signup rate limit', () => {
  it('lets 10 parsed attempts through and 429s the 11th, per IP', async () => {
    const env = makeEnv();
    const ip = '203.0.113.10';
    const other = '203.0.113.11';

    for (let i = 1; i <= 10; i++) {
      const res = await post(env, '/api/signup', ip, SIGNUP_BODY);
      assert.equal(res.status, 409, `attempt ${i} status`);
      assert.equal(res.json.error, 'username_taken', `attempt ${i} error`);
      assert.equal(res.headers.get('Retry-After'), null);
    }
    assert.equal(minuteCount(env, ip), 10);

    const blocked = await post(env, '/api/signup', ip, SIGNUP_BODY);
    const retry = assertRateLimited(blocked, 'Too many attempts. Slow down.');
    assert.ok(retry >= 1 && retry <= 60);
    assert.equal(minuteCount(env, ip), 11);
    assert.equal(env.counts.agentLookups, 10);

    const second = await post(env, '/api/signup', other, SIGNUP_BODY);
    assert.equal(second.status, 409);
    assert.equal(second.json.error, 'username_taken');
    assert.equal(second.headers.get('Retry-After'), null);
    assert.equal(minuteCount(env, other), 1);
  });

  it('does not count a body that is not JSON', async () => {
    const env = makeEnv();
    const ip = '203.0.113.20';
    const bad = await post(env, '/api/signup', ip, '{');
    assert.equal(bad.status, 400);
    assert.equal(bad.json.error, 'invalid_json');
    assert.equal(minuteCount(env, ip), 0);

    for (let i = 1; i <= 10; i++) {
      const res = await post(env, '/api/signup', ip, SIGNUP_BODY);
      assert.equal(res.status, 409, `parsed attempt ${i}`);
    }
    const blocked = await post(env, '/api/signup', ip, SIGNUP_BODY);
    assert.equal(blocked.status, 429);
    assert.equal(blocked.json.error, 'rate_limited');
  });
});

describe('POST /api/login rate limit', () => {
  it('lets 10 parsed attempts through and 429s the 11th, per IP', async () => {
    const env = makeEnv();
    const ip = '203.0.113.30';
    const other = '203.0.113.31';

    for (let i = 1; i <= 10; i++) {
      const res = await post(env, '/api/login', ip, LOGIN_BODY);
      assert.equal(res.status, 401, `attempt ${i} status`);
      assert.equal(res.json.error, 'invalid_credentials', `attempt ${i} error`);
      assert.equal(res.headers.get('Retry-After'), null);
    }

    const blocked = await post(env, '/api/login', ip, LOGIN_BODY);
    const retry = assertRateLimited(blocked, 'Too many attempts. Slow down.');
    assert.ok(retry >= 1 && retry <= 60);

    const second = await post(env, '/api/login', other, LOGIN_BODY);
    assert.equal(second.status, 401);
    assert.equal(second.json.error, 'invalid_credentials');
    assert.equal(second.headers.get('Retry-After'), null);
  });

  it('shares the per-IP counter with signup', async () => {
    const env = makeEnv();
    const ip = '203.0.113.40';
    for (let i = 1; i <= 10; i++) {
      const res = await post(env, '/api/signup', ip, SIGNUP_BODY);
      assert.equal(res.status, 409);
    }
    const login = await post(env, '/api/login', ip, LOGIN_BODY);
    assertRateLimited(login, 'Too many attempts. Slow down.');
  });
});

describe('signup/login daily cap', () => {
  it('returns 429 and Retry-After until UTC midnight', async () => {
    const env = makeEnv();
    const ip = '203.0.113.50';
    const first = await post(env, '/api/signup', ip, SIGNUP_BODY);
    assert.equal(first.status, 409);

    const day = new Date().toISOString().slice(0, 10);
    const info = env.sqlite.prepare(
      `UPDATE auth_attempt_counts SET n = 100 WHERE ip = ? AND scope = 'd' AND window_start = ?`
    ).run(ip, day);
    assert.equal(info.changes, 1);

    const blocked = await post(env, '/api/signup', ip, SIGNUP_BODY);
    const retry = assertRateLimited(blocked, 'Too many attempts today. Try again tomorrow.');
    const expected = secondsToUtcMidnight();
    assert.ok(Math.abs(retry - expected) <= 2, `Retry-After ${retry} vs ${expected}`);

    const login = await post(env, '/api/login', ip, LOGIN_BODY);
    assertRateLimited(login, 'Too many attempts today. Try again tomorrow.');

    const other = await post(env, '/api/login', '203.0.113.51', LOGIN_BODY);
    assert.equal(other.status, 401);
    assert.equal(other.json.error, 'invalid_credentials');
  });
});
