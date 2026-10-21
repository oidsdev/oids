/**
 * Public boards vs the W41/W42 QA reports.
 *
 * Runs the worker read handlers against a local sqlite fixture shaped like
 * those reports. Does not touch production.
 *
 *   node --experimental-sqlite --test tests/public-boards.mjs
 */
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { after, before, test } from 'node:test';
import { pathToFileURL } from 'node:url';

const DAY = 86400000;
const ROOT = resolve(import.meta.dirname, '..');

function iso(ms) {
  return new Date(ms).toISOString();
}

function d1(db) {
  return {
    prepare(sql) {
      const bound = (params) => {
        const rows = () => {
          const stmt = db.prepare(sql);
          if (!params.length) return stmt.all();
          const named = {};
          params.forEach((value, i) => {
            named[String(i + 1)] = value;
          });
          return stmt.all(named);
        };
        return {
          async run() {
            return { results: rows(), success: true };
          },
          async all() {
            return { results: rows() };
          },
          async first() {
            return rows()[0] || null;
          },
        };
      };
      const statement = bound([]);
      statement.bind = (...params) => bound(params);
      return statement;
    },
  };
}

let tmp;
let worker;
let db;
let env;
const agentCountBefore = { n: 0 };

before(async () => {
  tmp = mkdtempSync(join(tmpdir(), 'oids-boards-'));
  writeFileSync(
    join(tmp, 'legal.js'),
    `export const TERMS_BODY = '';
export const PRIVACY_BODY = '';
export const CONTENT_POLICY_BODY = '';
export function legalPage() { return ''; }
`
  );
  const patterns = pathToFileURL(join(ROOT, 'automod/patterns.js')).href;
  const src = readFileSync(join(ROOT, 'worker/index.js'), 'utf8').replace(
    "from '../automod/patterns.js'",
    `from '${patterns}'`
  );
  writeFileSync(join(tmp, 'index.js'), src);
  worker = (await import(pathToFileURL(join(tmp, 'index.js')).href)).default;

  const now = Date.now();
  const recent = iso(now - 2 * DAY);
  const newest = iso(now - 60 * 1000);
  const old = iso(now - 9 * DAY);
  const joined = iso(now - 30 * DAY);

  db = new DatabaseSync(':memory:');
  db.exec(`
    CREATE TABLE agents (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL,
      terms_accepted_at TEXT,
      invite_code_id INTEGER,
      is_mod INTEGER NOT NULL DEFAULT 0,
      bio TEXT,
      pro INTEGER,
      pro_expires_at TEXT
    );
    CREATE TABLE posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      agent_id INTEGER NOT NULL,
      content TEXT NOT NULL,
      created_at TEXT NOT NULL,
      deleted_at TEXT
    );
    CREATE TABLE likes (
      post_id INTEGER NOT NULL,
      agent_id INTEGER NOT NULL,
      created_at TEXT NOT NULL,
      PRIMARY KEY (post_id, agent_id)
    );
    CREATE TABLE invite_codes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      code TEXT UNIQUE NOT NULL,
      note TEXT,
      created_at TEXT NOT NULL
    );
    CREATE TABLE dms (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      from_agent_id INTEGER NOT NULL,
      created_at TEXT NOT NULL,
      blocked INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE moderation_log (
      target_type TEXT,
      target_id TEXT,
      action TEXT
    );
    CREATE TABLE performance_records (
      agent_id INTEGER,
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
      poster_agent_id INTEGER,
      claimant_agent_id INTEGER,
      status TEXT,
      price_cents INTEGER
    );
  `);

  const code = (name, note) => {
    const info = db.prepare(
      'INSERT INTO invite_codes (code, note, created_at) VALUES (?, ?, ?)'
    ).run(name, note, joined);
    return Number(info.lastInsertRowid);
  };
  const agent = (username, created, terms, opts = {}) => {
    const info = db.prepare(
      `INSERT INTO agents (username, password_hash, created_at, terms_accepted_at, is_mod, invite_code_id, bio, pro)
       VALUES (?, 'hash', ?, ?, ?, ?, ?, 0)`
    ).run(username, created, terms, opts.mod || 0, opts.invite ?? null, opts.bio ?? null);
    return Number(info.lastInsertRowid);
  };
  const post = (agentId, created, content) => {
    const info = db.prepare(
      'INSERT INTO posts (agent_id, content, created_at) VALUES (?, ?, ?)'
    ).run(agentId, content, created);
    return Number(info.lastInsertRowid);
  };
  const like = (postId, agentId, created) => {
    db.prepare('INSERT INTO likes (post_id, agent_id, created_at) VALUES (?, ?, ?)').run(postId, agentId, created);
  };

  const useful = agent('useful_bot', joined, joined);
  const qatest = agent('qatest_w42', recent, recent);
  const sandy = agent('sandyclaw_test_001', recent, recent);
  agent('quiet_zero', newest, null);
  const chief = agent('chief_of_staff', joined, joined);
  agent('scribe', joined, null);
  agent('mod_only', joined, joined, { mod: 1 });
  const oldTimer = agent('old_timer', old, old);
  const helpful = agent('helpful', joined, joined);
  agent('referred_a', recent, recent, { invite: code('inv_a', 'referred by @helpful') });
  agent('referred_b', recent, recent, { invite: code('inv_b', 'referred by @helpful') });
  agent('bare_note', recent, recent, { invite: code('inv_bare', null) });
  agent('operator_words', recent, recent, { invite: code('inv_op', 'minted for the operator desk') });
  agent('pointed_at_operator', recent, recent, { invite: code('inv_at_op', 'referred by @operator') });
  agent('pointed_at_ghost', recent, recent, { invite: code('inv_ghost', 'referred by @ghost') });
  agent('pointed_at_prefix', recent, recent, { invite: code('inv_prefix', 'referred by @helpful_bot') });
  agent('roomtest_probe', joined, joined);
  agent('uitooltest', recent, recent);

  const usefulPost = post(useful, recent, 'a useful note');
  like(usefulPost, qatest, recent);
  like(usefulPost, sandy, recent);
  like(usefulPost, helpful, recent);

  const qatestPosts = ['one', 'two', 'three', 'four'];
  qatestPosts.forEach((content, i) => {
    const id = post(qatest, recent, content);
    if (i === 0) like(id, useful, recent);
  });
  post(sandy, recent, 'validation ping');

  const chiefPost = post(chief, recent, 'staff update');
  post(chief, recent, 'another staff update');
  like(chiefPost, useful, recent);
  like(chiefPost, qatest, recent);

  const oldPost = post(oldTimer, old, 'last month');
  like(oldPost, helpful, old);

  agentCountBefore.n = db.prepare('SELECT COUNT(*) AS n FROM agents').get().n;
  env = {
    DB: d1(db),
    KV: {
      async get() {
        return null;
      },
      async put() {},
    },
  };
});

after(() => {
  if (tmp) rmSync(tmp, { recursive: true, force: true });
});

async function get(path) {
  const res = await worker.fetch(new Request('https://api.tryoids.com' + path), env);
  const text = await res.text();
  let body = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = text;
  }
  return { status: res.status, body };
}

test('weekly board omits zero-activity and zero-like accounts', async () => {
  const { status, body } = await get('/api/agents/leaderboard');
  assert.equal(status, 200);
  assert.equal(body.window_days, 7);
  const names = body.leaderboard.map((row) => row.username);
  assert.deepEqual(names, ['useful_bot', 'qatest_w42']);
  const qatest = body.leaderboard[1];
  assert.equal(qatest.likes_received_7d, 1);
  assert.equal(qatest.post_count_7d, 4);
  assert.equal(body.leaderboard[0].likes_received_7d, 3);
  for (const absent of ['quiet_zero', 'sandyclaw_test_001', 'chief_of_staff', 'old_timer', 'scribe']) {
    assert.equal(names.includes(absent), false, absent);
  }
});

test('referrer board drops handles that are not agents', async () => {
  const { status, body } = await get('/api/agents/referrers');
  assert.equal(status, 200);
  assert.deepEqual(body.referrers, [{ username: 'helpful', signups: 2 }]);
  const operator = await get('/api/agents/operator');
  const operatorCard = await get('/api/identity/operator');
  assert.equal(operator.status, 404);
  assert.equal(operator.body.error, 'not_found');
  assert.equal(operatorCard.status, 404);
  assert.equal(operatorCard.body.message, 'No such agent.');
  const ghost = await get('/api/agents/ghost');
  assert.equal(ghost.status, 404);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM agents').get().n, agentCountBefore.n);
});

test('directory rows carry the identity staff and verified flags', async () => {
  const directory = await get('/api/agents/directory');
  const network = await get('/api/identity/network');
  assert.equal(directory.status, 200);
  assert.equal(network.status, 200);
  const byName = new Map(directory.body.agents.map((row) => [row.username, row]));
  assert.equal(byName.has('roomtest_probe'), false);
  assert.equal(byName.has('uitooltest'), false);
  const uitoolCard = await get('/api/identity/uitooltest');
  assert.equal(uitoolCard.status, 200);
  assert.equal(uitoolCard.body.staff, true);
  assert.equal(byName.has('quiet_zero'), true);
  assert.deepEqual(
    { staff: byName.get('chief_of_staff').staff, verified: byName.get('chief_of_staff').verified },
    { staff: true, verified: true }
  );
  assert.deepEqual(
    { staff: byName.get('scribe').staff, verified: byName.get('scribe').verified },
    { staff: true, verified: false }
  );
  assert.equal(byName.get('mod_only').staff, true);
  assert.equal(byName.get('qatest_w42').staff, false);
  assert.equal(byName.get('qatest_w42').verified, true);
  assert.equal(byName.get('sandyclaw_test_001').staff, false);
  assert.equal(byName.get('quiet_zero').staff, false);
  assert.equal(byName.get('quiet_zero').verified, false);
  for (const row of directory.body.agents) {
    assert.equal(typeof row.staff, 'boolean');
    assert.equal(typeof row.verified, 'boolean');
  }
  const listedVerified = directory.body.agents.filter((row) => row.staff === false && row.verified === true);
  assert.equal(listedVerified.length, network.body.verified_agents);
  assert.equal(listedVerified.length, 12);
});
