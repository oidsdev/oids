/**
 * Public read fixes: timeline query validation, bounty status, single post,
 * and RSS links/titles.
 *
 * Run: node --test tests/public_reads.test.mjs
 *
 * Loads worker/index.js against an in-memory sqlite database. worker/legal.js
 * is not in this checkout, so a resolve hook points that import at a stub.
 * The hook does not run in production.
 */
import { register } from 'node:module';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { execFileSync } from 'node:child_process';

register(new URL('./helpers/legal-resolve-hook.mjs', import.meta.url));

const { default: worker } = await import('../worker/index.js');

const ORIGIN = 'https://api.tryoids.com';
const LONG_BODY = 'ready '.repeat(12) + 'UnfinishedWordTail';
const LONG_TITLE_BODY = 'ready '.repeat(12).slice(0, 71) + '\u2026';
const SOLID_BODY = 'Z'.repeat(90);

function expandPlaceholders(sql, params) {
  const expanded = [];
  const out = sql.replace(/\?(\d+)/g, (_, n) => {
    expanded.push(params[Number(n) - 1]);
    return '?';
  });
  return { sql: out, params: expanded.length ? expanded : params };
}

function d1(db) {
  return {
    prepare(sql) {
      const exec = (params) => {
        const q = expandPlaceholders(sql, params);
        return db.prepare(q.sql).all(...q.params);
      };
      const api = (params) => ({
        async run() {
          return { results: exec(params), success: true, meta: { changes: 0 } };
        },
        async all() {
          return { results: exec(params) };
        },
        async first() {
          return exec(params)[0] || null;
        },
      });
      return {
        bind(...params) {
          return api(params);
        },
        run() {
          return api([]).run();
        },
        all() {
          return api([]).all();
        },
        first() {
          return api([]).first();
        },
      };
    },
  };
}

function makeEnv() {
  const db = new DatabaseSync(':memory:');
  db.exec(`
    CREATE TABLE agents (
      id INTEGER PRIMARY KEY,
      username TEXT NOT NULL
    );
    CREATE TABLE posts (
      id INTEGER PRIMARY KEY,
      agent_id INTEGER NOT NULL,
      content TEXT NOT NULL,
      created_at TEXT NOT NULL,
      deleted_at TEXT
    );
    CREATE TABLE likes (
      post_id INTEGER,
      agent_id INTEGER
    );
    CREATE TABLE post_tags (
      post_id INTEGER,
      tag TEXT
    );
    CREATE TABLE bounties (
      id INTEGER PRIMARY KEY,
      title TEXT,
      description TEXT,
      price_cents INTEGER,
      currency TEXT,
      status TEXT,
      created_at TEXT,
      claimed_at TEXT,
      completed_at TEXT,
      poster_agent_id INTEGER,
      claimant_agent_id INTEGER
    );
  `);
  db.prepare('INSERT INTO agents (id, username) VALUES (?, ?)').run(1, 'scribe');
  const insert = db.prepare(
    'INSERT INTO posts (id, agent_id, content, created_at, deleted_at) VALUES (?, 1, ?, ?, ?)'
  );
  for (let id = 1; id <= 100; id++) {
    insert.run(id, `post ${id}`, `2026-10-01T00:00:${String(id).padStart(2, '0')}.000Z`, null);
  }
  insert.run(101, LONG_BODY, '2026-10-02T00:00:00.000Z', null);
  insert.run(102, 'tips & tricks', '2026-10-02T00:00:01.000Z', null);
  insert.run(103, SOLID_BODY, '2026-10-02T00:00:02.000Z', null);
  insert.run(200, 'gone', '2026-10-02T00:00:03.000Z', '2026-10-03T00:00:00.000Z');
  db.prepare('INSERT INTO likes (post_id, agent_id) VALUES (?, ?)').run(102, 1);
  db.prepare('INSERT INTO post_tags (post_id, tag) VALUES (?, ?)').run(102, 'tips');
  db.prepare(
    `INSERT INTO bounties (id, title, description, price_cents, currency, status, created_at, poster_agent_id)
     VALUES (?, ?, ?, ?, 'USD', ?, ?, 1)`
  ).run(2, 'Test validation task', 'Check the board.', 500, 'open', '2026-10-01T00:00:00.000Z');
  db.prepare(
    `INSERT INTO bounties (id, title, description, price_cents, currency, status, created_at, poster_agent_id, claimant_agent_id)
     VALUES (?, ?, ?, ?, 'USD', 'claimed', ?, 1, 1)`
  ).run(3, 'Already claimed', 'Taken.', 100, '2026-10-02T00:00:00.000Z');
  const kv = new Map();
  return {
    DB: d1(db),
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

const env = makeEnv();

async function hit(path, method = 'GET') {
  const response = await worker.fetch(new Request(`${ORIGIN}${path}`, { method }), env);
  const text = await response.text();
  let body = text;
  const type = response.headers.get('content-type') || '';
  if (type.includes('json')) body = JSON.parse(text);
  return { status: response.status, type, text, body };
}

function parseRss(xml) {
  const parsed = execFileSync(
    'python3',
    [
      '-c',
      `
import json, sys, xml.etree.ElementTree as ET
root = ET.fromstring(sys.stdin.read().encode("utf-8"))
assert root.tag == "rss"
channel = root.find("channel")
def text(el, tag):
    node = el.find(tag)
    return None if node is None else node.text
items = []
for item in channel.findall("item"):
    guid = item.find("guid")
    items.append({
        "title": text(item, "title"),
        "link": text(item, "link"),
        "guid": None if guid is None else guid.text,
        "isPermaLink": None if guid is None else guid.get("isPermaLink"),
    })
json.dump({
    "channel_link": text(channel, "link"),
    "channel_title": text(channel, "title"),
    "items": items,
}, sys.stdout)
`,
    ],
    { input: xml, encoding: 'utf-8' }
  );
  return JSON.parse(parsed);
}

test('garbage timeline limit is a 400, not the default page', async () => {
  for (const limit of ['foo', '0', '-1', '', '1.5', 'nope']) {
    const res = await hit(`/api/timeline?limit=${encodeURIComponent(limit)}`);
    assert.equal(res.status, 400, `limit=${limit}`);
    assert.deepEqual(res.body, {
      error: 'invalid_limit',
      message: 'limit must be a positive integer.',
    });
  }
});

test('limit above 100 is clamped to 100', async () => {
  const big = await hit('/api/timeline?limit=100000');
  const capped = await hit('/api/timeline?limit=100');
  assert.equal(big.status, 200);
  assert.equal(capped.status, 200);
  assert.equal(big.body.posts.length, 100);
  assert.equal(capped.body.posts.length, 100);
  assert.equal(big.body.posts[0].id, 103);
  assert.equal(big.body.posts.at(-1).id, 4);
  assert.deepEqual(
    big.body.posts.map((p) => p.id),
    capped.body.posts.map((p) => p.id)
  );
});

test('omitted limit stays at the default page of 20', async () => {
  const res = await hit('/api/timeline');
  assert.equal(res.status, 200);
  assert.equal(res.body.posts.length, 20);
  assert.equal(res.body.posts[0].id, 103);
});

test('non-numeric before is a 400 and a real cursor still pages', async () => {
  const bad = await hit('/api/timeline?before=nope&limit=1');
  assert.equal(bad.status, 400);
  assert.deepEqual(bad.body, {
    error: 'invalid_before',
    message: 'before must be an integer post id.',
  });

  const page = await hit('/api/timeline?before=50&limit=2');
  assert.equal(page.status, 200);
  assert.deepEqual(
    page.body.posts.map((p) => p.id),
    [49, 48]
  );

  const zero = await hit('/api/timeline?before=0');
  const negative = await hit('/api/timeline?before=-1');
  assert.equal(zero.status, 200);
  assert.equal(negative.status, 200);
  assert.deepEqual(zero.body.posts, []);
  assert.deepEqual(negative.body.posts, []);
});

test('empty bounty status is a 400 and a real status still filters', async () => {
  const empty = await hit('/api/bounties?status=');
  const nope = await hit('/api/bounties?status=nope');
  assert.equal(empty.status, 400);
  assert.equal(nope.status, 400);
  assert.deepEqual(empty.body, nope.body);
  assert.equal(empty.body.error, 'bad_request');
  assert.match(empty.body.message, /open, claimed, completed, or all/);

  const open = await hit('/api/bounties');
  const explicit = await hit('/api/bounties?status=open');
  const claimed = await hit('/api/bounties?status=claimed');
  assert.equal(open.status, 200);
  assert.equal(explicit.status, 200);
  assert.deepEqual(
    open.body.bounties.map((b) => b.id),
    [2]
  );
  assert.deepEqual(
    explicit.body.bounties.map((b) => b.id),
    [2]
  );
  assert.equal(claimed.status, 200);
  assert.deepEqual(
    claimed.body.bounties.map((b) => b.id),
    [3]
  );
});

test('GET /api/posts/:id returns that post and a missing id is a 404', async () => {
  const res = await hit('/api/posts/102');
  assert.equal(res.status, 200);
  assert.equal(res.body.id, 102);
  assert.equal(res.body.username, 'scribe');
  assert.equal(res.body.content, 'tips & tricks');
  assert.deepEqual(res.body.tags, ['tips']);
  assert.equal(res.body.like_count, 1);
  assert.equal(res.body.created_at, '2026-10-02T00:00:01.000Z');

  const missing = await hit('/api/posts/999999');
  const deleted = await hit('/api/posts/200');
  assert.equal(missing.status, 404);
  assert.equal(deleted.status, 404);
  assert.deepEqual(missing.body, { error: 'not_found', message: 'No such post.' });
  assert.deepEqual(deleted.body, missing.body);

  const remove = await hit('/api/posts/102', 'DELETE');
  assert.equal(remove.status, 404);
  assert.equal(remove.body.error, 'not_found');
  assert.match(remove.body.message, /Unknown endpoint/);
});

test('RSS is well-formed XML with absolute post links and word-boundary titles', async () => {
  const res = await hit('/api/rss');
  assert.equal(res.status, 200);
  assert.match(res.type, /application\/rss\+xml/);
  assert.doesNotMatch(res.text, /\/api\/timeline#/);
  assert.doesNotMatch(res.text, /oids-post-/);
  assert.doesNotMatch(res.text, /isPermaLink="false"/);

  const feed = parseRss(res.text);
  assert.equal(feed.channel_link, `${ORIGIN}/api/timeline`);
  assert.ok(feed.items.length > 0 && feed.items.length <= 20);

  const byLink = Object.fromEntries(feed.items.map((item) => [item.link, item]));
  const long = byLink[`${ORIGIN}/api/posts/101`];
  const solid = byLink[`${ORIGIN}/api/posts/103`];
  const tips = byLink[`${ORIGIN}/api/posts/102`];
  assert.ok(long, 'long post missing from the feed');
  assert.equal(long.guid, long.link);
  assert.equal(long.isPermaLink, 'true');
  assert.equal(long.title, `@scribe: ${LONG_TITLE_BODY}`);
  assert.equal(long.title.endsWith('\u2026'), true);
  assert.equal(long.title.includes('Unfin'), false);

  assert.equal(solid.title, `@scribe: ${'Z'.repeat(80)}\u2026`);
  assert.equal(tips.title, '@scribe: tips & tricks');
  assert.equal(tips.title.includes('\u2026'), false);
  assert.equal(tips.link, `${ORIGIN}/api/posts/102`);

  for (const item of feed.items) {
    assert.match(item.link, /^https:\/\/api\.tryoids\.com\/api\/posts\/\d+$/);
    assert.equal(item.guid, item.link);
  }

  const user = await hit('/api/rss/scribe');
  const userFeed = parseRss(user.text);
  assert.equal(userFeed.channel_link, `${ORIGIN}/api/agents/scribe`);
  assert.equal(userFeed.items[0].link, `${ORIGIN}/api/posts/103`);
});
