/**
 * Outbound event subscriptions: create/list/revoke plus signed delivery
 * for dm.received, mention, and bounty.posted.
 *
 * Runs the worker fetch handler against an in-memory SQLite database.
 * Outbound delivery fetches are captured by stubbing globalThis.fetch.
 *   node tests/event_subscriptions.mjs
 */
import { existsSync, writeFileSync, unlinkSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';

// worker/index.js imports ./legal.js, which is not in this tree. These
// tests do not render legal pages, so a stub is enough to load the module.
const legalPath = new URL('../worker/legal.js', import.meta.url);
const createdLegalStub = !existsSync(legalPath);
if (createdLegalStub) {
  writeFileSync(legalPath, [
    'export const TERMS_BODY = "";',
    'export const PRIVACY_BODY = "";',
    'export const CONTENT_POLICY_BODY = "";',
    'export function legalPage(title, body) { return String(title) + String(body); }',
    '',
  ].join('\n'));
}
const { default: worker } = await import('../worker/index.js');

const KEYS = {
  sender_bot: 'oids_test_sender_key',
  other_bot: 'oids_test_other_key',
  third_bot: 'oids_test_third_key',
};
const ORIGIN = 'https://api.tryoids.com';
const HOOK_OTHER = 'https://example.com/hook-other';
const HOOK_SENDER_DM = 'https://example.com/hook-sender-dm';
const HOOK_SENDER_BOUNTY = 'https://example.com/hook-sender-bounty';
const HOOK_THIRD = 'https://example.com/hook-third';

const deliveries = [];
const realFetch = globalThis.fetch;
globalThis.fetch = async (url, opts = {}) => {
  deliveries.push({
    url: String(url),
    method: opts.method || 'GET',
    headers: opts.headers || {},
    body: typeof opts.body === 'string' ? opts.body : '',
  });
  return new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } });
};

function fail(msg) {
  console.error('FAIL', msg);
  process.exitCode = 1;
  throw new Error(msg);
}

function assert(cond, msg) {
  if (!cond) fail(msg);
}

function sha256hex(str) {
  return crypto.subtle.digest('SHA-256', new TextEncoder().encode(str)).then((digest) => {
    return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
  });
}

async function hmacHex(secret, body) {
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const mac = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(body));
  return [...new Uint8Array(mac)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** D1-shaped wrapper. Worker SQL uses ?1, ?2, …; node:sqlite wants `?`. */
function d1(db) {
  return {
    prepare(sql) {
      return {
        bind(...args) {
          const order = [];
          const rewritten = sql.replace(/\?(\d+)/g, (_, n) => {
            order.push(Number(n) - 1);
            return '?';
          });
          const positional = order.map((i) => args[i]);
          const stmt = db.prepare(rewritten);
          return {
            async first() {
              const row = stmt.get(...positional);
              return row || null;
            },
            async all() {
              return { results: stmt.all(...positional) };
            },
            async run() {
              const info = stmt.run(...positional);
              return { meta: { last_row_id: Number(info.lastInsertRowid), changes: info.changes } };
            },
          };
        },
      };
    },
    async batch(statements) {
      const out = [];
      for (const s of statements) out.push(await s.run());
      return out;
    },
  };
}

function kv() {
  const store = new Map();
  return {
    async get(key) {
      return store.has(key) ? store.get(key) : null;
    },
    async put(key, value) {
      store.set(key, String(value));
    },
  };
}

function seed(db, keyHashes) {
  db.exec(`
    CREATE TABLE agents (
      id INTEGER PRIMARY KEY,
      username TEXT NOT NULL,
      password_hash TEXT NOT NULL DEFAULT 'x',
      is_mod INTEGER NOT NULL DEFAULT 0,
      read_only INTEGER NOT NULL DEFAULT 0,
      pro INTEGER NOT NULL DEFAULT 0,
      pro_expires_at TEXT
    );
    CREATE TABLE api_keys (
      id INTEGER PRIMARY KEY,
      agent_id INTEGER NOT NULL,
      key_hash TEXT NOT NULL,
      revoked INTEGER NOT NULL DEFAULT 0,
      expires_at TEXT
    );
    CREATE TABLE dms (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      from_agent_id INTEGER NOT NULL,
      to_agent_id INTEGER NOT NULL,
      content TEXT NOT NULL,
      created_at TEXT NOT NULL,
      read_at TEXT,
      blocked INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      agent_id INTEGER NOT NULL,
      content TEXT NOT NULL,
      created_at TEXT NOT NULL,
      deleted_at TEXT
    );
    CREATE TABLE post_tags (post_id INTEGER NOT NULL, tag TEXT NOT NULL);
    CREATE TABLE bounties (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      poster_agent_id INTEGER NOT NULL,
      claimant_agent_id INTEGER,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      price_cents INTEGER NOT NULL,
      currency TEXT NOT NULL DEFAULT 'USD',
      status TEXT NOT NULL DEFAULT 'open',
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      claimed_at TEXT,
      completed_at TEXT
    );
    CREATE TABLE client_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      agent_id INTEGER,
      client_type TEXT,
      ip TEXT
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
    CREATE TABLE event_subscriptions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      agent_id INTEGER NOT NULL REFERENCES agents(id),
      url TEXT NOT NULL,
      events TEXT NOT NULL,
      secret TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      revoked INTEGER NOT NULL DEFAULT 0
    );
    INSERT INTO agents (id, username) VALUES (1, 'sender_bot'), (2, 'other_bot'), (3, 'third_bot');
  `);
  const insKey = db.prepare('INSERT INTO api_keys (agent_id, key_hash, revoked, expires_at) VALUES (?, ?, 0, NULL)');
  insKey.run(1, keyHashes.sender_bot);
  insKey.run(2, keyHashes.other_bot);
  insKey.run(3, keyHashes.third_bot);
}

async function call(env, method, path, { key, body } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (key) headers.Authorization = 'Bearer ' + key;
  const res = await worker.fetch(new Request(ORIGIN + path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  }), env);
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* plain text */ }
  return { status: res.status, json, text };
}

/** Delivery is fire-and-forget; without ctx the worker awaits it inline, so
 *  this poll is only a safety net. */
async function waitForDeliveries(n, label) {
  for (let i = 0; i < 40 && deliveries.length < n; i++) {
    await new Promise((r) => setTimeout(r, 50));
  }
  assert(deliveries.length === n, `${label}: expected ${n} deliveries, got ${deliveries.length}`);
}

function deliveriesTo(url) {
  return deliveries.filter((d) => d.url === url);
}

async function main() {
  const db = new DatabaseSync(':memory:');
  const keyHashes = {
    sender_bot: await sha256hex(KEYS.sender_bot),
    other_bot: await sha256hex(KEYS.other_bot),
    third_bot: await sha256hex(KEYS.third_bot),
  };
  seed(db, keyHashes);
  const env = { DB: d1(db), KV: kv() };

  // Unauthenticated create and list are 401.
  const noAuth = await call(env, 'POST', '/api/subscriptions', { body: { url: HOOK_OTHER, events: ['dm.received'] } });
  assert(noAuth.status === 401, 'create without a key is 401, got ' + noAuth.status);
  const noAuthList = await call(env, 'GET', '/api/subscriptions');
  assert(noAuthList.status === 401, 'list without a key is 401, got ' + noAuthList.status);

  // Create: 201, secret present and 64 hex, shown-once note.
  const created = await call(env, 'POST', '/api/subscriptions', {
    key: KEYS.other_bot,
    body: { url: HOOK_OTHER, events: ['dm.received', 'mention'] },
  });
  assert(created.status === 201, 'create is 201, got ' + created.status + ' ' + created.text);
  assert(Number.isInteger(created.json.id), 'create returns an id');
  assert(/^[0-9a-f]{64}$/.test(created.json.secret), 'secret is 64 hex');
  assert(created.json.note && created.json.note.includes('shown once'), 'create note says shown once');
  assert(JSON.stringify(created.json.events) === JSON.stringify(['dm.received', 'mention']), 'create echoes events');
  const otherSubId = created.json.id;
  const otherSecret = created.json.secret;

  // Invalid creates are 400: http url, non-URL, unknown event, empty events.
  const httpUrl = await call(env, 'POST', '/api/subscriptions', {
    key: KEYS.sender_bot, body: { url: 'http://example.com/hook', events: ['dm.received'] },
  });
  assert(httpUrl.status === 400, 'http url is 400, got ' + httpUrl.status);
  const notUrl = await call(env, 'POST', '/api/subscriptions', {
    key: KEYS.sender_bot, body: { url: 'not a url', events: ['dm.received'] },
  });
  assert(notUrl.status === 400, 'non-URL is 400, got ' + notUrl.status);
  const badEvent = await call(env, 'POST', '/api/subscriptions', {
    key: KEYS.sender_bot, body: { url: HOOK_SENDER_DM, events: ['post.liked'] },
  });
  assert(badEvent.status === 400, 'unknown event is 400, got ' + badEvent.status);
  const emptyEvents = await call(env, 'POST', '/api/subscriptions', {
    key: KEYS.sender_bot, body: { url: HOOK_SENDER_DM, events: [] },
  });
  assert(emptyEvents.status === 400, 'empty events is 400, got ' + emptyEvents.status);

  // Sender and third-agent subscriptions for the delivery flows.
  const senderDm = await call(env, 'POST', '/api/subscriptions', {
    key: KEYS.sender_bot, body: { url: HOOK_SENDER_DM, events: ['dm.received'] },
  });
  assert(senderDm.status === 201, 'sender dm subscription creates');
  const senderBounty = await call(env, 'POST', '/api/subscriptions', {
    key: KEYS.sender_bot, body: { url: HOOK_SENDER_BOUNTY, events: ['bounty.posted'] },
  });
  assert(senderBounty.status === 201, 'sender bounty subscription creates');
  const thirdSub = await call(env, 'POST', '/api/subscriptions', {
    key: KEYS.third_bot, body: { url: HOOK_THIRD, events: ['bounty.posted'] },
  });
  assert(thirdSub.status === 201, 'third subscription creates');
  const thirdSecret = thirdSub.json.secret;

  // List: only the caller's own, secret absent, revoked is boolean false.
  const listed = await call(env, 'GET', '/api/subscriptions', { key: KEYS.other_bot });
  assert(listed.status === 200, 'list is 200');
  assert(listed.json.subscriptions.length === 1, 'list shows only the caller own subscriptions');
  const item = listed.json.subscriptions[0];
  assert(item.id === otherSubId && item.url === HOOK_OTHER, 'list item matches the created subscription');
  assert(item.revoked === false && typeof item.revoked === 'boolean', 'list revoked is boolean false');
  assert(!('secret' in item) && !listed.text.includes(otherSecret), 'list never returns the secret');

  // DM flow: recipient subscription receives dm.received, signed; sender does not.
  const dm = await call(env, 'POST', '/api/dms', {
    key: KEYS.sender_bot, body: { to: 'other_bot', content: 'hello there' },
  });
  assert(dm.status === 201, 'DM sends, got ' + dm.status + ' ' + dm.text);
  await waitForDeliveries(1, 'dm flow');
  const dmDelivery = deliveries[0];
  assert(dmDelivery.url === HOOK_OTHER, 'dm.received goes to the recipient URL');
  assert(dmDelivery.method === 'POST', 'delivery is a POST');
  assert(dmDelivery.headers['X-Oids-Event'] === 'dm.received', 'delivery carries X-Oids-Event');
  const dmPayload = JSON.parse(dmDelivery.body);
  assert(dmPayload.event === 'dm.received' && dmPayload.id && dmPayload.created_at, 'delivery envelope has id, event, created_at');
  assert(dmPayload.data.dm_id === dm.json.id, 'dm data names the dm id');
  assert(dmPayload.data.from === 'sender_bot' && dmPayload.data.to === 'other_bot', 'dm data names from and to');
  assert(dmPayload.data.content === 'hello there' && dmPayload.data.created_at === dm.json.created_at, 'dm data carries content and time');
  const expectedSig = 'sha256=' + (await hmacHex(otherSecret, dmDelivery.body));
  assert(dmDelivery.headers['X-Oids-Signature'] === expectedSig, 'dm signature verifies against the secret');
  assert(deliveriesTo(HOOK_SENDER_DM).length === 0, 'sender subscription does not receive its own DM');

  // Mention flow: a post naming @other_bot delivers mention; a plain post does not.
  const post = await call(env, 'POST', '/api/posts', {
    key: KEYS.sender_bot, body: { content: '@other_bot hello' },
  });
  assert(post.status === 201, 'post creates, got ' + post.status + ' ' + post.text);
  await waitForDeliveries(2, 'mention flow');
  const mentionDelivery = deliveries[1];
  assert(mentionDelivery.url === HOOK_OTHER, 'mention goes to the mentioned agent URL');
  assert(mentionDelivery.headers['X-Oids-Event'] === 'mention', 'mention carries X-Oids-Event');
  const mentionPayload = JSON.parse(mentionDelivery.body);
  assert(mentionPayload.data.post_id === post.json.id, 'mention data names the post id');
  assert(mentionPayload.data.from === 'sender_bot' && mentionPayload.data.content === '@other_bot hello', 'mention data names from and content');
  const plain = await call(env, 'POST', '/api/posts', {
    key: KEYS.sender_bot, body: { content: 'plain post, no names' },
  });
  assert(plain.status === 201, 'plain post creates');
  await new Promise((r) => setTimeout(r, 100));
  assert(deliveries.length === 2, 'a post with no mention delivers nothing, got ' + deliveries.length);

  // Bounty flow: third agent receives bounty.posted; the poster does not.
  const bounty = await call(env, 'POST', '/api/bounties', {
    key: KEYS.sender_bot,
    body: { title: 'Test bounty task', description: 'Do the thing and report back.', price_cents: 2500 },
  });
  assert(bounty.status === 200 && bounty.json.ok, 'bounty creates, got ' + bounty.status + ' ' + bounty.text);
  await waitForDeliveries(3, 'bounty flow');
  const bountyDelivery = deliveries[2];
  assert(bountyDelivery.url === HOOK_THIRD, 'bounty.posted goes to the third agent URL');
  assert(bountyDelivery.headers['X-Oids-Event'] === 'bounty.posted', 'bounty carries X-Oids-Event');
  const bountyPayload = JSON.parse(bountyDelivery.body);
  assert(bountyPayload.data.bounty_id === bounty.json.id, 'bounty data names the bounty id');
  assert(bountyPayload.data.title === 'Test bounty task' && bountyPayload.data.price_cents === 2500, 'bounty data carries title and price');
  assert(bountyPayload.data.currency === 'USD' && bountyPayload.data.poster === 'sender_bot', 'bounty data carries currency and poster');
  const bountySig = 'sha256=' + (await hmacHex(thirdSecret, bountyDelivery.body));
  assert(bountyDelivery.headers['X-Oids-Signature'] === bountySig, 'bounty signature verifies against the secret');
  assert(deliveriesTo(HOOK_SENDER_BOUNTY).length === 0, 'poster subscription does not receive its own bounty');

  // Cap: 10 active subscriptions per agent. other_bot has 1; 9 more fit, the 11th is 400.
  for (let i = 1; i <= 9; i++) {
    const extra = await call(env, 'POST', '/api/subscriptions', {
      key: KEYS.other_bot, body: { url: 'https://example.com/cap-' + i, events: ['mention'] },
    });
    assert(extra.status === 201, 'cap fill create ' + i + ' is 201, got ' + extra.status);
  }
  const overCap = await call(env, 'POST', '/api/subscriptions', {
    key: KEYS.other_bot, body: { url: 'https://example.com/cap-over', events: ['mention'] },
  });
  assert(overCap.status === 400 && overCap.json.error === 'bad_request', 'over-cap create is 400 bad_request, got ' + overCap.status + ' ' + overCap.text);

  // Revoke: another agent cannot revoke it (404). The owner can.
  const foreign = await call(env, 'DELETE', '/api/subscriptions/' + otherSubId, { key: KEYS.sender_bot });
  assert(foreign.status === 404, 'revoking another agent subscription is 404, got ' + foreign.status);
  const revoked = await call(env, 'DELETE', '/api/subscriptions/' + otherSubId, { key: KEYS.other_bot });
  assert(revoked.status === 200, 'revoke is 200, got ' + revoked.status);
  assert(revoked.json.revoked === otherSubId, 'revoke response is {revoked: id}');

  // A later DM produces no delivery to the revoked subscription.
  const dm2 = await call(env, 'POST', '/api/dms', {
    key: KEYS.sender_bot, body: { to: 'other_bot', content: 'after revoke' },
  });
  assert(dm2.status === 201, 'second DM sends');
  await new Promise((r) => setTimeout(r, 100));
  assert(deliveriesTo(HOOK_OTHER).length === 2, 'revoked subscription receives nothing more');
  assert(deliveries.length === 3, 'no new deliveries after revoke, got ' + deliveries.length);

  // List now shows revoked true, still without the secret.
  const listedAfter = await call(env, 'GET', '/api/subscriptions', { key: KEYS.other_bot });
  const afterItem = listedAfter.json.subscriptions.find((s) => s.id === otherSubId);
  assert(afterItem && afterItem.revoked === true && typeof afterItem.revoked === 'boolean', 'list shows revoked true after revoke');
  assert(!listedAfter.text.includes(otherSecret), 'list still never returns the secret');

  console.log('ok');
}

main().catch((err) => {
  if (!process.exitCode) {
    console.error(err);
    process.exitCode = 1;
  }
}).finally(() => {
  globalThis.fetch = realFetch;
  if (createdLegalStub) {
    try { unlinkSync(legalPath); } catch { /* already gone */ }
  }
});
