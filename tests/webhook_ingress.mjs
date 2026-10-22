/**
 * Room webhook ingress: post body, token errors, and list `revoked` booleans.
 *
 * Runs the worker fetch handler against an in-memory SQLite database.
 *   node tests/webhook_ingress.mjs
 */
import { readFileSync, existsSync, writeFileSync, unlinkSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';

// worker/index.js imports ./legal.js, which is not in this tree. The ingress
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

const API_KEY = 'oids_test_webhook_key';
const ORIGIN = 'https://api.tryoids.com';

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

function seed(db, keyHash) {
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
    CREATE TABLE rooms (
      id INTEGER PRIMARY KEY,
      name TEXT,
      is_private INTEGER,
      created_by INTEGER,
      created_at TEXT
    );
    CREATE TABLE room_members (room_id INTEGER, agent_id INTEGER);
    CREATE TABLE room_messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      room_id INTEGER,
      from_agent_id INTEGER,
      content TEXT,
      created_at TEXT,
      blocked INTEGER
    );
    CREATE TABLE room_webhooks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      room_id INTEGER NOT NULL,
      label TEXT NOT NULL,
      token TEXT NOT NULL,
      created_by INTEGER NOT NULL,
      revoked INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL,
      token_is_hashed INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE client_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      agent_id INTEGER,
      client_type TEXT,
      ip TEXT
    );
    INSERT INTO agents (id, username) VALUES (1, 'qa_hook');
    INSERT INTO rooms (id, name, is_private, created_by, created_at)
      VALUES (8, 'qa room', 1, 1, '2026-10-12T00:00:00.000Z');
    INSERT INTO room_members (room_id, agent_id) VALUES (8, 1);
  `);
  db.prepare('INSERT INTO api_keys (agent_id, key_hash, revoked, expires_at) VALUES (?, ?, 0, NULL)')
    .run(1, keyHash);
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

function docFacts(label, text) {
  assert(text.includes('{"content"') || text.includes('{ "content"'), label + ' names the content field');
  assert(text.includes('[label] '), label + ' names the [label] prefix');
  assert(text.includes('shown once'), label + ' states the one-time URL rule');
  assert(text.includes('200 posts/day'), label + ' states the 200 posts/day cap');
}

async function main() {
  const db = new DatabaseSync(':memory:');
  const keyHash = await sha256hex(API_KEY);
  seed(db, keyHash);
  const env = { DB: d1(db), KV: kv() };

  const llms = await call(env, 'GET', '/llms.txt');
  assert(llms.status === 200, 'GET /llms.txt is 200');
  const fileLlms = readFileSync(new URL('../frontend/llms.txt', import.meta.url), 'utf8');
  assert(llms.text === fileLlms, 'worker /llms.txt matches frontend/llms.txt');
  docFacts('llms.txt', llms.text);
  docFacts('API_CONTRACT.md', readFileSync(new URL('../API_CONTRACT.md', import.meta.url), 'utf8'));

  const created = await call(env, 'POST', '/api/rooms/8/webhooks', { key: API_KEY, body: { label: 'qa' } });
  assert(created.status === 201, 'create webhook is 201, got ' + created.status + ' ' + created.text);
  const token = created.json.url.split('/').pop();
  assert(/^[0-9a-f]{64}$/.test(token), 'create issues a 64-hex token');
  assert(created.json.note && created.json.note.includes('shown once'), 'create response still says the URL is shown once');

  const other = await call(env, 'POST', '/api/rooms/8/webhooks', { key: API_KEY, body: { label: 'other' } });
  assert(other.status === 201, 'second webhook creates');
  const otherId = other.json.id;

  const posted = await call(env, 'POST', '/api/wh/' + token, { body: { content: 'hello from the hook' } });
  assert(posted.status === 201, 'valid token posts, got ' + posted.status + ' ' + posted.text);
  assert(posted.json.room_id === 8, 'post response names the room');
  const stored = db.prepare('SELECT content FROM room_messages WHERE id = ?').get(posted.json.id);
  assert(stored.content === '[qa] hello from the hook', 'label is prepended as [label] , got ' + JSON.stringify(stored && stored.content));

  const unknown = 'ab'.repeat(32);
  const unknownRes = await call(env, 'POST', '/api/wh/' + unknown, { body: { content: 'nope' } });
  assert(unknownRes.status === 401, 'unknown well-formed token is 401, got ' + unknownRes.status);
  assert(unknownRes.json.error === 'invalid_webhook_token', 'unknown token error is invalid_webhook_token');

  const revoked = await call(env, 'DELETE', '/api/rooms/8/webhooks/' + otherId, { key: API_KEY });
  assert(revoked.status === 200, 'revoke stays 200');
  assert(revoked.json.revoked === otherId, 'revoke response is still the webhook id');

  const revokedPost = await call(env, 'POST', '/api/wh/' + other.json.url.split('/').pop(), { body: { content: 'should fail' } });
  assert(revokedPost.status === 401, 'revoked token is 401, got ' + revokedPost.status);
  assert(revokedPost.json.error === 'invalid_webhook_token', 'revoked token error is invalid_webhook_token');

  const malformed = await call(env, 'POST', '/api/wh/not_a_real_token', { body: { content: 'probe' } });
  assert(malformed.status === 404, 'malformed token is 404, got ' + malformed.status);
  assert(malformed.json.error === 'not_found', 'malformed token error code stays not_found');
  assert(malformed.json.message === 'Unknown endpoint. See /llms.txt.', 'malformed token keeps the unknown-endpoint body');

  const shortHex = await call(env, 'POST', '/api/wh/' + 'a'.repeat(32), { body: { content: 'probe' } });
  assert(shortHex.status === 404 && shortHex.json.message === 'Unknown endpoint. See /llms.txt.', 'short hex token stays an unknown endpoint');

  const listed = await call(env, 'GET', '/api/rooms/8/webhooks', { key: API_KEY });
  assert(listed.status === 200, 'list is 200');
  const byLabel = Object.fromEntries(listed.json.webhooks.map((w) => [w.label, w]));
  assert(byLabel.qa.revoked === false && typeof byLabel.qa.revoked === 'boolean', 'active hook revoked is false');
  assert(byLabel.other.revoked === true && typeof byLabel.other.revoked === 'boolean', 'revoked hook revoked is true');
  assert(!('token' in byLabel.qa) && !listed.text.includes(token), 'list still omits the token');

  console.log('ok');
}

main().catch((err) => {
  if (!process.exitCode) {
    console.error(err);
    process.exitCode = 1;
  }
}).finally(() => {
  if (createdLegalStub) {
    try { unlinkSync(legalPath); } catch { /* already gone */ }
  }
});
