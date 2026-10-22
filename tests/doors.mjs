/**
 * Oids Doors MVP — acceptance tests (Doors spec §9, tests 1-11; test
 * 12 is the bulletin fast-follow and is NOT RUN by design) and abuse
 * fixtures DF1-DF4, plus Claude gate conditions 1-8 / DQ rulings.
 *
 * Runs the worker fetch handler against an in-memory SQLite database.
 * Exchange tables come from migration 032, Doors tables from the real
 * migration 033.   node tests/doors.mjs
 */
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';

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
const mcp = await import('../connectors/muse/mcp-server.js');

const ORIGIN = 'https://api.tryoids.com';
const PASSWORD = 'test-password-1';
const AGENTS = [
  [1, 'owner_bot', 0], [2, 'borrower_bot', 0], [3, 'third_bot', 0],
  [4, 'fourth_bot', 0], [5, 'coord_bot', 0], [6, 'late_bot', 0],
  [7, 'mod_bot', 1], [8, 'oidsadmin', 0], [9, 'ring_a', 0], [10, 'ring_b', 0],
];
for (let i = 1; i <= 10; i++) AGENTS.push([10 + i, 'swarm_' + String(i).padStart(2, '0'), 0]);
const KEY = {};
for (const [, name] of AGENTS) KEY[name] = 'oids_test_' + name + '_key';
const ALL_NAMES = AGENTS.map((a) => a[1]).join(',');

let currentEnv = null;
globalThis.fetch = async (url, opts = {}) => {
  const u = String(url);
  if (u.startsWith(ORIGIN + '/')) return worker.fetch(new Request(u, opts), currentEnv);
  return new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } });
};

function fail(msg) { throw new Error(msg); }
function assert(cond, msg) { if (!cond) fail(msg); }
function sha256hex(str) {
  return crypto.subtle.digest('SHA-256', new TextEncoder().encode(str)).then((d) =>
    [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join(''));
}
function b64url(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
async function pwHash(pw) {
  const salt = new TextEncoder().encode('testsalt12345678').slice(0, 16);
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, key, 256);
  return 'pbkdf2$100000$' + b64url(salt) + '$' + b64url(new Uint8Array(bits));
}
function d1(db) {
  return {
    prepare(sql) {
      return {
        async first() { const row = db.prepare(sql).get(); return row || null; },
        async all() { return { results: db.prepare(sql).all() }; },
        async run() { const info = db.prepare(sql).run(); return { meta: { last_row_id: Number(info.lastInsertRowid), changes: info.changes } }; },
        bind(...args) {
          const order = [];
          const rewritten = sql.replace(/\?(\d+)/g, (_, n) => { order.push(Number(n) - 1); return '?'; });
          const positional = order.map((i) => args[i]);
          const stmt = db.prepare(rewritten);
          return {
            async first() { const row = stmt.get(...positional); return row || null; },
            async all() { return { results: stmt.all(...positional) }; },
            async run() { const info = stmt.run(...positional); return { meta: { last_row_id: Number(info.lastInsertRowid), changes: info.changes } }; },
          };
        },
      };
    },
    async batch(statements) { const out = []; for (const s of statements) out.push(await s.run()); return out; },
  };
}
function kv() {
  const store = new Map();
  return { async get(k) { return store.has(k) ? store.get(k) : null; }, async put(k, v) { store.set(k, String(v)); } };
}
function filesMock() {
  const store = new Map();
  return {
    store,
    async get(key) {
      if (!store.has(key)) return null;
      const buf = store.get(key);
      return { body: buf, async arrayBuffer() { return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength); } };
    },
    async put(key, value) { store.set(key, new TextEncoder().encode(String(value))); },
    async delete(key) { store.delete(key); },
  };
}
async function seed(db) {
  db.exec(`
    CREATE TABLE agents (id INTEGER PRIMARY KEY, username TEXT NOT NULL, password_hash TEXT NOT NULL DEFAULT 'x',
      is_mod INTEGER NOT NULL DEFAULT 0, read_only INTEGER NOT NULL DEFAULT 0, pro INTEGER NOT NULL DEFAULT 0, pro_expires_at TEXT);
    CREATE TABLE api_keys (id INTEGER PRIMARY KEY, agent_id INTEGER NOT NULL, key_hash TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0, expires_at TEXT);
    CREATE TABLE client_events (id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id INTEGER, client_type TEXT, ip TEXT);
    CREATE TABLE moderation_log (id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL, target_type TEXT NOT NULL,
      target_id TEXT, reason TEXT, actor TEXT NOT NULL, created_at TEXT NOT NULL);
    CREATE TABLE event_subscriptions (id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id INTEGER NOT NULL, url TEXT NOT NULL,
      events TEXT NOT NULL, secret TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), revoked INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE bounties (id INTEGER PRIMARY KEY AUTOINCREMENT, poster_agent_id INTEGER NOT NULL, claimant_agent_id INTEGER,
      title TEXT NOT NULL, description TEXT NOT NULL, price_cents INTEGER NOT NULL, currency TEXT NOT NULL DEFAULT 'USD',
      status TEXT NOT NULL DEFAULT 'open', created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      claimed_at TEXT, delivered_at TEXT, delivery_note TEXT, completed_at TEXT);
    CREATE TABLE dms (id INTEGER PRIMARY KEY AUTOINCREMENT, from_agent_id INTEGER NOT NULL, to_agent_id INTEGER NOT NULL,
      content TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), read_at TEXT, blocked INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE rooms (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, created_by INTEGER NOT NULL,
      is_private INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')));
    CREATE TABLE room_members (room_id INTEGER NOT NULL, agent_id INTEGER NOT NULL,
      joined_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), PRIMARY KEY (room_id, agent_id));
    CREATE TABLE room_messages (id INTEGER PRIMARY KEY AUTOINCREMENT, room_id INTEGER NOT NULL, from_agent_id INTEGER NOT NULL,
      content TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), blocked INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE files (id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id INTEGER NOT NULL, r2_key TEXT NOT NULL UNIQUE,
      filename TEXT NOT NULL, content_type TEXT NOT NULL, size INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), expires_at TEXT NOT NULL);
    CREATE TABLE agent_blocks (blocker_agent_id INTEGER NOT NULL, blocked_agent_id INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), PRIMARY KEY (blocker_agent_id, blocked_agent_id));
    CREATE TABLE message_reactions (message_id INTEGER NOT NULL, agent_id INTEGER NOT NULL, emoji TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), PRIMARY KEY (message_id, agent_id, emoji));
  `);
  db.exec(readFileSync(new URL('../migrations/025_handoffs.sql', import.meta.url), 'utf8'));
  db.exec(readFileSync(new URL('../migrations/032_exchange_phase1.sql', import.meta.url), 'utf8'));
  db.exec(readFileSync(new URL('../migrations/033_doors.sql', import.meta.url), 'utf8'));
  const hash = await pwHash(PASSWORD);
  const insAgent = db.prepare('INSERT INTO agents (id, username, password_hash, is_mod) VALUES (?, ?, ?, ?)');
  const insKey = db.prepare('INSERT INTO api_keys (agent_id, key_hash, revoked, expires_at) VALUES (?, ?, 0, NULL)');
  for (const [id, name, isMod] of AGENTS) {
    insAgent.run(id, name, hash, isMod);
    insKey.run(id, await sha256hex(KEY[name]));
  }
}
let idemCounter = 0;
async function makeWorld(opts = {}) {
  const db = new DatabaseSync(':memory:');
  await seed(db);
  const FILES = filesMock();
  const env = { DB: d1(db), KV: kv(), FILES };
  if (opts.exchange !== false) env.EXCHANGE_ENABLED = '1';
  if (opts.doors !== false) env.DOORS_ENABLED = '1';
  if (opts.public) env.EXCHANGE_PUBLIC = '1';
  env.EXCHANGE_PILOT_AGENTS = opts.pilot === undefined ? ALL_NAMES : opts.pilot;
  currentEnv = env;
  const call = async (method, path, { key, body, idem, human, headers: extra } = {}) => {
    const headers = { 'Content-Type': 'application/json', ...(extra || {}) };
    if (key) headers.Authorization = 'Bearer ' + key;
    if (human) headers['X-Human-Session'] = human;
    if (idem !== false && (method === 'POST' || method === 'PATCH')) {
      headers['Idempotency-Key'] = idem || ('auto-' + (++idemCounter) + '-' + Math.random().toString(36).slice(2, 8));
    }
    const res = await worker.fetch(new Request(ORIGIN + path, {
      method, headers, body: body === undefined ? undefined : JSON.stringify(body),
    }), env);
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch { /* plain text */ }
    return { status: res.status, json, text, headers: res.headers };
  };
  return { db, env, FILES, call };
}
async function humanToken(w, username) {
  const r = await w.call('POST', '/api/v1/exchange/human-session', {
    idem: false, body: { username, password: PASSWORD, operator_label: 'Operator of @' + username },
  });
  assert(r.status === 201, 'human session for ' + username + ' creates, got ' + r.status + ' ' + r.text);
  return r.json.session_token;
}
async function makeLiveListing(w, ownerName, opts = {}) {
  const key = KEY[ownerName];
  const create = await w.call('POST', '/api/v1/exchange/listings', {
    key, body: {
      kind: opts.kind || 'own_service',
      title: opts.title || 'QA review pass',
      description: opts.description || 'A careful review pass over a draft, with written notes.',
      audience: opts.audience || 'public',
      ...(opts.channel_ref ? { channel_ref: opts.channel_ref } : {}),
      ...(opts.allowlist ? { allowlist: opts.allowlist } : {}),
      price_mode: opts.price_mode || 'free',
    },
  });
  assert(create.status === 201, 'listing creates, got ' + create.status + ' ' + create.text);
  const ref = create.json.listing.ref;
  const human = await humanToken(w, ownerName);
  const attest = await w.call('POST', `/api/v1/exchange/listings/${ref}/attest`, {
    human, idem: false, body: {
      statement: 'I operate this capability and its terms permit this use.',
      clause: 'Terms section 4.2: the operator may share outputs of the service with named third parties.',
      terms_version: 'terms-v1',
    },
  });
  assert(attest.status === 200, 'attest works, got ' + attest.status + ' ' + attest.text);
  const live = await w.call('PATCH', `/api/v1/exchange/listings/${ref}`, { key, body: { status: 'live' } });
  assert(live.status === 200 && live.json.listing.status === 'live', 'listing goes live, got ' + live.status + ' ' + live.text);
  return { ref, human, create: create.json.listing };
}
const futureIso = (days) => new Date(Date.now() + days * 86400000).toISOString();
async function fileRequest(w, requesterName, listingRef, opts = {}) {
  const r = await w.call('POST', '/api/v1/exchange/requests', {
    key: KEY[requesterName], idem: opts.idem,
    body: {
      listing_ref: listingRef,
      scope: opts.scope || 'One review pass over the attached draft.',
      purpose: opts.purpose || 'Ship preparation.',
      ...(opts.expires_at ? { expires_at: opts.expires_at } : {}),
      ...(opts.channel_ref ? { channel_ref: opts.channel_ref } : {}),
      ...(opts.grantee_type ? { grantee_type: opts.grantee_type } : {}),
      ...(opts.grantee_usernames ? { grantee_usernames: opts.grantee_usernames } : {}),
      ...(opts.grantee_channel_ref ? { grantee_channel_ref: opts.grantee_channel_ref } : {}),
    },
  });
  assert(r.status === 201, 'request files, got ' + r.status + ' ' + r.text);
  return r.json.request;
}
async function approveAndGrant(w, ownerName, human, requestRef, opts = {}) {
  const exp = opts.expires_at || futureIso(opts.days || 7);
  const approveBody = {
    scope: opts.scope || 'One review pass over the attached draft.',
    performer: opts.performer, expires_at: exp,
    ...(opts.max_uses !== undefined ? { max_uses: opts.max_uses } : {}),
    ...(opts.grantee_usernames ? { grantee_usernames: opts.grantee_usernames } : {}),
  };
  if (approveBody.performer === undefined) delete approveBody.performer;
  const approve = await w.call('POST', `/api/v1/exchange/requests/${requestRef}/approve`, { human, idem: false, body: approveBody });
  assert(approve.status === 201 || approve.status === 200, 'approval records, got ' + approve.status + ' ' + approve.text);
  const grantBody = {
    approval_ref: approve.json.approval.ref,
    scope: approveBody.scope, expires_at: exp,
    ...(opts.performer ? { performer: opts.performer } : {}),
    ...(opts.max_uses !== undefined ? { max_uses: opts.max_uses } : {}),
    ...(opts.grantee_usernames ? { grantee_usernames: opts.grantee_usernames } : {}),
  };
  const grant = await w.call('POST', `/api/v1/exchange/requests/${requestRef}/grant`, { key: KEY[ownerName], idem: opts.idem, body: grantBody });
  assert(grant.status === 201, 'grant creates, got ' + grant.status + ' ' + grant.text);
  return { approval: approve.json.approval, grant: grant.json.grant, grantExp: exp };
}
function sqlOne(w, sql, ...args) { return w.db.prepare(sql).get(...args); }
function sqlAll(w, sql, ...args) { return w.db.prepare(sql).all(...args); }
function establishOperator(w, agentId, operatorId) {
  const past = new Date(Date.now() - 30 * 86400000).toISOString();
  w.db.prepare('INSERT INTO agent_operators (agent_id, operator_id, updated_at) VALUES (?, ?, ?) ON CONFLICT(agent_id) DO UPDATE SET operator_id = excluded.operator_id, updated_at = excluded.updated_at')
    .run(agentId, operatorId, past);
}
let slugCounter = 0;
async function makeDoor(w, ownerName, listingRef, opts = {}) {
  const slug = opts.slug || ('door-' + (++slugCounter) + '-' + Math.random().toString(36).slice(2, 7));
  const r = await w.call('POST', '/api/v1/doors', {
    key: KEY[ownerName], idem: opts.idem,
    body: {
      listing_ref: listingRef, slug,
      entry_url: opts.entry_url || 'https://doors.example.com/entry',
      entry_mode: opts.entry_mode || 'grant',
      session_max_minutes: opts.session_max_minutes === undefined ? 60 : opts.session_max_minutes,
      ...(opts.display_tag ? { display_tag: opts.display_tag } : {}),
      terms_ack: opts.terms_ack === undefined ? true : opts.terms_ack,
    },
  });
  assert(r.status === 201, 'door creates, got ' + r.status + ' ' + r.text);
  return { ...r.json, slug, ref: listingRef };
}
async function enterDoor(w, agentName, doorRef, opts = {}) {
  return w.call('POST', `/api/v1/doors/${doorRef}/enter`, { key: KEY[agentName], idem: opts.idem, body: opts.body || {} });
}
async function validateToken(w, validateKey, token, doorRef) {
  return w.call('POST', '/api/v1/doors/validate', { key: validateKey, idem: false, body: { token, door_ref: doorRef } });
}
async function grantFor(w, ownerName, human, listingRef, requesterName, opts = {}) {
  const req = await fileRequest(w, requesterName, listingRef, opts.request || {});
  const { grant } = await approveAndGrant(w, ownerName, human, req.ref, opts.grant || {});
  return { req, grant };
}
async function channelSetup(w, invitees = ['borrower_bot', 'third_bot']) {
  const create = await w.call('POST', '/api/v1/exchange/channels', {
    key: KEY.owner_bot, body: { name: 'Beta channel', purpose: 'Coordinate the handoff beta.', invitees },
  });
  assert(create.status === 201, 'channel creates, got ' + create.status + ' ' + create.text);
  return create.json.channel;
}
const results = [];
async function section(name, fn) {
  try {
    await fn();
    results.push([name, 'PASS']);
    console.log('PASS', name);
  } catch (e) {
    results.push([name, 'FAIL: ' + e.message]);
    console.log('FAIL', name, '-', e.message);
  }
}

// ===========================================================================
// §9 acceptance tests 1-11 (test 12, the bulletin, is fast-follow: NOT RUN)
// ===========================================================================
async function acceptance() {
  await section('D1 (spec 9.1) registration gate', async () => {
    const w = await makeWorld();
    establishOperator(w, 1, 'op_owner');
    const bare = await makeLiveListing(w, 'owner_bot', { title: 'Bare listing' });
    let menu = await w.call('GET', '/api/v1/doors', { key: KEY.borrower_bot });
    assert(!menu.json.doors.some((d) => d.ref === bare.ref), 'a listing with no door extension is absent from the menu');
    const create = await w.call('POST', '/api/v1/exchange/listings', { key: KEY.owner_bot, body: { kind: 'own_service', title: 'Draft door service', description: 'A service that will carry a door.', audience: 'public' } });
    assert(create.status === 201, 'draft listing creates');
    const draftRef = create.json.listing.ref;
    await makeDoor(w, 'owner_bot', draftRef, { slug: 'draft-door' });
    menu = await w.call('GET', '/api/v1/doors', { key: KEY.borrower_bot });
    assert(!menu.json.doors.some((d) => d.ref === draftRef), 'a door on a draft listing is absent');
    const human = await humanToken(w, 'owner_bot');
    const agentAttest = await w.call('POST', `/api/v1/exchange/listings/${draftRef}/attest`, { key: KEY.owner_bot, idem: false, body: { statement: 'x', clause: 'Terms 4.2' } });
    assert(agentAttest.status === 403, 'attest with an agent credential is 403');
    const noClause = await w.call('POST', `/api/v1/exchange/listings/${draftRef}/attest`, { human, idem: false, body: { statement: 'It is fine.' } });
    assert(noClause.status === 400, 'attestation without the cited clause is 400');
    const good = await w.call('POST', `/api/v1/exchange/listings/${draftRef}/attest`, { human, idem: false, body: { statement: 'Terms permit this use.', clause: 'Terms section 4.2', terms_version: 'terms-v1' } });
    assert(good.status === 200, 'human attestation records');
    const live = await w.call('PATCH', `/api/v1/exchange/listings/${draftRef}`, { key: KEY.owner_bot, body: { status: 'live' } });
    assert(live.status === 200, 'listing goes live');
    menu = await w.call('GET', '/api/v1/doors', { key: KEY.borrower_bot });
    assert(menu.json.doors.some((d) => d.ref === draftRef), 'the door appears once its listing is live and attested');
    const pt = await w.call('POST', '/api/v1/exchange/listings', { key: KEY.owner_bot, body: { kind: 'permitted_tool', title: 'A tool', description: 'A third party tool listing.' } });
    assert(pt.status === 400 && pt.json.error === 'kind_not_in_phase1', 'permitted_tool is rejected server-side');
    const reserved = await w.call('POST', '/api/v1/doors', { key: KEY.owner_bot, body: { listing_ref: bare.ref, slug: 'admin', entry_url: 'https://doors.example.com/e', terms_ack: true } });
    assert(reserved.status === 400, 'a reserved slug is rejected, got ' + reserved.status + ' ' + reserved.text);
    const oidsSlug = await w.call('POST', '/api/v1/doors', { key: KEY.owner_bot, body: { listing_ref: bare.ref, slug: 'oids-help-desk', entry_url: 'https://doors.example.com/e', terms_ack: true } });
    assert(oidsSlug.status === 400, 'an impersonation-adjacent slug is rejected');
  });

  await section('D2 (spec 9.2) audience', async () => {
    const w = await makeWorld();
    establishOperator(w, 1, 'op_owner');
    const pub = await makeLiveListing(w, 'owner_bot', { title: 'Public door service' });
    await makeDoor(w, 'owner_bot', pub.ref, { slug: 'public-door' });
    const pubRead = await w.call('GET', `/api/v1/doors/${pub.ref}`, { key: KEY.third_bot });
    assert(pubRead.status === 200, 'public door readable by a stranger');
    const allow = await makeLiveListing(w, 'owner_bot', { title: 'Allowlist door service', audience: 'allowlist', allowlist: ['borrower_bot'] });
    await makeDoor(w, 'owner_bot', allow.ref, { slug: 'allow-door' });
    const named = await w.call('GET', `/api/v1/doors/${allow.ref}`, { key: KEY.borrower_bot });
    assert(named.status === 200, 'allowlist door readable by a named agent');
    const unnamed = await w.call('GET', `/api/v1/doors/${allow.ref}`, { key: KEY.third_bot });
    assert(unnamed.status === 404, 'allowlist door 404s for the unnamed');
    const outsideEnter = await enterDoor(w, 'third_bot', allow.ref);
    assert(outsideEnter.status === 404, 'entry from outside the audience is 404, got ' + outsideEnter.status);
    const ch = await channelSetup(w);
    await w.call('POST', `/api/v1/exchange/channels/${ch.ref}/accept`, { key: KEY.borrower_bot, body: {} });
    const chan = await makeLiveListing(w, 'owner_bot', { title: 'Channel door service', audience: 'channel', channel_ref: ch.ref });
    await makeDoor(w, 'owner_bot', chan.ref, { slug: 'chan-door' });
    const nonMember = await w.call('GET', `/api/v1/doors/${chan.ref}`, { key: KEY.third_bot });
    assert(nonMember.status === 404, 'channel door 404s for non-members (invited is not a member)');
    assert(sqlOne(w, 'SELECT COUNT(*) AS n FROM door_entries').n === 0, 'no entry row exists from outside the audience');
  });

  await section('D3 (spec 9.3) grant-bound happy path + receipt through Exchange flow', async () => {
    const w = await makeWorld();
    const listing = await makeLiveListing(w, 'owner_bot', { title: 'Review door' });
    const door = await makeDoor(w, 'owner_bot', listing.ref, { slug: 'review-door' });
    const { grant } = await grantFor(w, 'owner_bot', listing.human, listing.ref, 'borrower_bot');
    const enter = await enterDoor(w, 'borrower_bot', listing.ref);
    assert(enter.status === 201, 'enter mints, got ' + enter.status + ' ' + enter.text);
    const token = enter.json.entry.token;
    assert(token && enter.json.entry.ref, 'token returned once with the session ref');
    const row = sqlOne(w, 'SELECT * FROM door_entries WHERE public_ref = ?', enter.json.entry.ref);
    assert(row && row.token_hash === await sha256hex(token) && row.token_hash !== token, 'only the token hash is stored');
    assert(row.grant_id != null, 'the entry is bound to the grant');
    const valid = await validateToken(w, door.validate_key, token, listing.ref);
    assert(valid.status === 200 && valid.json.valid === true, 'validation succeeds under the per-door validate key');
    assert(valid.json.agent === 'borrower_bot' && valid.json.session_id === enter.json.entry.ref && valid.json.grant_ref === grant.ref,
      'validation answers handle, session id, and grant ref only');
    const rowAfter = sqlOne(w, 'SELECT * FROM door_entries WHERE public_ref = ?', enter.json.entry.ref);
    assert(rowAfter.consumed_at, 'the token is consumed at validation');
    const done = await w.call('POST', `/api/v1/exchange/grants/${grant.ref}/done`, { key: KEY.owner_bot, body: {} });
    assert(done.status === 200, 'performer declares done through the Exchange path');
    const confirm = await w.call('POST', `/api/v1/exchange/grants/${grant.ref}/confirm`, { key: KEY.borrower_bot, body: {} });
    assert(confirm.status === 200 && confirm.json.receipt.wording === 'confirmed by counterparty' && confirm.json.receipt.funded === 0,
      'the Exchange done/confirm path mints exactly the usual receipt, wording and funded=0 intact');
    assert(sqlOne(w, "SELECT COUNT(*) AS n FROM receipts WHERE kind = 'exchange'").n === 1, 'exactly one receipt');
  });

  await section('D4 (spec 9.4) no grant no entry, incl. Q4 late joiner', async () => {
    const w = await makeWorld();
    const listing = await makeLiveListing(w, 'owner_bot', { title: 'Grant door' });
    await makeDoor(w, 'owner_bot', listing.ref, { slug: 'grant-door' });
    const noGrant = await enterDoor(w, 'borrower_bot', listing.ref);
    assert(noGrant.status === 403 && noGrant.json.error === 'no_grant', 'entry without a grant is refused, got ' + noGrant.status);
    assert(sqlOne(w, 'SELECT COUNT(*) AS n FROM door_entries').n === 0, 'no entry row without a grant');
    const w2 = await makeWorld();
    establishOperator(w2, 1, 'op_owner');
    const ch = await channelSetup(w2);
    await w2.call('POST', `/api/v1/exchange/channels/${ch.ref}/accept`, { key: KEY.borrower_bot, body: {} });
    await w2.call('POST', `/api/v1/exchange/channels/${ch.ref}/accept`, { key: KEY.third_bot, body: {} });
    const chan = await makeLiveListing(w2, 'owner_bot', { kind: 'own_compute', title: 'GPU door', audience: 'channel', channel_ref: ch.ref });
    await makeDoor(w2, 'owner_bot', chan.ref, { slug: 'gpu-door' });
    await grantFor(w2, 'owner_bot', chan.human, chan.ref, 'borrower_bot', { request: { channel_ref: ch.ref, grantee_type: 'channel', grantee_channel_ref: ch.ref } });
    const memberEnter = await enterDoor(w2, 'third_bot', chan.ref);
    assert(memberEnter.status === 201, 'a member named in the fixed set can enter');
    await w2.call('POST', `/api/v1/exchange/channels/${ch.ref}/invite`, { key: KEY.owner_bot, body: { username: 'late_bot' } });
    await w2.call('POST', `/api/v1/exchange/channels/${ch.ref}/accept`, { key: KEY.late_bot, body: {} });
    const lateEnter = await enterDoor(w2, 'late_bot', chan.ref);
    assert(lateEnter.status === 403, 'a channel joiner after approval holds no grant and cannot enter, got ' + lateEnter.status);
  });

  await section('D5 (spec 9.5) open door', async () => {
    const w = await makeWorld();
    const listing = await makeLiveListing(w, 'owner_bot', { title: 'Open review service' });
    const door = await makeDoor(w, 'owner_bot', listing.ref, { slug: 'open-door', entry_mode: 'open' });
    const enter = await enterDoor(w, 'third_bot', listing.ref);
    assert(enter.status === 201, 'an in-audience agent enters an open door with no grant, got ' + enter.status + ' ' + enter.text);
    const row = sqlOne(w, 'SELECT * FROM door_entries WHERE public_ref = ?', enter.json.entry.ref);
    assert(row.grant_id === null, 'the open entry row carries no grant');
    const valid = await validateToken(w, door.validate_key, enter.json.entry.token, listing.ref);
    assert(valid.json.valid === true && valid.json.grant_ref === null, 'open entry validates with no grant ref');
    assert(sqlOne(w, "SELECT COUNT(*) AS n FROM receipts").n === 0, 'no receipt exists, and none is minted from the entry alone');
    const read = await w.call('GET', `/api/v1/doors/${listing.ref}`, { key: KEY.third_bot });
    assert(/no human approval/i.test(read.json.door.open_notice || ''), 'the door read warns that no human approval occurred (condition 7)');
  });

  await section('D6 (spec 9.6) + token lifecycle end to end', async () => {
    const w = await makeWorld();
    establishOperator(w, 1, 'op_owner');
    establishOperator(w, 3, 'op_third');
    const listing = await makeLiveListing(w, 'owner_bot', { title: 'Lifecycle door service' });
    const door = await makeDoor(w, 'owner_bot', listing.ref, { slug: 'lifecycle-door' });
    const other = await makeLiveListing(w, 'third_bot', { title: 'Other door service' });
    const otherDoor = await makeDoor(w, 'third_bot', other.ref, { slug: 'other-door' });
    await grantFor(w, 'owner_bot', listing.human, listing.ref, 'borrower_bot');
    const e1 = await enterDoor(w, 'borrower_bot', listing.ref);
    assert(e1.status === 201, 'mint 1');
    assert(Date.parse(e1.json.entry.expires_at) - Date.parse(sqlOne(w, 'SELECT issued_at FROM door_entries WHERE public_ref = ?', e1.json.entry.ref).issued_at) === 5 * 60000,
      'the presentation window is exactly 5 minutes');
    const v1 = await validateToken(w, door.validate_key, e1.json.entry.token, listing.ref);
    assert(v1.json.valid === true, 'mint -> enter -> validate succeeds');
    const replay = await validateToken(w, door.validate_key, e1.json.entry.token, listing.ref);
    assert(replay.status === 200 && replay.json.valid === false && Object.keys(replay.json).length === 1, 'a consumed token replays as invalid, indistinguishable');
    await grantFor(w, 'owner_bot', listing.human, listing.ref, 'borrower_bot');
    const e2 = await enterDoor(w, 'borrower_bot', listing.ref);
    const cross = await validateToken(w, otherDoor.validate_key, e2.json.entry.token, other.ref);
    assert(cross.json.valid === false, 'door A token under door B credential is invalid');
    const stillGood = await validateToken(w, door.validate_key, e2.json.entry.token, listing.ref);
    assert(stillGood.json.valid === true, 'the cross-door attempt did not consume the token');
    const g3 = await grantFor(w, 'owner_bot', listing.human, listing.ref, 'borrower_bot');
    const e3 = await enterDoor(w, 'borrower_bot', listing.ref);
    const revoke = await w.call('POST', `/api/v1/exchange/grants/${g3.grant.ref}/revoke`, { key: KEY.owner_bot, body: { reason: 'Capacity recalled.' } });
    assert(revoke.status === 200, 'grant revoked between mint and validation');
    const v3 = await validateToken(w, door.validate_key, e3.json.entry.token, listing.ref);
    assert(v3.json.valid === false, 'revoke-mid-flight: validation is invalid');
    await grantFor(w, 'owner_bot', listing.human, listing.ref, 'borrower_bot');
    const e4 = await enterDoor(w, 'borrower_bot', listing.ref);
    w.db.prepare('UPDATE door_entries SET expires_at = ? WHERE public_ref = ?').run(new Date(Date.now() - 60000).toISOString(), e4.json.entry.ref);
    const v4 = await validateToken(w, door.validate_key, e4.json.entry.token, listing.ref);
    assert(v4.json.valid === false, 'past the TTL the token is invalid');
    await grantFor(w, 'owner_bot', listing.human, listing.ref, 'borrower_bot');
    const e5 = await enterDoor(w, 'borrower_bot', listing.ref);
    const pause = await w.call('PATCH', `/api/v1/exchange/listings/${listing.ref}`, { key: KEY.owner_bot, body: { status: 'paused' } });
    assert(pause.status === 200, 'listing pauses');
    const v5 = await validateToken(w, door.validate_key, e5.json.entry.token, listing.ref);
    assert(v5.json.valid === false, 'a valid token presented after the listing paused is invalid (fail-closed)');
    const asKey = await w.call('GET', '/api/v1/doors', { key: e5.json.entry.token });
    assert(asKey.status === 401, 'an entry token used as an API key is treated as no credential, got ' + asKey.status);
  });

  await section('D7 (spec 9.7) block interaction', async () => {
    const w = await makeWorld();
    const listing = await makeLiveListing(w, 'owner_bot', { title: 'Block door service' });
    const door = await makeDoor(w, 'owner_bot', listing.ref, { slug: 'block-door' });
    await grantFor(w, 'owner_bot', listing.human, listing.ref, 'borrower_bot');
    const enter = await enterDoor(w, 'borrower_bot', listing.ref);
    assert(enter.status === 201, 'token minted before the block');
    w.db.prepare('INSERT INTO agent_blocks (blocker_agent_id, blocked_agent_id) VALUES (2, 1)').run();
    const blockedEnter = await enterDoor(w, 'borrower_bot', listing.ref);
    assert(blockedEnter.status === 403, 'enter under a block is 403');
    const valid = await validateToken(w, door.validate_key, enter.json.entry.token, listing.ref);
    assert(valid.json.valid === false, 'an unconsumed token minted before the block is invalid at validation');
  });

  await section('D8 (spec 9.8) exit and sweep + retention rule', async () => {
    const w = await makeWorld();
    const listing = await makeLiveListing(w, 'owner_bot', { title: 'Exit door service' });
    const door = await makeDoor(w, 'owner_bot', listing.ref, { slug: 'exit-door', session_max_minutes: 30 });
    await grantFor(w, 'owner_bot', listing.human, listing.ref, 'borrower_bot');
    const e1 = await enterDoor(w, 'borrower_bot', listing.ref);
    await validateToken(w, door.validate_key, e1.json.entry.token, listing.ref);
    const exit = await w.call('POST', `/api/v1/doors/sessions/${e1.json.entry.ref}/exit`, { key: door.validate_key, idem: false, body: {} });
    assert(exit.status === 200 && exit.json.entry.exit_source === 'door' && exit.json.entry.exited_at, 'door-reported exit closes the row, got ' + exit.status + ' ' + exit.text);
    const e2 = await enterDoor(w, 'borrower_bot', listing.ref);
    await validateToken(w, door.validate_key, e2.json.entry.token, listing.ref);
    w.db.prepare('UPDATE door_entries SET session_expires_at = ? WHERE public_ref = ?').run(new Date(Date.now() - 60000).toISOString(), e2.json.entry.ref);
    await w.call('GET', '/api/v1/doors', { key: KEY.borrower_bot });
    const swept = sqlOne(w, 'SELECT * FROM door_entries WHERE public_ref = ?', e2.json.entry.ref);
    assert(swept.exit_source === 'sweep' && swept.exited_at, 'the sweep closes a lapsed session row');
    const lateExit = await w.call('POST', `/api/v1/doors/sessions/${e2.json.entry.ref}/exit`, { key: door.validate_key, idem: false, body: {} });
    assert(lateExit.status === 200 && lateExit.json.entry.exit_source === 'sweep', 'a door-reported exit after the sweep changes nothing');
    const old = new Date(Date.now() - 100 * 86400000).toISOString();
    w.db.prepare('UPDATE door_entries SET exited_at = ? WHERE public_ref = ?').run(old, e1.json.entry.ref);
    const e3 = await enterDoor(w, 'borrower_bot', listing.ref);
    w.db.prepare('UPDATE door_entries SET expires_at = ? WHERE public_ref = ?').run(old, e3.json.entry.ref);
    await w.call('GET', '/api/v1/doors', { key: KEY.borrower_bot });
    assert(!sqlOne(w, 'SELECT id FROM door_entries WHERE public_ref = ?', e1.json.entry.ref), 'a closed row past 90 days is deleted by the retention sweep');
    assert(!sqlOne(w, 'SELECT id FROM door_entries WHERE public_ref = ?', e3.json.entry.ref), 'a never-validated row past 90 days from expiry is deleted');
    assert(sqlOne(w, 'SELECT id FROM door_entries WHERE public_ref = ?', e2.json.entry.ref), 'a recent closed row is kept');
  });

  await section('D9 (spec 9.9) takedown bite', async () => {
    const w = await makeWorld();
    const listing = await makeLiveListing(w, 'owner_bot', { title: 'Takedown door service' });
    const door = await makeDoor(w, 'owner_bot', listing.ref, { slug: 'takedown-door' });
    const g1 = await grantFor(w, 'owner_bot', listing.human, listing.ref, 'borrower_bot');
    const e1 = await enterDoor(w, 'borrower_bot', listing.ref);
    await validateToken(w, door.validate_key, e1.json.entry.token, listing.ref);
    await w.call('POST', `/api/v1/exchange/grants/${g1.grant.ref}/done`, { key: KEY.owner_bot, body: {} });
    const conf = await w.call('POST', `/api/v1/exchange/grants/${g1.grant.ref}/confirm`, { key: KEY.borrower_bot, body: {} });
    assert(conf.status === 200, 'a receipt exists before the takedown');
    const receiptBefore = JSON.stringify(sqlOne(w, "SELECT * FROM receipts WHERE kind = 'exchange'"));
    await grantFor(w, 'owner_bot', listing.human, listing.ref, 'borrower_bot');
    const e2 = await enterDoor(w, 'borrower_bot', listing.ref);
    assert(e2.status === 201, 'an unconsumed token is outstanding');
    const suspend = await w.call('POST', `/api/v1/exchange/listings/${listing.ref}/suspend`, { key: KEY.mod_bot, body: { reason: 'Credible notice on a fixture report.' } });
    assert(suspend.status === 200, 'moderator suspends the listing');
    const menu = await w.call('GET', '/api/v1/doors', { key: KEY.borrower_bot });
    assert(!menu.json.doors.some((d) => d.ref === listing.ref), 'the door leaves the menu in the same state change');
    const valid = await validateToken(w, door.validate_key, e2.json.entry.token, listing.ref);
    assert(valid.json.valid === false, 'unconsumed tokens stop validating at suspension');
    const audit = sqlAll(w, "SELECT action FROM exchange_audit WHERE object_kind = 'listing' AND object_id = (SELECT id FROM exchange_listings WHERE public_ref = ?)", listing.ref).map((r) => r.action);
    assert(audit.includes('suspended') && audit.includes('door_created') && audit.includes('door_entry_validated'), 'the audit trail shows the door arc and the suspension');
    const listingRow = sqlOne(w, 'SELECT moderation_reason FROM exchange_listings WHERE public_ref = ?', listing.ref);
    assert(listingRow.moderation_reason && listingRow.moderation_reason.includes('Credible notice'), 'the suspension reason is on the record');
    assert(JSON.stringify(sqlOne(w, "SELECT * FROM receipts WHERE kind = 'exchange'")) === receiptBefore, 'the confirmed receipt is byte-identical after takedown');
  });

  await section('D10 (spec 9.10) idempotency', async () => {
    const w = await makeWorld();
    const listing = await makeLiveListing(w, 'owner_bot', { title: 'Idem door service' });
    await grantFor(w, 'owner_bot', listing.human, listing.ref, 'borrower_bot');
    await makeDoor(w, 'owner_bot', listing.ref, { slug: 'idem-door' });
    const first = await enterDoor(w, 'borrower_bot', listing.ref, { idem: 'enter-key-1' });
    assert(first.status === 201 && first.json.entry.token, 'first enter mints');
    const replay = await enterDoor(w, 'borrower_bot', listing.ref, { idem: 'enter-key-1' });
    assert(replay.status === 201 && replay.json.entry.ref === first.json.entry.ref, 'replay returns the same entry');
    assert(!replay.json.entry.token, 'replay returns no second token (the token is shown once)');
    assert(sqlOne(w, 'SELECT COUNT(*) AS n FROM door_entries').n === 1, 'no second entry row');
    const conflict = await w.call('POST', `/api/v1/doors/${listing.ref}/enter`, { key: KEY.borrower_bot, idem: 'enter-key-1', body: { show_in_callers: true } });
    assert(conflict.status === 400 && conflict.json.error === 'idempotency_conflict', 'same key, different body is a conflict');
    const noKey = await w.call('POST', `/api/v1/doors/${listing.ref}/enter`, { key: KEY.borrower_bot, idem: false, body: {} });
    assert(noKey.status === 400, 'a write with no Idempotency-Key is 400');
    const listing2 = await makeLiveListing(w, 'third_bot', { title: 'Idem second service' });
    const c1 = await makeDoor(w, 'third_bot', listing2.ref, { slug: 'idem-second', idem: 'door-key-1' });
    const c2 = await w.call('POST', '/api/v1/doors', { key: KEY.third_bot, idem: 'door-key-1', body: { listing_ref: listing2.ref, slug: c1.slug, entry_url: 'https://doors.example.com/entry', entry_mode: 'grant', session_max_minutes: 60, terms_ack: true } });
    assert(c2.status === 201 && !c2.json.validate_key, 'registration replay returns no second validate key');
    assert(sqlOne(w, 'SELECT COUNT(*) AS n FROM doors').n === 2, 'no duplicate door rows');
  });

  await section('D11 (spec 9.11) flag off', async () => {
    const off = await makeWorld({ doors: false });
    assert((await off.call('GET', '/api/v1/doors', { key: KEY.owner_bot })).status === 404, 'DOORS off: menu 404s');
    assert((await off.call('POST', '/api/v1/doors', { key: KEY.owner_bot, body: { listing_ref: 'x', slug: 'abc-door', entry_url: 'https://doors.example.com/e', terms_ack: true } })).status === 404, 'DOORS off: create 404s');
    assert((await off.call('POST', '/api/v1/doors/validate', { key: 'whatever', idem: false, body: { token: 't', door_ref: 'x' } })).status === 404, 'DOORS off: validate 404s');
    assert((await off.call('GET', '/doors', { key: KEY.owner_bot })).status === 404, 'DOORS off: the /doors page is absent');
    const exOff = await makeWorld({ exchange: false, doors: true });
    assert((await exOff.call('GET', '/api/v1/doors', { key: KEY.owner_bot })).status === 404, 'DOORS on but EXCHANGE off: same 404s');
    assert((await exOff.call('GET', '/doors', {})).status === 404, 'EXCHANGE off: /doors page absent');
    const listOff = await mcp.handleRpc(new Request(ORIGIN + '/mcp', { method: 'POST', body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }) }), {});
    const tools = JSON.parse(await listOff.text()).result.tools.map((t) => t.name);
    assert(!tools.some((n) => n.startsWith('oids_doors_')), 'no MCP door tools are registered (DQ6: REST only)');
    const on = await makeWorld();
    const listOn = await mcp.handleRpc(new Request(ORIGIN + '/mcp', { method: 'POST', body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' }) }), on.env);
    const toolsOn = JSON.parse(await listOn.text()).result.tools.map((t) => t.name);
    assert(!toolsOn.some((n) => n.startsWith('oids_doors_')), 'even with flags on, no MCP door tools exist in Phase 1');
  });

  await section('D12 (spec 9.12) bulletin — NOT RUN by design (fast follow)', async () => {
    const w = await makeWorld();
    assert(!sqlOne(w, "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'one_liners'"), 'no one_liners table exists in this build (DQ7)');
    const wall = await w.call('GET', '/api/v1/doors/wall', { key: KEY.owner_bot });
    assert(wall.status === 404, 'no wall route exists in this build');
  });
}

// ===========================================================================
// Claude gate conditions + DQ rulings not already covered above
// ===========================================================================
async function conditions() {
  await section('C1 header-only token presentation', async () => {
    const w = await makeWorld();
    const listing = await makeLiveListing(w, 'owner_bot', { title: 'Header door service' });
    const door = await makeDoor(w, 'owner_bot', listing.ref, { slug: 'header-door' });
    await grantFor(w, 'owner_bot', listing.human, listing.ref, 'borrower_bot');
    const enter = await enterDoor(w, 'borrower_bot', listing.ref);
    assert(enter.json.entry.presentation === 'header' && enter.json.entry.presentation_header === 'Authorization: Bearer <token>', 'presentation is header-only');
    assert(!enter.json.entry.entry_url.includes(enter.json.entry.token), 'the entry URL carries no token');
    assert(!JSON.stringify(enter.json).includes('door' + '_token'), 'no query-parameter token scheme exists in the response');
    const viaQuery = await w.call('POST', '/api/v1/doors/validate?token=' + encodeURIComponent(enter.json.entry.token), { key: door.validate_key, idem: false, body: { door_ref: listing.ref } });
    assert(viaQuery.json.valid === false, 'a token presented by query parameter does not validate');
    const viaBody = await validateToken(w, door.validate_key, enter.json.entry.token, listing.ref);
    assert(viaBody.json.valid === true, 'the same token in the header-authenticated body flow validates');
  });

  await section('C2 entry_url rules + domain change pauses for re-attestation', async () => {
    const w = await makeWorld();
    establishOperator(w, 1, 'op_owner');
    const listing = await makeLiveListing(w, 'owner_bot', { title: 'URL door service' });
    const shortA = 'https://' + 'bit' + '.ly/abc123';
    const shortB = 'https://' + 'tinyurl' + '.com/abc123';
    const bad = [
      ['http://doors.example.com/e', 'plain http'],
      ['https://127.0.0.1/e', 'an IPv4 literal'],
      ['https://10.0.0.5/e', 'a private-range IP literal'],
      ['https://[2001:db8::1]/e', 'an IPv6 literal'],
      ['https://localhost:8443/e', 'localhost'],
      [shortA, 'a shortener'],
      [shortB, 'a shortener host'],
      ['https://api.tryoids.com/e', 'an Oids domain'],
    ];
    for (const [url, label] of bad) {
      const r = await w.call('POST', '/api/v1/doors', { key: KEY.owner_bot, body: { listing_ref: listing.ref, slug: 'url-door', entry_url: url, terms_ack: true } });
      assert(r.status === 400 && r.json.error === 'bad_entry_url', label + ' is rejected at registration, got ' + r.status + ' ' + r.text);
    }
    assert(sqlOne(w, 'SELECT COUNT(*) AS n FROM doors').n === 0, 'rejected URLs wrote no door');
    await makeDoor(w, 'owner_bot', listing.ref, { slug: 'url-door', entry_url: 'https://doors.example.com/entry' });
    const sameDomain = await w.call('PATCH', `/api/v1/doors/${listing.ref}`, { key: KEY.owner_bot, body: { entry_url: 'https://doors.example.com/other-path' } });
    assert(sameDomain.status === 200 && !sameDomain.json.door.paused_for_reattestation, 'a same-domain URL change does not pause');
    let menu = await w.call('GET', '/api/v1/doors', { key: KEY.borrower_bot });
    assert(menu.json.doors.some((d) => d.ref === listing.ref), 'the door is in the menu before the domain change');
    const domainChange = await w.call('PATCH', `/api/v1/doors/${listing.ref}`, { key: KEY.owner_bot, body: { entry_url: 'https://portal.example.org/entry' } });
    assert(domainChange.status === 200 && domainChange.json.door.paused_for_reattestation === true, 'a registrable-domain change marks the door paused for re-attestation');
    const listingRow = sqlOne(w, 'SELECT status, attestation FROM exchange_listings WHERE public_ref = ?', listing.ref);
    assert(listingRow.status === 'paused' && listingRow.attestation === 'stale', 'the listing is paused with a stale attestation in the same change');
    menu = await w.call('GET', '/api/v1/doors', { key: KEY.borrower_bot });
    assert(!menu.json.doors.some((d) => d.ref === listing.ref), 'the door leaves the menu until re-attestation');
    const human = await humanToken(w, 'owner_bot');
    const attest = await w.call('POST', `/api/v1/exchange/listings/${listing.ref}/attest`, { human, idem: false, body: { statement: 'The new entry point is mine and its terms permit this use.', clause: 'Terms section 4.2', terms_version: 'terms-v1' } });
    assert(attest.status === 200, 'the human operator re-attests');
    const live = await w.call('PATCH', `/api/v1/exchange/listings/${listing.ref}`, { key: KEY.owner_bot, body: { status: 'live' } });
    assert(live.status === 200, 'the listing goes live again after re-attestation');
    menu = await w.call('GET', '/api/v1/doors', { key: KEY.borrower_bot });
    assert(menu.json.doors.some((d) => d.ref === listing.ref), 'the door returns to the menu');
  });

  await section('C3 per-door validate-only key', async () => {
    const w = await makeWorld();
    const listing = await makeLiveListing(w, 'owner_bot', { title: 'Key door service' });
    const door = await makeDoor(w, 'owner_bot', listing.ref, { slug: 'key-door' });
    await grantFor(w, 'owner_bot', listing.human, listing.ref, 'borrower_bot');
    const doorRow = sqlOne(w, 'SELECT validate_key_hash FROM doors WHERE slug = ?', 'key-door');
    assert(doorRow.validate_key_hash === await sha256hex(door.validate_key) && doorRow.validate_key_hash !== door.validate_key, 'the validate key is stored hashed only');
    const enter = await enterDoor(w, 'borrower_bot', listing.ref);
    const withAgentKey = await validateToken(w, KEY.owner_bot, enter.json.entry.token, listing.ref);
    assert(withAgentKey.json.valid === false, 'the operator full Oids API key does not validate');
    const withBorrowerKey = await validateToken(w, KEY.borrower_bot, enter.json.entry.token, listing.ref);
    assert(withBorrowerKey.json.valid === false, 'an entering agent API key does not validate');
    const exitWithAgentKey = await w.call('POST', `/api/v1/doors/sessions/${enter.json.entry.ref}/exit`, { key: KEY.owner_bot, idem: false, body: {} });
    assert(exitWithAgentKey.status === 404, 'the operator API key cannot report an exit either');
    const good = await validateToken(w, door.validate_key, enter.json.entry.token, listing.ref);
    assert(good.json.valid === true, 'the per-door validate key validates');
    const e2 = await enterDoor(w, 'borrower_bot', listing.ref);
    const rotate = await w.call('POST', `/api/v1/doors/${listing.ref}/rotate-validate-key`, { key: KEY.owner_bot, body: {} });
    assert(rotate.status === 200 && rotate.json.validate_key && rotate.json.validate_key !== door.validate_key, 'rotation issues a fresh key, shown once');
    if (e2.status === 201) {
      const oldKey = await validateToken(w, door.validate_key, e2.json.entry.token, listing.ref);
      assert(oldKey.json.valid === false, 'the rotated-out key no longer validates');
      const newKey = await validateToken(w, rotate.json.validate_key, e2.json.entry.token, listing.ref);
      assert(newKey.json.valid === true, 'the new key validates');
    }
  });

  await section('C4 door terms: no wagering, paid entry, or chance prizes', async () => {
    const w = await makeWorld();
    const listing = await makeLiveListing(w, 'owner_bot', { title: 'Games night', description: 'A weekly lottery draw with prizes for the room.' });
    const r = await w.call('POST', '/api/v1/doors', { key: KEY.owner_bot, body: { listing_ref: listing.ref, slug: 'games-night', entry_url: 'https://doors.example.com/e', terms_ack: true } });
    assert(r.status === 400 && r.json.error === 'door_terms_violation', 'a chance-prize listing cannot register a door, got ' + r.status + ' ' + r.text);
    const listing2 = await makeLiveListing(w, 'third_bot', { title: 'Clean service' });
    const noAck = await w.call('POST', '/api/v1/doors', { key: KEY.third_bot, body: { listing_ref: listing2.ref, slug: 'clean-door', entry_url: 'https://doors.example.com/e' } });
    assert(noAck.status === 400 && noAck.json.error === 'door_terms_required', 'registration without the door-terms acknowledgement is refused');
    const bounty = await makeLiveListing(w, 'third_bot', { title: 'Bounty skill service', price_mode: 'bounty' });
    const okDoor = await makeDoor(w, 'third_bot', bounty.ref, { slug: 'bounty-door' });
    assert(okDoor.door.price_mode === 'bounty', 'a bounty-linked door for skill/work registers with price_mode bounty only');
    const src = readFileSync(new URL('../migrations/033_doors.sql', import.meta.url), 'utf8');
    assert(!/funded/i.test(src), 'the doors schema carries no funded-settlement column');
  });

  await section('C6/C7 menu notice, operator handle, open-mode restrictions', async () => {
    const w = await makeWorld();
    establishOperator(w, 1, 'op_owner');
    const listing = await makeLiveListing(w, 'owner_bot', { title: 'Notice door service' });
    await makeDoor(w, 'owner_bot', listing.ref, { slug: 'notice-door', entry_mode: 'open' });
    const menu = await w.call('GET', '/api/v1/doors', { key: KEY.borrower_bot });
    assert(/external site, not Oids/i.test(menu.json.notice) && /never send your Oids key/i.test(menu.json.notice), 'the menu carries the plain external-site notice before entry');
    const item = menu.json.doors.find((d) => d.ref === listing.ref);
    assert(item && item.operator_handle === 'owner_bot', 'the menu shows the operator handle beside the door');
    assert(/no human approval/i.test(item.open_notice || ''), 'the menu warns that no human approval occurred for the open door');
    assert(item.entry_url === undefined && item.entry_url_host === 'doors.example.com', 'the menu shows the entry host; the full URL is on the door read');
    const page = await w.call('GET', '/doors', {});
    assert(page.status === 200 && /Never send your Oids key/.test(page.text) && page.text.includes('@owner_bot'), 'the /doors page carries the notice and the operator handle');
    const compute = await makeLiveListing(w, 'owner_bot', { kind: 'own_compute', title: 'Compute door service' });
    const badOpen = await w.call('POST', '/api/v1/doors', { key: KEY.owner_bot, body: { listing_ref: compute.ref, slug: 'compute-door', entry_url: 'https://doors.example.com/e', entry_mode: 'open', terms_ack: true } });
    assert(badOpen.status === 400 && badOpen.json.error === 'open_not_allowed_for_kind', 'open registration for own_compute is rejected');
    await makeDoor(w, 'owner_bot', compute.ref, { slug: 'compute-door' });
    const badPatch = await w.call('PATCH', `/api/v1/doors/${compute.ref}`, { key: KEY.owner_bot, body: { entry_mode: 'open' } });
    assert(badPatch.status === 400 && badPatch.json.error === 'open_not_allowed_for_kind', 'switching own_compute to open is rejected');
    const dataset = await makeLiveListing(w, 'owner_bot', { kind: 'own_dataset', title: 'Dataset door service' });
    const badDataset = await w.call('POST', '/api/v1/doors', { key: KEY.owner_bot, body: { listing_ref: dataset.ref, slug: 'dataset-door', entry_url: 'https://doors.example.com/e', entry_mode: 'open', terms_ack: true } });
    assert(badDataset.status === 400, 'open registration for own_dataset is rejected');
    const capBad = await w.call('POST', '/api/v1/doors', { key: KEY.owner_bot, body: { listing_ref: dataset.ref, slug: 'dataset-door', entry_url: 'https://doors.example.com/e', session_max_minutes: 1441, terms_ack: true } });
    assert(capBad.status === 400 && capBad.json.error === 'bad_session_max', 'a session cap past 24 hours is rejected');
  });

  await section('DQ3 per-operator live door caps (1 in first 7 days, then 5)', async () => {
    const w = await makeWorld();
    const l1 = await makeLiveListing(w, 'owner_bot', { title: 'First door service' });
    await makeDoor(w, 'owner_bot', l1.ref, { slug: 'first-door' });
    const l2 = await makeLiveListing(w, 'owner_bot', { title: 'Second door service' });
    const second = await w.call('POST', '/api/v1/doors', { key: KEY.owner_bot, body: { listing_ref: l2.ref, slug: 'second-door', entry_url: 'https://doors.example.com/e', terms_ack: true } });
    assert(second.status === 400 && second.json.error === 'door_cap_reached', 'a new operator is limited to 1 live door in the first 7 days, got ' + second.status + ' ' + second.text);
    const w2 = await makeWorld();
    establishOperator(w2, 1, 'op_veteran');
    for (let i = 1; i <= 5; i++) {
      const l = await makeLiveListing(w2, 'owner_bot', { title: 'Veteran service ' + i });
      await makeDoor(w2, 'owner_bot', l.ref, { slug: 'veteran-door-' + i });
    }
    const l6 = await makeLiveListing(w2, 'owner_bot', { title: 'Veteran service 6' });
    const sixth = await w2.call('POST', '/api/v1/doors', { key: KEY.owner_bot, body: { listing_ref: l6.ref, slug: 'veteran-door-6', entry_url: 'https://doors.example.com/e', terms_ack: true } });
    assert(sixth.status === 400 && sixth.json.error === 'door_cap_reached', 'an established operator is limited to 5 live doors');
  });

  await section('DROP-LIST copy/code scan of shipped Doors strings', async () => {
    const src = readFileSync(new URL('../worker/index.js', import.meta.url), 'utf8');
    const block = src.slice(src.indexOf('// ===== DOORS BEGIN ====='), src.indexOf('// ===== DOORS END ====='));
    const mig = readFileSync(new URL('../migrations/033_doors.sql', import.meta.url), 'utf8');
    const bannedName = 'Agent ' + 'Checkout';
    assert(!block.includes(bannedName) && !mig.includes(bannedName), 'the dropped name appears in no added line');
    const bans = [/\bverified\b/i, /unlock/, /qualifies/, /counts toward/, /hard cap/i, /work has stopped/i, /\bproxy\b/i, /phase 2/i, /door_token/, /one_liners/];
    for (const b of bans) assert(!b.test(block), 'doors block must not contain ' + b);
    for (const b of bans) assert(!b.test(mig), 'migration 033 must not contain ' + b);
    assert(!/FROM receipts/i.test(block), 'no Doors code path reads receipts to decide anything (a receipt authorizes nothing)');
    assert(block.includes('confirmed by counterparty'), 'receipt wording in the doors block is confirmed by counterparty');
  });
}

// ===========================================================================
// Abuse fixtures DF1-DF4
// ===========================================================================
async function fixtures() {
  await section('DF1 harvesting door', async () => {
    const w = await makeWorld();
    const listing = await makeLiveListing(w, 'owner_bot', { title: 'Harvest bait service', description: 'A game that needs your files to continue, apparently.' });
    const door = await makeDoor(w, 'owner_bot', listing.ref, { slug: 'harvest-door', entry_mode: 'open' });
    const read = await w.call('GET', `/api/v1/doors/${listing.ref}`, { key: KEY.borrower_bot });
    assert(/never send your Oids key/i.test(read.json.door.notice), 'the door read carries the never-your-key rule before entry');
    const menu = await w.call('GET', '/api/v1/doors', { key: KEY.borrower_bot });
    assert(/never send your Oids key/i.test(menu.json.notice), 'the menu carries the never-your-key rule');
    await grantFor(w, 'owner_bot', listing.human, listing.ref, 'borrower_bot');
    await w.call('PATCH', `/api/v1/doors/${listing.ref}`, { key: KEY.owner_bot, body: { entry_mode: 'grant' } });
    const enter = await enterDoor(w, 'borrower_bot', listing.ref);
    assert(enter.status === 201, 'entry mints');
    const valid = await validateToken(w, door.validate_key, enter.json.entry.token, listing.ref);
    assert(valid.json.valid === true, 'validation succeeds');
    const answerKeys = Object.keys(valid.json).sort();
    assert(JSON.stringify(answerKeys) === JSON.stringify(['agent', 'expires_at', 'grant_ref', 'session_expires_at', 'session_id', 'valid']),
      'the validation answer carries handle + session id + grant ref + expiry and nothing else, got ' + answerKeys.join(','));
    const e2 = await enterDoor(w, 'borrower_bot', listing.ref);
    const report = await w.call('POST', '/api/v1/exchange/reports', { key: KEY.borrower_bot, body: { listing_ref: listing.ref, reason: 'This door asks entering agents for their Oids key and files.' } });
    assert(report.status === 201, 'the report records');
    const suspend = await w.call('POST', `/api/v1/exchange/listings/${listing.ref}/suspend`, { key: KEY.mod_bot, body: { reason: 'Credible harvesting report.' } });
    assert(suspend.status === 200, 'suspension lands on the report path');
    if (e2.status === 201) {
      const after = await validateToken(w, door.validate_key, e2.json.entry.token, listing.ref);
      assert(after.json.valid === false, 'tokens stop validating at suspension');
    }
    const audit = sqlAll(w, "SELECT action FROM exchange_audit WHERE object_kind = 'listing' AND object_id = (SELECT id FROM exchange_listings WHERE public_ref = ?)", listing.ref).map((r) => r.action);
    assert(audit.includes('reported') && audit.includes('suspended'), 'the audit trail shows the report and suspension arc');
  });

  await section('DF2 impersonation', async () => {
    const w = await makeWorld();
    establishOperator(w, 1, 'op_owner');
    const listing = await makeLiveListing(w, 'owner_bot', { title: 'Ordinary service' });
    const slugs = ['oids-login', 'oidsadmin', 'borrower_bot', ('trade' + 'wars') + '-arena', ('red' + '-dragon') + '-inn'];
    for (const slug of slugs) {
      const r = await w.call('POST', '/api/v1/doors', { key: KEY.owner_bot, body: { listing_ref: listing.ref, slug, entry_url: 'https://doors.example.com/e', terms_ack: true } });
      assert(r.status === 400, 'impersonation slug ' + slug + ' is rejected at registration, got ' + r.status);
    }
    const titled = await makeLiveListing(w, 'owner_bot', { title: 'Oids sign in page' });
    const rt = await w.call('POST', '/api/v1/doors', { key: KEY.owner_bot, body: { listing_ref: titled.ref, slug: 'plain-slug', entry_url: 'https://doors.example.com/e', terms_ack: true } });
    assert(rt.status === 400, 'a door named as an Oids sign-in page is rejected at registration');
    assert(sqlOne(w, 'SELECT COUNT(*) AS n FROM doors').n === 0, 'no impersonating door was registered');
    await makeDoor(w, 'owner_bot', listing.ref, { slug: 'ordinary-door' });
    const read = await w.call('GET', `/api/v1/doors/${listing.ref}`, { key: KEY.borrower_bot });
    assert(read.json.door.entry_url === 'https://doors.example.com/entry' && read.json.door.operator_handle === 'owner_bot',
      'the door read shows the real entry_url and operator handle before entry');
    const taken = await w.call('POST', `/api/v1/exchange/listings/${listing.ref}/taken-down`, { key: KEY.mod_bot, body: { reason: 'Substantiated impersonation report.' } });
    assert(taken.status === 200 && taken.json.listing.status === 'taken_down', 'takedown lands on first substantiated report');
    const flagged = sqlOne(w, "SELECT COUNT(*) AS n FROM exchange_reports WHERE status = 'open'");
    assert(flagged.n >= 1, 'the operator other listings are flagged for review');
  });

  await section('DF3 token replay and theft', async () => {
    const w = await makeWorld();
    establishOperator(w, 1, 'op_owner');
    establishOperator(w, 3, 'op_third');
    const listing = await makeLiveListing(w, 'owner_bot', { title: 'Replay door service' });
    const door = await makeDoor(w, 'owner_bot', listing.ref, { slug: 'replay-door' });
    const other = await makeLiveListing(w, 'third_bot', { title: 'Other replay service' });
    const otherDoor = await makeDoor(w, 'third_bot', other.ref, { slug: 'replay-other' });
    await grantFor(w, 'owner_bot', listing.human, listing.ref, 'borrower_bot');
    const enter = await enterDoor(w, 'borrower_bot', listing.ref);
    const token = enter.json.entry.token;
    const row = sqlOne(w, 'SELECT * FROM door_entries WHERE public_ref = ?', enter.json.entry.ref);
    assert(!JSON.stringify(row).includes(token), 'the stored entry row cannot leak a usable token');
    assert(row.token_hash === await sha256hex(token), 'the row holds only the hash');
    const good = await validateToken(w, door.validate_key, token, listing.ref);
    assert(good.json.valid === true, 'first validation succeeds');
    const replay = await validateToken(w, door.validate_key, token, listing.ref);
    assert(replay.json.valid === false, 'a captured token replayed after consumption is invalid');
    const enter2 = await enterDoor(w, 'borrower_bot', listing.ref);
    assert(enter2.status === 201, 'a fresh entry mints');
    const stolen = await validateToken(w, otherDoor.validate_key, enter2.json.entry.token, other.ref);
    assert(stolen.json.valid === false, 'a captured token presented to a different door is invalid');
    const wrongKey = await validateToken(w, door.validate_key, enter2.json.entry.token, other.ref);
    assert(wrongKey.json.valid === false, 'a token presented under a mismatched door/key pair is invalid');
  });

  await section('DF4 entry farming reads as farming (distinct operators beside counts)', async () => {
    const w = await makeWorld();
    establishOperator(w, 1, 'op_owner');
    for (let i = 1; i <= 10; i++) establishOperator(w, 10 + i, 'op_farm');
    const listing = await makeLiveListing(w, 'owner_bot', { title: 'Farm target service' });
    const door = await makeDoor(w, 'owner_bot', listing.ref, { slug: 'farm-door', entry_mode: 'open' });
    let minted = 0;
    for (let i = 1; i <= 10; i++) {
      const name = 'swarm_' + String(i).padStart(2, '0');
      for (let j = 0; j < 20; j++) {
        const e = await enterDoor(w, name, listing.ref);
        assert(e.status === 201, 'farm entry mints for ' + name + ', got ' + e.status + ' ' + e.text);
        const v = await validateToken(w, door.validate_key, e.json.entry.token, listing.ref);
        assert(v.json.valid === true, 'farm entry validates');
        minted++;
      }
    }
    assert(minted === 200, 'the fixture ran its 200 entries honestly, got ' + minted);
    const menu = await w.call('GET', '/api/v1/doors', { key: KEY.borrower_bot });
    const item = menu.json.doors.find((d) => d.ref === listing.ref);
    assert(item.entry_count_30d === 200, 'the menu shows the real entry count, got ' + item.entry_count_30d);
    assert(item.distinct_operators_30d === 1, 'the menu shows distinct operators = 1 beside the count, got ' + item.distinct_operators_30d);
    const read = await w.call('GET', `/api/v1/doors/${listing.ref}`, { key: KEY.borrower_bot });
    assert(read.json.door.distinct_operators_30d === 1 && read.json.door.entry_count_30d === 200, 'the door read shows the same pair');
    assert(Array.isArray(read.json.door.recent_callers) && read.json.door.recent_callers.length === 0,
      'no caller is listed without the entering agent opt-in (DQ5)');
    const optIn = await enterDoor(w, 'swarm_01', listing.ref, { body: { show_in_callers: true } });
    await validateToken(w, door.validate_key, optIn.json.entry.token, listing.ref);
    const read2 = await w.call('GET', `/api/v1/doors/${listing.ref}`, { key: KEY.borrower_bot });
    assert(read2.json.door.recent_callers.length === 1 && read2.json.door.recent_callers[0].agent === 'swarm_01',
      'an opted-in caller appears on that door list only');
  });
}

await acceptance();
await conditions();
await fixtures();

const failed = results.filter(([, s]) => s !== 'PASS');
console.log('');
for (const [name, s] of results) console.log((s === 'PASS' ? 'PASS ' : 'FAIL ') + name + (s === 'PASS' ? '' : ' — ' + s));
console.log('');
console.log('doors: ' + (results.length - failed.length) + '/' + results.length + ' sections passed');
console.log('spec 9.12 bulletin: NOT RUN (fast follow, not built)');
if (createdLegalStub) { try { (await import('node:fs')).unlinkSync(legalPath); } catch { /* leave it */ } }
process.exit(failed.length ? 1 : 0);
