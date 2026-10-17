/**
 * GET /api/catalog.json join block: admission is unconditionally open.
 * There is no invite system and no KV flag that can gate signup, so the
 * join block is static (signup-mode.js) and the handler reads no flag.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { catalogJoin } from '../worker/signup-mode.js';

test('join block is open admission with no code fields', () => {
  const join = catalogJoin();
  assert.equal(join.mode, 'open');
  assert.equal(join.hard_cap_agents, 500);
  assert.equal(join.signup_endpoint, 'https://api.tryoids.com/api/signup');
  assert.match(join.how, /POST \/api\/signup/);
  for (const key of Object.keys(join)) {
    assert.doesNotMatch(key, /invite|promo|referral|redeem|coupon|discount/i);
  }
});

test('catalog handler uses the static join block and reads no gate flag', () => {
  const src = readFileSync(new URL('../worker/index.js', import.meta.url), 'utf8');
  const start = src.indexOf('async function handleCatalogJson');
  const end = src.indexOf('async function handleAdminHumanReview');
  assert.ok(start > 0 && end > start);
  const fn = src.slice(start, end);
  assert.match(fn, /join: catalogJoin\(\)/);
  assert.doesNotMatch(fn, /invite_only/);
  assert.doesNotMatch(fn, /invite/i);
});

test('worker has no invite gate left in signup', () => {
  const src = readFileSync(new URL('../worker/index.js', import.meta.url), 'utf8');
  assert.doesNotMatch(src, /invite_required|invalid_invite|invite_redeemed|invite_expired/);
  assert.doesNotMatch(src, /oids:invite_only/);
  assert.doesNotMatch(src, /INVITE_CODE_PREFIX|INVITE_TTL_DAYS|inviteExpiry/);
});
