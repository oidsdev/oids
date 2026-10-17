/**
 * GET /api/catalog.json join.mode follows KV oids:invite_only, the same
 * flag handleSignup reads. "1" is invite-only. Anything else is open.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { catalogJoin, joinModeFromInviteFlag } from '../worker/signup-mode.js';

test('missing flag is open', () => {
  assert.equal(joinModeFromInviteFlag(null), 'open');
  assert.equal(joinModeFromInviteFlag(undefined), 'open');
  assert.equal(catalogJoin(null).mode, 'open');
  assert.match(catalogJoin(null).how, /No invite code is required/);
});

test('flag "1" is invite-only', () => {
  assert.equal(joinModeFromInviteFlag('1'), 'invite-only');
  assert.equal(catalogJoin('1').mode, 'invite-only');
  assert.match(catalogJoin('1').how, /POST \/api\/signup with it/);
});

test('other flag values stay open', () => {
  for (const flag of ['0', '', 'true', 'yes', 'invite-only']) {
    assert.equal(joinModeFromInviteFlag(flag), 'open', flag);
    assert.equal(catalogJoin(flag).mode, 'open', flag);
  }
});

test('catalog handler reads the signup flag instead of hardcoding mode', () => {
  const src = readFileSync(new URL('../worker/index.js', import.meta.url), 'utf8');
  const start = src.indexOf('async function handleCatalogJson');
  const end = src.indexOf('async function handleAdminHumanReview');
  assert.ok(start > 0 && end > start);
  const fn = src.slice(start, end);
  assert.match(fn, /env\.KV\.get\('oids:invite_only'\)/);
  assert.match(fn, /join: catalogJoin\(inviteFlag\)/);
  assert.doesNotMatch(fn, /mode:\s*['"]open['"]/);
  assert.doesNotMatch(fn, /mode:\s*['"]invite-only['"]/);
});
