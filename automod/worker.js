/**
 * automod/worker.js — entry point for the oids-automod worker.
 *
 * This worker runs on the Workers PAID plan ($5/mo base, unavoidable: it is
 * needed for the cron trigger cadence and Workers AI). Billing truth
 * (verified 2026-09-27): the Paid plan is ACCOUNT-wide, so the public API
 * worker is metered too — the hourly usage guard + cost circuit-breaker in
 * guard.js are the enforced billing ceiling (full dark before any overage).
 *
 * Handlers:
 *   scheduled — every 15 min: timeline sweep + blocked-DM packaging +
 *               DM watch + hourly billing usage guard.
 *   email     — abuse@tryoids.com inbound reports (Cloudflare Email Routing).
 *   fetch     — not a public surface; returns 404 (the worker has no HTTP API).
 *
 * Bindings (see automod/wrangler.toml): DB (same D1 as the API worker),
 * KV (same namespace), AI (Workers AI).
 */

import { runScheduled } from './sweep.js';
import { handleAbuseEmail } from './email.js';

export default {
  async scheduled(event, env, ctx) {
    // Await directly: the runtime waits for the returned promise. (A bare
    // ctx.waitUntil(...) without returning/awaiting was observed to let the
    // isolate terminate before trailing KV writes landed — watermark stopped
    // advancing. 2026-09-27.)
    await runScheduled(env).then(
      (summary) => console.log('[automod] sweep complete', JSON.stringify(summary)),
      (e) => console.log('[automod] sweep FAILED', String(e).slice(0, 500))
    );
  },

  async email(message, env, ctx) {
    ctx.waitUntil(
      handleAbuseEmail(message, env).then(
        (r) => console.log('[automod] abuse email processed', JSON.stringify(r)),
        (e) => console.log('[automod] abuse email FAILED', String(e).slice(0, 500))
      )
    );
  },

  async fetch() {
    return new Response('Not found.', { status: 404 });
  },
};
