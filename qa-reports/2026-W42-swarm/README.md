# New-agent walk, 2026-W42

Walked the public product only: `https://tryoids.com`, `https://api.tryoids.com`, and `/llms.txt`. Homepage rendered in headless Chrome. Signup modal and in-app docs read from the `app.js` that site serves. No Stripe links opened. No performance records submitted. No invite codes guessed beyond one obvious fake.

Date of the walk: 2026-10-12, about 02:38 to 02:43 UTC.

## Result

I became an Oids agent by accident. `/llms.txt`, the homepage, the signup modal, and `/developers` all say invite-only. `POST /api/signup` with no invite code returned `201` and an API key. A second call with `invite_code` set to `inv_not_a_real_code` also returned `201`. Terms v1.4, section 3, is the page that matches the API: open signup, 500-agent cap.

The required test username cannot be registered. `qatest-w42` is `400 invalid_username` because hyphens are illegal. I used `qatest_w42` instead. The required bio, `automated QA bot`, was sent on signup and ignored. There is still no way to set a bio.

Posting works. Webhook ingress works once you already have a key, a room, and a body field the docs never name. Nothing I created can be deleted.

## What changed since W41

- `https://tryoids.com/llms.txt` is now `text/plain` and byte-identical to the API copy. Last week it was the SPA shell.
- Both Terms pages are v1.4 and both say open signup. Last week they disagreed with each other.
- `POST /api/wh/:token` is a real route. A 64-character token and `{"content":"..."}` posts into the room. A wrong-shaped token still answers `Unknown endpoint`.

## What actually worked

- `GET https://api.tryoids.com` returns JSON and points at `/llms.txt`.
- Public reads return JSON: timeline, directory, leaderboard, referrers, identity, bounties, network, RSS.
- Signup without a code returns a one-time `api_key` and `generated_password`.
- `accept_terms: false` and a missing `age_attest` are rejected with a clear message.
- Plain-text posts land on the public timeline. A `<script>` tag is stripped.
- `POST /api/logout` revokes the calling key.

## Reports

| file | what broke |
| --- | --- |
| [01-product-says-three-things.md](01-product-says-three-things.md) | Homepage, API, terms, and llms.txt still name different products. |
| [02-signup-open-but-told-closed.md](02-signup-open-but-told-closed.md) | API registers anyone. Site and llms.txt say invite-only. `qatest-` is illegal. |
| [03-docs-contradict.md](03-docs-contradict.md) | Five signup recipes. The homepage curl is not valid JSON. |
| [04-llms-txt.md](04-llms-txt.md) | Machine doc matches the site copy now. One sentence is the word `<redacted>`. |
| [05-posting.md](05-posting.md) | Posts work. No single-post URL. No delete. Duplicates allowed. Bad `limit` is silent. |
| [06-webhooks.md](06-webhooks.md) | Ingress works. Docs never say the JSON field. A bad token looks like a missing route. |
| [07-bio.md](07-bio.md) | Bots must identify in their bio. Signup drops `bio`. No update endpoint. |
| [08-public-reads.md](08-public-reads.md) | A zero-like QA account is "most useful this week". Referrer `operator` does not exist. |
| [09-cleanup.md](09-cleanup.md) | Keys revoked, webhook revoked. Posts, room, and three accounts are stuck. |
