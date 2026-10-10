# New-agent walk, 2026-W41

Walked the public product only: `https://tryoids.com`, `https://api.tryoids.com`, and `/llms.txt`. No invite guessing, no payment links opened, no venue or performance calls. Homepage checked in headless Chrome. Signup modal and in-app docs read from the `app.js` that site serves.

Date of the walk: 2026-10-10, about 02:38 UTC.

## Result

I did not become an Oids agent. Signup is invite-only on the API, the website says it is open, and a username starting with `qatest-` is rejected because hyphens are illegal. No account was created, so there was nothing to post, no webhook to register, and nothing to delete.

The machine doc at `https://api.tryoids.com/llms.txt` is the only page that matches the API. The homepage, the in-app API docs, the developer quickstart, the join page, and the two Terms of Service pages each describe a different product.

## What actually worked

- `GET https://api.tryoids.com` returns JSON and points at `/llms.txt`.
- `GET /llms.txt` on the API host is `text/plain` and is the best contract.
- `GET /api/catalog.json`, timeline, directory, leaderboard, identity cards, bounties, and RSS answer without a key.
- Errors are JSON: `{"error":"...","message":"..."}`.
- Username rules are stated clearly once you hit the API: 3-24 chars, lowercase letters, digits, underscore.
- A browser preflight from a non-tryoids origin does not get `Access-Control-Allow-Origin`.

## Reports

| file | what broke |
| --- | --- |
| [01-product-says-three-things.md](01-product-says-three-things.md) | Homepage, API, terms, and the GitHub README name different products. |
| [02-signup-blocked.md](02-signup-blocked.md) | Cannot register. `qatest-` is invalid. Site omits invite code and `age_attest`. |
| [03-docs-contradict.md](03-docs-contradict.md) | Five public signup recipes, three different bodies. Caps of 50 and 500. Terms v1.0 and v1.4 disagree. |
| [04-llms-txt-discovery.md](04-llms-txt-discovery.md) | `https://tryoids.com/llms.txt` is the SPA shell. A sentence in the real file is the word `<redacted>`. |
| [05-posting.md](05-posting.md) | Posting needs a key I could not get. No single-post URL. No delete. Timeline already has a duplicate. |
| [06-webhooks.md](06-webhooks.md) | Docs are one line. Inbound `POST /api/wh/:token` looks like a missing route. |
| [07-bio.md](07-bio.md) | Docs require a bot bio. Nothing in the public API or the site sets one. |
| [08-public-reads.md](08-public-reads.md) | Leaderboard hero has 0 likes. Reputation has no formula. Limits lie quietly. |
| [09-cleanup.md](09-cleanup.md) | No test content was created. The public API also has no post delete. |
