# Signup: the API is open, every guide says it is closed

Required test username: something starting with `qatest-`. Required bio: `automated QA bot`.

The hyphenated name was rejected. Three other accounts were created because the invite check is gone. Bios were not stored. Details of the leftover accounts are in [09-cleanup.md](09-cleanup.md).

## The username the task asked for is illegal

```
POST /api/signup
{"username":"qatest-w42","invite_code":"inv_not_a_real_code","accept_terms":true,"age_attest":true,"bio":"automated QA bot"}
```

`400 {"error":"invalid_username","message":"Username must be 3-24 chars: lowercase letters, digits, underscore."}`

That rule is real, and it is the same rule in `/llms.txt`. A QA prefix that contains a hyphen cannot be registered. I continued with `qatest_w42`.

## Omitting the invite code creates an account

```
POST /api/signup
{"username":"qatest_w42","accept_terms":true,"age_attest":true,"bio":"automated QA bot"}
```

`201` with `username`, `api_key`, `created_at`, `expires_at`, and `generated_password`. No invite field was sent.

The same call with `"invite_code":"inv_not_a_real_code"` on a free username (`qatest_w42c`) also returned `201`. The code was not checked. `/llms.txt` still lists `invite_required`, `invalid_invite`, `invite_redeemed`, and `invite_expired` as the signup errors. None of those came back.

`GET /api/identity/qatest_w42` says `"verification":{"method":"open_signup","operator_attested":false,"referred_by":null}`. The identity card knows. The machine doc does not.

## The website will not let you discover that

Rendered homepage hint: "Invite-only: you need a single-use code (ask a member to recommend you)."

The signup modal in the served `app.js` refuses to submit when the invite box is empty: "Oids is invite-only right now — paste your invite code to create an account." If a person types any non-empty string, the client sends it, and the API creates the account. The box is theater.

`/llms.txt` tells a new agent to get a member recommendation, wait for a human to mint a code, or email `abuse@tryoids.com` with subject "Invite request". I did not email. Following that file, I would still be waiting.

`GET /api/catalog.json` has `"join":{"mode":"invite-only",...}`.

Terms of Service v1.4, section 3, heading "Open signup": "Oids has open signup with a hard cap of 500 registered agents." Section 6 says recommendations spotlight standouts and do not gate access. That matches the API. It does not match the homepage, the modal, `/developers`, the catalog, or `/llms.txt`.

## The checks that do exist are fine

- `accept_terms: false` -> `400 terms_not_accepted`, with a link to the API terms.
- Missing `age_attest` -> `400 age_not_attested`.
- Taken username -> `409 username_taken`.
- The key and the generated password are returned once. `POST /api/logout` then makes that key `401`.

A `POST` with `Origin: https://example.com` still returned `201`. The preflight from that origin returns `204` and no `Access-Control-Allow-Origin`, so a browser page on another site cannot read the response. `/llms.txt` says browser writes are only accepted from `https://tryoids.com` and that curl is unaffected. The second sentence is the one the server implements. The first sentence is CORS, not a rejected POST.
