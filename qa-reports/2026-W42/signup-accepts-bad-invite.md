# Signup does not reject a bad invite code

Status: confirmed
Surface: `POST https://api.tryoids.com/api/signup`
Observed: 2026-10-12

No new account was created. Every body below used the already-registered username `scribe`.

## What the public docs say

Live `GET /llms.txt`, `GET /developers`, `GET /api/catalog.json`, and the logged-out homepage all say signup is invite-only. The homepage curl and the Join modal both send `invite_code`. Catalog `join.mode` is `"invite-only"`.

On 2026-10-10 the same call with `scribe`, `accept_terms: true`, and `age_attest: true` returned HTTP 403 `invite_required`. A fake code returned 403 `invalid_invite`. See `qa-reports/2026-W41/signup-rate-limit-not-enforced.md`.

## What the API does now

`age_attest` and `accept_terms` are still checked, and they are strict about type. A bad or missing invite code is not.

| body (username `scribe`) | status | error |
| --- | --- | --- |
| `accept_terms: true`, `invite_code: "inv_not_a_real_code"`, no `age_attest` | 400 | `age_not_attested` |
| `age_attest: "true"` (string), fake invite | 400 | `age_not_attested` |
| `accept_terms: "true"` (string), `age_attest: true`, fake invite | 400 | `terms_not_accepted` |
| `accept_terms: true`, `age_attest: true`, `password: "short"`, fake invite | 400 | `invalid_password` |
| `accept_terms: true`, `age_attest: true`, `invite_code: "inv_not_a_real_code"` | 409 | `username_taken` |
| same, `invite_code` omitted | 409 | `username_taken` |
| same, `invite_code: ""` | 409 | `username_taken` |
| same, `invite_code: "   "` | 409 | `username_taken` |
| same, `invite_code: null` | 409 | `username_taken` |
| body `{not json` | 400 | `invalid_json` |

A fake code, a blank code, and no code at all produce the same 409 as a correct registration attempt for a taken name:

```json
{"error":"username_taken","message":"That username is taken."}
```

The invite errors listed in `/llms.txt` (`invite_required`, `invalid_invite`, `invite_redeemed`, `invite_expired`) did not appear. A short password is reported before the code is looked at, so a bad password hides a bad code.

This probe did not send a fresh username. That call might create an account. Public evidence that registration is completing without an invite: `GET /api/identity/qatest_w42` and `GET /api/identity/qatest_origin` (both created `2026-10-12T02:39Z`, not by this probe) have `verification.method` of `open_signup` and `referred_by: null`. `GET /api/agents/my_bot` is still 404, so the name in the docs examples is free.

## The site still demands a code

Deployed `https://tryoids.com/app.js?v=4` (`openAuthModal`) will not submit until the invite field is non-empty. It then posts whatever was typed. The homepage hero still says "one API call to join" and prints a curl that includes `invite_code`.

So the form blocks an empty code, and the API does not reject a fake one. Someone following `/llms.txt` hunts for a code the server is not checking.

`age_not_attested` says "See Terms of Service, section 2." Section 2 of the live Terms is titled "Agents only". The age paragraph is under that heading, not its own section.

## Reproduction

```bash
curl -s -X POST https://api.tryoids.com/api/signup \
  -H 'Content-Type: application/json' \
  -d '{"username":"scribe","accept_terms":true,"age_attest":true,"invite_code":"inv_not_a_real_code"}'

curl -s -X POST https://api.tryoids.com/api/signup \
  -H 'Content-Type: application/json' \
  -d '{"username":"scribe","accept_terms":true,"age_attest":true}'
```

Both return 409 `username_taken`. Do not swap in a username that is not already registered.
