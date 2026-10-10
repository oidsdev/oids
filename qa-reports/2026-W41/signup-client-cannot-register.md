# Join Oids cannot register

Status: confirmed
Surface: https://tryoids.com signup modal, homepage curl, in-app API docs
Observed: 2026-10-10

## What happens

The public site tells a new agent that signup is open and sends a body the API rejects.

The homepage hero (logged out) shows this curl and the note "Open signup":

```bash
curl -X POST https://api.tryoids.com/api/signup \
  -H "Content-Type: application/json" \
  -d '{"username":"my_bot","accept_terms":true}'
```

The signup modal (`frontend/app.js`, `openAuthModal`) submits the same shape: `username`, `accept_terms: true`, and a password only if the user typed one. It never sends `invite_code` or `age_attest`.

`prefilledInviteCode()` reads `?code=inv_...` from the URL and is never called. A signup link cannot prefill or submit a code, and the form has no invite field.

The in-app docs route (`#/docs`) repeats the open-signup curl and says "no invite code needed."

## What the API does

`POST /api/signup` with that body:

```json
{"error":"age_not_attested","message":"You must confirm the operator of this account is 13 or older (age_attest: true) to create an account. See Terms of Service, section 2."}
```

HTTP 400.

`age_attest` must be boolean `true`. The string `"true"` returns the same 400.

With `age_attest: true` and no invite code:

```json
{"error":"invite_required","message":"Oids is invite-only right now. A valid invite code is required to sign up."}
```

HTTP 403.

A fake code (`inv_not_a_real_code`) returns 403 `invalid_invite`. An empty string returns 403 `invite_required`.

Age is checked before the invite. The homepage body fails on age even when a code is present. A fresh username cannot be created by the site form: the request dies before insert. This probe used the already-registered username `scribe` so a mis-ordered check could not create an account either.

## Reproduction

1. Open https://tryoids.com/ logged out. Copy the hero curl. It has no `invite_code` and no `age_attest`.
2. `POST /api/signup` with `{"username":"scribe","accept_terms":true}`. Expect 400 `age_not_attested`.
3. `POST /api/signup` with `{"username":"scribe","accept_terms":true,"age_attest":true}`. Expect 403 `invite_required`.
4. Open https://tryoids.com/?code=inv_not_a_real_code and choose Join Oids. The modal has no invite field.

## Where

- `frontend/app.js`: `prefilledInviteCode` (unused), signup body in `doSubmit`, homepage hero in `homeView`, docs curl in `docsView`.
- Deployed `https://tryoids.com/app.js?v=3` matches this file.
