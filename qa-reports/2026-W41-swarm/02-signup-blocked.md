# Signup: the path a new agent is told to walk does not work

Required test username: something starting with `qatest-`. Required bio: `automated QA bot`.

No account was created.

## Hyphen usernames are rejected

```
POST /api/signup
{"username":"qatest-swarm","invite_code":"inv_not_a_real_code","accept_terms":true,"age_attest":true}
```

`400 {"error":"invalid_username","message":"Username must be 3-24 chars: lowercase letters, digits, underscore."}`

The same 400 is returned for `ab` and for a 25+ character name. `qatest` and `qatest_swarm` get past the username check and fail later on the invite. The hyphen fails first, so a real invite code would not save `qatest-swarm`. The rule is also in the signup modal hint. The required QA prefix and the product rule conflict.

`QATest_swarm` did not return `invalid_username`. It returned `invalid_invite`. The server accepts uppercase, or it lowercases before the check. The docs only say lowercase. I could not see which, because signup never succeeded.

## The API is invite-only

With a legal username, terms accepted, and `age_attest: true`, and no invite code:

`403 {"error":"invite_required","message":"Oids is invite-only right now. A valid invite code is required to sign up."}`

A fake `inv_...` code:

`403 {"error":"invalid_invite","message":"That invite code is not valid."}`

`/llms.txt` says codes are minted by the operator, never self-serve. The fallback is to email `abuse@tryoids.com` with subject "Invite request", or to ask an agent who is already on the network to `POST /api/recommend`. That recommend call itself requires a Bearer key. A new agent cannot recommend itself. I did not email the abuse mailbox.

There is no public test invite on the site, the catalog, or `/llms.txt`.

## The website tells you signup is open, then sends a body the API rejects

Rendered homepage quickstart:

```
curl -X POST https://api.tryoids.com/api/signup \
  -H "Content-Type: application/json" \
  -d '{"username":"my_bot","accept_terms":true}'
```

Hint under it: "Open signup: the key in the response is shown once."

That body, sent to the live API:

`403 invite_required`

The live `app.js` signup modal matches the hint. The comment in the file is "Registration is open (500-agent cap). No invite code required." The submit body is `{username, accept_terms: true}` plus an optional password. It does not send `invite_code`. It does not send `age_attest`. There is no invite field and no age checkbox.

`age_attest` is required and is checked before the invite code. Same username, fake invite, `accept_terms: true`, no `age_attest`:

`400 {"error":"age_not_attested","message":"You must confirm the operator of this account is 13 or older (age_attest: true) to create an account. See Terms of Service, section 2."}`

So a person who uses the Join button fails on age before they ever hear about the invite. `friendlyError` in `app.js` has no entry for `age_not_attested`. The modal would show the raw API sentence, and there is still nowhere to type a code.

`prefilledInviteCode()` reads `?code=inv_...` and is never called. A signup link of that shape does nothing.

## Check order, from probes

1. Username shape, including the hyphen ban (`400 invalid_username`).
2. `accept_terms: true` (`400 terms_not_accepted` even when the invite is fake).
3. `age_attest: true` (`400 age_not_attested` even when the invite is fake).
4. Invite present (`403 invite_required`).
5. Invite real (`403 invalid_invite` for a made-up code).

The terms error points at two URLs that are not the same document. See [03-docs-contradict.md](03-docs-contradict.md).

## Bio never comes up

Signup has no bio field. After a successful signup I would still have no documented way to set `automated QA bot`. See [07-bio.md](07-bio.md).
