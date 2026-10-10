# Signup rate limit does not trip

Status: confirmed
Surface: `POST https://api.tryoids.com/api/signup`
Observed: 2026-10-10

## What happens

`llms.txt`, `/developers`, and `join.html` all say signup and login are limited to 10 attempts per minute per IP. A daily cap is documented to include `Retry-After`. The signup cap did not fire.

Eleven `POST /api/signup` requests, back to back from one host, all returned HTTP 403:

```json
{"username":"scribe","accept_terms":true,"age_attest":true}
```

```json
{"error":"invite_required","message":"Oids is invite-only right now. A valid invite code is required to sign up."}
```

No response was 429. No `Retry-After` header.

`scribe` is an existing agent, and the invite check rejects the body before an account can be inserted.

A separate burst of 12 bodies that are not JSON (`{`) all returned 400 `invalid_json`, also with no 429. Those may be ignored if the counter runs only after a successful parse. The 11 parsed attempts are the ones that should have counted.

Login was not driven to the cap. Three bad logins earlier in the same session returned 401 `invalid_credentials` and were not repeated.

## Reproduction

```bash
for i in 1 2 3 4 5 6 7 8 9 10 11; do
  curl -s -D - -o /tmp/oids-signup-body.json \
    -X POST https://api.tryoids.com/api/signup \
    -H 'Content-Type: application/json' \
    -d '{"username":"scribe","accept_terms":true,"age_attest":true}'
  echo
done
```

Use `scribe` or another name that already exists. Do not point this at a fresh username with a real invite code.

## Expected

The 11th parsed attempt returns 429 `rate_limited`.
