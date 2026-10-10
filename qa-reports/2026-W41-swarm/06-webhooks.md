# Webhooks: documented in a line, not exercisable

I could not create a webhook or post to one. Creating one needs a room, and a room needs an account. I stopped at auth. I did not send a webhook at any third party.

## Where the docs are

`/llms.txt` mentions webhooks twice, neither with a schema:

- Room features include "incoming webhooks".
- Team tools: `POST /api/rooms/:id/webhooks`, then `POST /api/wh/:token`.

No label field, no response shape, no body for the inbound call, no auth note for the token URL.

The in-app `#/docs` section "Team tooling" is better, and it is buried under prompt packs, a CLI playbook, legal, and source. It says:

- `POST /api/rooms/:id/webhooks {"label"}` returns a post URL, shown once.
- `GET` lists hooks without tokens.
- `DELETE /api/rooms/:id/webhooks/:id` revokes.
- 200 posts a day each.

The room UI copy matches that: the token in the URL is the credential, shown once, posts appear as `[label]`.

There is still no documented JSON body for `POST /api/wh/:token`. I do not know if the receiver wants `content`, `text`, or something else.

`GET /docs/webhooks` and `GET /api/webhooks` on the API are the generic 404.

## What the live routes do

`POST /api/rooms/1/webhooks` with `{"label":"qa"}` and no key:

`401 {"error":"unauthorized","message":"Valid Bearer <api_key> required."}`

The create route exists and is gated. Good.

Inbound posts, all `404 {"error":"not_found","message":"Unknown endpoint. See /llms.txt."}`:

- `POST /api/wh`
- `POST /api/wh/abc`
- `POST /api/wh/inv_test`
- `POST /api/wh/wh_abcdefghijklmnopqrstuvwxyz012345`
- `POST /api/wh/oids_abcdefghijklmnopqrstuvwxyz012345`

Same body for GET on those paths. The error is the generic unknown-endpoint error, not an invalid-token error. Either the receiver is not deployed, or it only matches a live token and uses the fallback 404 for everything else. From outside, those two cases look the same. I could not complete the webhook path the docs describe.

## Related scrub

`POST /api/files` (the other "hand something to another agent" API) returns `Valid Bearer <redacted> required.` See [04-llms-txt-discovery.md](04-llms-txt-discovery.md). File upload is listed in `/llms.txt` (25 MB, 7-day expiry) and is missing from the free-tier object in `catalog.json`. I did not upload a file.
