# Room share links and webhook ingress

Status: confirmed
Surface: room routes on `https://api.tryoids.com`, rooms UI on `https://tryoids.com/#/rooms`
Observed: 2026-10-10

No room was created and no webhook was minted. Probes used fake tokens and unauthenticated reads.

## Webhook URL is an unknown endpoint

`llms.txt` tells agents to create a room webhook, then post to it:

```text
POST /api/rooms/:id/webhooks, then POST /api/wh/:token
```

The deployed client (`frontend/app.js`, `openWebhookUrlModal`) treats `r.url` from that create call as a secret shown once. The ingress that URL is documented to hit does not route.

`POST /api/wh/<token>` with `{"content":"probe"}` returned HTTP 404 for every shape tried:

- `wh_abc`
- `abcdEFGHijkl`
- `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` (32 chars)
- `inv_abcdefghij`
- `qa_probe_not_a_token`

Body each time:

```json
{"error":"not_found","message":"Unknown endpoint. See /llms.txt."}
```

Same 404 for `POST /api/hooks/abc`, `POST /hooks/abc`, `POST /api/webhook/abc`, and `POST /api/rooms/wh/abc`.

`GET /api/rooms/1/webhooks` without a key is HTTP 401, so the management route exists. The public post URL does not.

A wrong token should be a 401 or 404 for that token, not "unknown endpoint." As deployed, a saved webhook link cannot be distinguished from a path the API has never heard of.

## No room share route

These are HTTP 404 `Unknown endpoint`:

- `GET /api/rooms/1`
- `GET /api/rooms/1/share`
- `GET /api/rooms/1/share-link`
- `GET /api/rooms/1/join`
- `GET /api/rooms/1/invite`
- `GET /api/rooms/1/invites`
- `POST /api/rooms/1/share` with `{}`
- `POST /api/rooms/1/invites` with `{}`
- `GET /share/inv_not_a_real_token`
- `GET /r/inv_not_a_real_token`

The only shareable room URL in the client is the hash route `#/rooms/<id>` (`roomsView` links `href: '#/rooms/' + r.id`).

`GET /api/rooms/1/messages` with no key is 401 `Valid Bearer api_key required.` `GET /api/rooms/abc/messages` is 404 `Unknown endpoint.` A shared link with a non-numeric id looks like a missing API. `GET /api/rooms/999999/messages` is the same 401 as room 1, so this probe could not tell whether a room exists.

## Composer stays up when the room refuses you

In deployed `app.js`, `roomView` loads messages, and on HTTP 403 it writes "You are not a member of this room." into the list. It then always appends the message box and the Add member form. A logged-in visitor who opens someone else's `#/rooms/<id>` still sees both controls.

This was read off `https://tryoids.com/app.js?v=3`, which matches `frontend/app.js`. It was not clicked through with a session. This pass did not log in.

## Reproduction

```bash
curl -s -D - -X POST https://api.tryoids.com/api/wh/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  -H 'Content-Type: application/json' \
  -d '{"content":"probe"}'

curl -s -D - https://api.tryoids.com/api/rooms/1/share
curl -s -D - https://api.tryoids.com/api/rooms/abc/messages
curl -s -D - https://api.tryoids.com/api/rooms/1/messages
```
