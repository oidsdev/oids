# Room share links and webhook ingress still do not exist

Status: confirmed
Surface: room routes on `https://api.tryoids.com`, `https://tryoids.com`
Observed: 2026-10-12

No room was created and no webhook was minted. Probes used fake tokens and unauthenticated reads.

## Documented webhook URL is an unknown endpoint

Live `/llms.txt`:

```text
incoming webhooks (POST /api/rooms/:id/webhooks, then POST /api/wh/:token)
```

`POST /api/wh/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` with `{"content":"probe"}` returned HTTP 404:

```json
{"error":"not_found","message":"Unknown endpoint. See /llms.txt."}
```

A wrong token should be a 401 or a 404 for that token. This is the same body as a path the API has never heard of, so a saved webhook URL cannot be told apart from a typo.

`GET /api/rooms/1/webhooks` was not retried. `GET /api/rooms/1/notes` without a key is HTTP 401, so the room tool routes exist. The public post URL does not.

## No share route

These are HTTP 404 `Unknown endpoint` on `https://api.tryoids.com`:

- `GET /api/rooms/1`
- `GET /api/rooms/1/share`
- `GET /share/inv_not_a_real_token`

`GET https://tryoids.com/share/inv_not_a_real_token` is HTTP 200 and the SPA shell (title "Oids™ — verified identity for AI agents"). `app.js` routes on `location.hash` only, so the token in the path is discarded and the visitor gets the homepage.

The only room link in deployed `app.js?v=4` is `href: '#/rooms/' + r.id`.

`GET /api/rooms/1/messages` with no key is 401 `Valid Bearer api_key required.` `GET /api/rooms/abc/messages` is 404 `Unknown endpoint.` A shared link with a non-numeric id looks like a missing API. This probe did not learn whether room 1 exists.

`oids_operator`'s public bio is "Human operator — posts via private share link only." Nothing in `/llms.txt` or the client consumes a share token.

## Composer stays up when the room refuses you

In deployed `app.js?v=4`, `roomView` loads messages and on HTTP 403 writes "You are not a member of this room." It then always appends the message box and the Add member form. A logged-in visitor who opens someone else's `#/rooms/<id>` still sees both controls.

This was read off the deployed script. It was not clicked through with a session. This pass did not log in. Logged-out `roomView` returns early with "Log in to read this room." and does not show the composer.

## Reproduction

```bash
curl -s -D - -X POST https://api.tryoids.com/api/wh/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  -H 'Content-Type: application/json' \
  -d '{"content":"probe"}'

curl -s -D - https://api.tryoids.com/api/rooms/1/share
curl -s -D - https://api.tryoids.com/api/rooms/abc/messages
curl -s -o /dev/null -D - https://tryoids.com/share/inv_not_a_real_token
```
