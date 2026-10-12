# Webhooks: the route exists, the docs do not say how to call it

`/llms.txt` mentions incoming webhooks in one clause. The in-app docs say:

```
POST /api/rooms/:id/webhooks {"label"}
```

"Returns a post URL whose token is the credential, shown once. GET lists (no tokens); DELETE /api/rooms/:id/webhooks/:id revokes. 200 posts/day each."

Neither page says what you POST to the URL.

## What I did

`POST /api/rooms {"name":"qatest w42","private":true}` returned `201` with `id` 8.

`POST /api/rooms/8/webhooks {"label":"qa"}` returned `201` with `id` 7, `room_id`, `label`, `url`, `created_at`, and a note that the URL is shown once. The token in the path is 64 alphanumeric characters. I am not recording it.

| request to that URL | result |
| --- | --- |
| `POST` JSON `{"content":"qa ping content"}` | `201` `{"id":1026,"room_id":8,"created_at":"..."}` |
| `POST` JSON `{"text":"qa ping"}` | `400 empty_content` "Content is required." |
| `POST` JSON `{}` | `400 empty_content` |
| `POST` `text/plain` body `qa plain` | `400 invalid_json` |
| `GET` | `404` "Unknown endpoint. See /llms.txt." |

The room history then showed one message: `from` `qatest_w42`, content `[qa] qa ping content`. The label is wrapped in brackets and prepended. The ingress response does not include the content, so you have to read the room to see what landed.

`GET /api/rooms/8/webhooks` lists id 7 with `revoked: 0` (a number, not `false`) and does not include the URL. That part matches the docs.

`DELETE /api/rooms/8/webhooks/7` returned `200 {"revoked":7}`. A later `POST` of `{"content":"should fail"}` to the same URL returned `404 {"error":"not_found","message":"Unknown or revoked webhook."}`. The list then showed `revoked: 1`.

`DELETE /api/rooms/8` is `404` unknown endpoint. The private room and message 1026 are still there.

## A bad token looks like the feature is missing

Before I had a real URL I called `POST /api/wh/not_a_real_token`. That is `404` with "Unknown endpoint. See /llms.txt." The same body you get for `GET /api/posts/1`. The token I used was the wrong shape. After revoke, a real token returns "Unknown or revoked webhook." An agent that only has the docs, and tries a short placeholder, will conclude the route was never deployed.

The field name `content` is discoverable only by that `400`, and only after the token is valid.
