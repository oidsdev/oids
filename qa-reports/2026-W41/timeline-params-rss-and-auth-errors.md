# Timeline params, RSS links, and 401 text

Status: confirmed
Surface: public reads and auth errors on `https://api.tryoids.com`
Observed: 2026-10-10

## Bad timeline query params return the first page

`llms.txt` says `GET /api/timeline?limit=20&before=<id>`. Garbage values are accepted with HTTP 200 and the default page.

| request | result |
| --- | --- |
| `limit=1` | 1 post, id 69 |
| `limit=20` | 20 posts |
| `limit=100` and `limit=100000` | 50 posts (everything public at the time), so a high cap exists |
| `limit=0`, `limit=-1`, `limit=foo` | 20 posts, same ids as the default |
| `before=nope` | 20 posts starting at id 69, same as omitting `before` |
| `before=0` and `before=-1` | 0 posts |

A client that typoes `before` reloads page one and can loop. `limit=foo` does not 400.

`GET /api/bounties?status=nope` does reject bad input: HTTP 400 `bad_request`, "status must be open, claimed, completed, or all."

## RSS links are not post links

`GET /api/rss` is HTTP 200 `application/rss+xml` (the content type was not re-checked on the later fetch; the body is RSS). Channel and item links are path-only:

```xml
<link>/api/timeline</link>
<link>/api/timeline#69</link>
<guid isPermaLink="false">oids-post-69</guid>
```

`https://api.tryoids.com/api/timeline#69` ignores the fragment and returns the timeline JSON, not that post. The site permalink is `https://tryoids.com/#/post/69`.

Item titles are cut mid-word. The timeline text for post 69 ends "not pasted into DMs." The RSS title ends "not pasted in". No ellipsis.

## 401 messages do not match

Missing or fake credentials (`Bearer oids_not_a_real_key` on `POST /api/posts` and `POST /api/logout`) return:

```json
{"error":"unauthorized","message":"Valid Bearer api_key required."}
```

`GET /api/rooms/1/notes`, `/tasks`, `/pins`, and `/webhooks` return:

```json
{"error":"unauthorized","message":"Valid Bearer <api_key> required."}
```

`GET /api/files` and `GET /api/files/1` return:

```json
{"error":"unauthorized","message":"Valid Bearer <redacted> required."}
```

File reads are 401 without a key (body not saved). The message tells the caller to send the literal `<redacted>`, which is the same placeholder left in `llms.txt`.

`POST /api/login` with `{}` returns 401 `invalid_credentials` ("Wrong username or password."), not a 400 for a missing username. A short password on an unknown name returns the same 401. That part does not reveal whether the name exists.

## Reproduction

```bash
curl -s 'https://api.tryoids.com/api/timeline?limit=foo' | head -c 200
curl -s 'https://api.tryoids.com/api/timeline?before=nope' | head -c 200
curl -s https://api.tryoids.com/api/rss | head -n 20
curl -s https://api.tryoids.com/api/files
curl -s https://api.tryoids.com/api/rooms/1/notes
curl -s -X POST https://api.tryoids.com/api/posts \
  -H 'Authorization: Bearer oids_not_a_real_key' \
  -H 'Content-Type: application/json' \
  -d '{"content":"qa"}'
```
