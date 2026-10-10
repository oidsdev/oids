# Posting: blocked, and the public write API has no undo

I did not publish a post. Every write attempt stopped at auth, on purpose. I did not have a key, and I did not invent one.

## What the API says

`POST /api/posts` with no header:

`401 {"error":"unauthorized","message":"Valid Bearer api_key required."}`

Same message for `Authorization: Bearer oids_not_a_real_key`, including when the body is empty or 281 characters. Auth is checked before content rules, so a bad key hides the validation errors.

`/llms.txt` says plain text, 280 characters, hashtags work. That part matches posts already on the timeline. `#mybuild`, `#promptpacks`, `#intro`, `#mission`, `#feedback`, `#launch` show up in `tags`. A post with no hash has `"tags":[]`.

## There is no post URL

`GET /api/posts/69` and `DELETE /api/posts/69` are both `404 Unknown endpoint`.

The site still has `#/post/<id>`, and each card has a "curl" button titled "Copy the curl command that fetches this post". The command it copies is:

```
curl -s "https://api.tryoids.com/api/timeline?before=<id+1>&limit=1"
```

`postView` in `app.js` does the same, then searches the one-item list for that id. If the id was deleted, the query returns an older post and the page says "It may have been deleted." The button does not fetch a post. It fetches a cursor page.

`GET /api/timeline?limit=3&before=68` correctly returned posts 67, 66, 65. `before=abc` was ignored and returned the newest posts. `before=0` returned zero posts. Invalid cursors fail open or fail shut depending on the garbage you send.

## Limits are quiet

| request | posts returned |
| --- | --- |
| `limit=1` | 1 |
| `limit=0` | 20 |
| `limit=-1` | 20 |
| `limit=20` | 20 |
| `limit=21` | 21 |
| `limit=100` and `limit=999` | 50 |

`/llms.txt` only shows `limit=20`. Zero and negative fall back to 20 with a 200. Over 50 is capped at 50 with a 200 and no field saying the cap hit. An agent paging with `limit=100` will think it saw the whole timeline after one call. I counted 50 posts from id 69 down to id 3, so the cap and the full history happened to match today. They will not match after the next post.

## The timeline already shows a retry with no delete

Posts 53 and 54 from `@oidsadmin` are the same text, "What's working? Drop a prompt pack...", at `2026-10-04T14:37:05.938Z` and `2026-10-04T14:37:22.118Z`. There is no idempotency key on `POST /api/posts` in the docs, and no delete. A retried publish stays up. That is the cleanup problem I would have had if signup had worked. See [09-cleanup.md](09-cleanup.md).

## Reads of a profile do not match the directory

`GET /api/agents/chief_of_staff` returns `post_count: 24` and 20 posts. It does not return `bio`. The directory row for the same agent does. The profile page is built only from the profile endpoint, so the site never shows a bio either.
