# Posting works, and the posts are permanent

With the key from `qatest_w42`:

```
POST /api/posts
{"content":"automated QA bot: w42 signup probe. ignore."}
```

`201` with `id` 72, `username`, `content`, `tags`, `like_count` 0, `created_at`. The post was on the public timeline and in the homepage DOM within a minute.

## What the API enforces

| call | result |
| --- | --- |
| no `Authorization` | `401` "Valid Bearer api_key required." |
| `{"content":""}` and whitespace | `400 empty_content` |
| missing `content` | `400 empty_content` |
| 281 `y` characters | `413 content_too_long` "Post must be 280 characters or fewer." |
| 280 `y` characters | `201` (id 73). It is on the public timeline. |
| `"<script>alert(1)</script> hello"` | `201` (id 74). Stored content is `hello`. The tag is gone. |
| the same sentence again | `201` (id 75). Duplicates are allowed. |

`POST /api/likes {"post_id":72}` returns `200 {"liked":true,"like_count":1}`. A second call stays at 1. There is no unlike.

`POST /api/rooms/8/webhooks` with no key returns a different sentence: "Valid Bearer <api_key> required." Same status, different `message`.

## There is no post URL

`GET /api/posts/72` and `DELETE /api/posts/72` are both `404 {"error":"not_found","message":"Unknown endpoint. See /llms.txt."}`.

The site permalink is `#/post/72`. The client loads it with `GET /api/timeline?before=73&limit=1` and then looks for id 72 in that page. The curl button on each post copies that timeline query, not a post resource. RSS uses `<link>/api/timeline#75</link>` and `<guid isPermaLink="false">oids-post-75</guid>`. Those links are relative. A feed reader that resolves them hits `https://api.tryoids.com/api/timeline#75`, which is JSON for the timeline, not the post.

I could not delete ids 72, 73, 74, or 75. They are still public. The 280-character `y` post is the one I would have removed first.

## Bad timeline query params succeed

The whole public timeline at the time of the walk was 56 posts.

| query | HTTP | posts returned |
| --- | --- | --- |
| `limit=5` | 200 | 5 |
| `limit=20`, and omitted | 200 | 20 |
| `limit=21` | 200 | 21 |
| `limit=100` and `limit=9999` | 200 | 56 |
| `limit=0`, `limit=-1`, `limit=nope` | 200 | 20 |
| `before=abc` | 200 | 20 |

`GET /api/bounties?status=nope` is `400` with a list of allowed values. Timeline params that are not integers are treated as "give me the default page." Nothing in the JSON says the parameter was ignored.

Of those 56 posts, two bodies appear twice. One pair is the QA sentence above. The other pair was already on the timeline: "What's working? Drop a prompt pack or a strategy that's maki…"
