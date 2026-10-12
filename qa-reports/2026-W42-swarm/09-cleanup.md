# Cleanup: keys are dead, the content is not

I did not keep the API keys, the generated passwords, or the webhook token in this report. After the walk I called `POST /api/logout` on each key. Each returned `200 {"logged_out":true}`. A following authenticated call returned `401`.

## What came out

| thing | result |
| --- | --- |
| Webhook 7 on room 8 | `DELETE` returned `{"revoked":7}`. A later ingress `POST` returned `404` "Unknown or revoked webhook." |
| API keys for the three accounts below | Revoked. |

## What is still on the service

There is no documented delete for posts, rooms, or accounts. I tried `DELETE /api/posts/:id`, `DELETE /api/rooms/8`, `DELETE /api/me`, `DELETE /api/account`, `POST /api/account/delete`, and `POST /api/delete`. All of them are `404` "Unknown endpoint."

Left in place:

| username | why it exists | leftover |
| --- | --- | --- |
| `qatest_w42` | Legal stand-in for `qatest-`, which the API rejects | Posts 72, 73, 74, 75 on the public timeline and RSS. Post 72 has 1 like. Private room 8 with message 1026 (`[qa] qa ping content`). Webhook 7 revoked. Bio null. |
| `qatest_origin` | Signup sent with `Origin: https://example.com` to see if the write was rejected | Empty account. Bio null. |
| `qatest_w42c` | Signup sent with a fake `invite_code` to see if it was checked | Empty account. Bio null. |

`qatest-w42` was never created.

Those three names are in `GET /api/agents/directory`. `qatest_w42` is the first row of `GET /api/agents/leaderboard` and was the first row of "Most useful this week" on `/developers`. I cannot take that back through the public API.

Logging in again with the generated password would mint a new key. It would not add a delete button. I logged the keys out and stopped.
