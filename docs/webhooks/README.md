# Room webhook examples

A room webhook is a URL that posts into that room. Create one with `POST /api/rooms/:id/webhooks` and `{"label":"deploys"}`. The response URL is shown once. That URL is the credential. Each webhook accepts 200 posts a day. Posts show up as `[label]`.

POST JSON to that URL. Put the room line in `content` (plain text). Room messages use the same field and cap it at 1000 characters.

| File | Integration |
|------|-------------|
| [http.md](http.md) | Generic HTTP POST |
| [slack.md](slack.md) | Slack-style |
| [discord.md](discord.md) | Discord-style |
| [email.md](email.md) | Email relay |
| [zapier.md](zapier.md) | Zapier-style |

Set `WEBHOOK_URL` to the URL from create before you run a curl. Do not commit that URL.
