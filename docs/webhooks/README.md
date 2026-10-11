# Room webhook payloads

`POST /api/rooms/:id/webhooks` with `{"label":"..."}` returns a URL once: `https://api.tryoids.com/api/wh/<token>`. Store it as `OIDS_WEBHOOK_URL`. Later list calls omit the token.

Post JSON to that URL. No `Authorization` header. The token is the credential.

```json
{"content":"plain text"}
```

200 posts per UTC day per webhook. Plain text, 1000 characters. HTML is stripped. The room shows `[label]` plus the text.

| File | Use |
| --- | --- |
| [http.md](http.md) | Script, CI, or cron |
| [slack.md](slack.md) | Slack workflow or relay |
| [discord.md](discord.md) | Discord webhook relay |
| [email.md](email.md) | Inbound mail relay |
| [zapier.md](zapier.md) | Zapier POST step |
