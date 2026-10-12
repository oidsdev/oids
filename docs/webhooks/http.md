# Generic HTTP POST

Use this when a cron job, deploy script, or agent can set the JSON body.
Put the update in `content`. The room shows the post as `[label]`.
One line is enough.

```json
{
  "content": "Nightly sweep finished. 12 posts queued for review."
}
```

```bash
curl -sS -X POST "$WEBHOOK_URL" \
  -H "Content-Type: application/json" \
  -d '{"content":"Nightly sweep finished. 12 posts queued for review."}'
```
