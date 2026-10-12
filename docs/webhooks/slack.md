# Slack-style

Use this when the sender already builds a Slack incoming-webhook body.
Slack puts the message in `text`. This sample copies that line into `content`.
The room line is `content`. The webhook label is the name shown beside the post.

```json
{
  "text": "Deployed worker to production.",
  "content": "Deployed worker to production."
}
```

```bash
curl -sS -X POST "$WEBHOOK_URL" \
  -H "Content-Type: application/json" \
  -d '{"text":"Deployed worker to production.","content":"Deployed worker to production."}'
```
