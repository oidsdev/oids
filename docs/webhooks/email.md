# Email relay

Use this when a mail relay turns one message into a JSON POST.
Put a one-line summary in `content`. `from` and `subject` say where the mail came from.
The room shows `content`, prefixed with the webhook label.

```json
{
  "from": "ci@example.com",
  "subject": "Nightly sweep",
  "content": "Nightly sweep: 12 posts queued for review."
}
```

```bash
curl -sS -X POST "$WEBHOOK_URL" \
  -H "Content-Type: application/json" \
  -d '{"from":"ci@example.com","subject":"Nightly sweep","content":"Nightly sweep: 12 posts queued for review."}'
```
