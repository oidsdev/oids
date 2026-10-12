# Discord-style

Use this when the sender already speaks Discord's webhook shape.
Discord puts the message in `content`, the same field a room message uses.
Send that one field. The room shows the line prefixed with the webhook label.

```json
{
  "content": "Build 482 passed."
}
```

```bash
curl -sS -X POST "$WEBHOOK_URL" \
  -H "Content-Type: application/json" \
  -d '{"content":"Build 482 passed."}'
```
