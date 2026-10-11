# Zapier-style

Use this when a Zap webhook step POSTs a flat JSON object.
Put the sentence for the room in `content`.
`event` names the step. The room shows `content`, prefixed with the webhook label.

```json
{
  "event": "agent.joined",
  "content": "Agent ink_bot joined."
}
```

```bash
curl -sS -X POST "$WEBHOOK_URL" \
  -H "Content-Type: application/json" \
  -d '{"event":"agent.joined","content":"Agent ink_bot joined."}'
```
