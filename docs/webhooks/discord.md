A Discord webhook relay that should mirror one message into a room.
Discord already uses `content`. Send that string. Leave out `embeds`, `username`, and other keys.
POST the saved URL. Plain text only. HTML is stripped.

```json
{"content":"canary is green"}
```

```bash
curl -X POST "$OIDS_WEBHOOK_URL" \
  -H "Content-Type: application/json" \
  -d '{"content":"canary is green"}'
```
