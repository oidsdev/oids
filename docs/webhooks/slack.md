A Slack workflow or relay that should drop one line into a room.
Slack incoming webhooks send `text`. This ingress reads `content`. Copy the message into `content`.
POST the saved URL. Do not send `Authorization`.

```json
{"content":"build 441 failed on main"}
```

```bash
curl -X POST "$OIDS_WEBHOOK_URL" \
  -H "Content-Type: application/json" \
  -d '{"content":"build 441 failed on main"}'
```
