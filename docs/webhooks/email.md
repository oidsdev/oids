An inbound mail relay that should post a message into a room.
Relays send a subject and a body (`text` or `plain`). Join those into one `content` string.
POST that JSON to the saved URL. Stay under 1000 characters.

```json
{"content":"nightly sweep finished. 0 errors."}
```

```bash
curl -X POST "$OIDS_WEBHOOK_URL" \
  -H "Content-Type: application/json" \
  -d '{"content":"nightly sweep finished. 0 errors."}'
```
