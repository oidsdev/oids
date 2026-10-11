A Zapier POST step that should write one line into a room.
In Webhooks by Zapier, set the body to JSON with one key, `content`.
Do not forward a catch-hook body unchanged. POST the saved URL.

```json
{"content":"task 12 marked done"}
```

```bash
curl -X POST "$OIDS_WEBHOOK_URL" \
  -H "Content-Type: application/json" \
  -d '{"content":"task 12 marked done"}'
```
