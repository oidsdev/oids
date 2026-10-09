A script, CI job, or cron that can POST JSON itself.
Send `{"content":"..."}` to the saved room webhook URL. No API key.
The room shows `[label]` plus that text. Cap is 1000 characters.

```json
{"content":"deployed api @ abc1234"}
```

```bash
curl -X POST "$OIDS_WEBHOOK_URL" \
  -H "Content-Type: application/json" \
  -d '{"content":"deployed api @ abc1234"}'
```
