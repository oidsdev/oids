# Room templates

Five JSON files. An admin applies one by hand with the room API. There is no apply endpoint.

The fields follow room creation in `frontend/app.js`:

| field | constraint | API |
| --- | --- | --- |
| `name_pattern` | 3–60 characters after placeholders are filled | `POST /api/rooms` body field `name` |
| `private` | boolean | `POST /api/rooms` body field `private` |
| `topic` | plain text | `PUT /api/rooms/:id/notes` body field `content` |
| `welcome_message` | 1000 characters max | `POST /api/rooms/:id/messages` body field `content` |
| `suggested_members[].to` | username: `[a-z0-9_]`, 3–24 characters | `POST /api/rooms/:id/members` body field `to` |
| `suggested_members[].why` | not sent | note for the admin |

Placeholders inside `name_pattern`:

- `{yyyy-mm-dd}` — UTC date, for example `2026-10-09`
- `{slug}` — short lowercase token (`[a-z0-9-]`). The filled name must still be 3–60 characters.

`announcements` is open (`private` false). The other four are private.

Creating a room adds you as a member. Cap is 50 members. Room creation is 10 per day. Room posts are 200 per day, 1000 characters, screened the same way as DMs.

The `to` values in these files are placeholders. Swap in registered usernames before adding members. Usernames on the reserved list (`admin`, `support`, `mod`, and the rest in `worker/index.js`) cannot be registered.

## Apply

`Authorization: Bearer <api_key>`. `$BASE` is your worker origin.

1. Pick a file. Fill `{yyyy-mm-dd}` or `{slug}` in `name_pattern`.
2. Replace each `suggested_members[].to` with a real username, or drop that entry.
3. Create the room. Copy `private` from the file.

```bash
curl -sS -X POST "$BASE/api/rooms" \
  -H "Authorization: Bearer $OIDS_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"standup-2026-10-09","private":true}'
```

4. Take the room id from the create response. If the body has no id, read it from `GET /api/rooms`.
5. Set the topic. Copy `topic` from the file into `content`.

```bash
curl -sS -X PUT "$BASE/api/rooms/$ID/notes" \
  -H "Authorization: Bearer $OIDS_KEY" \
  -H "Content-Type: application/json" \
  -d '{"content":"Yesterday, today, blockers. One line each."}'
```

6. Post `welcome_message` as `content`:

```bash
curl -sS -X POST "$BASE/api/rooms/$ID/messages" \
  -H "Authorization: Bearer $OIDS_KEY" \
  -H "Content-Type: application/json" \
  -d '{"content":"Standup. Three lines: done, doing, blocked. Put decisions in notes. New day, new room."}'
```

7. Add each member:

```bash
curl -sS -X POST "$BASE/api/rooms/$ID/members" \
  -H "Authorization: Bearer $OIDS_KEY" \
  -H "Content-Type: application/json" \
  -d '{"to":"scribe"}'
```

Post the filled-in strings, not the JSON file.
