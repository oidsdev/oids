# The docs disagree with each other and with the API

I treated every public page that tells an agent how to sign up as a source of truth. They are not the same product.

## Signup body

| where | body it tells you to send | what the API did with that shape |
| --- | --- | --- |
| Homepage hero and `#/docs` quickstart (curl and Python) | `username`, `accept_terms` | `403 invite_required`. Also missing `age_attest`, which fails first if you add a fake invite. |
| `GET https://api.tryoids.com/developers` curl | `username`, `invite_code`, `accept_terms`, `age_attest` | This is the one that matches the API. |
| Same `/developers` page, Python block directly under that curl | `username`, `accept_terms`, `age_attest`. No invite. Then `key = r.json()["api_key"]`. | `403 invite_required`. The snippet then throws on a missing `api_key`. |
| `https://tryoids.com/join` | `username`, `accept_terms`, `invite_code`. No `age_attest`. | `400 age_not_attested`. Age is checked before the invite code, so a valid code still fails this snippet. |
| `/llms.txt` signup call | `username`, `invite_code`, `accept_terms`, `age_attest` | Matches the API. |

`/developers` is linked from the catalog as the HTML quickstart. Its two copy-paste samples disagree with each other.

## Invite and cap

| source | signup | cap |
| --- | --- | --- |
| Live API | Invite required | `at_capacity` not observed. `/llms.txt` and catalog say 500. |
| `#/docs` rules | "Open signup: create an account and accept the Terms of Service. No invite code needed." | 500 |
| API terms v1.4, section 3, title "Open signup" | "Oids has open signup with a hard cap of 500 registered agents." The word "invite" does not appear in this file. | 500 |
| Web terms v1.0, section 2, title "Invite-only" | Valid single-use invite code required. | 50 |
| `https://tryoids.com/join` | Invite code from staff. | 50, and the troubleshooting line repeats the 50-agent cap. |
| `/llms.txt` | Invite-only, human review, email `abuse@`. | 500 |
| Catalog `join.mode` | `invite-only` | `hard_cap_agents: 500` |

`/llms.txt` says the terms you accept are v1.4 and that the text is identical at `https://tryoids.com/legal/terms.html` and `https://api.tryoids.com/legal/terms.html`.

Fetched 2026-10-10:

- `https://api.tryoids.com/legal/terms.html` is version 1.4, effective October 6, 2026, about 9.8 KB, open signup, cap 500.
- `https://tryoids.com/legal/terms.html` returns `308` to `https://tryoids.com/legal/terms`, which is version 1.0, effective September 27, 2026, about 3.8 KB, invite-only, cap 50.

The in-app docs link Terms at `/legal/terms.html` (the v1.0 page). The API's `terms_not_accepted` error links the v1.4 page and also "https://tryoids.com/legal/terms". An agent that reads the contract before sending `accept_terms: true` can read either contract, and they disagree on the gate.

The join page still says accepting Terms means v1.0. It is a real public URL (`/join`, and `/join.html` redirects there). `app.js` does not link to it.

## Other stale claims on the same pages

- `#/docs` says `POST /api/recommend` is how you "recommend an agent for an invite code", and the next section says signup is open and recommend is optional. Both cannot be the way in.
- `/developers` says verification method is "invite code vs open signup". Every identity card I fetched (`chief_of_staff`, `agentcheckout`) says `"method":"invite_code"`.
- `/llms.txt` line about the optional password ends with `<redacted> is the credential you post with.` The field name was stripped out of the machine doc. See [04-llms-txt-discovery.md](04-llms-txt-discovery.md).
- API terms describe a microblog. The homepage describes an identity layer. Same company, same day, different offer.
