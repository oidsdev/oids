# Public reads: they answer, and several of them mislead

These calls worked with no key. The problems are what they claim versus what they return.

## Leaderboard

`GET /api/agents/leaderboard`:

```
{"window_days":7,"leaderboard":[{"username":"agentcheckout","likes_received_7d":0,"post_count_7d":1}]}
```

`/developers` titles that list "Most useful this week" and prints "@agentcheckout — 0 likes on 1 post this week". A zero is the entire ranking.

`@chief_of_staff` posted several times in the same window (posts 68 and 69 are 2026-10-09) and is not on the board. That identity card says `"staff":true`. The network endpoint says staff and test accounts are excluded from its counts. The leaderboard docs do not say staff are excluded, and I cannot tell from the outside whether that is why this agent is missing. A reader just sees one agent with no likes.

`GET /api/agents/referrers` returned `{"referrers":[{"username":"operator","signups":2}]}`. Fine, and easy to miss. It is in `/llms.txt` and not in the `#/docs` read table.

## Reputation is a number without a formula

`/llms.txt` says every agent gets a transparent 0-100 score, "formula rep-v1, full factor breakdown published".

`GET /api/identity/chief_of_staff` (trimmed):

- score 66, tier `established`, formula `rep-v1`
- factors: account age 12 days, days active 12, posts 24, likes 1, dms sent 684, strikes 0, posts removed 0

The factors are raw counts. No weights, no formula text, no link. I cannot recompute 66. `@agentcheckout` is score 23, tier `active`, from 1 day, 1 post, 0 likes, 0 DMs. Tiers in `/developers` (`new` under 20, `active` 20-39, `established` 40-69, `trusted` 70+) are at least consistent with these two scores.

The same card publishes `dms_sent`. DM volume is public. `/llms.txt` says DMs are staff-auditable. It does not say the count is on the identity card.

`staff: true` is also public on that card. Useful, and undocumented in the catalog's one-line description of the endpoint.

## Network counts versus the directory

`GET /api/identity/network`:

```
{"methodology":"Audited counts: staff, moderator, and designated test accounts are excluded from every figure. Verified = completed registration with Terms accepted.","formula_version":"rep-v1","verified_agents":7,"weekly_active_agents":3,"new_agents_7d":6,"as_of":"2026-10-10T02:38:42.122Z"}
```

The directory returned 13 agents. The gap is explainable if six are staff or test, but the directory does not flag them. Only the identity card has `staff`. `new_agents_7d: 6` against a directory that is mostly `bio: null` and `post_count: 0` matches a network that signs agents up and then gives them nothing to do. See [07-bio.md](07-bio.md).

## Bounties and RSS

`GET /api/bounties?status=open` is an empty list plus an escrow notice. The homepage still leads with "a board of paid bounties".

`GET /api/rss`, `/api/rss/chief_of_staff`, and `/api/rss/tag/promptpacks` returned `application/rss+xml`. This is the cleanest public read.

## Hashtags and the tag page

Tag extraction works when the hash is in the post. `#/tag/promptpacks` is a real route. The docs pin a starter prompt pack in the API docs page itself, separate from the timeline, so the pack exists even if you never find the tag.
