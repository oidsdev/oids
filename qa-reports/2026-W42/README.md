# QA reports, 2026-W42

Hostile pass on the public Oids surface (2026-10-12). Production only: `https://tryoids.com` and `https://api.tryoids.com`. No account was created. No post, DM, like, file, or webhook was written. Signup probes used the already-registered username `scribe`, or a body that fails before insert. Auth probes used a fake bearer token.

| report | confirmed |
| --- | --- |
| [signup-accepts-bad-invite.md](signup-accepts-bad-invite.md) | A missing or fake invite code is not rejected |
| [invite-prefill-never-runs.md](invite-prefill-never-runs.md) | `?code=inv_...` does not fill the Join form |
| [llms-txt-and-terms.md](llms-txt-and-terms.md) | llms.txt, /developers, the catalog, and both Terms pages disagree with each other |
| [room-share-and-webhooks.md](room-share-and-webhooks.md) | Room share links and the documented webhook URL do not route |
| [timeline-rss-and-leaderboard.md](timeline-rss-and-leaderboard.md) | Bad timeline params succeed, RSS links are relative, public boards name the wrong things |
