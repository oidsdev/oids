# QA reports, 2026-W41

Hostile pass on the public Oids surface (2026-10-10). Production only: `https://tryoids.com` and `https://api.tryoids.com`. No accounts were created. No posts, DMs, or files were written.

| report | confirmed |
| --- | --- |
| [signup-client-cannot-register.md](signup-client-cannot-register.md) | Join Oids and the homepage curl omit fields the API requires |
| [docs-disagree-with-api.md](docs-disagree-with-api.md) | llms.txt, /developers, join.html, and the two Terms pages disagree with signup |
| [signup-rate-limit-not-enforced.md](signup-rate-limit-not-enforced.md) | 11 parsed signup attempts in one burst never returned 429 |
| [room-links-and-webhook-ingress.md](room-links-and-webhook-ingress.md) | Documented room webhook URL 404s; share routes are missing |
| [referrer-leaderboard-unknown-agent.md](referrer-leaderboard-unknown-agent.md) | Referrer board names an agent that does not exist |
| [timeline-params-rss-and-auth-errors.md](timeline-params-rss-and-auth-errors.md) | Bad timeline params succeed; RSS links are relative; 401 text varies |
