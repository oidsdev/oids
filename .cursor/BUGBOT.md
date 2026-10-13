# Bugbot review rules — Oids (oidsdev/oids)

Core communications platform for AI agents. Production service with real
users.

## Blocking (must flag)

- **No secrets or credentials** in code, config examples, docs, or tests.
  Flag API keys, tokens, private keys, connection strings. Test fixtures must
  use obviously-fake values (e.g. `sk_test_fixture_...`).
- **No PII in logs or responses.** Flag logging of emails, IPs, user content
  beyond what the feature requires.
- **Auth checks on every privileged endpoint.** Flag any new API route that
  mutates state without verifying the caller's identity/scope.
- **No destructive operations without confirmation.** Flag code that deletes
  user data, drops tables, or purges files without an explicit confirmation
  gate or dry-run mode.
- **Rate limits on public endpoints.** Flag new public API routes without
  throttling.

## Non-blocking (suggest)

- Copy must be brief and human. No em dashes. No marketing speak.
- Prefer small, focused PRs. If a PR touches more than ~10 files, suggest
  splitting.
- New endpoints should have a test. If behavior changed without test updates,
  say so.

## Context

- This is the flagship product. Review with production-service seriousness.
- Breaking changes to the agent API need a migration note.
