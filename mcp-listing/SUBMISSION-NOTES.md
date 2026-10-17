# Submission notes — what is left, and who has to do it

Status on 2026-10-17: pack complete, nothing submitted. No submission was
attempted programmatically, for the reasons in step 0. Nothing here needs
new code; the blockers are a deploy decision and two interactive account
sign-ins that belong to David (or Muse acting in David's signed-in
browser).

## Step 0 — point the public endpoint at the public server (Muse / David)

The listing names `https://api.tryoids.com/mcp` as the remote endpoint.
Today that route answers with the team-internal worker (token-gated,
acts as @dot). Before any registry submission:

- Deploy `connectors/muse/mcp-server.js` (this repo) as the worker on the
  `api.tryoids.com/mcp` route. It is secret-free; per-user auth is the
  caller's own Oids API key.
- Move the team worker to its own route (for example
  `https://api.tryoids.com/mcp-dot` or its workers.dev URL) so @dot keeps
  working, and update the team's MCP client config to the new URL.
- Verify after the swap: `GET /mcp` returns 405, and a JSON-RPC
  `tools/list` POST returns the 17 public tools with no auth.

Submitting before this swap would register metadata for an endpoint that
does not match it. Do not submit first and fix later.

## Step 1 — official MCP Registry (David's GitHub sign-in)

The registry ties the namespace `io.github.oidsdev/oids` to the GitHub
account that owns the oidsdev org/repo. Publishing is an interactive
GitHub OAuth flow; there is no API key or bot token path for a first
publish, and the `mcp-publisher` CLI is not installed in this workspace.

Exact steps for whoever runs it (with David's GitHub session):

1. Install the publisher: `brew install mcp-publisher` (or download from
   the modelcontextprotocol/registry releases).
2. From this directory: `mcp-publisher login github` and complete the
   device sign-in as the oidsdev owner.
3. `mcp-publisher publish server.json` (validates against the registry
   schema first; `server.json` in this pack is ready to hand to it).
4. Confirm the listing at https://registry.modelcontextprotocol.io
   (search "oids") and record the registry URL in this file.

## Step 2 — Claude Directory (David's Claude account action)

Anthropic's connector directory submission is a web form tied to a
Claude account; it cannot be filed from this workspace.

Exact steps:

1. Sign in at claude.com with the account that will own the listing.
2. Open the Connectors directory submission flow (Settings → Connectors →
   submit a connector, or the directory submission form linked from
   docs.claude.com/connectors). 
3. Paste the fields from `claude-directory.md` in this pack: name,
   tagline, description, categories, endpoint URL, auth description,
   privacy and terms links, support contact, and upload `icon.svg`.
4. Submit and record the confirmation in this file.

## After both submissions

- Host `icon.svg` at https://tryoids.com/.well-known/oids-icon.svg so the
  registry icon URL in server.json resolves.
- Add the registry listing URLs to the Oids developers page and llms.txt
  in a follow-up PR.
