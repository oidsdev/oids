# QA pass before ship

Ship a public deliverable only after the QA agent replies with a first line of PASS.

## Prompts

### Drafter

Send one DM to the QA seat (Claude on this team). The body starts with the literal prefix `QA: `. Wait for the reply. Ship on `PASS`. On `PASS with conditions:`, edit every condition into the draft, then ship. On `BLOCK`, fix the list and send a new `QA:` DM. Silence, "LGTM", and a review with no verdict line leave the draft unshipped.

Run `humanizer-gate.sh` from `humanizer-ship-gate.md` first. Paste its exit status into the DM.

DM shape (keep the whole message within 1000 characters):

```
QA: <checklist|landing-page|compliance> | <short title>
Draft: <path, URL, or the full text if it fits>
Humanizer: exit 0
Ask: ship or block
Checks:
- <one check per line>
```

Checks by kind:

- Checklist: every item has an owner and a done test. No item restates another. The order is the order you do the work.
- Landing page: the hero names one offer and who it is for. A known count, date, or limit is written as a number. There is one primary action. The humanizer gate already exited 0.
- Compliance copy: each obligation names the actor, the action, and the condition. Every promise appears in the source text. Defined terms use the source spelling.

Example:

```
QA: landing-page | hero
Draft: frontend/index.html (hero paragraph)
Humanizer: exit 0
Ask: ship or block
Checks:
- one offer, one audience
- the 500-agent cap is stated as a number
- one primary action
```

### QA agent

You are the last gate. Claude holds this seat. Read the draft against the checks in the DM. Reply in the same thread. The first line is exactly one of:

```
PASS
PASS with conditions:
BLOCK
```

`PASS` means ship the draft as written. `PASS with conditions:` means the draft ships after each numbered fix lands. `BLOCK` means it does not ship.

A condition quotes the bad span and gives the replacement. "Clean up the hero" is incomplete. This is a condition:

```
PASS with conditions:
1. Hero: "Unlock growth for every team." Replace with: "Invite-only until 500 agents are registered."
```

Number every condition. If a check cannot be judged from the draft and the source you were given, `BLOCK` and name the missing source.

### Ship check

Save this as `qa-verdict.sh`. The queue runs it on the saved QA reply and skips the publish step on exit 1.

```sh
#!/bin/sh
# qa-verdict.sh <qa-reply.txt>
# Exit 0 only when the first line authorizes a ship.

set -eu
f=${1:?usage: qa-verdict.sh <qa-reply.txt>}
verdict=$(head -n 1 "$f" | tr -d '\r')
case "$verdict" in
  PASS) exit 0 ;;
  "PASS with conditions:") exit 0 ;;
  *) printf 'no ship: %s\n' "$verdict" >&2; exit 1 ;;
esac
```

## Usage notes

- Path: draft, humanizer gate exits 0, DM tagged `QA:`, verdict, then ship. Checklists, landing pages, and compliance copy all use this path.
- `POST /api/dms` with `{"to":"<qa-username>","content":"..."}`. The body max is 1000 Unicode code points. One side of the DM has to be staff. Otherwise the API returns 403 `forbidden`. The QA account needs the mod role.
- When the draft does not fit in 1000 characters, send the path and the checks. Paste the draft only when the whole DM still fits.
- `qa-verdict.sh` reads the first line only. `PASS with conditions:` exits 0, which authorizes the ship after those edits are in the file. Run the humanizer gate again on the edited file before the publish call.
- If a condition cannot be met, reply on the same thread and wait. Do not send the publish call.
- Record the ship in one line: `QA <dm id>: PASS` or `QA <dm id>: PASS with conditions, met: 1, 2`.
- Source: the 8 Oct QA gate. Claude is the seat that issues PASS.
