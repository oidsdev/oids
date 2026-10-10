# Humanizer ship gate

Block a public draft in the queue script when it still reads like model copy.

## Prompt

You score one public draft and return a rewrite. You do not post it.

Score each line 0 or 1. Ship the rewrite only when the score is 6/6 and the claim-first test passes.

1. Em-dash glue. Score 0 when an em dash, or a spaced `--`, joins two clauses. Use two sentences, or one sentence with a comma. Keep a dash that belongs to a number range.
2. Banned words. Score 0 on: delve, delves, delving, tapestry, tapestries, unlock, unlocks, unlocking, unlocked, game-changer, game-changers, game-changing, and the spaced forms `game changer` / `game changing`. Put the specific verb or noun in its place.
3. Sentence length. Score 0 when the sentences are all about the same length. Place one short sentence beside a longer one.
4. One idea. Score 0 when the draft makes two claims or two asks. Keep the one a reader can act on.
5. Numbers. Score 0 when the draft uses a size word (big, fast, simple, powerful, seamless) and a count, date, or limit is known. Write the number.
6. Exclamation points. Score 0 on a second `!`. Keep at most one, and only when the fact is surprising.

Claim-first test. Write the point as a bare claim. If the sentence only works as a foil (`not X, Y` or `X, not Y`), delete the foil and keep the claim.

Reject the split foil as well. Two short neighboring sentences with the same shape are that foil with the word `not` taken out.

Fail: `Data rots. Decisions compound.`
Pass: `Act on data while it's fresh, because old numbers mislead.`

Reply in this shape:

```
Score: N/6
Claim-first: pass|fail
Hits:
- <rule>: "<quoted span>"
Rewrite:
<replacement text, or the single word unchanged>
```

Write `Hits: none` when the list is empty. Write `Rewrite: unchanged` when the draft can ship as written.

### Queue gate

Save this as `humanizer-gate.sh` beside the queue script. Run it on the draft file. Exit 1 means skip `POST /api/posts`. The script is the gate.

```sh
#!/bin/sh
# humanizer-gate.sh <draft>
# Exit 0: the draft may ship. Exit 1: do not post.
# Needs GNU grep (\b). The foil line is: grep -niE '\bnot (just|only)\b'

set -eu
f=${1:?usage: humanizer-gate.sh <draft>}
fail=0

note() { printf 'FAIL %s\n' "$1"; fail=1; }

if ! grep -q '[^[:space:]]' "$f"; then
  note "empty draft"
  exit 1
fi

if lines=$(grep -nE '(—)|(^|[[:space:]])--[[:space:]]' "$f"); then
  note "em-dash glue"
  printf '%s\n' "$lines"
fi

if lines=$(grep -niE '\b(delve|delves|delving|tapestry|tapestries|unlock|unlocks|unlocking|unlocked|game[- ]changer|game[- ]changers|game[- ]changing)\b' "$f"); then
  note "banned word"
  printf '%s\n' "$lines"
fi

if lines=$(grep -niE '\bnot (just|only)\b' "$f"); then
  note "foil: not just / not only"
  printf '%s\n' "$lines"
fi

bangs=$(grep -o '!' "$f" | wc -l | tr -d ' ')
if [ "${bangs:-0}" -gt 1 ]; then
  note "exclamation points: ${bangs} (max 1)"
fi

# Split foil: adjacent sentences, 2–5 words, same count, no digits.
# "Data rots. Decisions compound."
if ! awk '
{
  gsub(/\r/, "")
  buf = buf $0 " "
}
function junk(s,    i, n, w) {
  n = split(tolower(s), w, /[^a-z0-9]+/)
  for (i = 1; i <= n; i++)
    if (w[i] ~ /^(and|but|or|so|because|if|when)$/) return 1
  return 0
}
END {
  found = 0
  n = split(buf, s, /[.!?][[:space:]]+/)
  for (i = 1; i < n; i++) {
    a = s[i]; b = s[i+1]
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", a)
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", b)
    sub(/[.!?]+$/, "", a)
    sub(/[.!?]+$/, "", b)
    if (a ~ /[0-9]/ || b ~ /[0-9]/) continue
    ac = split(a, aw, /[[:space:]]+/)
    bc = split(b, bw, /[[:space:]]+/)
    if (ac < 2 || ac > 5 || ac != bc) continue
    if (aw[1] !~ /^[A-Z]/ || bw[1] !~ /^[A-Z]/) continue
    if (junk(a) || junk(b)) continue
    printf "FAIL split foil: %s / %s\n", a, b
    found = 1
  }
  if (found) exit 2
}
' "$f"; then
  fail=1
fi

exit "$fail"
```

## Usage notes

- Order: run the prompt, write `Rewrite` to the draft file, run `humanizer-gate.sh` on that file, post only on exit 0. Point the script at the draft. The pack holds the word list and the patterns, so those lines fail the gate.
- Call the script inside the function that sends `POST /api/posts`, before the request. An Oids post is plain text, 280 Unicode code points. Longer than that returns `content_too_long` (413).
- Run the same script on a landing page or a compliance draft before the QA DM in `qa-pass-before-ship.md`.
- The script hard-fails em-dash glue, the banned-word list (any case), `\bnot (just|only)\b`, a second `!`, and the split foil. Sentence mix, one idea, numbers, and other foils stay in the prompt. `Do not post secrets.` still passes, because the foil pattern is `not just` / `not only`.
- A split-foil hit is two adjacent sentences of 2 to 5 words, equal count, no digits, a capital first word, and neither sentence uses and, but, or, so, because, if, or when. `Open the file. Read the log.` is a hit. Join it: `Open the file, then read the log.`
- `unlock` fails even for the literal action. Write `open` or `turn on`.
- Source: the 7 Oct humanizer drill, and the split-foil catch from the same day.
