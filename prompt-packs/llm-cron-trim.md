# LLM cron trim

Run scheduled model check-ins on four ET windows, on Sonnet.

## Prompt

You migrate one LLM cron onto the schedule file below. Keep the run count at 4.

List the current runs first: name, cadence, model, room. Then map each one.

- A check-in folds into the four windows. The model line is `sonnet`.
- An hourly check-in maps to `off hourly`.
- Live-desk in room 7 maps to `off live-desk room 7`.
- The KDP watch maps to `off kdp-watch`.
- A QA submission maps to `bounce qa`. It waits for the next window.

The windows are 09:00, 12:00, 15:00, and 18:00 in `America/New_York`. That clock is ET, including the DST shift. Store those local times. `0 13 * * *` matches 09:00 during EDT and misses it during EST, so leave UTC crons out of this file.

Keep every `off` line in the file. The next edit needs the line so the job stays off. The Honeypot generator put a deleted page back because the generator still emitted it. A dropped `off` line does the same thing to a cron.

Write this block. `#` comments may sit above it. The ten lines are the whole schedule.

```
tz America/New_York
model sonnet
window 09:00
window 12:00
window 15:00
window 18:00
off hourly
off live-desk room 7
off kdp-watch
bounce qa
```

The scheduler reads those ten lines and converts the four clock times in `America/New_York`. QA submissions bounce. The next of 09:00, 12:00, 15:00, and 18:00 reads the queue.

### Queue gate

Save this as `cron-trim.sh`. Run it on the schedule file before the scheduler is enabled. Exit 1 means the new scheduler stays off.

```sh
#!/bin/sh
# cron-trim.sh <schedule>
# Exit 0 and print PASS when the file matches the 10-11 Oct trim.
# Exit 1 and print FAIL lines, then HOLD.
# Blank lines and # comments are ignored. Every other line is matched in order.

set -eu
f=${1:?usage: cron-trim.sh <schedule>}
if [ ! -f "$f" ]; then
  printf 'FAIL missing file\nHOLD\n'
  exit 1
fi

expected=$(cat <<'EOF'
tz America/New_York
model sonnet
window 09:00
window 12:00
window 15:00
window 18:00
off hourly
off live-desk room 7
off kdp-watch
bounce qa
EOF
)

got=$(awk '
  { sub(/\r$/, "") }
  /^[[:space:]]*#/ { next }
  /^[[:space:]]*$/ { next }
  {
    sub(/^[[:space:]]+/, "")
    sub(/[[:space:]]+$/, "")
    print
  }
' "$f")

if [ "$got" = "$expected" ]; then
  printf 'PASS\n'
  exit 0
fi

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT
printf '%s\n' "$expected" > "$tmpdir/expected"
printf '%s\n' "$got" > "$tmpdir/got"

awk '
  BEGIN { en = 0; gn = 0 }
  NR == FNR { want[NR] = $0; en = NR; next }
  { have[FNR] = $0; gn = FNR }
  END {
    n = en
    if (gn > n) n = gn
    for (i = 1; i <= n; i++) {
      e = want[i]
      g = have[i]
      if (e == "") e = "<missing>"
      if (g == "") g = "<missing>"
      if (e != g) printf "FAIL line %d: got [%s] want [%s]\n", i, g, e
    }
  }
' "$tmpdir/expected" "$tmpdir/got"

printf 'HOLD\n'
exit 1
```

## Usage notes

- The cap is 4 model runs a day. Check-ins were about 26 a day before this trim. A fifth `window` line fails the script.
- The `model` line is the word `sonnet`. Map the scheduler's Sonnet id to that line.
- `bounce qa` queues a QA submission for 09:00, 12:00, 15:00, or 18:00 `America/New_York`. The submission waits for that window.
- Enable the scheduler only after `cron-trim.sh` prints PASS. Until then the old hourly, room 7, and KDP triggers stay disabled.
- Record the cut in one line: `Cron trim: PASS, 4 windows, sonnet`.
- Source: Dave's trim on 10 and 11 Oct. Hourly check-ins, live-desk room 7, and the KDP watch went off. The remaining check-ins run at those four times.
