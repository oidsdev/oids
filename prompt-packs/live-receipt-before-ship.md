# Live receipt before ship

Call a launch PASS only when curl receipts show the live URL serving this commit.

## Prompts

### Verifier

You are Dot. Muse deploys. You curl the live origin. Claude's sandbox cannot open sites, so the curls are yours.

Write one punchlist. Each finding has evidence, one fix, an acceptance check, and a status.

Evidence is the command and the output you captured. A commit hash shows the repo moved. PASS waits for the live curl.

The acceptance check is curl of the live URL: status, then `cf-cache-status`, `age`, and `cache-control`. Paste that output under the finding.

```
Launch: <name>
Commit: <sha>
Origin: <url>
Checked: <time>
Findings:
1. <title>
   Evidence: <command and output>
   Fix: <one change>
   Accept: <curl and the result that closes it>
   Status: OPEN|CLOSED
Generator: <path patched in this change, or none>
History: retain | rewrite | n/a
Verdict: PASS|HOLD
```

Status CLOSED carries that acceptance curl and the result matches. A repo diff, a deploy log, or a dashboard shot leaves the finding OPEN.

Write `Generator: none` only when nothing regenerates the public tree. When `gen.py` or another generator writes the site, patch it in the same change and name the path. On the Honeypot launch the generator had to drop `submitters.md` and include `/dots`. Run that regen, then curl again. An unpatched generator keeps the launch on HOLD, because the next regen puts the file back.

Write `History: n/a` when this launch removes no public file. When it removes one, write `retain` or `rewrite`. A move into `internal/` on a public repo leaves the file on the origin and in git history. Record the history decision in the receipt. Leave the rewrite itself to the human who owns the repo.

HOLD when any finding is OPEN, when the generator is unpatched, or when a removed public file still says `History: n/a`.

Worked failure, 11 Oct, commit `08a78c9`, curls between 18:32 and 18:55: `submitters.md` returned HTTP 200 with `cf-cache-status: HIT`, `age: 8252`, and `s-maxage=604800`. That object does not expire in time for a launch. Purge the URL, then curl again. The pre-purge response stays OPEN.

### Copy rulings

You are Claude. Judge each public claim. The launch PASS comes from `live-receipt.sh`, after your rulings are all `pass`.

```
- <claim>: pass | <curl status and the header or body span>
- <claim>: conditions | 1. "<bad span>" Replace with: "<replacement>" | receipt still open
- <claim>: uncertain | missing <source>
```

A claim with no live receipt is `uncertain`. `conditions` and `uncertain` hold the launch. The 11 Oct line "all MIT" closed only with a curl showing the phrase gone from the served page.

### Shipper

You are Muse. Land the repo change and the deploy. Write this receipt. The PASS line belongs to the script.

```
Deploy: <sha>
Origin: <url>
At: <time>
Id: <deployment id>
Purged: <url, or none>
```

When the curl shows `cf-cache-status: HIT` with an `age` in the thousands and `s-maxage=604800`, purge that URL, then hand the spec to the verifier.

### Queue gate

Save this as `live-receipt.sh`. The queue runs it on a spec file and skips the ship post on exit 1. The last line is `PASS` or `HOLD`.

One check per line. Blank lines and `#` comments are ignored.

```
status <code> <url>
fresh <max-age-seconds> <url>
body-absent <url> <literal text>
deploy <url> <header-name> <id>
```

`fresh` fails when the HTTP status is anything other than 200, or when `cf-cache-status` is `HIT` and `age` is missing or greater than the max. Use `120` after a purge. `deploy` passes only when that response header equals the id in the shipper receipt. Add a `deploy` line when the origin echoes the id. The status, fresh, and body lines are the receipt either way.

Receipt lines contain the HTTP status and the cache headers from the first response.

```sh
#!/bin/sh
# live-receipt.sh <spec>
# Exit 0 and print PASS when every curl check matches.
# Exit 1 and print HOLD when any receipt fails, or the spec has no checks.
# Needs curl. No redirect follow. Response body is kept for the check and left out of the log.

set -eu
spec=${1:?usage: live-receipt.sh <spec>}
fail=0
checks=0
n=0
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

note() { printf 'FAIL %s\n' "$1"; fail=1; }
ok() { printf 'OK %s\n' "$1"; }

header_value() {
  awk -v name="$2" '
    BEGIN { want = tolower(name) }
    {
      sub(/\r$/, "")
      sep = index($0, ":")
      if (sep < 2) next
      key = tolower(substr($0, 1, sep - 1))
      if (key != want) next
      val = substr($0, sep + 1)
      sub(/^[[:space:]]+/, "", val)
      sub(/[[:space:]]+$/, "", val)
      print val
      exit
    }
  ' "$1"
}

fetch() {
  n=$((n + 1))
  hdr="$tmpdir/$n.hdr"
  body="$tmpdir/$n.body"
  # Called directly so hdr, body, and http stay in this shell.
  http=$(curl -sS --max-time 20 --max-filesize 2000000 \
    -D "$hdr" -o "$body" -w '%{http_code}' "$1") || return 1
  return 0
}

trim() {
  t=$1
  while :; do
    case "$t" in
      [[:space:]]*) t=${t#?} ;;
      *) break ;;
    esac
  done
  while :; do
    case "$t" in
      *[[:space:]]) t=${t%?} ;;
      *) break ;;
    esac
  done
  printf '%s' "$t"
}

while IFS= read -r raw || [ -n "$raw" ]; do
  line=$(trim "$(printf '%s' "$raw" | tr -d '\r')")
  case "$line" in
    ''|'#'*) continue ;;
  esac
  cmd=${line%% *}
  rest=${line#* }
  checks=$((checks + 1))
  case "$cmd" in
    status)
      code=${rest%% *}
      url=${rest#* }
      case "$code" in
        [0-9][0-9][0-9]) ;;
        *) note "status bad code [$code]"; continue ;;
      esac
      if [ "$url" = "$code" ]; then
        note "status missing url"
        continue
      fi
      if ! fetch "$url"; then
        note "status curl $url"
        continue
      fi
      if [ "$http" = "$code" ]; then
        ok "status $code $url"
      else
        note "status $url got=$http want=$code"
      fi
      ;;
    fresh)
      max=${rest%% *}
      url=${rest#* }
      case "$max" in
        *[!0-9]*|'') note "fresh bad max [$max]"; continue ;;
      esac
      if [ "$url" = "$max" ]; then
        note "fresh missing url"
        continue
      fi
      if ! fetch "$url"; then
        note "fresh curl $url"
        continue
      fi
      if [ "$http" != "200" ]; then
        note "fresh $url http=$http"
        continue
      fi
      cache=$(header_value "$hdr" cf-cache-status || true)
      age=$(header_value "$hdr" age || true)
      cc=$(header_value "$hdr" cache-control || true)
      cache_lc=$(printf '%s' "$cache" | tr '[:upper:]' '[:lower:]')
      if [ "$cache_lc" = "hit" ]; then
        case "$age" in
          *[!0-9]*|'')
            note "fresh $url HIT age=${age:-missing} cache-control=${cc:-none}"
            ;;
          *)
            if [ "$age" -gt "$max" ]; then
              note "fresh $url HIT age=$age max=$max cache-control=${cc:-none}"
            else
              ok "fresh $url HIT age=$age max=$max cache-control=${cc:-none}"
            fi
            ;;
        esac
      else
        ok "fresh $url cf-cache-status=${cache:-none} age=${age:-none} cache-control=${cc:-none}"
      fi
      ;;
    body-absent)
      url=${rest%% *}
      literal=${rest#* }
      if [ "$literal" = "$url" ]; then
        note "body-absent needs a url and a literal"
        continue
      fi
      if ! fetch "$url"; then
        note "body-absent curl $url"
        continue
      fi
      if grep -F -q -e "$literal" "$body"; then
        note "body-absent $url http=$http still has: $literal"
      else
        ok "body-absent $url http=$http absent: $literal"
      fi
      ;;
    deploy)
      url=${rest%% *}
      tail=${rest#* }
      hname=${tail%% *}
      id=${tail#* }
      if [ "$url" = "$rest" ] || [ "$hname" = "$tail" ] || [ "$id" = "$hname" ]; then
        note "deploy needs url, header, id"
        continue
      fi
      if ! fetch "$url"; then
        note "deploy curl $url"
        continue
      fi
      got=$(header_value "$hdr" "$hname" || true)
      if [ -n "$got" ] && [ "$got" = "$id" ]; then
        ok "deploy $url http=$http $hname=$got"
      else
        note "deploy $url http=$http $hname=${got:-missing} want=$id"
      fi
      ;;
    *)
      note "unknown check [$cmd]"
      ;;
  esac
done < "$spec"

if [ "$checks" -eq 0 ]; then
  note "no checks"
fi

if [ "$fail" -eq 0 ]; then
  printf 'PASS\n'
  exit 0
fi
printf 'HOLD\n'
exit 1
```

## Usage notes

- Order: shipper receipt, spec file, `live-receipt.sh`, copy rulings, then the ship post. Exit 1 skips the post.
- Announcement copy still runs `humanizer-gate.sh` and the QA DM in `qa-pass-before-ship.md`. This pack checks the origin.
- An empty spec, or a spec of only comments, exits 1.
- `body-absent` matches the literal exactly, including case. Use the span you saw on the served page.
- Curl stops at 20 seconds and at 2,000,000 bytes. A transfer past either limit is a FAIL.
- Sample spec for the 11 Oct hold:

```
status 404 https://honeypot-e6c.pages.dev/submitters.md
fresh 120 https://honeypot-e6c.pages.dev/
body-absent https://honeypot-e6c.pages.dev/ all MIT
```

- Record the ship in one line: `Live <sha>: PASS`, then the script's OK lines.
- Source: the 11 Oct Honeypot launch audit. Dot ran the live checks, Muse shipped the repo and the deploy, Claude kept the rulings log.
