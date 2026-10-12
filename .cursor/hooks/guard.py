#!/usr/bin/env python3
"""Cursor project hook: guardrails for cloud agents in this repo.

Registered in .cursor/hooks.json for two events:
  - beforeShellExecution: deny merge commands, deny commands that touch
    trading / payment / credential paths, deny printing or uploading secrets.
  - beforeReadFile: deny reads of secret / trading / payment files.

Policy (team rule): agents deliver branches and PRs. They never merge,
never touch trading, payment, or credential material, and never print or
exfiltrate secrets. This hook turns those prompt-level rules into
enforcement. It is a guardrail, not a sandbox: it matches the literal
command string, so deliberate obfuscation can evade it. GitHub branch
protection remains the backstop for merges.

Protocol (Cursor hooks docs): JSON in on stdin, JSON decision on stdout.
Exit 0 always; the decision is carried by the JSON body.
"""

import json
import re
import sys

# ---------------------------------------------------------------------------
# Sensitive-path matching
# ---------------------------------------------------------------------------

# Venue / trading keywords: matched as a whole path segment or as a
# '-'/ '_'/' .'-delimited part of a segment (covers robinhood-agent,
# mac-trading-rig, kalshi_sweep.py).
VENUE_WORDS = {"trading", "robinhood", "kalshi", "polymarket", "coinbase"}

# Directory / file components that are always off limits.
BLOCKED_COMPONENTS = {
    "vault", "credentials",
    ".ssh", ".aws", ".gnupg", ".kalshi", ".cloudflare",
    ".netrc", ".dev.vars",
}

# Basenames treated as sensitive even when they appear without a slash.
SECRET_BASENAME_RE = re.compile(
    r"^(\.env($|\.)|credentials($|\.)|.*secret.*|.*\.pem$|.*\.key$"
    r"|.*\.p12$|.*\.pfx$|id_(rsa|ed25519|ecdsa|dsa)($|\.)|\.netrc$"
    r"|\.dev\.vars$|\.git-credentials$)"
)


def _segments(token):
    return [seg for seg in token.split("/") if seg not in ("", ".")]


def is_sensitive_path(token):
    """True if a command token points at a trading/payment/credential path."""
    t = token.split("=")[-1].strip(",;:\"'`")
    if not t or t.startswith("-"):
        return False
    segments = _segments(t)
    if not segments:
        return False
    basename = segments[-1].lower()
    if "/" not in t:
        # Bare word, not a path: only treat it as a sensitive file when it
        # actually looks like a filename (WEBHOOK_SECRET is an env var name
        # in a grep pattern, not a file).
        looks_like_file = (
            basename.startswith(".")
            or "." in basename
            or basename.startswith("id_")
            or basename == "credentials"
        )
        if not (looks_like_file and SECRET_BASENAME_RE.match(basename)):
            return False
    # gh's hosts.yml stores the OAuth token in plaintext.
    lowered = [seg.lower() for seg in segments]
    if basename == "hosts.yml" and "gh" in lowered[:-1]:
        return True
    in_hidden_dir = any(seg.startswith(".") and seg != ".." for seg in segments[:-1])
    for seg in segments:
        low = seg.lower()
        parts = [p for p in re.split(r"[-_.]", low) if p]
        if any(p in VENUE_WORDS for p in parts):
            return True
        if low in BLOCKED_COMPONENTS:
            return True
        if low.startswith(".env"):
            return True
        if "secret" in low:
            return True
        if low.startswith("credentials"):
            return True
        if low.startswith(("id_rsa", "id_ed25519", "id_ecdsa", "id_dsa")):
            return True
        if low.endswith((".pem", ".key", ".p12", ".pfx")):
            return True
        if "stripe" in low and any(w in low for w in ("key", "secret", "token")):
            return True
        if low == "token.json" and in_hidden_dir:
            return True
    return False


def command_tokens(command):
    return [tok for tok in re.split(r"[\s|;&<>()\"'`]+", command) if tok]


# ---------------------------------------------------------------------------
# Shell rules
# ---------------------------------------------------------------------------

MERGE_RULES = [
    (re.compile(r"\bgh\s+pr\s+merge\b", re.I),
     "PR merges are denied: agents open PRs, a human merges."),
    (re.compile(r"\bgh\s+api\b.*(/pulls/\d+/merge|mergePullRequest)", re.I),
     "Merging a PR through the GitHub API is denied."),
    (re.compile(r"\bgit\s+merge\b", re.I),
     "git merge is denied: deliver work as a branch + PR, never a merge."),
    (re.compile(r"\bgit\s+push\b[^|;&]*(?::|\s)(main|master)(?=[\s:]|$)", re.I),
     "Pushing directly to main/master is denied: open a PR instead."),
]

SECRET_RULES = [
    (re.compile(r"\bgh\s+auth\s+token\b", re.I),
     "Printing an auth token is denied."),
    (re.compile(r"\bwrangler\s+secret\b", re.I),
     "Managing deployed secrets is denied."),
    (re.compile(r"\b(echo|printf)\b[^|;&]*\$\{?[A-Za-z0-9_]*"
                r"(KEY|TOKEN|SECRET|PASSWORD|PASSWD)[A-Za-z0-9_]*", re.I),
     "Printing secret environment variables is denied."),
    (re.compile(r"\bprintenv\b[^|;&]*\b[A-Za-z0-9_]*"
                r"(KEY|TOKEN|SECRET|PASSWORD|PASSWD)[A-Za-z0-9_]*", re.I),
     "Printing secret environment variables is denied."),
    (re.compile(r"^\s*(env|printenv)\s*$", re.I),
     "Dumping the whole environment is denied."),
]


def check_shell(command):
    """Return a deny reason, or None to allow."""
    for pattern, reason in MERGE_RULES + SECRET_RULES:
        if pattern.search(command):
            return reason
    for token in command_tokens(command):
        if is_sensitive_path(token):
            return ("Command touches a trading, payment, or credential "
                    "path (%s): denied." % token.split("=")[-1])
    return None


def check_read(file_path):
    """Return a deny reason, or None to allow."""
    if file_path and is_sensitive_path(file_path):
        return "Reading secret, trading, or payment files is denied."
    return None


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    try:
        data = json.load(sys.stdin)
    except Exception:
        data = {}

    event = data.get("hook_event_name", "")

    if "command" in data or event == "beforeShellExecution":
        reason = check_shell(data.get("command") or "")
        if reason:
            print(json.dumps({
                "permission": "deny",
                "user_message": "Blocked by repo guardrail hook: " + reason,
                "agent_message": (
                    "This command was denied by the repo's Cursor guardrail "
                    "hook (.cursor/hooks/guard.py). " + reason +
                    " Do not work around it; note the block in your summary "
                    "and continue with other work."),
            }))
        else:
            print(json.dumps({"permission": "allow"}))
        return

    # beforeReadFile: fields are file_path (+ attachments). Deny if the
    # target file or any attachment is a sensitive path.
    paths = []
    if data.get("file_path"):
        paths.append(data["file_path"])
    for att in data.get("attachments") or []:
        if isinstance(att, dict) and att.get("file_path"):
            paths.append(att["file_path"])
    for path in paths:
        reason = check_read(path)
        if reason:
            print(json.dumps({
                "permission": "deny",
                "user_message": "Blocked by repo guardrail hook: " + reason,
            }))
            return
    print(json.dumps({"permission": "allow"}))


if __name__ == "__main__":
    main()
