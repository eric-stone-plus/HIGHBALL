#!/bin/bash
# BANNIN (番人) — push gate guard for KENGEN
# Part of HIGHBALL: https://github.com/eric-stone-plus/HIGHBALL
#
# Three integration tiers (see README § KENGEN for context):
#   Tier 1 — git pre-push hook: cp to .git/hooks/pre-push
#   Tier 2 — shell wrapper: alias git='bannin-push-guard --wrap git'
#   Tier 3 — Hermes plugin (future, requires Hermes plugin API)
#
# AUTHORIZATION CHECK (two-tier):
#   1. Session marker file /tmp/hermes-push-auth-* (fast path)
#      Written by Hermes when it detects user authorization keywords.
#   2. Session DB sqlite3 query (fallback)
#      Searches current session for user messages with push/推送/推.
#
# BEHAVIOR: Unauthorized → blocked with explanation to stderr, exit 1.
#           BANNIN never asks the agent to solicit authorization.

set -euo pipefail

HERMES_PROFILE="${HERMES_PROFILE:-technical}"
HERMES_DB="${HOME}/.hermes/profiles/${HERMES_PROFILE}/sessions.db"
AUTH_KEYWORDS=("push" "推送" "推")
AUTH_WINDOW=300  # seconds

check_marker() {
    local now=$(date +%s)
    for f in /tmp/hermes-push-auth-*; do
        [[ -f "$f" ]] || continue
        local age=$((now - $(stat -f %m "$f" 2>/dev/null || stat -c %Y "$f" 2>/dev/null || echo 0)))
        [[ $age -lt $AUTH_WINDOW ]] && return 0
    done
    return 1
}

check_session() {
    [[ -f "$HERMES_DB" ]] || return 1
    command -v sqlite3 &>/dev/null || return 1

    local pattern=""
    for kw in "${AUTH_KEYWORDS[@]}"; do
        [[ -n "$pattern" ]] && pattern="${pattern} OR "
        pattern="${pattern}content LIKE '%${kw}%'"
    done

    local found=$(sqlite3 "$HERMES_DB" \
        "SELECT COUNT(*) FROM messages 
         WHERE role='user' AND (${pattern})
         AND session_id = (SELECT id FROM sessions ORDER BY updated_at DESC LIMIT 1)" 2>/dev/null || echo "0")
    [[ "$found" -gt 0 ]] && return 0
    return 1
}

block() {
    cat >&2 << 'EOF'

╔══════════════════════════════════════════════════════╗
║  KENGEN · BANNIN — PUSH BLOCKED                     ║
╠══════════════════════════════════════════════════════╣
║  git push requires explicit user authorization.      ║
║  Keywords: push / 推送 / 推  not found in session.    ║
║  BANNIN blocks silently — agent cannot solicit.      ║
║  HIGHBALL · https://github.com/eric-stone-plus/HIGHBALL
╚══════════════════════════════════════════════════════╝

EOF
    exit 1
}

case "${1:-}" in
    --wrap) shift; [[ "$*" =~ push ]] && { check_marker || check_session || block; }; exec "$@" ;;
    *)      { check_marker || check_session || block; }; exit 0 ;;
esac
