#!/usr/bin/env bash
# bannin.sh — BANNIN Tier 2 shell guard (HIGHBALL)
#
# Standalone session guard. No Hermes plugin API required.
#
# Scans session log for trigger phrases that indicate protected engineering
# changes require QUINTE review: "全量 quinte", "architecture decision",
# "protocol change"
#
# Checks for recent QUINTE verdict files when the host provides a verdict root.
# When a verdict contains a residual closure ledger, BANNIN enforces high-risk closure:
# HIGH/CRITICAL/P0 findings must be closed, blocked, waived, or not applicable
# with adequate closure evidence and scope.
#
# Returns:
#   0 — no blocking condition
#   1 — block: protected engineering write detected without verdict trail
#
# Usage:
#   bannin.sh --check /path/to/session.log
#
# Example:
#   bannin.sh --check /tmp/session.log
#   if [ $? -eq 1 ]; then echo "BLOCKED by BANNIN"; fi
#
# Architecture-critical patterns:
#   $WORKSPACE_ROOT/{QUINTE,RASHOMON,HIGHBALL,MAGI}/(README.md|specs/*.md|scripts/*.py|lib/*.sh)
#   host Hermes profile SOUL.md
#   plus git push/commit targeting them

set -euo pipefail

CRITICAL_REGEX='(QUINTE|RASHOMON|HIGHBALL|MAGI)/(README|specs/|scripts/|lib/)|SOUL\.md|git (push|commit).* (QUINTE|RASHOMON|HIGHBALL|MAGI)'
TRIGGER_REGEX='全量 quinte|architecture decision|protocol change'

usage() {
  echo "Usage: $(basename "$0") --check <session.log>"
  echo "Example: bannin.sh --check /path/to/session.log"
  exit 2
}

check_verdict_trail() {
  local today
  today="$(date +%Y-%m-%d)"
  local roots=()

  [ -n "${QUINTE_VERDICT_ROOT:-}" ] && roots+=("$QUINTE_VERDICT_ROOT")

  if [ "${#roots[@]}" -eq 0 ]; then
    return 1
  fi

  local root match
  for root in "${roots[@]}"; do
    [ -d "$root" ] || continue
    match="$(find "$root" -type f \( -iname '*verdict*.md' -o -iname 'r3-*.md' -o -iname '*R3*.md' \) -mtime -2 -print -quit 2>/dev/null || true)"
    if [ -n "$match" ]; then
      echo "$match"
      return 0
    fi
  done

  return 1
}

check_residual_closure() {
  local verdict_file="$1"
  local script_dir validator

  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  validator="$script_dir/../bin/validate-residual-trace.py"

  if [ ! -f "$validator" ]; then
    echo "[BANNIN] WARNING: residual trace validator missing; closure cannot be verified" >&2
    return 0
  fi

  if python3 "$validator" "$verdict_file"; then
    return 0
  fi

  return 1
}

has_arch_critical_write() {
  local log="$1"
  grep -qiE "$CRITICAL_REGEX" "$log" 2>/dev/null
}

has_trigger() {
  local log="$1"
  grep -qiE "$TRIGGER_REGEX" "$log" 2>/dev/null
}

cmd="${1:-}"
case "$cmd" in
  --check)
    log="${2:-}"
    [ -z "$log" ] && usage
    [ ! -f "$log" ] && { echo "[BANNIN] ERROR: log not found: $log" >&2; exit 2; }

    triggers_found=0
    if has_trigger "$log"; then
      triggers_found=1
      echo "[BANNIN] trigger phrase(s) detected in session log"
    fi

    if has_arch_critical_write "$log"; then
      echo "[BANNIN] protected engineering write detected in session log"
      verdict_file="$(check_verdict_trail || true)"
      if [ -n "$verdict_file" ]; then
        echo "[BANNIN] QUINTE verdict trail found: $verdict_file"
        check_residual_closure "$verdict_file"
        echo "[BANNIN] PASS (exit 0)"
        exit 0
      else
        echo "[BANNIN] BLOCK: protected engineering write without verdict trail" >&2
        exit 1
      fi
    fi

    # No critical write: allow (even if trigger seen — flag is advisory for subsequent ops)
    echo "[BANNIN] no protected engineering write in log; no block condition"
    echo "[BANNIN] PASS (exit 0)"
    exit 0
    ;;

  --help|-h)
    usage
    ;;

  *)
    usage
    ;;
esac
