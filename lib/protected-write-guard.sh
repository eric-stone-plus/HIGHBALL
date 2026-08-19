#!/usr/bin/env bash
# HIGHBALL protected-write guard. Every uncertainty fails closed.

set -euo pipefail

# Session logs may record repository-relative targets without the repository
# prefix (for example `Edit src/route.rs` after the agent cd'd into the repo),
# so the bare-directory alternative also fires. It requires the directory to
# start a path token so unrelated words such as `mysrc/` or `/usr/bin/` do not
# match. Bare `git commit`/`git push` lines carry no repo identity and stay out
# of scope; they are caught indirectly when the session log also shows a
# protected path target.
CRITICAL_REGEX='(QUINTE|RASHOMON|HIGHBALL)/(README[^/[:space:]]*|specs/|scripts/|bin/|lib/|src/|schemas/|container/|configs/|skills/|Cargo\.(toml|lock)|pyproject\.toml|Dockerfile|compose[^/[:space:]]*\.ya?ml)|(^|[^[:alnum:]_/.-])(src|specs|scripts|bin|lib|schemas|container|configs|skills)/|SOUL\.md|git (push|commit).* (QUINTE|RASHOMON|HIGHBALL)'

usage() {
  echo "Usage: $(basename "$0") --check <session.log> --action-packet <packet.json>" >&2
  exit 2
}

has_arch_critical_write() {
  grep -qiE "$CRITICAL_REGEX" "$1" 2>/dev/null
}

cmd="${1:-}"
[ "$cmd" = "--check" ] || usage
log="${2:-}"
[ "${3:-}" = "--action-packet" ] || usage
packet="${4:-}"
[ -n "$log" ] && [ -n "$packet" ] || usage
[ -f "$log" ] || { echo "[Protected-Write Guard] ERROR: log not found: $log" >&2; exit 2; }
[ -r "$log" ] || { echo "[Protected-Write Guard] ERROR: log is not readable: $log" >&2; exit 2; }

log_snapshot="$(mktemp "${TMPDIR:-/tmp}/highball-log.XXXXXX")"
critical_snapshot=""
packet_snapshot=""
request_file=""
trap 'rm -f "$log_snapshot" "$critical_snapshot" "$packet_snapshot" "$request_file"' EXIT
cp "$log" "$log_snapshot" || {
  echo "[Protected-Write Guard] BLOCK: cannot snapshot session log" >&2
  exit 1
}
chmod 600 "$log_snapshot" 2>/dev/null || true

if ! has_arch_critical_write "$log_snapshot"; then
  echo "[Protected-Write Guard] no protected engineering write in log"
  exit 0
fi

critical_snapshot="$(mktemp "${TMPDIR:-/tmp}/highball-critical.XXXXXX")"
grep -iE "$CRITICAL_REGEX" "$log_snapshot" > "$critical_snapshot" || true

echo "[Protected-Write Guard] protected engineering write detected"
highball_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.."
if [ -x "$highball_root/target/debug/highball" ]; then
  highball="$highball_root/target/debug/highball"
elif [ -x "$highball_root/target/release/highball" ]; then
  highball="$highball_root/target/release/highball"
elif command -v highball >/dev/null 2>&1; then
  highball="$(command -v highball)"
else
  echo "[Protected-Write Guard] BLOCK: Action Packet validator missing" >&2
  exit 1
fi
[ -f "$packet" ] || { echo "[Protected-Write Guard] BLOCK: bound Action Packet missing" >&2; exit 1; }
packet_base="$(cd "$(dirname "$packet")" && pwd)"

# Validate and consume one immutable packet snapshot so replacements at the
# caller-supplied path cannot change the authorized scope after validation.
packet_snapshot="$(mktemp "${TMPDIR:-/tmp}/highball-packet.XXXXXX")"
cp "$packet" "$packet_snapshot" || {
  echo "[Protected-Write Guard] BLOCK: cannot snapshot Action Packet" >&2
  exit 1
}
chmod 600 "$packet_snapshot" 2>/dev/null || true

set +e
"$highball" validate-action-packet "$packet_snapshot" --base-dir "$packet_base"
status=$?
set -e
if [ "$status" -ne 0 ]; then
  echo "[Protected-Write Guard] BLOCK: Action Packet does not authorize this protected write" >&2
  exit 1
fi

python3 - "$log_snapshot" "$packet_snapshot" "$critical_snapshot" <<'PY'
import hashlib
import json
import pathlib
import re
import sys

log_path = pathlib.Path(sys.argv[1]).resolve()
packet_path = pathlib.Path(sys.argv[2]).resolve()
critical_path = pathlib.Path(sys.argv[3]).resolve()
packet = json.loads(packet_path.read_text(encoding="utf-8"))
paths = packet["route_request"]["affected_paths"]
log = log_path.read_text(encoding="utf-8", errors="replace")
if not paths or not all(path in log for path in paths):
    raise SystemExit("[Protected-Write Guard] BLOCK: session log is not bound to every affected path")

# The check above proves the log mentions every authorized path. The reverse
# direction also matters: every protected write target the guard detected in
# the log must fall inside the packet's authorized scope, so a packet bound to
# one file cannot authorize a protected write to another.
critical = critical_path.read_text(encoding="utf-8", errors="replace")


def covers(authorized: str, target: str) -> bool:
    if authorized == target:
        return True
    # Session logs may record repository-relative targets without the prefix
    # bound into the packet, or absolute targets that embed it.
    if target.endswith("/" + authorized) or authorized.endswith("/" + target):
        return True
    if target.endswith("/"):
        return authorized.startswith(target) or ("/" + target) in authorized
    return False


for token in re.findall(r"[^\s'\"(){}\[\]<>|;`=:,]+", critical):
    target = token.strip("`'\"").rstrip(".,:;!?")
    if not target or ("/" not in target and target != "SOUL.md"):
        continue
    if not any(covers(path, target) for path in paths):
        raise SystemExit(
            "[Protected-Write Guard] BLOCK: session log write target is "
            "outside the Action Packet scope: " + target
        )
packet_digest = "sha256:" + hashlib.sha256(packet_path.read_bytes()).hexdigest()
print(f"[Protected-Write Guard] packet binding verified: {packet_digest}")
PY

authorization_binding="$(python3 - "$packet_snapshot" "$packet_base" <<'PY'
import json
import pathlib
import sys

packet = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
authorization = packet.get("authorization", {})
if authorization.get("required") is True:
    ref = authorization.get("artifact_ref")
    if not isinstance(ref, str) or not ref:
        raise SystemExit(2)
    path = pathlib.Path(ref)
    if not path.is_absolute():
        path = pathlib.Path(sys.argv[2]) / path
    digest = authorization.get("artifact_sha256")
    if not isinstance(digest, str) or not digest:
        raise SystemExit(2)
    print(f"{path.resolve()}\t{digest}")
PY
)" || { echo "[Protected-Write Guard] BLOCK: required Authorization Gate artifact is not bound" >&2; exit 1; }

if [ -n "$authorization_binding" ]; then
  IFS=$'\t' read -r authorization_ref authorization_sha256 <<<"$authorization_binding"
  request_file="$(mktemp "${TMPDIR:-/tmp}/highball-request.XXXXXX")"
  python3 - "$packet_snapshot" "$request_file" <<'PY'
import json
import pathlib
import sys

packet = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
pathlib.Path(sys.argv[2]).write_text(
    json.dumps(packet["route_request"], ensure_ascii=False, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
PY
  "$highball" consume-authorization "$request_file" "$authorization_ref" --expected-sha256 "$authorization_sha256" || {
    echo "[Protected-Write Guard] BLOCK: authorization could not be consumed" >&2
    exit 1
  }
fi

echo "[Protected-Write Guard] PASS"
