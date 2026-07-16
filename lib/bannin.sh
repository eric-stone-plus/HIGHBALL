#!/usr/bin/env bash
# BANNIN protected-write guard. Every uncertainty fails closed.

set -euo pipefail

CRITICAL_REGEX='(QUINTE|RASHOMON|HIGHBALL|MAGI)/(README[^/[:space:]]*|specs/|scripts/|bin/[^/[:space:]]*\.py|lib/)|SOUL\.md|git (push|commit).* (QUINTE|RASHOMON|HIGHBALL|MAGI)'

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
[ -f "$log" ] || { echo "[BANNIN] ERROR: log not found: $log" >&2; exit 2; }
[ -r "$log" ] || { echo "[BANNIN] ERROR: log is not readable: $log" >&2; exit 2; }

if ! has_arch_critical_write "$log"; then
  echo "[BANNIN] no protected engineering write in log"
  exit 0
fi

echo "[BANNIN] protected engineering write detected"
validator="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../bin/validate-action-packet.py"
[ -f "$validator" ] || { echo "[BANNIN] BLOCK: Action Packet validator missing" >&2; exit 1; }
[ -f "$packet" ] || { echo "[BANNIN] BLOCK: bound Action Packet missing" >&2; exit 1; }

set +e
python3 "$validator" "$packet"
status=$?
set -e
if [ "$status" -ne 0 ]; then
  echo "[BANNIN] BLOCK: Action Packet does not authorize this protected write" >&2
  exit 1
fi

python3 - "$log" "$packet" <<'PY'
import hashlib
import json
import pathlib
import sys

log_path = pathlib.Path(sys.argv[1]).resolve()
packet_path = pathlib.Path(sys.argv[2]).resolve()
packet = json.loads(packet_path.read_text(encoding="utf-8"))
paths = packet["route_request"]["affected_paths"]
log = log_path.read_text(encoding="utf-8", errors="replace")
if not paths or not all(path in log for path in paths):
    raise SystemExit("[BANNIN] BLOCK: session log is not bound to every affected path")
packet_digest = "sha256:" + hashlib.sha256(packet_path.read_bytes()).hexdigest()
print(f"[BANNIN] packet binding verified: {packet_digest}")
PY

authorization_ref="$(python3 - "$packet" <<'PY'
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
        path = pathlib.Path(sys.argv[1]).resolve().parent / path
    print(path.resolve())
PY
)" || { echo "[BANNIN] BLOCK: required KENGEN artifact is not bound" >&2; exit 1; }

if [ -n "$authorization_ref" ]; then
  request_file="$(mktemp "${TMPDIR:-/tmp}/highball-request.XXXXXX")"
  trap 'rm -f "$request_file"' EXIT
  python3 - "$packet" "$request_file" <<'PY'
import json
import pathlib
import sys

packet = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
pathlib.Path(sys.argv[2]).write_text(
    json.dumps(packet["route_request"], ensure_ascii=False, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
PY
  consumer="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../bin/consume-kengen-authorization.py"
  [ -f "$consumer" ] || { echo "[BANNIN] BLOCK: KENGEN consumer missing" >&2; exit 1; }
  python3 "$consumer" "$request_file" "$authorization_ref" || {
    echo "[BANNIN] BLOCK: KENGEN authorization could not be consumed" >&2
    exit 1
  }
fi

echo "[BANNIN] PASS"
