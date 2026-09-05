#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

cargo test --offline --lib
python3 -m unittest discover -s tests -p 'test_*.py' -v
PYTHONDONTWRITEBYTECODE=1 python3 -m py_compile tests/*.py
# Remaining Python CLIs are residual-route report helpers, not the control plane.
if compgen -G 'bin/*.py' > /dev/null; then
  PYTHONDONTWRITEBYTECODE=1 python3 -m py_compile bin/*.py
fi
python3 -m json.tool schemas/action-packet.schema.json >/dev/null
python3 -m json.tool schemas/route-execution-report.schema.json >/dev/null
if python3 -c 'import jsonschema' 2>/dev/null; then
  python3 - <<'PY'
import json
from pathlib import Path

from jsonschema.validators import validator_for

for path in sorted(Path("schemas").glob("*.json")):
    schema = json.loads(path.read_text(encoding="utf-8"))
    validator_for(schema).check_schema(schema)
PY
else
  echo "[HIGHBALL] WARN: jsonschema unavailable; skipped schema meta-validation" >&2
fi
bash -n lib/protected-write-guard.sh scripts/release-guard.sh scripts/test-release-guard.sh scripts/check-local.sh
scripts/test-release-guard.sh
retired_pattern="$(printf '%s' 'sh' 'imei|ken' 'gen|ban' 'nin|ハイボール|指名|権限|番人')"
if rg -n -i "$retired_pattern" \
    --glob '!**/.git/**' --glob '!**/__pycache__/**' \
    --glob '!scripts/check-local.sh' .; then
  echo "retired component vocabulary remains" >&2
  exit 1
fi
git diff --check
