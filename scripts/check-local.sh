#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

python3 -m unittest discover -s tests -p 'test_*.py' -v
python3 -m py_compile bin/*.py tests/*.py
python3 -m json.tool schemas/action-packet.schema.json >/dev/null
python3 -m json.tool schemas/route-execution-report.schema.json >/dev/null
bash -n lib/bannin.sh scripts/check-local.sh
git diff --check
