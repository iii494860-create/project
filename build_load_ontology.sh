#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
if [ ! -x "$ROOT/.venv/bin/python" ]; then
  echo "먼저 ./install.sh 를 실행하세요." >&2
  exit 1
fi
if [ ! -d "$ROOT/docs" ]; then
  bash "$ROOT/download_docs.sh"
fi
"$ROOT/.venv/bin/python" "$ROOT/build_ontology.py"
set -a
. "$ROOT/.env"
set +a
"$ROOT/.venv/bin/python" "$ROOT/load_neo4j.py"
