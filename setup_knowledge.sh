#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

if [ ! -x "$ROOT/.venv/bin/python" ] || [ ! -f "$ROOT/.env" ]; then
  echo "먼저 ./install.sh 또는 ./setup.sh 를 실행하세요." >&2
  exit 1
fi

echo "[1/2] 문서에서 온톨로지를 생성하고 Neo4j에 적재합니다."
bash "$ROOT/build_load_ontology.sh"

echo "[2/2] 임베딩을 생성하고 Neo4j 벡터 색인을 준비합니다."
set -a
. "$ROOT/.env"
set +a
"$ROOT/.venv/bin/python" "$ROOT/embed_knowledge.py"
