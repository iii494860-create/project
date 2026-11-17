#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

if [ ! -x "$ROOT/.venv/bin/python" ] || [ ! -f "$ROOT/.env" ]; then
  echo "먼저 ./install.sh 또는 ./setup.sh 를 실행하세요." >&2
  exit 1
fi

echo "[1/4] 배포본에 포함된 전체 온톨로지와 문서를 준비합니다."
"$ROOT/.venv/bin/python" "$ROOT/knowledge_assets.py" prepare
bash "$ROOT/build_load_ontology.sh"

. "$ROOT/env.sh"
echo "[2/4] KISA 공지와 CVE 관계를 적재합니다."
"$ROOT/.venv/bin/python" "$ROOT/knowledge_assets.py" import
echo "[3/4] 임베딩을 생성하고 Neo4j 벡터 색인을 준비합니다."
"$ROOT/.venv/bin/python" "$ROOT/embed_knowledge.py"
echo "[4/4] 노드 식별자·속성·관계·임베딩·색인을 검증합니다."
"$ROOT/.venv/bin/python" "$ROOT/knowledge_assets.py" verify
