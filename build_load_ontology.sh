#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
if [ ! -x "$ROOT/.venv/bin/python" ]; then
  echo "먼저 ./install.sh 를 실행하세요." >&2
  exit 1
fi
"$ROOT/.venv/bin/python" "$ROOT/knowledge_assets.py" prepare
. "$ROOT/env.sh"
# A rerun may refresh this release, but never discard site-specific knowledge.
"$ROOT/.venv/bin/python" - <<'PY'
import os
from neo4j import GraphDatabase
from load_neo4j import Plan
plan = Plan('out/ontology_all.ttl', 'schema.ttl')
with GraphDatabase.driver(os.environ['NEO4J_URI'], auth=(os.environ['NEO4J_USER'],os.environ['NEO4J_PASSWORD'])) as d:
    rows,_,_=d.execute_query('MATCH(n:Knowledge) RETURN n.uri AS uri', database_=os.environ.get('NEO4J_DATABASE','neo4j'))
    if {r['uri'] for r in rows} - set(plan.nodes):
        raise SystemExit('기존 DB에 배포본 외 지식이 있습니다. 별도 DB에서 설치하세요.')
PY
"$ROOT/.venv/bin/python" "$ROOT/load_neo4j.py"
