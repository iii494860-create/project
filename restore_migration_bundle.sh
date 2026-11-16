#!/usr/bin/env bash
# Restore a migration bundle into this project's Docker Neo4j volume.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ARCHIVE="${1:-$ROOT/migration_bundle.tar.gz}"
if [ ! -f "$ARCHIVE" ] || [ ! -x "$ROOT/.venv/bin/python" ]; then
  echo "이식 묶음과 설치된 .venv가 필요합니다." >&2
  exit 1
fi

TMP="$(mktemp -d)"
WAS_STOPPED=0
COMPOSE=()
if docker info >/dev/null 2>&1; then
  COMPOSE=(docker compose)
elif command -v sudo >/dev/null 2>&1; then
  COMPOSE=(sudo docker compose)
else
  echo "Docker 접근 권한이 없습니다." >&2
  exit 1
fi
cleanup() {
  rm -rf -- "$TMP"
  if [ "$WAS_STOPPED" -eq 1 ]; then
    "${COMPOSE[@]}" up -d neo4j >/dev/null || true
  fi
}
trap cleanup EXIT

tar -xzf "$ARCHIVE" -C "$TMP"
DB_NAME="$(sed -n 's/^database=//p' "$TMP/migration_manifest.txt" | head -1)"
DB_NAME="${DB_NAME:-neo4j}"
if [ ! -f "$TMP/neo4j/$DB_NAME.dump" ] || [ ! -d "$TMP/docs" ] || [ ! -f "$TMP/out/ontology_all.ttl" ]; then
  echo "이식 묶음의 DB 백업이나 온톨로지 자료가 누락되었습니다." >&2
  exit 1
fi

rm -rf "$ROOT/docs"
cp -a "$TMP/docs" "$ROOT/docs"
mkdir -p "$ROOT/out" "$ROOT/migration_bundle/neo4j"
cp -a "$TMP/out/ontology_all.ttl" "$ROOT/out/ontology_all.ttl"
if [ -f "$TMP/embeddings_cache.jsonl" ]; then
  cp -a "$TMP/embeddings_cache.jsonl" "$ROOT/embeddings_cache.jsonl"
fi
cp -a "$TMP/neo4j/$DB_NAME.dump" "$ROOT/migration_bundle/neo4j/$DB_NAME.dump"

"${COMPOSE[@]}" stop neo4j
WAS_STOPPED=1
"${COMPOSE[@]}" run --rm --no-deps neo4j neo4j-admin database load "$DB_NAME" \
  --from-path=/backups --overwrite-destination=true
"${COMPOSE[@]}" up -d neo4j
WAS_STOPPED=0
rm -rf "$ROOT/migration_bundle"
echo "Neo4j 데이터와 생성 자료를 이식했습니다. 적용된 새 주소는 로컬 .env를 확인하세요."
