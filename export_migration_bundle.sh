#!/usr/bin/env bash
# Export a portable data bundle from an existing Linux Neo4j installation.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="${1:-}"
DB_NAME="${NEO4J_DATABASE_NAME:-neo4j}"
SERVICE="${NEO4J_SYSTEMD_SERVICE:-neo4j}"
OUTPUT="${2:-$ROOT/migration_bundle.tar.gz}"
OUTPUT="$(realpath -m -- "$OUTPUT")"

if [ -z "$SOURCE_DIR" ] || [ ! -d "$SOURCE_DIR/docs" ] || [ ! -f "$SOURCE_DIR/out/ontology_all.ttl" ] || [ ! -f "$SOURCE_DIR/embeddings_cache.jsonl" ]; then
  cat >&2 <<'EOF'
사용법: ./export_migration_bundle.sh /경로/기존-프로젝트 [출력-파일]
기존 프로젝트 폴더에 docs/, out/ontology_all.ttl, embeddings_cache.jsonl이 있어야 합니다.
EOF
  exit 2
fi
if ! command -v neo4j-admin >/dev/null 2>&1 || ! command -v systemctl >/dev/null 2>&1; then
  echo "Linux systemd Neo4j와 neo4j-admin이 필요합니다." >&2
  exit 1
fi

SUDO=()
RUN_AS_NEO4J=()
if [ "$EUID" -ne 0 ]; then
  command -v sudo >/dev/null 2>&1 || { echo "Neo4j 데이터 읽기에 sudo 권한이 필요합니다." >&2; exit 1; }
  SUDO=(sudo)
  RUN_AS_NEO4J=(sudo -u neo4j)
else
  RUN_AS_NEO4J=(runuser -u neo4j --)
fi

STAGE="$(mktemp -d "$ROOT/.migration-export.XXXXXX")"
DUMP_DIR="/var/lib/neo4j/migration-export-$$"
WAS_ACTIVE=0
cleanup() {
  if [ "$WAS_ACTIVE" -eq 1 ]; then
    "${SUDO[@]}" systemctl start "$SERVICE" || echo "경고: Neo4j를 다시 시작하지 못했습니다." >&2
  fi
  "${SUDO[@]}" rm -rf -- "$DUMP_DIR" 2>/dev/null || true
  rm -rf -- "$STAGE"
}
trap cleanup EXIT

mkdir -p "$STAGE/neo4j"
"${SUDO[@]}" install -d -o neo4j -g adm -m 750 "$DUMP_DIR"
if "${SUDO[@]}" systemctl is-active --quiet "$SERVICE"; then
  WAS_ACTIVE=1
  echo "Neo4j를 잠시 중지해 일관된 백업을 만듭니다."
  "${SUDO[@]}" systemctl stop "$SERVICE"
fi
"${RUN_AS_NEO4J[@]}" neo4j-admin database dump "$DB_NAME" --to-path="$DUMP_DIR"
"${SUDO[@]}" cp "$DUMP_DIR/$DB_NAME.dump" "$STAGE/neo4j/$DB_NAME.dump"
"${SUDO[@]}" chown "$(id -u):$(id -g)" "$STAGE/neo4j/$DB_NAME.dump"
chmod 600 "$STAGE/neo4j/$DB_NAME.dump"
if [ "$WAS_ACTIVE" -eq 1 ]; then
  "${SUDO[@]}" systemctl start "$SERVICE"
  WAS_ACTIVE=0
  echo "Neo4j가 다시 시작되었습니다."
fi

cp -a "$SOURCE_DIR/docs" "$STAGE/docs"
mkdir -p "$STAGE/out"
cp -a "$SOURCE_DIR/out/ontology_all.ttl" "$STAGE/out/ontology_all.ttl"
cp -a "$SOURCE_DIR/embeddings_cache.jsonl" "$STAGE/embeddings_cache.jsonl"
cat > "$STAGE/migration_manifest.txt" <<EOF
database=$DB_NAME
source_neo4j_version=$(neo4j-admin --version 2>&1 | head -1)
created_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF

mkdir -p "$(dirname -- "$OUTPUT")"
tar -czf "$OUTPUT" -C "$STAGE" .
chmod 600 "$OUTPUT"
if [ "$EUID" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
  chown "$SUDO_USER" "$OUTPUT"
fi
echo "이식 묶음 생성 완료: $OUTPUT"
du -h "$OUTPUT"
echo "이 파일은 비밀 데이터가 포함될 수 있으므로 Git에 추가하지 말고 안전하게 새 PC로 복사하세요."
