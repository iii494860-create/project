#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
if ! command -v docker >/dev/null 2>&1; then
  echo "Docker Engine과 Compose plugin을 먼저 설치하세요." >&2
  exit 1
fi
docker compose version >/dev/null
docker compose up -d neo4j
echo "Neo4j 시작 요청 완료. http://127.0.0.1:7474 / bolt://127.0.0.1:7687"
