#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
if ! command -v docker >/dev/null 2>&1; then
  echo "Docker Engine을 찾을 수 없습니다. ./setup.sh에서 설치할 수 있습니다." >&2
  exit 1
fi
if docker info >/dev/null 2>&1; then
  DOCKER=(docker)
elif command -v sudo >/dev/null 2>&1 && sudo docker info >/dev/null 2>&1; then
  DOCKER=(sudo docker)
else
  echo "Docker 데몬 접근 권한이 없습니다. ./setup.sh를 다시 실행하거나 sudo 권한을 확인하세요." >&2
  exit 1
fi
"${DOCKER[@]}" compose version >/dev/null
"${DOCKER[@]}" compose up -d neo4j
echo "Neo4j 시작 요청 완료. http://127.0.0.1:7474 / bolt://127.0.0.1:7687"
