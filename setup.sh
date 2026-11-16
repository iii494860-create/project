#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
MIGRATION_RELEASE_TAG="${MIGRATION_RELEASE_TAG:-migration-data-2026-11-16}"
MIGRATION_SHA256="3fff2ee992176e8f1f51b9ac07816a5d539f596af27f2faf209fbc58572634e7"
if [ ! -t 0 ]; then
  echo "대화형 설정이 필요합니다. 터미널에서 ./setup.sh 를 실행하세요." >&2
  exit 1
fi
SUDO=()
if [ "$EUID" -ne 0 ]; then
  if ! command -v sudo >/dev/null 2>&1; then
    echo "시스템 패키지 설치에 sudo 권한이 필요합니다." >&2
    exit 1
  fi
  sudo -v
  SUDO=(sudo)
fi

ensure_base_tools() {
  local os_id=""
  if [ -r /etc/os-release ]; then
    . /etc/os-release
    os_id="${ID:-}"
  fi
  if [[ "$os_id" != "ubuntu" ]]; then
    echo "자동 설치는 Ubuntu에서 지원합니다. 현재 OS: ${os_id:-unknown}" >&2
    exit 1
  fi
  "${SUDO[@]}" apt-get update
  "${SUDO[@]}" apt-get install -y software-properties-common
  "${SUDO[@]}" add-apt-repository -y universe
  "${SUDO[@]}" apt-get update
  "${SUDO[@]}" apt-get install -y ca-certificates curl python3 python3-venv python3-pip gh
}

ensure_docker() {
  if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
    echo "Docker Engine과 Compose를 설치합니다. sudo 비밀번호를 요청할 수 있습니다."
    "${SUDO[@]}" apt-get update
    if ! command -v docker >/dev/null 2>&1; then
      "${SUDO[@]}" apt-get install -y docker.io docker-compose-v2
    else
      "${SUDO[@]}" apt-get install -y docker-compose-v2
    fi
  fi
  if command -v systemctl >/dev/null 2>&1; then
    "${SUDO[@]}" systemctl enable --now docker
  fi
  if ! docker info >/dev/null 2>&1; then
    "${SUDO[@]}" docker info >/dev/null
  fi
  if ! docker compose version >/dev/null 2>&1 && ! "${SUDO[@]}" docker compose version >/dev/null 2>&1; then
    echo "Docker Compose 설치를 확인하지 못했습니다." >&2
    exit 1
  fi
}

ensure_base_tools
ensure_docker

if [ ! -f "$ROOT/migration_bundle.tar.gz" ] && [ "${MIGRATION_MODE:-restore}" != "rebuild" ]; then
  if ! command -v gh >/dev/null 2>&1; then
    echo "비공개 GitHub Release에서 이식 데이터를 받으려면 GitHub CLI(gh)가 필요합니다." >&2
    echo "gh를 설치한 뒤 'gh auth login'으로 iii494860-create 계정에 로그인하고 다시 실행하세요." >&2
    exit 1
  fi
  if ! gh auth status >/dev/null 2>&1; then
    echo "비공개 Release 다운로드를 위해 먼저 'gh auth login'을 완료하세요." >&2
    exit 1
  fi
  echo "비공개 GitHub Release에서 기존 DB 이식 묶음을 받습니다."
  gh release download "$MIGRATION_RELEASE_TAG" --repo iii494860-create/project \
    --pattern migration_bundle.tar.gz --dir "$ROOT"
fi

if [ -f "$ROOT/migration_bundle.tar.gz" ]; then
  printf '%s  %s\n' "$MIGRATION_SHA256" "$ROOT/migration_bundle.tar.gz" | sha256sum --check --status || {
    echo "이식 묶음 SHA-256 검증에 실패했습니다." >&2
    exit 1
  }
  chmod 600 "$ROOT/migration_bundle.tar.gz"
fi

echo "=== 1/4 Python 설치 및 접속 정보 설정 ==="
bash "$ROOT/install.sh"

echo "=== 2/4 Neo4j 시작 ==="
bash "$ROOT/start_services.sh"

echo "Neo4j 준비를 기다립니다 (최대 180초)..."
set -a
. "$ROOT/.env"
set +a
"$ROOT/.venv/bin/python" - <<'PY'
import os, sys, time, subprocess
from neo4j import GraphDatabase

uri = os.environ.get("NEO4J_URI", "bolt://127.0.0.1:7687")
auth = (os.environ.get("NEO4J_USER", "neo4j"), os.environ["NEO4J_PASSWORD"])
driver = GraphDatabase.driver(uri, auth=auth)
try:
    for attempt in range(180):
        try:
            driver.verify_connectivity()
            print("Neo4j 연결 완료")
            break
        except Exception:
            if attempt == 179:
                raise SystemExit("Neo4j가 준비되지 않았습니다. docker compose logs neo4j 로 확인하세요.")
            time.sleep(1)
finally:
    driver.close()
PY

echo "=== 3/4 온톨로지 생성·적재 및 벡터 임베딩 ==="
if [ -f "$ROOT/migration_bundle.tar.gz" ]; then
  echo "이식 묶음을 찾아 기존 온톨로지와 임베딩을 복원합니다."
  bash "$ROOT/restore_migration_bundle.sh" "$ROOT/migration_bundle.tar.gz"
else
  echo "이식 묶음이 없어 온톨로지와 임베딩을 새로 생성합니다."
  bash "$ROOT/setup_knowledge.sh"
fi

echo "=== 4/4 설치 완료 ==="
echo "대시보드를 시작합니다. 종료하려면 Ctrl+C를 누르세요."
exec "$ROOT/run_dashboard.sh"
