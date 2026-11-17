#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
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
  "${SUDO[@]}" apt-get install -y ca-certificates curl python3 python3-venv python3-pip
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

if [ -f "$ROOT/migration_bundle.tar.gz" ]; then
  echo "=== 3/4 기존 Neo4j·로그·임베딩 백업 복원 ==="
  bash "$ROOT/restore_migration_bundle.sh"
else
  echo "=== 3/4 새 온톨로지 생성·적재 및 벡터 임베딩 ==="
  bash "$ROOT/setup_knowledge.sh"
fi

echo "=== 4/4 설치 완료 ==="
echo "대시보드를 시작합니다. 종료하려면 Ctrl+C를 누르세요."
exec "$ROOT/run_dashboard.sh"
