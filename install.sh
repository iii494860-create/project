#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

PYTHON_BIN="${PYTHON_BIN:-python3}"
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "Python 3.10 이상이 필요합니다." >&2
  exit 1
fi
"$PYTHON_BIN" - <<'PY'
import sys
if sys.version_info < (3, 10):
    raise SystemExit('Python 3.10 이상이 필요합니다.')
PY

"$PYTHON_BIN" -m venv "$ROOT/.venv"
"$ROOT/.venv/bin/python" -m pip install --upgrade pip
"$ROOT/.venv/bin/python" -m pip install -r "$ROOT/requirements.txt"

if [ ! -f "$ROOT/.env" ]; then
  cp "$ROOT/.env.example" "$ROOT/.env"
  PASSWORD="$("$PYTHON_BIN" -c 'import secrets; print(secrets.token_urlsafe(32))')"
  sed -i "s/^NEO4J_PASSWORD=.*/NEO4J_PASSWORD=$PASSWORD/" "$ROOT/.env"
  chmod 600 "$ROOT/.env"
fi
if [ ! -f "$ROOT/qwen_api_config.json" ]; then
  cp "$ROOT/qwen_api_config.example.json" "$ROOT/qwen_api_config.json"
fi

echo
echo "Python 패키지 설치가 완료되었습니다."
if [ -t 0 ]; then
  "$ROOT/.venv/bin/python" "$ROOT/configure.py"
else
  echo "대화형 설정을 하려면 나중에 .venv/bin/python configure.py 를 실행하세요."
fi
echo "Neo4j는 Docker가 설치된 뒤 ./start_services.sh 로 별도 컨테이너에 시작합니다."
