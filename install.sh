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
  echo "Neo4j 초기 로그인은 neo4j 사용자로 설정됩니다."
  PASSWORD=""
  if [ -t 0 ]; then
    while true; do
      read -r -s -p "Neo4j 비밀번호 (8자 이상, 비우면 안전한 값 자동 생성): " PASSWORD
      echo
      if [ -z "$PASSWORD" ]; then
        break
      fi
      if [ "${#PASSWORD}" -lt 8 ]; then
        echo "Neo4j 기본 최소 길이는 8자입니다. 다시 입력하세요." >&2
        continue
      fi
      # .env is sourced by Bash as well as read by Docker Compose. Keep
      # custom values safe for both parsers; generated values use URL-safe chars.
      case "$PASSWORD" in
        *'$'*|*'`'*|*'\'*)
          echo '비밀번호에 $, 백틱, 백슬래시는 사용할 수 없습니다. 다시 입력하세요.' >&2
          continue
          ;;
      esac
      break
    done
  fi
  if [ -z "$PASSWORD" ]; then
    PASSWORD="$("$PYTHON_BIN" -c 'import secrets; print(secrets.token_urlsafe(32))')"
  fi
  NEO4J_PASSWORD_VALUE="$PASSWORD" "$PYTHON_BIN" - "$ROOT/.env" <<'PY'
import json
import os
import sys
from pathlib import Path

path = Path(sys.argv[1])
password = os.environ["NEO4J_PASSWORD_VALUE"]
lines = path.read_text(encoding="utf-8").splitlines()
for i, line in enumerate(lines):
    if line.startswith("NEO4J_PASSWORD="):
        lines[i] = "NEO4J_PASSWORD=" + json.dumps(password, ensure_ascii=False)
        break
path.write_text("\n".join(lines) + "\n", encoding="utf-8")
PY
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
