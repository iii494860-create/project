#!/usr/bin/env bash
set -euo pipefail
umask 077
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
if [ ! -x "$ROOT/.venv/bin/python" ] || [ ! -f "$ROOT/.env" ]; then
  echo "기존 .venv와 .env가 없습니다. 새 설치는 ./setup.sh를 사용하세요." >&2
  exit 1
fi
echo "대시보드를 종료한 상태에서 적용하세요. 기존 로그·인증정보는 유지합니다."
"$ROOT/.venv/bin/python" -m pip install -r "$ROOT/requirements.txt"
exec "$ROOT/.venv/bin/python" -u "$ROOT/update_install.py"
