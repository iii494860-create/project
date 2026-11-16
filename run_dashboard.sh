#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [ ! -x "$ROOT/.venv/bin/streamlit" ]; then
  echo "먼저 ./install.sh 를 실행하세요." >&2
  exit 1
fi
if [ ! -f "$ROOT/.env" ]; then
  echo ".env가 없습니다. 먼저 ./install.sh 를 실행하세요." >&2
  exit 1
fi
cd "$ROOT"
set -a
. "$ROOT/.env"
set +a
"$ROOT/.venv/bin/python" "$ROOT/sync_openstack_config.py"
if [ -f "$ROOT/.qwen_api_key" ]; then
  export QWEN_API_KEY="$(cat "$ROOT/.qwen_api_key")"
fi
export OS_CLIENT_CONFIG_FILE="$ROOT/clouds.yaml"
export CTO_PROJECT_ROOT="$ROOT"
BIND_ADDRESS="${DASHBOARD_BIND_ADDRESS:-127.0.0.1}"
exec "$ROOT/.venv/bin/streamlit" run "$ROOT/dashboard_app.py" --server.address "$BIND_ADDRESS"
