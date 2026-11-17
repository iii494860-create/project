#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
. "$ROOT/env.sh"
if [ "${CTO_EMBED_LOCAL:-true}" = true ]; then
  bash "$ROOT/compose.sh" --profile embedding up -d embeddings
  echo "임베딩 모델을 설치합니다. 첫 다운로드와 CPU 임베딩은 오래 걸릴 수 있습니다."
  "$ROOT/.venv/bin/python" - <<'PY'
import os, time, urllib.request
for attempt in range(90):
    try:
        with urllib.request.urlopen(os.environ['CTO_EMBED_URL'] + '/api/tags', timeout=5):
            break
    except Exception:
        if attempt == 89:
            raise SystemExit('임베딩 서버가 준비되지 않았습니다.')
        time.sleep(2)
PY
  bash "$ROOT/compose.sh" exec -T embeddings ollama pull "$CTO_EMBED_MODEL"
fi
"$ROOT/.venv/bin/python" - <<'PY'
from embed_knowledge import query_vector, DIM
vector = query_vector('OpenStack 로그인 실패 분석')
if len(vector) != DIM:
    raise SystemExit('임베딩 차원 불일치')
print('임베딩 API 실제 호출 확인: 4096차원')
PY
