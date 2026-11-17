#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
. "$ROOT/env.sh"
umask 077
case "${1:-}" in
  consumer) exec "$ROOT/.venv/bin/python" -u "$ROOT/live_notification_consumer.py" ;;
  detect) exec "$ROOT/.venv/bin/python" -u "$ROOT/live_detection_runner.py" ;;
  bindings) exec "$ROOT/.venv/bin/python" "$ROOT/live_notification_consumer.py" --check ;;
  *) echo 'Usage: run_component.sh consumer|detect|bindings' >&2; exit 2 ;;
esac
