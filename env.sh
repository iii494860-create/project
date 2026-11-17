# Source this helper, not .env. Values containing $(), quotes or backticks remain data.
ENV_EXPORTS="$("$ROOT/.venv/bin/python" "$ROOT/runtime_env.py" --shell)" || return 1
eval "$ENV_EXPORTS"
unset ENV_EXPORTS
export CTO_PROJECT_ROOT="$ROOT"
export OS_CLIENT_CONFIG_FILE="$ROOT/clouds.yaml"
