#!/usr/bin/env python3
"""Read local configuration as data, never as executable shell commands."""
import os
from pathlib import Path
import re
import shlex
import sys
import subprocess
from dotenv import dotenv_values

ROOT = Path(__file__).resolve().parent


def values(path=None):
    return {k: v for k, v in dotenv_values(path or ROOT / '.env', interpolate=False).items()
            if v is not None and re.fullmatch(r'[A-Z][A-Z0-9_]*', k)}


def load():
    os.environ.update(values())
    os.environ['CTO_PROJECT_ROOT'] = str(ROOT)
    os.environ['OS_CLIENT_CONFIG_FILE'] = str(ROOT / 'clouds.yaml')
    if (ROOT / '.qwen_api_key').exists():
        os.environ['QWEN_API_KEY'] = (ROOT / '.qwen_api_key').read_text().strip()


if __name__ == '__main__':
    if sys.argv[1:] == ['--shell']:
        for k, v in values().items():
            print(f'export {k}={shlex.quote(v)}')
    elif sys.argv[1:2] == ['--compose']:
        load()
        accessible = subprocess.run(['docker', 'info'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
        command = ([] if accessible else ['sudo', '--preserve-env=NEO4J_USER,NEO4J_PASSWORD,DOCKER_CONFIG'])
        command += ['docker', 'compose', '--env-file', '/dev/null', *sys.argv[2:]]
        raise SystemExit(subprocess.run(command, cwd=ROOT).returncode)
    else:
        raise SystemExit('Usage: runtime_env.py --shell | --compose [arguments]')
