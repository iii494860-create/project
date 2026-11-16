"""Read-only OpenStack discovery for 3K1H dashboard and Hermes MCP.

Uses the existing OpenStack CLI credentials (OPENSTACK_CLOUD/OS_CLOUD or OS_*).
No privileged mutating actions, arbitrary command execution, or secret output.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

_ALLOWED_ACTIONS = {
    'get_openstack_user',
    'get_openstack_user_roles',
    'get_openstack_server',
    'get_openstack_security_group',
    'get_openstack_project_resources',
}
_NAME_RE = re.compile(r'^[\w.:@/+\-]{1,128}$', re.UNICODE)
_SENSITIVE = re.compile(r'password|secret|token|authorization|private[_-]?key|credential', re.I)


class OpenStackLookupError(RuntimeError):
    pass


def _valid_id(value: str, title: str) -> str:
    value = (value or '').strip()
    if not _NAME_RE.fullmatch(value) or value.startswith('-'):
        raise OpenStackLookupError(f'{title}: ID/이름은 1~128자의 허용된 식별자여야 합니다.')
    return value


def _redact(data: Any, depth: int = 0) -> Any:
    if depth > 12:
        return '[nested data omitted]'
    if isinstance(data, dict):
        return {
            str(key): '[REDACTED]' if _SENSITIVE.search(str(key)) else _redact(val, depth+1)
            for key, val in data.items()
        }
    if isinstance(data, list):
        return [_redact(item, depth+1) for item in data[:150]]
    if isinstance(data, str) and len(data) > 1500:
        return data[:1500] + ' ...[truncated]'
    return data


def _openstack_binary() -> str:
    configured = os.environ.get('OPENSTACK_CLI')
    if configured:
        p = Path(configured)
        if not p.is_absolute() or not p.is_file():
            raise OpenStackLookupError('OPENSTACK_CLI는 설치된 openstack 실행 파일의 절대 경로여야 합니다.')
        return str(p)
    candidate = Path(sys.executable).parent / 'openstack'
    found = shutil.which('openstack')
    if candidate.is_file():
        return str(candidate)
    if found:
        return found
    raise OpenStackLookupError(
        'OpenStack CLI를 찾을 수 없습니다. Agent venv에서 python-openstackclient를 설치하세요.'
    )


def configuration_status() -> dict[str, Any]:
    """Returns a non-secret readiness summary; never prints cloud credentials."""
    cloud = os.environ.get('OPENSTACK_CLOUD') or os.environ.get('OS_CLOUD')
    auth_url = os.environ.get('OS_AUTH_URL')
    try:
        cli = _openstack_binary()
    except OpenStackLookupError as exc:
        return {'ready': False, 'reason': str(exc), 'cloud': cloud or '', 'cli': ''}
    if not cloud and not auth_url:
        return {
            'ready': False,
            'reason': 'OPENSTACK_CLOUD/OS_CLOUD 또는 OS_AUTH_URL 등의 인증 환경변수가 없습니다.',
            'cloud': '', 'cli': cli,
        }
    return {'ready': True, 'reason': '실제 API 권한은 조회할 때 검증됩니다.',
            'cloud': cloud or '(OS_* 환경변수)', 'cli': cli}


def _friendly_cli_failure(stderr: str, code: int) -> str:
    """Keep credentials, URLs and long Nova policies out of the dashboard."""
    raw = stderr or ""
    lower = raw.lower()
    if "403" in lower or "forbidden" in lower or "policy doesn't allow" in lower:
        return ("조회 권한 없음 (HTTP 403): 현재 OpenStack 계정으로는 이 정보를 조회할 수 없습니다. "
                "설정된 프로젝트의 읽기 전용 권한 범위에서 확인 가능한 정보만 표시합니다.")
    if "401" in lower or "unauthorized" in lower or "requires authentication" in lower:
        return "인증 실패 (HTTP 401): OpenStack 계정 및 프로젝트 인증 설정을 확인해 주세요."
    if "404" in lower or "not found" in lower:
        return "조회 대상이 없거나 현재 계정에서 볼 수 없습니다 (HTTP 404)."
    # Never echo raw URLs, request IDs, headers or potentially secret-bearing error text.
    return f"OpenStack 조회에 실패했습니다 (종료 코드 {code}). CLI 연결과 권한을 확인해 주세요."


def _run_cli(args: list[str], *, timeout: int = 25, empty_list_ok: bool = False) -> Any:
    status = configuration_status()
    if not status['ready']:
        raise OpenStackLookupError(status['reason'])
    command = [status['cli']]
    cloud = os.environ.get('OPENSTACK_CLOUD') or os.environ.get('OS_CLOUD')
    if cloud:
        command.extend(['--os-cloud', _valid_id(cloud, 'Cloud 이름')])
    command.extend(args)
    command.extend(['-f', 'json'])
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=timeout,
                              check=False, env=os.environ.copy())
    except subprocess.TimeoutExpired as exc:
        raise OpenStackLookupError(f'OpenStack API 조회 시간 초과({timeout}초)') from exc
    except OSError as exc:
        raise OpenStackLookupError(f'OpenStack CLI 실행 실패: {type(exc).__name__}') from exc
    if proc.returncode != 0:
        raise OpenStackLookupError(_friendly_cli_failure(proc.stderr, proc.returncode))
    # Some installations emit no JSON for an empty collection (exit code 0).
    if not proc.stdout.strip() and empty_list_ok:
        return []
    try:
        return _redact(json.loads(proc.stdout))
    except (ValueError, TypeError) as exc:
        raise OpenStackLookupError('OpenStack CLI가 올바른 JSON을 반환하지 않았습니다.') from exc


def lookup_openstack(action: str, identifier: str, project_id: str = '') -> dict[str, Any]:
    """Fixed allowlisted CLI operations; never constructs shell commands.

    Each tool returns API data with provenance, or raises on unavailable access.
    The current API state is not historical proof of what happened at event time.
    """
    if action not in _ALLOWED_ACTIONS:
        raise OpenStackLookupError('허용되지 않은 조회 종류입니다.')
    identifier = _valid_id(identifier, '조회 대상')
    if project_id:
        project_id = _valid_id(project_id, '프로젝트')

    if action == 'get_openstack_user':
        data = _run_cli(['user', 'show', identifier])
    elif action == 'get_openstack_user_roles':
        # --user alone is read-only and permitted by the Keystone policy.
        cmd = ['role', 'assignment', 'list', '--user', identifier, '--names']
        if project_id:
            cmd.extend(['--project', project_id])
        data = _run_cli(cmd)
    elif action == 'get_openstack_server':
        data = _run_cli(['server', 'show', identifier])
    elif action == 'get_openstack_security_group':
        info = _run_cli(['security', 'group', 'show', identifier])
        rules = _run_cli(['security', 'group', 'rule', 'list', identifier])
        data = {'security_group': info, 'rules': rules}
    elif action == 'get_openstack_project_resources':
        # Nova's `server list --project UUID` may request `all_tenants=True`,
        # which the project's reader role cannot use. `server list` without
        # a --project flag is scoped to the project of the authenticated token.
        # Reject requests for a different project instead of silently returning
        # the current project's resources under a misleading project name.
        expected_id = os.environ.get('CTO_OPENSTACK_PROJECT_ID', '')
        expected_name = os.environ.get('CTO_OPENSTACK_PROJECT_NAME', '')
        if identifier not in (expected_id, expected_name):
            raise OpenStackLookupError(
                f'현재 조회는 {expected_name} 프로젝트에 한정됩니다. 다른 프로젝트는 이 계정으로 확인할 수 없습니다.'
            )
        servers = _run_cli(['server', 'list'], empty_list_ok=True)
        groups = _run_cli(['security', 'group', 'list'], empty_list_ok=True)
        data = {'servers': servers, 'security_groups': groups}
    else:
        raise OpenStackLookupError('허용되지 않은 조회 종류입니다.')

    return {
        'source': 'OpenStack CLI API (live, read-only)',
        'action': action,
        'identifier': identifier,
        'project_id': ((expected_id if identifier == expected_name else identifier) if action == 'get_openstack_project_resources' else project_id or None),
        'data': data,
        'note': '현재 상태 조회 결과이며 과거 공격 발생 시점의 상태를 보증하지 않습니다.',
    }
