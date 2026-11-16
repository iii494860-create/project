"""Pasted non-JSON log parsing for 3K1H Graph RAG Inspector.

The returned query is an ontology *semantic retrieval*, not an Alert or
proven attack classification. User-controlled log text is UNTRUSTED.
"""
from __future__ import annotations

import re
from datetime import datetime
from urllib.parse import urlsplit
from typing import Any

MAX_CHARS = 120_000

# Apache combined access logs (and common logs without referer/user-agent).
_APACHE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<when>[^\]\r\n]+)\]\s+'
    r'"(?P<request>(?:\\.|[^"\\])*)"\s+'
    r'(?P<status>[1-5][0-9]{2})\s+(?P<size>\d+|-)'
    r'(?:\s+"(?P<referer>(?:\\.|[^"\\])*)"'
    r'\s+"(?P<agent>(?:\\.|[^"\\])*)")?'
    r'(?:\s+.*)?$',
)
_OPENSTACK = re.compile(
    r'^(?P<when>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)'
    r'\s+(?:(?P<pid>\d+)\s+)?'
    r'(?P<level>DEBUG|INFO|WARNING|WARN|ERROR|CRITICAL)'
    r'\s+(?P<service>[a-zA-Z_][a-zA-Z_0-9.]*)\s*'
    r'(?P<message>.*)$', re.I,
)
_HTTP_METHOD = re.compile(r'^[A-Z]{2,16}$')


def _safe(value: str, limit: int = 140) -> str:
    # Hide control characters and common secret-bearing query parameters.
    value = re.sub(r'[\r\n\t\x00-\x1f]+', ' ', str(value or ''))
    value = re.sub(r'(?i)(authorization|token|password|secret|api_key)\s*[=:]\s*\S+', r'\1=[REDACTED]', value)
    return value[:limit].strip()


def _path_only(target: str) -> str:
    """Preserve URL path for search but omit the query/fragment (possible secrets)."""
    target = str(target or '').strip()
    try:
        parts = urlsplit(target)
        return _safe(parts.path or '/', 160)
    except ValueError:
        return _safe(target.split('?', 1)[0].split('#', 1)[0], 160)


def parse_plaintext_log_for_rag(raw_text: str) -> dict[str, Any]:
    raw = str(raw_text or '').strip()
    if not raw:
        raise ValueError('일반 텍스트 로그 한 건을 붙여넣어 주세요.')
    if len(raw) > MAX_CHARS:
        raise ValueError(f'입력 로그가 너무 깁니다 (최대 {MAX_CHARS:,}자).')
    if raw.startswith('```'):
        raw = re.sub(r'^```(?:apache|log|text)?\s*', '', raw, count=1, flags=re.I)
        raw = re.sub(r'\s*```$', '', raw).strip()

    # Only the first actual log entry is parsed; don't silently merge multiple events.
    records = [line.strip() for line in raw.splitlines() if line.strip()]
    if len(records) > 1:
        raise ValueError('한 번에 로그 1건만 넣어 주세요. 일반 텍스트 로그가 여러 줄입니다.')
    logline = records[0] if records else ''
    found = _APACHE.fullmatch(logline)
    if found:
        d = found.groupdict()
        request = d.get('request') or ''
        pieces = request.split(' ')
        method = pieces[0] if pieces else ''
        if not _HTTP_METHOD.fullmatch(method):
            method = '확인 불가'
        target = pieces[1] if len(pieces) >= 2 else ''
        protocol = pieces[2] if len(pieces) >= 3 else ''
        path = _path_only(target)
        status = int(d['status'])
        raw_time = d.get('when') or ''
        try:
            timestamp = datetime.strptime(raw_time, '%d/%b/%Y:%H:%M:%S %z').isoformat()
        except ValueError:
            timestamp = raw_time
        # An HTTP response code alone is never an attack verdict.
        assessment = (
            'HTTP 응답 200은 요청이 처리됐다는 정보이며, 이 로그 한 건만으로 공격이나 정상 여부를 확정할 수 없습니다.'
            if status == 200 else
            'HTTP 상태 코드만으로 공격을 확정할 수 없습니다. 추가 요청 패턴과 관련 이벤트가 필요합니다.'
        )
        query = (
            'OpenStack Horizon Apache 웹 접근 로그와 관련된 온톨로지의 이벤트, 보안 분석 근거, '
            '탐지 규칙을 검색. '
            f'HTTP 메서드 {_safe(method, 20)}, 요청 경로 {path}, '
            f'HTTP 응답 코드 {status}, 응답 상태 계열 {status // 100}xx. '
            '관련된 온톨로지 지식만 검색하며 로그 한 건의 공격 여부는 확정하지 않는다.'
        )
        return {
            'format': 'Apache HTTP 접근 로그',
            'mode': 'semantic',
            'event_type': '',  # Cannot claim to be an ontology-registered OpenStack Notification
            'outcome': '',
            'query': query,
            'timestamp': timestamp,
            'ip': _safe(d.get('ip') or '', 90),
            'user': '',
            'method': method,
            'path': path,
            'http_status': status,
            'protocol': _safe(protocol, 30),
            'referer_path': _path_only(d.get('referer') or '') if d.get('referer') not in (None, '-') else '',
            'user_agent': _safe(d.get('agent') or '', 160),
            'assessment': assessment,
        }

    osmatch = _OPENSTACK.fullmatch(logline)
    if osmatch:
        d = osmatch.groupdict()
        msg = _safe(d.get('message') or '', 350)
        level = str(d.get('level') or '').upper()
        service = _safe(d.get('service') or '', 90)
        query = (
            'OpenStack 서비스 텍스트 로그 관련 보안 온톨로지 근거 검색. '
            f'서비스 {service}, 로그 수준 {level}, 메시지 요약: {msg}. '
            '로그 레벨만으로 공격을 확정하지 않으며 근거 없는 ATT&CK 매핑은 금지.'
        )
        return {
            'format': 'OpenStack 서비스 텍스트 로그', 'mode': 'semantic',
            'event_type': '', 'outcome': '', 'query': query,
            'timestamp': d.get('when') or '', 'ip': '', 'user': '',
            'service': service, 'level': level, 'message': msg,
            'assessment': '서비스 로그의 오류 수준은 침해 증거가 아닙니다. 온톨로지에 직접 매핑이 없을 수 있습니다.',
        }

    # Generic text is allowed, but is explicitly marked as unknown format.
    # Never present it as a validated OpenStack event mapping.
    compact = _safe(logline, 450)
    return {
        'format': '기타 텍스트 로그 (형식 미인식)', 'mode': 'semantic',
        'event_type': '', 'outcome': '',
        'query': '입력된 보안 로그 문장과 의미상 관련된 기존 온톨로지 근거만 검색: '
                 + compact + '. 정확한 이벤트 매핑이 없으면 추측하지 않는다.',
        'timestamp': '', 'ip': '', 'user': '',
        'message': compact,
        'assessment': '형식이 인식되지 않아 정확한 로그 필드 및 공격 여부를 검증하지 못했습니다. 의미 검색만 실행합니다.',
    }
