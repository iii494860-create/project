"""3K1H source-aware display helpers, no database writes or threat inference."""
from __future__ import annotations
from datetime import datetime, timezone, timedelta
import json
import ipaddress

MISSING = {'', '-', 'null', 'none', 'n/a'}


def has_account(value):
    return str(value or '').strip().casefold() not in MISSING


def display_account(event):
    source = str(event.get('source_type') or (event.get('neo4j_properties') or {}).get('sourceType') or '')
    value = event.get('username') or ''
    if has_account(value):
        return str(value)
    if source == 'windows_security':
        return '원본 계정명 미제공'
    return '계정명 미확인'


def source_name(event):
    from cto_unified_security import is_linux_event, is_windows_event
    if is_windows_event(event): return 'Windows'
    if is_linux_event(event): return 'Linux SSH'
    return 'OpenStack'


def detected_state(event):
    from cto_unified_security import is_observation_event
    return '관측 · 미평가' if is_observation_event(event) else 'Alert 연결'


def display_ip(value):
    s = str(value or '').strip()
    if not s or s == '-': return '-'
    try:
        obj = ipaddress.ip_address(s)
        if obj.is_loopback: return s + ' (로컬)'
    except ValueError:
        pass
    return s


def short_event(event):
    from cto_unified_security import is_linux_event, is_windows_event
    if is_windows_event(event): return '로그인 실패 (4625)'
    if is_linux_event(event): return 'SSH 인증 실패'
    mapping={'identity.authenticate':'사용자 인증', 'image.member.create':'이미지 공유',
             'security_group_rule.create.end':'보안그룹 규칙 추가'}
    return mapping.get(str(event.get('event_type') or ''), '')


def filter_rows(events, source='전체', state='전체', query='', days='전체'):
    query = (query or '').strip().casefold()
    cutoff = None
    if days != '전체':
        cutoff = datetime.now(timezone.utc) - timedelta(days=int(days))
    result = []
    for e in events:
        if source != '전체' and source_name(e) != source: continue
        if state == 'Alert 연결' and detected_state(e) != 'Alert 연결': continue
        if state == '관측 · 미평가' and detected_state(e) != '관측 · 미평가': continue
        if cutoff:
            try:
                value = datetime.fromisoformat(str(e.get('event_time') or '').replace('Z','+00:00'))
                if value.tzinfo is None or value.astimezone(timezone.utc) < cutoff: continue
            except (ValueError, OverflowError): continue
        text = ' '.join(str(v or '') for v in (
            source_name(e), detected_state(e), display_account(e), e.get('source_ip'),
            e.get('event_type'), e.get('event_id'), ' '.join(e.get('rules') or [])))
        if query and query not in text.casefold(): continue
        result.append(e)
    return result
