# CTO_MULTISOURCE_UI_WINDOWS_AUTO_V2
"""Source-aware merging and safe HTML evidence for OpenStack & Linux SSH.

A standalone SSH login failure is an observation, not a 3K1H Alert.
Do NOT attach Linux journal events to a fabricated Alert or incident.
"""
from __future__ import annotations
import html
import json
from datetime import datetime

LINUX_CYPHER = '''
MATCH (e:ObservedEvent {sourceType:'linux_ssh'})
WHERE e.eventTypeName = 'linux.ssh.authentication_failure'
RETURN e.recordId AS event_id,
       elementId(e) AS neo4j_node_id,
       toString(e.observedAt) AS event_time,
       e.eventTypeName AS event_type,
       e.outcome AS outcome,
       e.user AS username,
       e.ip AS source_ip,
       e.fieldsJson AS fields_json
ORDER BY e.observedAt DESC LIMIT $limit
'''


def is_linux_event(event):
    return isinstance(event, dict) and (
        (event.get('neo4j_properties') or {}).get('sourceType') == 'linux_ssh'
        or event.get('source_type') == 'linux_ssh'
    )


def is_windows_event(event):
    return isinstance(event, dict) and (
        (event.get('neo4j_properties') or {}).get('sourceType') == 'windows_security'
        or event.get('source_type') == 'windows_security'
    )


def is_observation_event(event):
    return is_linux_event(event) or is_windows_event(event)


def source_label(event):
    if is_linux_event(event):
        return 'Linux SSH'
    if is_windows_event(event):
        return 'Windows'
    return 'OpenStack'


def detection_label(event):
    return '관측 · 미평가' if is_observation_event(event) else 'Alert 연결'


def load_linux_rows(neo4j_query, limit=80):
    rows = neo4j_query(LINUX_CYPHER, limit=limit)
    result = []
    for row in rows:
        if not isinstance(row, dict) or not row.get('event_id'):
            continue
        try:
            fields = json.loads(row.get('fields_json') or '{}')
            if not isinstance(fields, dict):
                fields = {}
        except (TypeError, ValueError):
            fields = {}
        result.append({
            'event_id': str(row['event_id']),
            'record_id': str(row['event_id']),
            'neo4j_node_id': row.get('neo4j_node_id') or '',
            'event_time': row.get('event_time') or '',
            'event_type': row.get('event_type') or 'linux.ssh.authentication_failure',
            'outcome': row.get('outcome') or 'failure',
            'username': row.get('username') or '',
            'source_ip': row.get('source_ip') or '',
            'rules': [], 'severities': [], 'alert_ids': [],
            'neo4j_properties': {'sourceType': 'linux_ssh', 'fieldsJson': row.get('fields_json') or '{}'},
            'source_type': 'linux_ssh',
        })
    return result


def combine_events(openstack_rows, linux_rows, windows_rows=None, limit=160):
    """Stable source-aware merge; never invent Alert associations."""
    seen = set()
    merged = []
    for event in list(openstack_rows) + list(linux_rows) + list(windows_rows or []):
        if not isinstance(event, dict):
            continue
        key = (source_label(event), str(event.get('event_id') or event.get('neo4j_node_id') or ''))
        if not key[1] or key in seen:
            continue
        seen.add(key)
        merged.append(event)
    def order_value(event):
        value = str(event.get('event_time') or '')
        try:
            dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
            return dt.timestamp()
        except (ValueError, OverflowError, OSError):
            return float('-inf')
    merged.sort(key=order_value, reverse=True)
    return merged[:limit]


def linux_inline_detail(event):
    """Escaped observational evidence. No attack labels, action link, or RAG guess."""
    props = event.get('neo4j_properties') or {}
    try:
        fields = json.loads(props.get('fieldsJson') or '{}')
        if not isinstance(fields, dict):
            fields = {}
    except (ValueError, TypeError):
        fields = {}
    def safe(v):
        return html.escape(str(v if v is not None else '-'), quote=True)
    pieces = [
        ('이벤트', event.get('event_type') or 'linux.ssh.authentication_failure'),
        ('호스트', fields.get('hostname') or '-'),
        ('계정', event.get('username') or '-'),
        ('출발지 IP', event.get('source_ip') or '-'),
        ('인증 방식', fields.get('auth_method') or '-'),
        ('실제 SSH 메시지 일부', fields.get('message_excerpt') or '없음'),
    ]
    blocks = ''.join('<div style="padding:6px 0"><b>' + safe(k) + '</b>: ' + safe(v) + '</div>' for k, v in pieces)
    return ('<div class="cto-detail" style="padding:16px 20px;color:#eaf2ff">'
            '<strong style="font-size:16px">Linux SSH 인증 실패 · 관측된 이벤트</strong>'
            '<p>이 이벤트는 3K1H 탐지 엔진 Alert가 아닙니다. 한 번의 인증 실패로 공격 또는 침해를 확정하지 않습니다.</p>'
            + blocks + '<p style="color:#bdc9dd">원본 전체가 아닌 마스킹된 정규화 근거입니다. '
            'Linux SSH AI 분석은 통합 표 아래의 접힌 분석 영역에서 할 수 있습니다.</p></div>')


WINDOWS_CYPHER = """
MATCH (e:ObservedEvent {sourceType:'windows_security'})
WHERE e.eventTypeName = 'windows.security.logon_failure'
RETURN e.recordId AS event_id,
       elementId(e) AS neo4j_node_id,
       toString(e.observedAt) AS event_time,
       e.eventTypeName AS event_type,
       e.outcome AS outcome,
       e.user AS username,
       e.ip AS source_ip,
       e.fieldsJson AS fields_json
ORDER BY e.observedAt DESC LIMIT $limit
"""


def load_windows_rows(neo4j_query, limit=80):
    rows=neo4j_query(WINDOWS_CYPHER,limit=limit)
    result=[]
    for row in rows:
        if not isinstance(row,dict) or not row.get('event_id'):
            continue
        result.append({
            'event_id':str(row['event_id']), 'record_id':str(row['event_id']),
            'neo4j_node_id':row.get('neo4j_node_id') or '',
            'event_time':row.get('event_time') or '',
            'event_type':row.get('event_type') or 'windows.security.logon_failure',
            'outcome':row.get('outcome') or 'failure',
            'username':row.get('username') or '',
            'source_ip':row.get('source_ip') or '',
            'rules':[], 'severities':[], 'alert_ids':[],
            'neo4j_properties':{'sourceType':'windows_security',
                                'fieldsJson':row.get('fields_json') or '{}'},
            'source_type':'windows_security',
        })
    return result


def windows_inline_detail(event):
    props=event.get('neo4j_properties') or {}
    try:
        f=json.loads(props.get('fieldsJson') or '{}')
        if not isinstance(f,dict):f={}
    except (ValueError,TypeError):f={}
    def safe(v):return html.escape(str(v if v is not None else '-'),quote=True)
    items=(('이벤트','Windows Security 4625'),('호스트',f.get('hostname') or '-'),
           ('계정',event.get('username') or '원본 계정명 미제공'),('도메인',f.get('domain') if f.get('domain') not in ('', '-', None) else '원본 도메인 미제공'),
           ('출발지 IP',event.get('source_ip') or '미확인'),
           ('로그온 유형',f.get('logon_type') if f.get('logon_type') is not None else '미확인'),
           ('실패 상태 코드',f.get('status') or '-'),('보조 상태 코드',f.get('sub_status') or '-'))
    body=''.join('<div style="padding:6px 0"><b>'+safe(k)+'</b>: '+safe(v)+'</div>' for k,v in items)
    return ('<div class="cto-detail" style="padding:16px 20px;color:#eaf2ff">'
            '<strong style="font-size:16px">Windows 로그인 실패 (4625) · 관측된 이벤트</strong>'
            '<p>이 이벤트는 공격 확정이나 3K1H 탐지 Alert가 아닙니다.</p>'
            +body+'<p style="color:#bdc9dd">선택 필드만 보존한 로그이며 전체 Windows Event XML이 아닙니다. '
            'AI 분석은 통합 표 아래의 Windows 분석 영역에서 실행하세요.</p></div>')


def observation_inline_detail(event):
    return windows_inline_detail(event) if is_windows_event(event) else linux_inline_detail(event)
