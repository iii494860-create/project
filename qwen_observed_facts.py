"""Source-owned answers for focused notification questions.

The router uses question intent and event semantics, never case IDs or expected
answers. Values, counts, rule text and mappings come only from this request.
Broader action/knowledge questions retain the ordinary analysis path.
"""
from collections import Counter
from datetime import datetime
import json
import re

from qwen_answer_quality import _display, _field_values, _timestamp
from qwen_evidence import requested_keys, task_question


MISSING = object()
CONFLICT = object()


def value(raw, *paths):
    values = []
    for path in paths:
        for v in _field_values(raw, path):
            if v is None or v == '':
                continue
            # Notification payloads are typed JSON; the extraction table stores
            # port/count values as strings. Normalize only declared numeric
            # fields, never arbitrary identifiers (including leading zeros).
            if (path.rsplit('.', 1)[-1] in ('port_range_min', 'port_range_max',
                    'distinct_partial_password_hashes', 'distinct_hash_count')
                    and isinstance(v, str) and re.fullmatch(r'0|[1-9][0-9]*', v)):
                v = int(v)
            values.append(v)
    if not values:
        return MISSING
    unique = {json.dumps(v, sort_keys=True, ensure_ascii=False) for v in values}
    return values[0] if len(unique) == 1 else CONFLICT


def show(v):
    if v is MISSING:
        return '미기록(null 또는 필드 없음)'
    if v is CONFLICT:
        return '필드 값 충돌로 미확인'
    if v is None:
        return 'null'
    return _display(json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list, bool)) else v)


def date(v):
    try:
        d = datetime.fromisoformat(v.replace('Z', '+00:00'))
        return d if d.tzinfo else None
    except (ValueError, AttributeError, TypeError):
        return None


def event_raw(event):
    data = event.get('log_data') or {}
    return {'fieldsJson': [[f['path'], f.get('value')] for f in data.get('fields', [])
                           if isinstance(f, dict) and 'path' in f],
            'user_id': data.get('user'), 'source_ip': data.get('ip'),
            'request_id': data.get('request_id')}


def rule_description(raw, prefix):
    fields = ['direction', 'remote_ip_prefix', 'protocol', 'port_range_min', 'port_range_max']
    vals = {f: value(raw, prefix + '.' + f) for f in fields}
    text = ', '.join(f'{f}={show(v)}' for f, v in vals.items()) + '.'
    if vals['remote_ip_prefix'] in ('0.0.0.0/0', '::/0'):
        family = 'IPv4' if vals['remote_ip_prefix'] == '0.0.0.0/0' else 'IPv6'
        text += f' 원격 주소 범위는 모든 {family} 주소이며, 포트 범위와는 별개입니다.'
    lo, hi = vals['port_range_min'], vals['port_range_max']
    if (str(lo).isdigit() and str(hi).isdigit() and vals['protocol'] in ('tcp', 'udp', '6', '17', 6, 17)
            and 0 <= int(lo) <= int(hi) <= 65535):
        text += f' 이 규칙의 포트 범위는 `{lo}~{hi}`이며, '
        text += '전체 포트 범위입니다.' if int(lo) <= 1 and int(hi) == 65535 else '`1~65535` 전체 포트 개방은 아닙니다.'
    else:
        text += ' 비어 있는 포트 값은 프로토콜과 함께 해석해야 하며, 임의의 포트 범위로 바꾸지 않습니다.'
    return text


def build_observed_answer_plan(question, context, evidence):
    q = task_question(question)
    raw = context.get('raw_event')
    if not context.get('question_only') or not isinstance(raw, dict) or requested_keys(question):
        return None
    event = raw.get('event_type') or context.get('event_type')
    auth = event == 'identity.authenticate'
    role = event == 'identity.role_assignment.created'
    group = bool(re.fullmatch(r'security_group\.(?:create|delete)\.(?:start|end)', str(event)))
    rule = bool(re.fullmatch(r'security_group_rule\.(?:create|delete)\.(?:start|end)', str(event)))
    if not (auth or role or group or rule):
        return None
    if re.search(r'명령|커맨드|코드|스크립트|대응\s*(?:방법|절차)|완화|복구|번역|전술|가정|만약|T\d{4}', q, re.I):
        return None
    # A live lookup needs its own response semantics; never replace its result
    # with a static "not queried" statement.
    if any(e.get('tool', '').startswith('get_openstack_') for e in evidence):
        return None
    has = lambda pattern: bool(re.search(pattern, q, re.I))
    mapping = has(r'ATT(?:&|A)?CK|매핑|기법|온톨로지.*등록')
    alerts_needed = has(r'경보|탐지') and not mapping and not has(r'포트.*모두|전체\s*개방.{0,30}포트')
    actor = has(r'사용자\s*ID|사용자명|username|요청\s*ID|출발지\s*IP|누가|누구')
    client = has(r'user\s*agent|에이전트|SDK|자동화|사람이|직접\s*수행')
    current = has(r'지금|현재|활성\s*상태|활성\s*여부')
    uncertainty = has(r'확정|침해|탈취|정상|승인|접속.*성공|로그인.*성공|추가\s*확인|노출.*사라|삭제.*끝|완료|판정')
    hashes = has(r'해시|비밀번호|설정\s*오류')
    spray = has(r'스프레이|spray')
    aggregate = has(r'건수|이벤트\s*수|집계|시간창|시간\s*간격|계정\s*수') or spray
    later_success = (auth and value(raw, 'outcome', 'payload.outcome') == 'failure'
                     and has(r'나중|이후|후속|성공\s*기록|실제\s*성공'))
    ports = (rule or group) and has(r'포트|방향|IP\s*버전|규칙|TCP|SSH|22번|외부.*개방') and not mapping
    role_fields = role and has(r'payload\.|역할|role|사용자|username')
    group_fields = group and has(r'ID|이름|설명|TEST|unattached|대상')
    if not any((mapping, alerts_needed, actor, client, current, uncertainty, hashes, aggregate,
                later_success, ports, role_fields, group_fields, has(r'결과|이벤트|기록\s*시각'))):
        return None

    facts = []
    def add(key, text, *sources):
        facts.append({'id': key, 'text': text, 'sources': list(sources)})

    related = set(context.get('related_alert_ids') or [])
    alerts = [e['result'] for e in evidence if e.get('tool') == 'get_alert'
              and isinstance(e.get('result'), dict) and e['result'].get('found') is True
              and e['result'].get('alert_id') in related and not e['result'].get('error')]
    explain = [e['result'] for e in evidence if e.get('tool') == 'explain_log_event'
               and e.get('arguments', {}).get('event_type') == event
               and isinstance(e.get('result'), dict) and not e['result'].get('error')
               and e['result'].get('event_type') == event
               and e.get('arguments', {}).get('outcome') in (None, context.get('outcome'), raw.get('outcome'))]
    rows = [r for e in explain if e.get('matched') is True for r in e.get('results', [])
            if event in r.get('event_type_names', [])
            and r.get('outcome') in (None, raw.get('outcome'), context.get('outcome'))]
    # Deduplicate only identical observations. Inconsistent duplicates are not
    # usable for counts or temporal assertions.
    observed = {}
    conflicts = set()
    for a in alerts:
        for e in a.get('evidence_events', []):
            ident = e.get('event_id')
            if not isinstance(ident, str):
                continue
            if ident in observed and observed[ident] != e:
                conflicts.add(ident)
            observed[ident] = e
    events = [e for k, e in observed.items() if k not in conflicts]

    if actor or (auth and has(r'결과')):
        paths = [('사용자 ID', ('user_id', 'payload.initiator.user_id', 'payload.initiator.id', '_context_user_id')),
                 ('요청 ID', ('request_id', 'payload.initiator.request_id', '_context_request_id')),
                 ('출발지 IP', ('source_ip', 'payload.initiator.host.address', '_context_remote_address'))]
        if auth or has(r'사용자명|username'):
            paths.insert(0, ('사용자명', ('payload.initiator.username',)))
        text = '; '.join(name + ': ' + show(value(raw, *ps)) for name, ps in paths) + '.'
        if auth:
            text = '선택한 원본의 결과(outcome): ' + show(value(raw, 'outcome', 'payload.outcome')) + '. ' + text
        add('selected_actor', text + ' 다른 이벤트의 IP를 이 요청의 출발지로 대입하지 않습니다.', 'raw_event:actor_fields')

    if role_fields:
        add('assigned_role', '선택한 원본: ' + '; '.join(p + '=' + show(value(raw, p))
            for p in ('payload.role', 'payload.user', 'payload.project')) + '.', 'raw_event:payload')
        if has(r'admin|관리자|승인|정상|username'):
            add('role_name_limit', '작업 수행자의 username은 ' + show(value(raw, 'payload.initiator.username'))
                + '입니다. username과 부여된 role ID는 별개이며, role ID의 이름 및 실제 관리자 역할·허용 목록을 조회하지 않아 admin 역할인지 확정할 수 없습니다.',
                'raw_event:payload.initiator.username', 'executed_tool_scope')
        if has(r'승인|정상'):
            add('approval_limit', '역할·사용자·프로젝트 식별자는 승인 기록이 아닙니다. 정상 관리 작업인지와 승인 여부는 변경 요청·승인 이력 등 별도 근거가 필요하며 현재 자료로는 미확인입니다.', 'event_semantics:role_assignment')

    if client and auth:
        add('client_agent', '원본 user agent(payload.initiator.host.agent): ' + show(value(raw, 'payload.initiator.host.agent'))
            + '. 이 값은 클라이언트가 기록한 식별 문자열입니다. SDK 이름이 있어도 사람이 실행한 CLI·스크립트와 자동 실행을 구분할 수 없으며, 문자열 자체도 위조될 수 있습니다. 실제 실행 주체·자동화 여부·정상 또는 악성 여부는 별도 실행·감사 기록으로 확인해야 합니다.',
            'raw_event:payload.initiator.host.agent', 'event_semantics:client_identification')

    if alerts_needed:
        if alerts:
            text = '선택 로그에 실제 연결되어 조회된 경보는 다음과 같습니다.\n\n' + '\n'.join(
                '- ' + show(a['alert_id']) + ': ' + show((a.get('rule') or {}).get('name', MISSING))
                + ', 심각도 ' + show((a.get('rule') or {}).get('severity', MISSING))
                + '. 실제 경보 조건: ' + show((a.get('rule') or {}).get('condition', MISSING)) + '.' for a in alerts)
        else:
            text = '이번 조회에서 선택 로그에 연결된 경보의 상세 정보를 확인하지 못했습니다.'
        text += '\n\n위 목록과 온톨로지의 일반 탐지 규칙 후보는 별개입니다. 목록에 없는 경보가 이 로그에서 발생했다고 확정할 수 없습니다.'
        add('linked_alerts', text, *['get_alert:' + a['alert_id'] + '.rule' for a in alerts])

    if mapping:
        direct = {t['id']: t['name'] for r in rows for b in r.get('behaviors', [])
                  for t in b.get('suggested_techniques', []) if isinstance(t, dict) and t.get('id') and t.get('name')}
        related_techniques = {t['id']: t['name'] for a in alerts for t in a.get('techniques', [])
                              if isinstance(t, dict) and t.get('id') and t.get('name')}
        listing = lambda ts: '; '.join(show(k) + ' — ' + show(v) for k, v in sorted(ts.items()))
        if direct:
            text = f'선택 이벤트 {show(event)}의 행위에 직접 연결된 ATT&CK 기법: {listing(direct)}.'
        elif rows:
            text = f'선택 이벤트 {show(event)}는 온톨로지 등록 이벤트이지만 조회된 행위의 직접 ATT&CK 매핑은 비어 있습니다.'
        elif any(e.get('matched') is False for e in explain):
            text = f'선택 이벤트 {show(event)} 자체는 이번 온톨로지 조회에서 미등록(matched=false)이며 직접 ATT&CK 매핑도 확인되지 않았습니다.'
        else:
            text = '선택 이벤트 자체의 온톨로지 등록 여부와 직접 ATT&CK 매핑을 확인하지 못했습니다.'
        text += '\n\n연결 경보의 관련 기법: ' + (listing(related_techniques) if related_techniques else '이번 조회에서 확인되지 않음') + '.'
        text += ' 경보 전체의 관련 기법을 선택 이벤트 자체의 직접 매핑으로 옮겨 붙이지 않으며, 매핑 자체가 공격 성공을 증명하지 않습니다.'
        add('scoped_mapping', text, 'explain_log_event:exact_event.behaviors', 'get_alert:techniques')

    if rule and (ports or uncertainty):
        add('selected_rule', '선택 원본 payload.security_group_rule: ' + rule_description(raw, 'payload.security_group_rule')
            + ' 경보 이름이 아닌 이 필드 값으로 실제 범위를 설명해야 합니다.', 'raw_event:payload.security_group_rule')
        if has(r'경보\s*이름|경보명|이름.{0,15}경보'):
            for i, a in enumerate(alerts):
                add('rule_name_scope_' + str(i), '실제 경보 “' + show((a.get('rule') or {}).get('name', MISSING))
                    + '”의 조건은 “' + show((a.get('rule') or {}).get('condition', MISSING))
                    + '”입니다. 이름은 탐지 조건의 요약이며 모든 포트가 열렸다는 원본 필드가 아닙니다.',
                    'get_alert:' + a['alert_id'] + '.rule')

    if group_fields:
        if '.create.' in event:
            text = '; '.join(p + '=' + show(value(raw, 'payload.security_group.' + p))
                             for p in ('id', 'name', 'project_id', 'description'))
        else:
            text = 'payload.security_group_id=' + show(value(raw, 'payload.security_group_id'))
        add('selected_group', '선택 원본: ' + text + '.', 'raw_event:payload')

    if group and '.delete.' in event and (uncertainty or has(r'이벤트|결과|시작')):
        phase = '시작 알림' if event.endswith('.start') else '종료 알림'
        add('operation_phase', f'선택 이벤트 이름은 {show(event)}이며 보안그룹 삭제 {phase}입니다. 원본 outcome은 '
            + show(value(raw, 'outcome', 'payload.outcome')) + '.'
            + (' 시작 알림 한 건은 삭제 완료의 증거가 아닙니다.' if event.endswith('.start') else ' 종료 알림과 별도 성공 결과 값은 구분해야 합니다.')
            + ' 규칙 삭제와 보안그룹 삭제는 다른 작업입니다. 후속 완료를 확인하려면 같은 작업·대상·요청 ID와 시각이 연결되는 기록을 확인해야 합니다.',
            'raw_event:event_type', 'raw_event:outcome', 'event_semantics:operation_phase')

    if group and '.create.' in event and ports:
        rs = value(raw, 'payload.security_group.security_group_rules')
        if isinstance(rs, list) and all(isinstance(r, dict) for r in rs):
            text = f'선택 생성 원본 security_group_rules에는 {len(rs)}개 규칙이 있습니다.\n\n'
            for i, r in enumerate(rs, 1):
                text += f'- 규칙 {i}: ' + ', '.join(k + '=' + show(r.get(k, MISSING)) for k in
                    ('direction', 'ethertype', 'protocol', 'port_range_min', 'port_range_max')) + '.\n'
            if all(r.get('direction') == 'egress' for r in rs):
                text += '\n이 목록에는 수신(ingress) 규칙이 없습니다. 따라서 이 생성 원본에 수신 TCP 22 규칙이 있다고 설명할 수 없습니다.'
        else:
            text = '선택 원본의 security_group_rules 목록이 없거나 충돌하여 규칙 수와 수신 규칙을 확인할 수 없습니다.'
        add('selected_group_rules', text.strip(), 'raw_event:payload.security_group.security_group_rules')
        if has(r'다른\s*이벤트|별도|누적|외부|개방|접속'):
            target = value(raw, 'payload.security_group.id')
            others = [e for e in events if e.get('event_type') == 'security_group_rule.create.end'
                      and isinstance(target, str)
                      and value(event_raw(e), 'payload.security_group_rule.security_group_id') == target]
            text = '같은 경보에서 조회된 별도 규칙 생성 기록: '
            if others:
                text += '\n\n' + '\n'.join('- ' + show(e['event_id']) + ', ' + show(e.get('time', MISSING))
                    + ': ' + rule_description(event_raw(e), 'payload.security_group_rule') for e in others)
                text += '\n\n이 별도 이벤트의 값은 선택한 생성 원본의 규칙 목록에 포함된 값이 아닙니다.'
            else:
                text += '같은 보안그룹 ID로 확인되는 별도 규칙 생성 기록이 이번 자료에는 없습니다.'
            add('separate_rule_events', text, 'get_alert:evidence_events.same_security_group')

    if group and has(r'TEST|unattached|설명|정상\s*테스트|연결되지'):
        add('label_limit', '이름·설명의 TEST 또는 unattached 같은 문자열은 작성자가 붙인 표기입니다. 실제 서버·포트 연결 상태나 정상 테스트 승인 여부를 증명하지 않습니다. 생성·삭제의 시간 간격만으로 미연결 상태를 추정할 수도 없습니다. 실제 연결 정보와 승인 이력은 이번 실행에서 확인하지 않았습니다.',
            'event_semantics:resource_label', 'executed_tool_scope')

    if aggregate:
        for i, a in enumerate(alerts):
            es = [e for e in a.get('evidence_events', []) if e.get('event_id') in observed
                  and e.get('event_id') not in conflicts]
            es = list({e['event_id']: e for e in es}.values())
            times = [date(e.get('time')) for e in es]
            text = f'선택 원본은 1건입니다. 경보 {show(a["alert_id"])}의 evidence_total은 {show(a.get("evidence_total", MISSING))}건, 이번에 반환된 고유 근거 이벤트는 {len(es)}건입니다.'
            counts = Counter((e.get('event_type'), e.get('outcome')) for e in es)
            text += ' 반환 자료의 구분: ' + '; '.join(f'{show(k[0])}/{show(k[1])} {v}건' for k, v in counts.items()) + '.'
            if times and all(times):
                lo, hi = min(times), max(times)
                text += f' 관측 시각은 {lo.isoformat()} ~ {hi.isoformat()}, 실제 간격은 {(hi-lo).total_seconds():g}초입니다.'
            else:
                text += ' 유효한 시간대 포함 시각이 부족하여 실제 시간 간격은 미확인입니다.'
            text += ' 적용된 경보 규칙의 시간창·조건은 “' + show((a.get('rule') or {}).get('condition', MISSING)) + '”입니다. 관측 간격과 규칙 시간창은 별개입니다.'
            add('aggregation_' + str(i), text, 'get_alert:' + a['alert_id'] + '.evidence_events', 'get_alert:rule.condition')

    if auth and hashes:
        hash_value = value(raw, 'partial_password_hash', 'payload.partial_password_hash')
        attachments = value(raw, 'payload.attachments')
        if isinstance(attachments, list):
            found = [a.get('content') for a in attachments if isinstance(a, dict) and a.get('name') == 'partial_password_hash']
            if found:
                hash_value = found[0] if len({str(v) for v in found}) == 1 else CONFLICT
        count = value(raw, 'distinct_partial_password_hashes', 'distinct_hash_count')
        text = '선택 원본의 비밀번호 부분 해시는 ' + ('미기록' if hash_value is MISSING else '충돌로 미확인' if hash_value is CONFLICT else '필드가 있음')
        text += ', 해시 종류 수는 ' + show(count) + '입니다.'
        text += ' 단일 인증 실패나 경보 발생만으로 비밀번호를 바꿔 가며 시도한 공격인지, 저장된 자격증명 설정 오류인지 확정할 수 없습니다. 반복 시도의 해시 변화·실행 주체·설정 근거가 필요합니다.'
        add('password_evidence', text, 'raw_event:password_hash_fields', 'event_semantics:authentication')

    if spray:
        failures = [e for e in events if e.get('event_type') == 'identity.authenticate' and e.get('outcome') == 'failure']
        users = [value(event_raw(e), 'user_id', 'payload.initiator.id', 'payload.initiator.user_id') for e in failures]
        known = {v for v in users if isinstance(v, str)}
        text = f'반환된 인증 실패 {len(failures)}건에서 확인된 서로 다른 계정은 {len(known)}개입니다.'
        if len(users) != sum(isinstance(v, str) for v in users):
            text += ' 사용자 ID가 없거나 충돌하는 기록이 있어 전체 계정 수는 확정할 수 없습니다.'
        spray_rules = [r for e in explain for r in e.get('rule_definitions', [])
                       if '스프레이' in str(r.get('label_ko', '')) or 'spray' in str(r.get('uri', '')).lower()]
        for r in spray_rules:
            text += ' 온톨로지의 ' + show(r.get('label_ko', MISSING)) + ' 조건: ' + show(r.get('condition_ko', MISSING)) + '.'
        text += ' 계정 수·같은 출발지·규칙 시간창 등 해당 조건을 확인해야 하며, 해시가 없다는 사실을 비밀번호 스프레이 성립 근거로 삼을 수 없습니다.'
        mins = [r.get('distinctMin') for r in spray_rules if type(r.get('distinctMin')) is int]
        if mins and len(known) < min(mins):
            text += ' 이번 확인된 계정 수는 조회된 최소 조건보다 작으므로 제공 자료로 스프레이라고 확정할 수 없습니다.'
        add('spray_scope', text, 'get_alert:evidence_events.authentication_users', 'explain_log_event:rule_definitions')

    if later_success:
        successes = [e for e in events if e.get('event_type') == 'identity.authenticate' and e.get('outcome') == 'success']
        failures = [e for e in events if e.get('event_type') == 'identity.authenticate' and e.get('outcome') == 'failure']
        if not successes:
            text = f'반환된 경보 근거의 인증 실패(failure)는 {len(failures)}건, 성공(success)은 0건입니다. 선택 로그와 반환된 경보 근거 안에는 실제 인증 성공 기록이 없습니다. 이후 로그인 성공 여부는 미확인입니다. 성공 기록이 없다는 것은 나중에도 성공하지 않았다는 뜻은 아닙니다.'
        else:
            text = f'반환된 경보 근거에는 인증 성공 기록이 {len(successes)}건 있습니다. 선택 실패 이후 같은 계정·IP의 성공인지 시각과 주체를 대조해야 하며, 다른 성공 기록을 이 실패의 후속 성공으로 단정하지 않습니다.'
        add('success_evidence', text, 'get_alert:evidence_events.outcome')

    if current:
        add('current_state', '선택 로그는 과거 기록이며 현재 계정·자원 상태는 이번 실행에서 실시간 조회하지 않았습니다. 과거 인증 성공이나 자원 작업 기록만으로 지금의 활성 상태를 판단할 수 없습니다.',
            'raw_event:observedAt', 'executed_tool_scope')
    if uncertainty and auth and not (hashes or later_success or current or client):
        add('authentication_limit', '선택 로그의 인증 결과는 ' + show(value(raw, 'outcome', 'payload.outcome'))
            + '입니다. 이는 기록된 인증 결과이며 계정 탈취 또는 정상 사용자 로그인이라는 판정은 아닙니다. 정상·침해 여부 모두 추가 인증 이력, 사용자 확인 및 실행·접근 근거가 필요합니다.',
            'raw_event:outcome', 'event_semantics:authentication')
    if uncertainty and (group or rule):
        add('network_limit', '이 자원 작업 로그만으로 외부 SSH 접속 성공·서버 침해 또는 외부 노출 해소를 확정할 수 없습니다. 실제 서버·포트의 보안그룹 연결, 네트워크 경로와 현재 규칙, 접속·인증 기록을 추가 확인해야 합니다.',
            'event_semantics:security_group', 'executed_tool_scope')
    if has(r'시각|시간대|언제'):
        add('record_time', '선택 로그의 시간대 포함 기록 시각: ' + show(_timestamp(raw) or MISSING) + '.', 'raw_event:observedAt')
    if not facts:
        return None
    return {'kind': 'observed_notification_facts', 'strict': True,
            'required_fact_ids': [f['id'] for f in facts], 'facts': facts}


def fact_response_format(plan):
    return {'type': 'json_schema', 'json_schema': {'name': 'grounded_notification_facts', 'strict': True,
        'schema': {'type': 'object', 'additionalProperties': False,
                   'required': ['fact_ids', 'explanation'], 'properties': {
                       'fact_ids': {'type': 'array', 'items': {'type': 'string', 'enum': plan['required_fact_ids']},
                                    'minItems': len(plan['required_fact_ids']), 'maxItems': len(plan['required_fact_ids']),
                                    'uniqueItems': True},
                       'explanation': {'type': 'string', 'enum': ['']}}}}}
