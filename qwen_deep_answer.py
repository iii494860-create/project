"""Deep-only grounded details and a complete prose response contract.

Fast answers do not call this module. Facts are derived from the selected log,
not evaluation answers. The model's explanation is retained and audited.
"""
from copy import deepcopy
import json
import re

from qwen_answer_quality import completion_errors
from qwen_evidence import task_question
from qwen_observed_facts import value, show, MISSING, CONFLICT

NETWORK_REFERENCE = 'https://docs.openstack.org/api-ref/network/v2/#security-groups-security-groups'
IDENTITY_REFERENCE = 'https://docs.openstack.org/keystone/latest/admin/event_notifications.html'


def normalize_deep_text(text):
    """Repair double-escaped prose list breaks without touching code/paths."""
    if '\n' in text or '`' in text or text.count('\\n') < 2 or not re.search(r'\\n[-•·] ', text):
        return text
    text = text.replace('\\n\\n', '\n\n')
    return re.sub(r'\\n(?=[-•·] )', '\n', text)


def deep_name_text(answer):
    """Expose explicit labels even when a parenthetical ID has a qualifier."""
    return re.sub(r'([A-Za-z][A-Za-z /&-]{1,120})\s*\((?:일반적으로|통상|보통|전술\s*ID\s*[:：]?|기법\s*ID\s*[:：]?|ID\s*[:：]?)\s*'
                  r'((?:TA\d{4}|T\d{4}(?:\.\d{3})?|M\d{4}|D3-[A-Z0-9-]+))\)',
                  lambda m: m[1].rstrip() + '(' + m[2] + ')', answer)


def deep_citation_text(answer):
    """Keep sentence punctuation from looking like an identifier suffix.

    Only the validation view changes; preserve clause boundaries and the actual
    displayed answer. Malformed numeric subtechniques remain whole IDs.
    """
    return re.sub(r'([A-Za-z0-9])\.(?=\s|$)', r'\1 .', answer)


def deep_prose_errors(body, plan):
    """Reject observed unambiguous terminology/scope contradictions in prose.

    This is intentionally not an arbitrary natural-language truth evaluator.
    Source-owned details cannot mask a contradictory model introduction.
    """
    errors = []
    plain = re.sub(r'[`*]', '', body)
    for binding in plan.get('resource_bindings', []):
        pattern = (binding['label_pattern'] + r'(?:\s*(?:ID|식별자))?\s*[:=]?\s*[\[(]?\s*'
                   r'([A-Za-z0-9][A-Za-z0-9_-]{5,})')
        for match in re.finditer(pattern, plain, re.I):
            candidate = match[1]
            if (candidate != binding['value'] and
                    (candidate in binding['other_ids'] or re.fullmatch(r'(?:ev-|al-)[\w-]+|[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', candidate, re.I))):
                errors.append(binding['label'] + ' 식별자 오류: ' + candidate + ' 대신 원본 필드 '
                              + binding['field'] + '=' + binding['value']
                              + '를 사용하세요. 이벤트 ID·경보 ID·상위 자원 ID를 조치 대상 자원 ID로 바꾸어 쓰지 마세요.')
    if 'deep:meaning:shared' in plan['required_fact_ids']:
        for line in plain.splitlines():
            if not re.search(r'(?<![A-Za-z0-9_])shared(?![A-Za-z0-9_])', line, re.I):
                continue
            private_claim = re.search(r'false.{0,60}(?:비공개|비공유|사설)', line, re.I)
            explicit_rejection = re.search(r'(?:비공개|비공유|사설)[^.!?]{0,30}(?:아니|아닌|아님|아닙|단정할\s*수\s*없|뜻하지\s*않|의미하지\s*않)', line)
            if private_claim and not explicit_rejection:
                errors.append('shared=false를 비공개·비공유·사설 상태로 바꾸어 설명하지 마세요. '
                              '요청자 프로젝트에 공유되어 있는지의 값만 설명하고, 다른 프로젝트의 공유 정책은 미확인이라고 하세요.')
                break
            if re.search(r'프로젝트\s*외부|모든\s*프로젝트.{0,25}공유', line, re.I):
                if not re.search(r'(?:단정|판정|의미|확정).{0,12}(?:없|않|못|아니)', line):
                    errors.append('shared 설명 오류: 요청자 프로젝트에 이 보안그룹이 공유되어 있는지의 값입니다. '
                                  'false를 전체 비공유·사설 또는 다른 모든 프로젝트에 공유되지 않음으로 해석하지 마세요. '
                                  '하단의 검증된 필드 정의와 일치하게 고치세요.')
                    break
    if re.search(r'고정\s*IP\s*\(\s*Floating\s*IP\s*\)', plain, re.I):
        errors.append('용어 불일치: Floating IP는 유동 IP이고 fixed IP와 구분됩니다. 고정 IP(Floating IP)라는 표기를 고치세요.')
    conditions = [f.get('rule_condition', '') for f in plan['facts']]
    requires_both = any(re.search(r'remote_ip_prefix\s*와\s*remote_group_id\s*가\s*모두\s*비어', c) for c in conditions)
    if (requires_both and re.search(r'remote_ip_prefix[^\n]{0,100}(?:공백|비어|빈\s*값)', plain)
            and 'remote_group_id' not in plain):
        errors.append('탐지 조건 누락: remote_ip_prefix가 비어 있다는 조건만으로 대체하지 마세요. '
                      '실제 규칙은 remote_ip_prefix와 remote_group_id가 모두 비어 있음을 요구합니다. '
                      '규칙의 IPv4·IPv6 범위와 AND/OR 조건을 원문대로 보존해서 설명하세요.')
    return errors


def deep_context(context):
    """Unwrap a single pasted JSON event without inventing fields from prose."""
    raw = context.get('raw_event')
    if not isinstance(raw, dict) or any(k in raw for k in ('notification', 'fieldsJson', 'payload')):
        return context
    wrapped = raw.get('log')
    if isinstance(wrapped, str):
        try:
            wrapped = json.loads(wrapped)
        except ValueError:
            return context
    if isinstance(wrapped, dict):
        return {**context, 'raw_event': wrapped}
    return context


def build_deep_plan(question, context, base_plan, requirements, evidence=()):
    """Supplement source facts with supported, evidence-owned interpretations."""
    plan = deepcopy(base_plan) if base_plan else {'facts': [], 'required_fact_ids': []}
    plan['kind'] = 'deep_grounded_analysis'
    q = task_question(question)
    raw = context.get('raw_event') or {}
    if not isinstance(raw, dict):
        return plan
    if 'log' in raw and not any(k in raw for k in ('notification', 'fieldsJson', 'payload')):
        return plan  # Unparsed text or multiple events are not a selected record.
    event = str(raw.get('event_type') or context.get('event_type') or '')
    full = not context.get('question_only')
    has = lambda pattern: bool(re.search(pattern, q, re.I))

    def add(ident, text, *sources):
        if ident not in plan['required_fact_ids']:
            plan['facts'].append({'id': ident, 'text': text, 'sources': list(sources)})
            plan['required_fact_ids'].append(ident)

    if full and event.startswith('security_group_rule.'):
        rule_id = value(raw, 'payload.security_group_rule.id')
        group_id = value(raw, 'payload.security_group_rule.security_group_id')
        record_id = raw.get('recordId') or context.get('event_id')
        add('deep:resource_identity', '보안그룹 규칙 ID는 '
            + show(rule_id) + ', 상위 보안그룹 ID는 ' + show(group_id)
            + '입니다. 이벤트 ID ' + show(record_id if record_id else MISSING)
            + '는 로그 기록 식별자이므로 규칙 조회·변경·삭제 대상 ID로 사용하지 않습니다.',
            'raw_event:payload.security_group_rule.id', 'raw_event:payload.security_group_rule.security_group_id',
            'raw_event:recordId')
        if isinstance(rule_id, str) and rule_id:
            plan['resource_bindings'] = [{'label': '보안그룹 규칙', 'label_pattern': r'(?:보안그룹\s*규칙|security_group_rule)',
                'field': 'payload.security_group_rule.id', 'value': rule_id,
                'other_ids': [x for x in [group_id, record_id, *(context.get('related_alert_ids') or [])]
                              if isinstance(x, str) and x != rule_id]}]

    if full:
        related = set(context.get('related_alert_ids') or [])
        for item in evidence:
            result = item.get('result', {})
            if item.get('tool') != 'get_alert' or result.get('found') is not True or result.get('alert_id') not in related:
                continue
            rule = result.get('rule') or {}
            condition = rule.get('condition')
            if isinstance(condition, str) and condition.strip():
                ident = 'deep:rule:' + result['alert_id']
                add(ident, '실제 경보 ' + result['alert_id'] + '의 규칙 “' + show(rule.get('name', MISSING))
                    + '” 원문 조건: ' + show(condition) + '.', 'get_alert:' + result['alert_id'] + '.rule.condition')
                next(f for f in plan['facts'] if f['id'] == ident)['rule_condition'] = condition

    named = [row for item in evidence if item.get('tool') == 'lookup_named_tactics'
             for row in item.get('result', {}).get('results', [])]
    plan['reference_definitions'] = [{'id': row['id'], 'name': row['name'], 'description': row['description']}
                                     for row in named if row.get('description')]
    for row in named:
        add('deep:tactic_name:' + row['id'], '질문에 나온 전술의 실제 정식 명칭: '
            + row['id'] + ' — ' + row['name'] + '.', 'lookup_named_tactics:' + row['id'])
    for item in evidence:
        r = item.get('result', {})
        if item.get('tool') != 'lookup_technique' or r.get('found') is not True:
            continue
        if named and isinstance(r.get('tactics'), list):
            tactics = [t for t in r['tactics'] if isinstance(t, dict) and t.get('id') and t.get('name')]
            listed = '; '.join(t['id'] + ' — ' + t['name'] for t in tactics) or '조회된 소속 전술 없음'
            text = r['id'] + ' (' + r.get('name', '') + ')의 실제 소속 전술 조회 결과: ' + listed + '.'
            for target in named:
                text += ' ' + target['name'] + '(' + target['id'] + ')는 이 조회 목록에 '
                text += '포함됩니다.' if any(t['id'] == target['id'] for t in tactics) else '포함되지 않습니다.'
            add('deep:tactic_membership:' + r['id'], text, 'lookup_technique:' + r['id'] + '.tactics')

    # Explicit scalar requests are also honored when the old fast router has
    # no fact plan. Preserve missing/conflicting states and their field owner.
    for field in requirements:
        ident = 'requested_field:' + field['field']
        if not any(field['text'] == f['text'] for f in plan['facts']):
            add(ident, field['text'], 'raw_event:' + field['field'])

    if re.fullmatch(r'security_group(?:_rule)?\.(?:create|delete)\.(?:start|end)', event) and (
            full or has(r'시작|완료|종료|성공|실패|진행\s*단계')):
        phase = '시작' if event.endswith('.start') else '종료'
        outcome = value(raw, 'outcome', 'payload.outcome')
        text = f'이벤트 `{event}`는 작업 {phase} 알림입니다. 기록된 outcome은 {show(outcome)}입니다. '
        text += ('시작 알림만으로 작업 완료·성공을 판단할 수 없습니다.' if phase == '시작' else
                 '종료 알림이라는 사실과 작업 성공 여부는 구분합니다. 성공 여부는 outcome 및 같은 요청의 후속 결과를 함께 확인해야 합니다.')
        add('deep:operation_phase', text, 'raw_event:event_type', 'raw_event:outcome')

    if event.startswith('security_group.create.') and (full or has(r'뜻|의미|설명|무엇|불리언')):
        definitions = {
            'shared': 'shared는 요청자 프로젝트에 이 보안그룹이 공유되어 있는지를 나타냅니다. false만으로 다른 모든 프로젝트에 대한 공유 정책까지 판정할 수는 없습니다. false를 비공개·사설 상태와 같은 뜻으로 바꾸어 설명하면 안 됩니다.',
            'stateful': 'stateful은 연결 상태 추적을 사용하는 보안그룹인지 나타냅니다. true는 연결 상태를 추적하는 방식이고, false는 상태 추적을 우회하므로 양방향 통신에 필요한 규칙을 각각 정의해야 합니다.',
        }
        for key, definition in definitions.items():
            if full or has(r'(?<![A-Za-z0-9_])' + key + r'(?![A-Za-z0-9_])'):
                path = 'payload.security_group.' + key
                add('deep:meaning:' + key, f'`{key}`의 원본 값은 {show(value(raw, path))}입니다. ' + definition,
                    'raw_event:' + path, NETWORK_REFERENCE)

    pairs = []
    compare = has(r'비교|같(?:은|다|아|니|은지)|동일|서로\s*다|차이|바꿔\s*써')
    paths = [r['field'] for r in requirements]
    if compare:
        candidates = [
            ('payload.initiator.project_id', 'payload.project'),
            ('payload.user', 'payload.target.id'),
            ('payload.initiator.id', 'payload.target.id'),
        ]
        pairs = [(a, b) for a, b in candidates if a in paths and b in paths]
        if not pairs and len(paths) == 2:
            pairs = [tuple(paths)]
    for a, b in pairs:
        left, right = value(raw, a), value(raw, b)
        if any(v is MISSING or v is CONFLICT for v in (left, right)):
            conclusion = '한쪽 이상의 값이 없거나 충돌하여 값의 동일 여부를 확인할 수 없습니다.'
        elif type(left) is type(right) and left == right:
            conclusion = '두 필드의 값은 같습니다. 값의 일치만으로 두 필드의 의미나 식별 대상까지 같다고 단정하지 않습니다.'
        else:
            conclusion = '두 필드의 값은 서로 다릅니다.'
        add('deep:compare:' + a + ':' + b,
            f'`{a}`={show(left)}, `{b}`={show(right)}. ' + conclusion,
            'raw_event:' + a, 'raw_event:' + b)

    if event == 'identity.role_assignment.created':
        if full or ('payload.initiator.project_id' in paths and 'payload.project' in paths):
            add('deep:project_roles', '`payload.initiator.project_id`는 작업 수행자의 인증 컨텍스트에 기록된 프로젝트이고, '
                '`payload.project`는 역할을 부여하는 대상 프로젝트입니다. 작업자 컨텍스트와 역할 부여 대상 범위를 구분해야 합니다.',
                'event_semantics:identity.role_assignment', IDENTITY_REFERENCE)
        if full or has(r'누가|누구|무슨\s*역할|역할.*(?:이름|명칭)|이름.*역할'):
            add('deep:role_participants',
                '작업 수행자: username=' + show(value(raw, 'payload.initiator.username'))
                + ', ID=' + show(value(raw, 'payload.initiator.id', 'payload.initiator.user_id', '_context_user_id'))
                + '. 역할 부여 대상 사용자(payload.user)=' + show(value(raw, 'payload.user'))
                + ', 대상 프로젝트(payload.project)=' + show(value(raw, 'payload.project'))
                + ', 부여된 역할 ID(payload.role)=' + show(value(raw, 'payload.role'))
                + '. 이 선택 로그의 역할 ID만으로 역할 이름은 확인할 수 없습니다. 수행자 이름을 부여된 역할 이름으로 해석하지 않습니다.',
                'raw_event:payload', IDENTITY_REFERENCE)
    if event.startswith('identity.') and (full or (has(r'target\.id') and has(r'사람|사용자|로그인|같|동일|비교|바꿔'))):
        add('deep:target_identity', '`payload.initiator.id`는 작업 수행자 식별자이고, `payload.target.id`는 CADF 이벤트 대상 식별자입니다. '
            '대상의 typeURI는 ' + show(value(raw, 'payload.target.typeURI')) + '입니다. '
            '이번 원본만으로 target.id를 로그인 사용자 ID나 payload.user의 대체 값으로 사용할 근거는 확인되지 않았습니다. '
            '동일인 여부를 판단하려면 대상 유형과 실제 사용자 자원 연결을 확인해야 합니다.',
            'raw_event:payload.target', IDENTITY_REFERENCE)
    return plan


def deep_response_format(model_keys, plan):
    ids = plan['required_fact_ids']
    schema = {
        'type': 'object', 'additionalProperties': False,
        'properties': {
            'answers': {'type': 'object', 'properties': {k: {} for k in model_keys},
                        'required': list(model_keys), 'additionalProperties': False},
            'explanation': {'type': 'string', 'minLength': 1},
            'fact_ids': {'type': 'array', 'items': {'type': 'string', 'enum': ids} if ids else {'type': 'string'},
                         'minItems': len(ids), 'maxItems': len(ids), 'uniqueItems': True},
        },
        'required': ['answers', 'explanation', 'fact_ids'],
    }
    return {'type': 'json_schema', 'json_schema': {'name': 'deep_grounded_answer', 'strict': True, 'schema': schema}}


def validate_deep_response(raw, model_keys, plan):
    obj = json.loads(raw)
    if not isinstance(obj, dict) or set(obj) != {'answers', 'explanation', 'fact_ids'}:
        raise ValueError('심층 출력 형식: answers, explanation, fact_ids 세 필드가 필요합니다. 답변 본문은 비어 있지 않은 explanation 문자열에 작성하세요.')
    if not isinstance(obj['answers'], dict) or set(obj['answers']) != set(model_keys):
        raise ValueError('심층 answers에는 지정된 키만 넣으세요: ' + json.dumps(model_keys))
    errors = completion_errors(obj['explanation'])
    if errors:
        raise ValueError('심층 explanation에 사용자에게 보여줄 완성된 답변 본문을 작성하세요: ' + '; '.join(errors))
    ids = obj['fact_ids']
    if (not isinstance(ids, list) or any(not isinstance(i, str) for i in ids)
            or len(ids) != len(set(ids)) or set(ids) != set(plan['required_fact_ids'])):
        raise ValueError('심층 답변의 필수 사실·비교·의미·판단 항목이 누락됐습니다. fact_ids: '
                         + json.dumps(plan['required_fact_ids'], ensure_ascii=False))
    return obj


def render_deep_details(body, plan, requested_keys):
    details = '\n\n'.join(f['text'] for f in plan['facts'])
    if not details:
        return body
    if requested_keys:
        obj = json.loads(body)
        obj['explanation'] += '\n\n**원본 확인과 해석**\n\n' + details
        return json.dumps(obj, ensure_ascii=False)
    return body + '\n\n**원본 확인과 해석**\n\n' + details
