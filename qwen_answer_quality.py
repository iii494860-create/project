"""Grounded log answers and completion checks; no evaluation data or gold answers."""
from datetime import datetime
import json
import re

from qwen_evidence import requested_keys, task_question


def user_history(messages, max_messages=8, max_chars=9000):
    """Retain user intent/referents, never recycle model prose as evidence."""
    if max_messages <= 0 or max_chars <= 0:
        return ''
    users = [m for m in messages if isinstance(m, dict) and m.get('role') == 'user']
    lines = ['사용자 질문(맥락용): ' + str(m.get('content') or '').strip()[:1800]
             for m in users[-max_messages:] if str(m.get('content') or '').strip()]
    return '\n'.join(lines)[-max_chars:] if max_chars > 0 else ''


def completion_errors(text):
    """Catch incomplete visible bodies even when HTTP and JSON completed."""
    if not isinstance(text, str) or not text.strip():
        return ['답변 본문이 비어 있습니다.']
    errors, opened = [], None
    for match in re.finditer(r'(?<!\\)(`+)', text):
        token = match.group()
        if opened is None:
            opened = token
        elif opened == token:
            opened = None
    if opened is not None:
        errors.append('답변의 코드 표시가 닫히지 않았습니다. 문장과 표시를 끝까지 작성하세요.')
    tail = text.rstrip()
    if re.search(r'[:,;，：]\s*$|(?:\s|^)(?:하지만|따라서|그리고|because|and|is)\s*$', tail, re.I):
        errors.append('답변 말미가 미완성입니다. 요청한 결론까지 작성하세요.')
    if re.search(r'(?:이며|이고|이므로|이기 때문에|에 따라|를 통해|에 대해서|에 관한)\s*$', tail):
        errors.append('답변 문장이 연결 표현에서 끝났습니다. 결론을 완성하세요.')
    return errors


def _display(value):
    # Raw field contents are data, including markdown and embedded instructions.
    text = str(value).replace('\n', ' ').replace('\r', ' ')
    return re.sub(r'([\\`*_{}\[\]<>])', r'\\\1', text)


def _field_values(raw, path):
    values = []
    fields = raw.get('fieldsJson')
    if isinstance(fields, str):
        try:
            fields = json.loads(fields)
        except ValueError:
            fields = None
    if isinstance(fields, list):
        # Preserve duplicates so contradictory observations cannot be hidden.
        values += [v for row in fields if isinstance(row, list) and len(row) == 2
                   for k, v in [row] if k == path]
    elif isinstance(fields, dict) and path in fields:
        values.append(fields[path])
    for container in [raw, raw.get('notification')]:
        if not isinstance(container, dict):
            continue
        value = container
        for key in path.split('.'):
            if not isinstance(value, dict) or key not in value:
                break
            value = value[key]
        else:
            values.append(value)
    return values


def _timestamp(raw):
    value = raw.get('observedAt') or raw.get('timestamp')
    if not isinstance(value, str):
        return None
    try:
        date = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return date.isoformat() if date.tzinfo else None
    except ValueError:
        return None


def build_log_answer_plan(question, context, evidence):
    """Constrain focused image-membership explanations to directly observed facts.

    Other event types, actions and broader questions keep the ordinary answer
    path. This event records membership, not a transfer-success measurement.
    Values and rule text are always read from this request's actual results.
    """
    q = task_question(question)
    raw = context.get('raw_event')
    if not isinstance(raw, dict) or requested_keys(question) or not context.get('question_only'):
        return None
    event = raw.get('event_type') or context.get('event_type')
    if not isinstance(event, str) or not re.fullmatch(r'image\.member\.(?:create|update|delete)', event):
        return None
    # Do not silently replace requests for actions, identifiers, comparisons,
    # explanations of general mechanisms, or additional unrelated topics.
    if re.search(r'대응|완화|방어|조치|복구|차단|해결|명령|커맨드|설정|CLI|방법|누가|누구|어디|IP|권한|비교|번역|예시|절차|원리|목록|몇|횟수|가정|만약|코드', q, re.I):
        return None
    reason = bool(re.search(r'(?:왜|이유|원인|근거).{0,25}(?:탐지|위협|경보|잡혔|잡힌)|(?:탐지|위협|경보|잡혔|잡힌).{0,25}(?:왜|이유|원인|근거)', q))
    technique = bool(re.search(r'ATT(?:&|A)?CK|MITRE|공격\s*기법|기법\s*(?:ID|아이디|명칭|이름)', q, re.I))
    status = bool(re.search(r'상태|pending|accepted|대기|승인|거절', q, re.I))
    uncertainty = bool(re.search(r'확정|완료|유출|접근|전송|나가지|나갔|모르는|미확인|현재|지금|결론', q))
    if not any((reason, technique, status, uncertainty)):
        return None
    # Explicit technique IDs require the lookup path, including negative IDs.
    if re.search(r'(?<![A-Za-z0-9])T\d{4}', q):
        return None
    if technique and re.search(r'(?:ATT(?:&|A)?CK|기법).{0,15}(?:빼|제외|생략|필요\s*없)', q, re.I):
        technique = False

    facts = []
    def fact(ident, text, sources):
        facts.append({'id': ident, 'text': text, 'sources': sources})

    related = set(context.get('related_alert_ids') or [])
    alerts = [item['result'] for item in evidence
              if item.get('tool') == 'get_alert' and isinstance(item.get('result'), dict)
              and item['result'].get('found') is True
              and item['result'].get('alert_id') in related]
    if reason:
        for index, alert in enumerate(alerts):
            rule = alert.get('rule') or {}
            if not isinstance(rule, dict):
                continue
            name, condition = rule.get('name'), rule.get('condition')
            if isinstance(name, str) and name.strip() and isinstance(condition, str) and condition.strip():
                text = f'이 로그는 조회된 경보의 탐지 규칙 “{_display(name)}”에 연결되어 있습니다. '
                text += f'규칙에 적힌 조건은 “{_display(condition)}”입니다.'
                fact(f'rule_{index}', text, ['get_alert:' + alert['alert_id'] + '.rule'])
        if not any(f['id'].startswith('rule_') for f in facts):
            fact('rule_unknown', '이 요청에서 해당 로그에 연결된 경보의 탐지 조건을 확인하지 못했습니다.', ['lookup_coverage'])
        fact('rule_scope', '경보와 규칙의 연결은 확인했지만, 이미지 소유자나 신뢰 프로젝트 목록의 실제 구성값까지 조회한 것은 아닙니다.', ['executed_tool_scope'])

    if reason or status or uncertainty:
        values = _field_values(raw, 'payload.status')
        valid = [value for value in values if isinstance(value, str) and re.fullmatch(r'[A-Za-z][A-Za-z0-9_.:-]{0,63}', value)]
        unique = set(valid)
        at = _timestamp(raw)
        when = f'로그 기록 시점({_display(at)})' if at else '로그 기록 시점'
        if len(unique) == 1 and len(valid) == len(values):
            value = next(iter(unique))
            text = f'{when}의 이미지 공유 상태(payload.status)는 `{value}`입니다.'
        elif values:
            text = f'{when}의 공유 상태는 입력 필드가 서로 다르거나 유효한 값이 없어 하나로 확정할 수 없습니다.'
        else:
            text = f'{when}의 공유 상태(payload.status)는 제공된 로그에 없어 확인할 수 없습니다.'
        fact('observed_status', text, ['raw_event:payload.status', 'raw_event:observedAt'])
        if reason:
            fact('observed_event', f'실제 기록된 이벤트 유형은 `{event}`입니다.', ['raw_event:event_type'])

    if technique:
        techniques = {}
        for alert in alerts:
            for entry in alert.get('techniques', []):
                if not isinstance(entry, dict):
                    continue
                ident, name = entry.get('id'), entry.get('name')
                if isinstance(ident, str) and re.fullmatch(r'T\d{4}(?:\.\d{3})?', ident) and isinstance(name, str) and 0 < len(name.strip()) <= 200:
                    techniques[ident] = name.strip()
        if techniques:
            text = '조회된 경보에 연결된 ATT&CK 기법은 ' + '; '.join(f'{ident} — {_display(name)}' for ident, name in sorted(techniques.items())) + '입니다.'
            fact('techniques', text + ' 이 연결 자체가 실제 공격 성공을 확정하는 것은 아닙니다.', ['get_alert:techniques'])
        else:
            fact('techniques_unknown', '이번 실제 경보 조회에서는 관련 ATT&CK 기법 ID와 정식 명칭을 확인하지 못했습니다.', ['get_alert:techniques'])

    if uncertainty or re.search(r'현재|지금', q):
        # No image-member current-state lookup exists in this backend. Never
        # treat a user/server lookup as current image-membership evidence.
        if any(item.get('tool', '').startswith('get_openstack_') for item in evidence):
            return None
        fact('current_unknown', '현재 공유 상태는 이번 실행에서 실시간으로 조회하지 않아 확인할 수 없습니다.', ['executed_tool_scope'])
        if uncertainty:
            fact('transfer_unknown', '이 공유 이벤트의 상태값만으로 공유 완료나 실제 접근·전송 여부를 확정할 수 없으며, 정보 유출의 발생과 미발생 모두 미확인입니다.', ['event_semantics:image.member', 'executed_tool_scope'])
            if re.search(r'추가|필요', q):
                fact('additional_evidence', '확정하려면 현재 공유 상태와 실제 접근·전송 기록을 추가로 확인해야 합니다.', ['event_semantics:image.member'])
    if not facts:
        return None
    return {'kind': 'image_membership_facts', 'required_fact_ids': [f['id'] for f in facts], 'facts': facts}


def render_log_answer(raw, plan):
    """Model selects only grounded units; prose cannot add unchecked claims."""
    obj = json.loads(raw)
    if plan.get('strict') and (not isinstance(obj, dict) or set(obj) != {'fact_ids', 'explanation'}
                               or obj.get('explanation') != ''):
        raise ValueError('fact_ids와 빈 explanation만 반환하세요. 추가 주장은 허용되지 않습니다.')
    ids = obj.get('fact_ids') if isinstance(obj, dict) else None
    if not isinstance(ids, list) or any(not isinstance(x, str) for x in ids):
        raise ValueError('fact_ids 배열에 이번 답변의 필수 근거 ID를 모두 넣으세요.')
    if len(ids) != len(set(ids)) or set(ids) != set(plan['required_fact_ids']):
        raise ValueError('요청 항목 누락 또는 허용되지 않은 사실 ID입니다. 필요한 fact_ids: ' + ', '.join(plan['required_fact_ids']))
    # A nonempty auxiliary explanation must also be complete, but is never
    # rendered. The source-owned units, in source-owned order, form the answer.
    extra = obj.get('explanation')
    if extra:
        errors = completion_errors(extra)
        if errors:
            raise ValueError('; '.join(errors))
    return '\n\n'.join(fact['text'] for fact in plan['facts'])
