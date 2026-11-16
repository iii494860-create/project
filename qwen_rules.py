"""Evaluate supported ontology conditions from input facts, without an LLM.

Thresholds come from actual ontology rule properties. Unsupported conditions,
missing fields and mixed aggregates remain unknown. No benchmark data is read.
"""
from datetime import datetime
import json
import ipaddress
import re


def records(context):
    result = []
    def visit(node, depth=0):
        if depth > 6:
            return
        if isinstance(node, str) and len(node) <= 64000:
            try: node = json.loads(node)
            except ValueError: return
        if isinstance(node, list):
            for item in node[:100]: visit(item, depth + 1)
        elif isinstance(node, dict):
            if node.get('event_type') or node.get('eventTypeName'):
                result.append(node)
            else:
                for key in ('raw_event', 'log', 'event', 'notification', 'events', 'records', 'logs'):
                    visit(node.get(key), depth + 1)
    # Context-level event type is routing metadata; the raw event holds facts.
    visit(context.get('raw_event') or context)
    return result


def integer(value):
    return value if type(value) is int and value >= 0 else None


def seconds(start, end):
    try:
        a, b = (datetime.fromisoformat(str(v).replace('Z', '+00:00')) for v in (start, end))
        if a.tzinfo is None or b.tzinfo is None:
            return None
        value = (b - a).total_seconds()
        return int(value) if value >= 0 and value.is_integer() else None
    except (TypeError, ValueError):
        return None


def authentication_facts(items):
    failures = [x for x in items if x.get('event_type', x.get('eventTypeName')) == 'identity.authenticate'
                and (x.get('outcome') or (x.get('payload') or {}).get('outcome')) == 'failure']
    if len(failures) != 1:
        return {}  # Do not merge summaries or invent a shared aggregation window.
    raw = failures[0]
    count = integer(raw.get('count'))
    window = integer(raw.get('window_seconds'))
    if window is None:
        window = seconds(raw.get('first_at'), raw.get('last_at'))
    hashes = integer(raw.get('distinct_partial_password_hashes'))
    if hashes == 0 or count is not None and hashes is not None and hashes > count:
        hashes = None
    source = raw.get('source_ip')
    try:
        if not isinstance(source, str): raise ValueError('not an IP string')
        source = str(ipaddress.ip_address(source))
    except ValueError:
        source = None
    return {'count': count, 'window': window, 'hashes': hashes,
            'source_ip': source, 'event_type': 'identity.authenticate', 'outcome': 'failure'}


def assess(context, evidence):
    """Return authoritative values only when a supported live rule applies."""
    facts = authentication_facts(records(context))
    evaluations, values = [], {}
    # Keep actual rule metadata separate from condition evaluation. A rule may
    # have a known name/severity even when this input cannot satisfy its trigger.
    catalog = {}
    for item in evidence:
        if item.get('tool') == 'explain_log_event':
            for rule in item.get('result', {}).get('rule_definitions', []):
                if rule.get('uri'):
                    catalog[rule['uri']] = rule
    result = {'values': values, 'evaluations': evaluations, 'rule_catalog': catalog}
    if not facts:
        return result
    rules = {}
    for item in evidence:
        if item.get('tool') != 'explain_log_event':
            continue
        args = item.get('arguments', {})
        if args.get('event_type') != facts['event_type'] or args.get('outcome') != 'failure':
            continue
        for rule in item.get('result', {}).get('rule_definitions', []):
            rules[rule['uri']] = rule
    hash_minima = {r['distinctMin'] for r in rules.values()
                   if r.get('ruleType') == 'threshold'
                   and 'partial_password_hash' in str(r.get('distinctField', ''))
                   and integer(r.get('distinctMin')) not in (None, 0)}
    if len(hash_minima) == 1:
        # This is the rule's required minimum, not the observed hash count or
        # a claim that the rule fired. Ambiguous requirements stay model-owned.
        values['required_distinct_hashes'] = next(iter(hash_minima))
    for rule in rules.values():
        condition = str(rule.get('condition_ko') or '')
        syntax = re.fullmatch(
            r'같은\s*출발지\s*IP\s*에서\s*(\d+)초\s*안에\s*인증\s*실패\s*(\d+)회\s*이상\.\s*'
            r'partial_password_hash\s*가\s*계속\s*바뀌면\s*공격,\s*같으면\s*설정\s*오류로\s*분류\.?', condition)
        if not (rule.get('ruleType') == 'threshold' and rule.get('groupBy') == '@ip' and syntax):
            continue
        threshold, window = integer(rule.get('threshold')), integer(rule.get('windowSeconds'))
        if threshold is None or threshold == 0 or window is None or window == 0 or rule.get('filter'):
            continue
        if (window, threshold) != tuple(map(int, syntax.groups())):
            continue  # A stale/inconsistent textual condition is not executable evidence.
        count, duration, hashes = facts['count'], facts['window'], facts['hashes']
        verdict = 'insufficient_evidence'
        checks = {'same_source_ip': bool(facts['source_ip']),
                  'count_met': None if count is None else count >= threshold,
                  'window_met': None if duration is None else duration <= window,
                  'distinct_hashes': hashes}
        if count is not None and count < threshold or duration is not None and duration > window:
            verdict = 'not_matched'
        elif all(checks.get(k) is True for k in ('same_source_ip', 'count_met', 'window_met')) and hashes is not None:
            verdict = 'configuration_error' if hashes == 1 else 'attack'
        evaluations.append({'rule_uri': rule['uri'], 'rule_name': rule.get('label_ko'),
            'condition': condition, 'classification': verdict, 'checks': checks,
            'actual_alert_confirmed': False,
            'note': '제공된 입력에 대한 규칙 조건 평가이며 실제 경보 발동·침해 성공 판정이 아닙니다.'})
        # Multiple supported conflicting rules do not collapse into a fake verdict.
        classifications = {e['classification'] for e in evaluations}
        values['rule_classification'] = verdict if len(classifications) == 1 else 'insufficient_evidence'
        thresholds = {rules[e['rule_uri']]['threshold'] for e in evaluations}
        if len(thresholds) == 1:
            values['rule_min_failures'] = threshold
        else:
            values.pop('rule_min_failures', None)
        if count is not None: values['failure_count'] = count
        if duration is not None: values['elapsed_seconds'] = duration
        if hashes is not None: values['password_changed'] = hashes > 1
    return result


def decision_summary(assessment):
    labels = {'configuration_error': '설정 오류', 'attack': '공격 조건 충족',
              'not_matched': '조건 불충족', 'insufficient_evidence': '판정 근거 부족'}
    return '\n'.join(f"규칙 판정: {labels[e['classification']]} ({e['rule_name']}). "
                     '입력에 대한 조건 평가이며 실제 침해 확정은 아닙니다.'
                     for e in assessment['evaluations'])


def assemble_answer(raw, requested, assessment, include_summary=True, normalizations=None):
    """The backend owns rule values; the model supplies remaining fields/prose."""
    obj = json.loads(raw)
    if not isinstance(obj, dict) or not isinstance(obj.get('explanation'), str):
        raise ValueError('explanation 문자열이 필요합니다.')
    if not obj['explanation'].strip():
        raise ValueError('답변 본문이 비어 있습니다.')
    if not requested:
        # Auxiliary JSON fields are not a user-requested schema in ordinary
        # chat. Render only the nonempty body; the caller still checks its IDs
        # and source links. Even a list/null in unused "answers" is irrelevant.
        summary = decision_summary(assessment) if include_summary else ''
        return (summary + '\n\n' if summary else '') + obj['explanation'].strip()
    model_values = obj.get('answers', {})
    if not isinstance(model_values, dict):
        raise ValueError('answers 객체가 필요합니다.')
    fixed = {k: v for k, v in assessment['values'].items() if k in requested}
    for key, value in fixed.items():
        if key in model_values and (type(model_values[key]) is not type(value) or model_values[key] != value):
            raise ValueError(f'{key}는 백엔드 규칙 판정 {value!r}과 일치해야 합니다. 설명도 이 판정에 맞춰 주세요.')
    model_values = {k: v for k, v in model_values.items() if k not in fixed}
    remaining = set(requested) - set(fixed)
    if set(model_values) != remaining:
        raise ValueError('모델 answers 키는 다음과 정확히 같아야 합니다: ' + ', '.join(sorted(remaining)))
    catalog = assessment.get('rule_catalog', {})
    severities = {r['severity'] for r in catalog.values() if isinstance(r.get('severity'), str)}
    for key, value in model_values.items():
        replacement, reason = value, None
        if key.endswith('_confirmed'):
            if value is None:
                # Unknown is unconfirmed, not confirmed absence. Preserve this
                # meaning without blocking an otherwise valid cautious answer.
                replacement, reason = False, '미확인 상태를 확정 여부 false로 표현'
            elif type(value) is not bool:
                raise ValueError(key + '는 확정 여부 Boolean입니다. 확정 근거가 없으면 false입니다.')
        if key.endswith('_rule') and isinstance(value, str) and value in catalog:
            label = catalog[value].get('label_ko')
            if isinstance(label, str) and label:
                replacement, reason = label, '조회된 규칙 URI를 실제 규칙 이름으로 표시'
        if key.endswith('_severity') and value is not None and severities:
            if not isinstance(value, str) or value not in severities:
                raise ValueError(key + '는 숫자 위험 점수가 아니라 조회된 severity 문자열이어야 합니다: '
                                 + ', '.join(sorted(severities)))
        if reason:
            model_values[key] = replacement
            if normalizations is not None:
                normalizations.append({'field': key, 'from': value, 'to': replacement, 'reason': reason})
    return json.dumps({'answers': {**model_values, **fixed}, 'explanation': obj['explanation']}, ensure_ascii=False)
