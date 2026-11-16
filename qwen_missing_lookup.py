"""Render a focused missing-technique answer from successful backend lookups.

Absence is a typed lookup result, not a positive attack citation. The model
acknowledges those results in a closed schema; it cannot add narrative claims
that the renderer would silently discard. Found IDs in a focused mixed lookup
still pass the ordinary positive citation gate; incident analysis stays separate.
"""
import json
import re

from qwen_evidence import CITATION_RE, requested_keys, task_question


LOOKUP_KEYS = frozenset(('requested_id', 'requested_technique_id',
    'exists_in_ontology', 'official_name', 'response_command', 'executed', 'lookup_status'))


def build_missing_lookup_plan(question, requested_ids, evidence):
    ids = sorted(set(requested_ids))
    if not ids:
        return None
    keys = requested_keys(question)
    if keys:
        # A singular requested-ID schema cannot represent multiple lookups.
        if len(ids) != 1 or not set(keys) <= LOOKUP_KEYS:
            return None
    else:
        task = task_question(question)
        # Only focused lookup requests: do not replace an incident analysis,
        # comparison, live-state question, or a request about another record.
        if set(CITATION_RE.findall(task)) != set(ids):
            return None
        if not re.search(r'조회|등록|존재|찾|검색|공식|명칭|이름|기법|대응|명령|lookup|exist|register', task, re.I):
            return None
        if re.search(r'로그|이벤트|사건|탐지|공유|유출|침해|성공|확정|매핑|비교|연관|원인|왜|현재\s*상태|실시간|실행해|실행하|log|event|incident|detect|compare|execute', task, re.I):
            return None

    rows, facts = [], []
    absent = []
    for ident in ids:
        observed = [item.get('result') for item in evidence
            if item.get('tool') == 'lookup_technique'
            and item.get('arguments', {}).get('technique_id') == ident]
        # Missing, failed, malformed, mismatched, or conflicting responses
        # cannot become a successful lookup verdict.
        if not observed or any(not isinstance(body, dict) or body.get('error')
                or body.get('id') != ident or type(body.get('found')) is not bool
                for body in observed):
            return None
        found = observed[0]['found']
        if any(body['found'] is not found for body in observed):
            return None
        name = observed[0].get('name') if found else None
        if found and (not isinstance(name, str) or not name.strip()
                      or any(body.get('name') != name for body in observed)):
            return None
        rows.append({'requested_id': ident, 'exists_in_ontology': found,
                     'official_name': name, 'lookup_status': 'available' if found else 'not_found'})
        if found:
            text = f'기법 ID {ident}은 이번 프로젝트 온톨로지 조회에서 확인되었으며, 공식 명칭은 {json.dumps(name, ensure_ascii=False)}입니다.'
        else:
            absent.append(ident)
            text = (f'요청한 기법 ID {ident}은 이번 프로젝트 온톨로지 조회에서 찾지 못했습니다.'
                    ' 이 ID의 조회 상태는 not_found이며, 공식 명칭과 대응 명령을 확인할 근거가 없습니다.')
        facts.append({'id': ('found:' if found else 'missing:') + ident, 'text': text,
            'sources': [{'tool': 'lookup_technique', 'technique_id': ident, 'found': found}]})
    if not absent:
        return None
    if len(absent) != len(ids) and re.search(
            r'대응|명령|완화|방어|절차|방법|설명|특징|용도|설정|차단|command|defen|mitigat|explain',
            task_question(question), re.I):
        # Existing technique responses need their actual defense/command facts.
        # This plan only owns registration and names for mixed lookups.
        return None
    return {'kind': 'confirmed_missing_lookup', 'requested_keys': keys,
            'required_fact_ids': [fact['id'] for fact in facts], 'facts': facts,
            'expected_response': {'lookup_results': rows, 'executed': False, 'explanation': ''}}


def _same_typed_value(value, expected):
    if type(value) is not type(expected):
        return False
    if isinstance(expected, dict):
        return value.keys() == expected.keys() and all(_same_typed_value(value[k], v) for k, v in expected.items())
    if isinstance(expected, list):
        return len(value) == len(expected) and all(_same_typed_value(a, b) for a, b in zip(value, expected))
    return value == expected


def missing_lookup_response_format(plan):
    """Constrain the API's shape; host validation still verifies every value."""
    observed = plan['expected_response']['lookup_results']
    row = {'type': 'object', 'additionalProperties': False, 'properties': {
        'requested_id': {'type': 'string', 'enum': [r['requested_id'] for r in observed]},
        'exists_in_ontology': {'type': 'boolean', 'enum': list(dict.fromkeys(r['exists_in_ontology'] for r in observed))},
        'official_name': {'type': ['string', 'null'], 'enum': list(dict.fromkeys(r['official_name'] for r in observed))},
        'lookup_status': {'type': 'string', 'enum': list(dict.fromkeys(r['lookup_status'] for r in observed))}}}
    row['required'] = list(row['properties'])
    schema = {'type': 'object', 'additionalProperties': False, 'properties': {
        'lookup_results': {'type': 'array', 'items': row,
                           'minItems': len(plan['facts']), 'maxItems': len(plan['facts'])},
        'executed': {'type': 'boolean', 'enum': [False]}, 'explanation': {'type': 'string', 'enum': ['']}},
        'required': ['lookup_results', 'executed', 'explanation']}
    return {'type': 'json_schema', 'json_schema': {
        'name': 'verified_missing_lookup', 'strict': True, 'schema': schema}}


def render_missing_lookup(raw, plan):
    def unique_object(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise ValueError('미등록 조회 응답에 중복 키가 있습니다.')
            obj[key] = value
        return obj
    obj = json.loads(raw, object_pairs_hook=unique_object)
    if isinstance(obj, dict) and isinstance(obj.get('lookup_results'), list):
        rows = obj['lookup_results']
        if all(isinstance(row, dict) and isinstance(row.get('requested_id'), str) for row in rows):
            obj['lookup_results'] = sorted(rows, key=lambda row: row['requested_id'])
    if not _same_typed_value(obj, plan['expected_response']):
        raise ValueError('미등록 조회 응답은 실제 lookup_results 및 executed=false와 정확히 일치해야 합니다. '
                         '공식 명칭·대응 명령을 만들거나 공격 근거로 채택하지 마라. '
                         'explanation은 빈 문자열이어야 하며 추가 필드·설명은 허용하지 않습니다. '
                         '요구된 JSON: ' + json.dumps(plan['expected_response'], ensure_ascii=False))
    explanation = ' '.join(fact['text'] for fact in plan['facts']) + (
        ' 미등록 판정은 현재 프로젝트 데이터에 대한 결과이며 공식 ATT&CK 전체의 존재 여부를 판정한 결과는 아닙니다.'
        ' 명령은 실행하지 않았습니다.')
    keys = plan['requested_keys']
    if not keys:
        return explanation
    row = plan['expected_response']['lookup_results'][0]
    values = {**row, 'requested_technique_id': row['requested_id'], 'response_command': None, 'executed': False}
    return json.dumps({'answers': {key: values[key] for key in keys}, 'explanation': explanation}, ensure_ascii=False)
