"""Deterministic checks against this request's observed fields and knowledge.

No model calls, benchmark answers, inferred current state, or external writes.
"""
from copy import deepcopy
import json
import re

from qwen_answer_quality import _display
from qwen_evidence import requested_keys, task_question
from qwen_observed_facts import value, MISSING, CONFLICT


def requested_fields(question, context):
    """Select explicit raw paths and supported field aliases from the latest question."""
    raw = context.get('raw_event')
    if not context.get('question_only') or not isinstance(raw, dict) or requested_keys(question):
        return []
    q = task_question(question)
    def requested(pattern):
        for match in re.finditer(pattern, q, re.I):
            tail = q[match.end():match.end()+18]
            if not re.match(r'\s*(?:은|는|을|를)?\s*(?:빼고|빼줘|제외(?:해|하고)|생략(?:해|하고)|쓰지\s*마|표시하지\s*마|언급하지\s*마|말고)', tail):
                return True
        return False
    # Command arguments have a separate target contract; do not require a
    # prose field table in an answer explicitly asking for commands only.
    if re.search(r'명령|커맨드|\bCLI\b|\bcommand', q, re.I):
        return []
    event = str(raw.get('event_type') or context.get('event_type') or '')
    specs = {}
    def add(path, label, pattern, *alternatives):
        specs[path] = (label, pattern, (path,) + alternatives)
    add('payload.initiator.username', '사용자명', r'사용자명|username')
    add('user_id', '작업 수행자 사용자 ID', r'사용자\s*(?:ID|아이디)',
        'payload.initiator.user_id', 'payload.initiator.id', '_context_user_id')
    add('request_id', '요청 ID', r'요청\s*(?:ID|아이디)', 'payload.initiator.request_id', '_context_request_id')
    add('source_ip', '출발지 IP', r'출발지\s*IP|source_ip', 'payload.initiator.host.address', '_context_remote_address')
    add('payload.target.id', 'target.id', r'(?<![A-Za-z0-9_.])target\.id(?![A-Za-z0-9_])')
    if event.startswith('security_group_rule.'):
        add('payload.security_group_rule.id', '규칙 ID', r'(?:규칙|룰)\s*(?:의\s*)?(?:ID|아이디)')
        add('payload.security_group_rule.security_group_id', '보안그룹 ID', r'(?:보안\s*)?그룹\s*(?:의\s*)?(?:ID|아이디)')
        add('payload.security_group_rule.description', '규칙 설명', r'description|설명\s*문구')
    elif event.startswith('security_group.'):
        path = 'payload.security_group_id' if '.delete.' in event else 'payload.security_group.id'
        add(path, '보안그룹 ID', r'(?:보안\s*)?그룹\s*(?:의\s*)?(?:ID|아이디)')
        if '.create.' in event:
            add('payload.security_group.project_id', '프로젝트 ID', r'프로젝트\s*(?:ID|아이디)')
            add('payload.security_group.shared', 'shared', r'(?<![A-Za-z0-9_])shared(?![A-Za-z0-9_])')
            add('payload.security_group.stateful', 'stateful', r'(?<![A-Za-z0-9_])stateful(?![A-Za-z0-9_])')
            add('payload.security_group.description', '보안그룹 설명', r'description|설명\s*문구')
    selected = {path for path, (_, pattern, _) in specs.items() if requested(pattern)}
    # Explicit paths must retain their owner, e.g. target.id != initiator.id.
    explicit = set(re.findall(r'(?<![A-Za-z0-9_.])(?:payload\.[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*|_context_[A-Za-z0-9_]+)(?![A-Za-z0-9_.])', q))
    explicit = {path for path in explicit if requested(re.escape(path))}
    # "payload.security_group의 name, id, project_id" requests its leaves,
    # not a byte-for-byte dump of the whole object.
    for container in list(explicit):
        observed = value(raw, container)
        if isinstance(observed, dict):
            tail = q[q.index(container)+len(container):][:180]
            for child in set(observed) | {'id', 'name', 'project_id', 'description', 'shared', 'stateful'}:
                if re.search(r'(?<![A-Za-z0-9_.])' + re.escape(child) + r'(?![A-Za-z0-9_])', tail):
                    explicit.add(container + '.' + child)
    selected.update(explicit)
    result = []
    for path in sorted(selected):
        if re.search(r'password|secret|token|credential|authorization|cookie|private_key', path, re.I):
            continue
        label, _, paths = specs.get(path, (path, '', (path,)))
        # A literal field path requests exactly that field, not its aliases.
        observed = value(raw, *((path,) if path in explicit else paths))
        if isinstance(observed, (dict, list)):
            continue  # Containers/counts/comparisons need their own semantics.
        state = 'missing' if observed is MISSING else 'conflict' if observed is CONFLICT else 'present'
        display = ('원본에서 확인 불가(필드 없음 또는 null)' if state == 'missing' else
                   '원본 필드 값 충돌로 확인 불가' if state == 'conflict' else
                   _display(json.dumps(observed, ensure_ascii=False) if isinstance(observed, (dict, list, bool)) else observed))
        result.append({'field': path, 'label': label, 'state': state,
                       'value': observed if state == 'present' else None,
                       'text': f'{label} ({path}): {display}.'})
    return result


def field_errors(answer, requirements):
    """Require observed values, or field-specific unavailable/conflict statements."""
    errors = []
    plain = re.sub(r'[`*\\]', '', str(answer))
    for item in requirements:
        if item['state'] == 'present':
            v = item['value']
            expected = json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list, bool)) else str(v)
            if isinstance(v, bool):
                # Do not accept another field's false/true as this field's value.
                found = False
                for label in re.finditer(re.escape(item['label']), plain, re.I):
                    tail = re.split(r'[\n;,]', plain[label.end():label.end()+80], maxsplit=1)[0]
                    observed = re.search(r'(?<![A-Za-z0-9_])(true|false)(?![A-Za-z0-9_])', tail, re.I)
                    if observed and observed[1].casefold() == expected:
                        found = True
                        break
            else:
                found = (bool(re.search(r'(?<![A-Za-z0-9_-])' + re.escape(expected)
                         + r'(?![A-Za-z0-9_-]|\.[A-Za-z0-9])', plain))
                         if re.fullmatch(r'[A-Za-z0-9_.:@/-]+', expected) else expected in plain)
            if not found:
                errors.append(f'요청 필드 누락: {item["field"]}. 실제 원본 값: {expected}')
        else:
            aliases = (item['field'], item['label'])
            found = any(any(alias in line for alias in aliases) and re.search(
                r'충돌|서로\s*다르' if item['state'] == 'conflict' else r'확인\s*(?:불가|할\s*수\s*없)|미기록|필드\s*없|없(?:음|습니다)|누락', line)
                for line in plain.splitlines())
            if not found:
                errors.append(f'요청 필드의 {item["state"]} 상태를 명시해야 합니다: {item["text"]}')
    return errors


def extend_fact_plan(plan, requirements):
    """Add omitted requested facts before model selection; never invent missing values."""
    if not plan or plan.get('kind') == 'confirmed_missing_lookup':
        return plan
    plan = deepcopy(plan)
    body = '\n\n'.join(f['text'] for f in plan['facts'])
    for item in requirements:
        if field_errors(body, [item]):
            ident = 'requested_field:' + item['field']
            plan['facts'].append({'id': ident, 'text': item['text'], 'sources': ['raw_event:' + item['field']]})
            plan['required_fact_ids'].append(ident)
    return plan


KNOWLEDGE_ID = r'(?:TA\d{4}|T\d{4}(?:\.\d{3})?|M\d{4}|D3-[A-Z][A-Z0-9-]*)'
NAME = r'[A-Za-z][A-Za-z0-9 /&\-]{1,140}'
# Translations of labels, never hard-coded ID mappings. IDs and canonical
# English names still come from the current ontology lookup.
LABEL_TRANSLATIONS = {'초기 접근': 'Initial Access', '자격 증명 접근': 'Credential Access',
                      '지속성': 'Persistence', '권한 상승': 'Privilege Escalation',
                      '권한 승급': 'Privilege Escalation'}


def _prose(answer):
    try:
        obj = json.loads(answer)
    except (ValueError, TypeError):
        obj = None
    return obj.get('explanation', '') if isinstance(obj, dict) else str(answer)


def name_pairs(answer):
    """Recognize explicit English label/ID pairs, not arbitrary nearby mentions."""
    text = re.sub(r'```.*?```', '', _prose(answer), flags=re.S)
    text = re.sub(r'[*`_]', '', text)
    pairs = []
    try:
        obj = json.loads(answer)
    except (ValueError, TypeError):
        obj = None
    def structured(node):
        if isinstance(node, dict):
            for id_key, name_key in [('id', 'name'), ('tactic_id', 'tactic_name'),
                                     ('technique_id', 'technique_name'), ('requested_id', 'official_name'),
                                     ('requested_technique_id', 'official_name')]:
                ident, label = node.get(id_key), node.get(name_key)
                if isinstance(ident, str) and re.fullmatch(KNOWLEDGE_ID, ident) and isinstance(label, str):
                    pairs.append({'id': ident, 'written': label, 'direction': 'exact'})
            for v in node.values():
                if isinstance(v, (dict, list)): structured(v)
        elif isinstance(node, list):
            for v in node: structured(v)
    if isinstance(obj, dict): structured(obj.get('answers'))
    patterns = [(rf'(?P<name>{NAME})\s*\((?P<id>{KNOWLEDGE_ID})\)', 'before'),
                (rf'\((?P<name>{NAME})\s*,\s*(?P<id>{KNOWLEDGE_ID})\)', 'before'),
                (rf'(?P<name>{NAME})(?:\s*[—–:|]\s*|\s+-\s+)(?P<id>{KNOWLEDGE_ID})(?![A-Za-z0-9_.])', 'before'),
                (rf'(?<![A-Za-z0-9_.])(?P<id>{KNOWLEDGE_ID})\s*\((?P<name>{NAME})\)', 'after'),
                (rf'(?P<id>{KNOWLEDGE_ID})(?:의)?\s*(?:공식|정식)?\s*(?:명칭|이름|기법명)(?:은|는|:)?\s*(?P<name>{NAME})', 'after'),
                (rf'(?<![A-Za-z0-9_.])(?P<id>{KNOWLEDGE_ID})(?:\s*[—–:|]\s*|\s+-\s+|[ \t]+)(?P<name>{NAME})', 'after')]
    translated = '|'.join(re.escape(k).replace(r'\ ', r'\s*') for k in LABEL_TRANSLATIONS)
    patterns.append((rf'(?P<name>{translated})\s*\((?P<id>[A-Z]{{1,3}}\d{{4}}(?:\.\d{{3}})?)\)', 'exact'))
    official = '|'.join(re.escape(n) for n in set(LABEL_TRANSLATIONS.values()))
    patterns.append((rf'(?P<name>{official})\s*\((?P<id>[A-Z]{{1,3}}\d{{4}}(?:\.\d{{3}})?)\)', 'exact'))
    for pattern, direction in patterns:
        for m in re.finditer(pattern, text):
            written = m['name'].strip(' ,:-')
            if re.fullmatch(KNOWLEDGE_ID, written) or written.lower() in ('id', 'true', 'false'):
                continue
            if direction == 'after' and re.match(r'(?:is|are|was|were|and|or|does|has|can|may|means)\b', written, re.I):
                continue
            line = text[text.rfind('\n', 0, m.start())+1:text.find('\n', m.end()) if '\n' in text[m.end():] else len(text)]
            # An explicitly identified wrong label quoted for correction is not an assertion.
            if re.search(r'잘못된\s*(?:표기|명칭)|오표기|(?:라는\s*)?표기는\s*(?:잘못|틀)', line):
                continue
            pairs.append({'id': m['id'], 'written': written, 'direction': direction})
    return [dict(t) for t in dict.fromkeys(tuple(x.items()) for x in pairs)]


def knowledge_name_errors(answer, probes, evidence):
    names = {}
    def visit(node):
        if isinstance(node, dict):
            ident, name = node.get('id'), node.get('name')
            if isinstance(ident, str) and re.fullmatch(KNOWLEDGE_ID, ident) and isinstance(name, str) and name.strip():
                names.setdefault(ident, name.strip())
            for key, v in node.items():
                if key not in ('raw_log', 'log_data', 'evidence_events', 'notification', 'fieldsJson', 'raw_event') and isinstance(v, (dict, list)):
                    visit(v)
        elif isinstance(node, list):
            for v in node: visit(v)
    for e in evidence:
        result = e.get('result', {})
        if not result.get('error') and result.get('found') is not False:
            visit(result)
    # Fresh canonical labels override labels from contextual lookup structures.
    for probe in probes:
        for row in probe.get('results', []):
            if isinstance(row.get('canonical_name'), str) and row['canonical_name'].strip():
                names[row['id']] = row['canonical_name'].strip()
    errors, checked = [], []
    for pair in name_pairs(answer):
        expected = names.get(pair['id'])
        normalize = lambda s: re.sub(r'\s+', ' ', s).strip().casefold()
        written = normalize(next((v for k, v in LABEL_TRANSLATIONS.items()
                            if re.sub(r'\s+', '', k) == re.sub(r'\s+', '', pair['written'])), pair['written']))
        # Allow explanatory suffixes after an ID-first official name, and
        # introductory English words before a parenthesized ID.
        ok = bool(expected) and (written == normalize(expected)
             or pair['direction'] == 'after' and written.startswith(normalize(expected) + ' ')
             or pair['direction'] == 'before' and written.endswith(' ' + normalize(expected)))
        checked.append({**pair, 'expected': expected, 'pass': ok})
        if not ok:
            errors.append(f'ID·명칭 불일치 또는 명칭 미확인: {pair["id"]}에 {pair["written"]!r}를 붙였습니다. '
                          + (f'실제 온톨로지 정식 명칭은 {expected!r}입니다. 잘못 연결한 이름/ID를 고치거나 근거 없는 표기를 제거하세요.'
                             if expected else '이번 실제 조회에서 정식 명칭을 확인하지 못했습니다. 근거 없는 명칭을 제거하세요.'))
    return errors, checked
