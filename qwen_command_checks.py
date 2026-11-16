"""Grounded security-group read-only command plans and local output checks.

Supported syntax is checked against the installed OpenStack client's help in
tests. Suggested commands are parsed as text and are never executed here.
"""
from copy import deepcopy
import json
import re
import shlex

from qwen_answer_quality import _display
from qwen_evidence import requested_keys, task_question
from qwen_observed_facts import value, MISSING, CONFLICT

PREFIXES = {
    'group_show': ('openstack', 'security', 'group', 'show'),
    'rule_show': ('openstack', 'security', 'group', 'rule', 'show'),
    'rule_list': ('openstack', 'security', 'group', 'rule', 'list'),
}


def build_response_command_block(question, context, evidence):
    """Own command text from actual linked-alert lookups, leaving prose to Qwen."""
    q = task_question(question)
    if requested_keys(q) or not re.search(r'명령|커맨드|\bCLI\b|\bcommands?\b|대응|조치|복구|완화|차단', q, re.I):
        return None
    scope = re.sub(r'(?:변경|삭제|차단)\s*명령어?(?:는|를|은|을)?\s*(?:없이|빼\w*|제외\w*|생략\w*)', '', q)
    if re.search(r'(?:명령어?|커맨드|CLI)(?:는|를|은|을)?\s*(?:없이|빼|제외|생략|쓰지|넣지|필요\s*없)', scope, re.I):
        return None
    read_only = bool(re.search(r'읽기\s*전용|read.only|(?:변경|삭제|차단)\s*(?:명령어?|조치)?(?:는|를|은|을)?\s*(?:없이|제외|빼|생략|하지\s*말)', q, re.I))
    asks_read = bool(re.search(r'확인|조회|조사|목록|\bshow\b|\blist\b', q, re.I))
    asks_change = bool(re.search(r'대응|조치|복구|완화|차단|삭제|해제|취소|비활성', q))
    groups = ['investigate'] if read_only or asks_read and not asks_change else ['respond']
    if asks_read and asks_change and not read_only:
        groups.insert(0, 'investigate')
    allowed = set(context.get('related_alert_ids') or [])
    allowed.update(re.findall(r'(?<![A-Za-z0-9_])al-[0-9a-f]{24}(?![A-Za-z0-9_])', q))
    rows, alerts = [], set()
    for item in evidence:
        result = item.get('result') or {}
        alert = item.get('arguments', {}).get('alert_id')
        if (item.get('tool') != 'get_alert' or result.get('found') is not True or result.get('error')
                or alert not in allowed or result.get('alert_id') != alert):
            continue
        alerts.add(alert)
        for group in groups:
            candidates = result.get(group)
            if not isinstance(candidates, list):
                continue
            for index, row in enumerate(candidates):
                if not isinstance(row, dict) or not isinstance(row.get('command'), str) or not row['command'].strip():
                    continue
                command = row['command'].strip()
                rollback = row.get('rollback') if group == 'respond' else None
                rollback = rollback.strip() if isinstance(rollback, str) and rollback.strip() else None
                missing = row.get('missing') if isinstance(row.get('missing'), list) else []
                missing = [str(v) for v in missing]
                missing += re.findall(r'<[^<>\n]+>', command)
                if '...' in command:
                    missing.append('생략된 명령 인수')
                candidate = {'kind': group, 'label': str(row.get('label') or ('확인 명령' if group == 'investigate' else '대응 명령')),
                             'command': command, 'rollback': rollback, 'missing': sorted(set(missing)),
                             'requires_approval': row.get('requires_approval'), 'status': row.get('status'),
                             'purpose': str(row.get('purpose') or ''),
                             'source': f'get_alert:{alert}.{group}[{index}]', 'alert_ids': [alert]}
                duplicate = next((r for r in rows if all(r[k] == candidate[k] for k in
                                  ('kind', 'label', 'command', 'rollback', 'missing', 'requires_approval', 'status', 'purpose'))), None)
                if duplicate:
                    duplicate['alert_ids'] = sorted(set(duplicate['alert_ids']) | {alert})
                else:
                    candidate['id'] = 'command:' + str(len(rows))
                    rows.append(candidate)
    return {'kind': 'server_command_block', 'revision': 'commands-1', 'groups': groups,
            'source_alert_ids': sorted(alerts), 'commands': rows}


def command_block_response_format(block, base_format=None):
    """Qwen selects source-owned command IDs; it never generates command text."""
    response = deepcopy(base_format) if base_format else {'type': 'json_schema', 'json_schema': {
        'name': 'grounded_command_answer', 'strict': True, 'schema': {
            'type': 'object', 'additionalProperties': False,
            'properties': {'answers': {'type': 'object', 'properties': {}, 'additionalProperties': False},
                           'explanation': {'type': 'string', 'minLength': 1}},
            'required': ['answers', 'explanation']}}}
    ids = [r['id'] for r in block['commands']]
    schema = response['json_schema']['schema']
    schema['properties']['command_ids'] = {'type': 'array', 'uniqueItems': True, 'maxItems': len(ids),
        'items': {'type': 'string', 'enum': ids} if ids else {'type': 'string'}}
    schema['required'].append('command_ids')
    return response


def select_response_commands(raw, block):
    obj = json.loads(raw)
    if not isinstance(obj, dict) or 'command_ids' not in obj:
        raise ValueError('command_ids에 이번 질문에 필요한 조회 명령의 ID 목록을 넣으세요.')
    ids = obj.pop('command_ids')
    allowed = {r['id'] for r in block['commands']}
    if (not isinstance(ids, list) or any(not isinstance(i, str) for i in ids)
            or len(ids) != len(set(ids)) or not set(ids) <= allowed):
        raise ValueError('command_ids에는 이번 실제 조회 목록의 ID만 중복 없이 선택하세요.')
    selected = {**block, 'commands': [r for r in block['commands'] if r['id'] in ids]}
    selected['selection_empty'] = bool(block['commands']) and not ids
    selected['normalizations'] = []
    if isinstance(obj.get('explanation'), str):
        lines = []
        for line in obj['explanation'].splitlines():
            duplicate = re.fullmatch(r'\s*`?command_ids`?\s*[:：]\s*(\[.*\])\s*', line)
            try:
                echoed = json.loads(duplicate[1]) if duplicate else None
            except ValueError:
                echoed = None
            if duplicate and echoed == ids:
                selected['normalizations'].append('duplicate_command_selection_metadata')
            else:
                lines.append(line)
        obj['explanation'] = '\n'.join(lines).strip()
    return json.dumps(obj, ensure_ascii=False), selected


def model_command_block_errors(body, block):
    """The explanation may discuss an action, but executable text is server-owned."""
    if block is None:
        return []
    roots = {'openstack', 'aws', 'az', 'gcloud', 'kubectl', 'curl', 'ssh', 'sudo'}
    for row in block['commands']:
        root = row['command'].split()[0]
        if re.fullmatch(r'[a-z][a-z0-9_-]*', root):
            roots.add(root)
    cli = r'(?<![A-Za-z0-9_])(?:' + '|'.join(re.escape(s) for s in sorted(roots)) + r')\s+[a-z-][a-z0-9_-]*'
    if re.search(cli, body) or '```' in body or '~~~' in body:
        return ['명령어는 실제 조회 결과로 서버가 별도 표시합니다. explanation에서 명령문·CLI 옵션·코드블록을 제거하고 '
                '조치의 필요성, 근거와 미확인 사항만 설명하세요. 복구 명령을 새로 만들지 마세요. '
                '제거한 명령에 해당하는 항목은 command_ids에서 선택해야 최종 답변에 표시됩니다. 가능한 항목: '
                + '; '.join(r['id'] + ' — ' + r['label'] for r in block['commands'])]
    return []


def render_response_command_block(body, block):
    """Append exact retrieved commands; never fill IDs or synthesize rollback."""
    if block is None:
        return body

    def code(command):
        longest = max((len(x) for x in re.findall(r'`+', command)), default=0)
        fence = '`' * max(3, longest + 1)
        return fence + 'bash\n' + command + '\n' + fence

    parts = [body.rstrip()]
    groups = [g for g in block['groups'] if any(r['kind'] == g for r in block['commands'])]
    for group in groups or block['groups']:
        rows = [r for r in block['commands'] if r['kind'] == group]
        parts.append('### ' + ('확인 명령어' if group == 'investigate' else '대응 명령어'))
        if not rows:
            parts.append('이 질문에 맞는 명령 항목을 선택하지 못했습니다.' if block.get('selection_empty')
                         else '이번 조회에서 확인된 명령어가 없습니다.')
        for row in rows:
            parts.append('**' + _display(row['label']) + '**')
            if row['purpose']:
                parts.append(_display(row['purpose']))
            if row['missing']:
                parts.append('미완성 명령 예시 — 필요한 값: ' + ', '.join(_display(v) for v in row['missing']))
            if row['status'] != '공식문서확인':
                parts.append('명령어 문법 확인 상태: ' + _display(row['status'] or '미확인'))
            parts.append(code(row['command']))
            if group == 'respond':
                if row['requires_approval'] is True:
                    parts.append('실행 승인: 필요')
                elif row['requires_approval'] is not False:
                    parts.append('실행 승인 여부: 미확인')
                if row['rollback']:
                    parts.append('복구 명령' + (' — 실제 값 확인이 필요한 예시' if re.search(r'<[^<>\n]+>|\.\.\.', row['rollback']) else ''))
                    parts.append(code(row['rollback']))
                else:
                    parts.append('복구: 조회된 복구 명령 없음')
    if block['source_alert_ids']:
        parts.append('명령어 출처: ' + ', '.join(block['source_alert_ids']))
    parts.append('명령어를 제시했으며 실제로 실행하지 않았습니다.')
    return '\n\n'.join(parts)


def build_command_plan(question, context):
    q = task_question(question)
    event = str((context.get('raw_event') or {}).get('event_type') or context.get('event_type') or '')
    if not context.get('question_only') or requested_keys(q) or not event.startswith(('security_group.', 'security_group_rule.')):
        return None
    if not re.search(r'명령|커맨드|\bCLI\b|\bcommand', q, re.I):
        return None
    scope = re.sub(r'(?:변경|삭제|차단)\s*명령[^.!?\n]{0,12}(?:빼\w*|제외\w*|생략\w*|쓰지\w*|넣지\w*|없이)', '', q)
    if re.search(r'명령[^.!?\n]{0,12}(?:빼|제외|생략|쓰지|넣지|없이)|(?:삭제|차단|변경|수정|생성|추가)\s*(?:해줘|하라|명령을?\s*(?:알려|써))|전술|공격\s*기법|원인|왜\s*탐지|역할|계정|서버|포트.*연결|연결.*포트', scope, re.I):
        return None
    if not re.search(r'읽기\s*전용|확인|조회|목록|\bshow\b|\blist\b', q, re.I):
        return None
    listing = bool(re.search(r'(?:규칙|룰).{0,12}목록|목록.{0,12}(?:규칙|룰)|rule\s+list', q, re.I))
    group = bool(re.search(r'보안\s*그룹|security\s+group|그룹\s*상세', q, re.I))
    rule = bool(re.search(r'(?:해당|개별|특정|이)\s*(?:규칙|룰)|(?:규칙|룰).{0,12}(?:상세|각각)|rule\s+show', q, re.I))
    operations = []
    if group and (not listing or re.search(r'그룹.{0,8}상세', q)):
        operations.append('group_show')
    if listing: operations.append('rule_list')
    if rule and not listing: operations.append('rule_show')
    if not operations:
        operations.append('rule_show' if event.startswith('security_group_rule.') else 'group_show')
    if (re.search(r'(?:두|2)\s*개', q) and len(operations) != 2
            or re.search(r'이름과\s*프로젝트|프로젝트로\s*찾', q)):
        return None  # Resource discovery is outside the direct show/list contract.
    raw = context.get('raw_event') or {}
    group_path = ('payload.security_group_rule.security_group_id' if event.startswith('security_group_rule.')
                  else 'payload.security_group_id' if '.delete.' in event else 'payload.security_group.id')
    facts, commands = [], []
    labels = {'group_show': '보안그룹 자체의 상세 조회', 'rule_show': '개별 보안그룹 규칙의 상세 조회',
              'rule_list': '보안그룹에 속한 규칙 목록 조회'}
    for operation in operations:
        path = 'payload.security_group_rule.id' if operation == 'rule_show' else group_path
        observed = value(raw, path)
        # A group name is a valid show/list selector; a rule name is not a rule ID.
        if observed is MISSING and operation != 'rule_show' and event.startswith('security_group.create.'):
            path = 'payload.security_group.name'; observed = value(raw, path)
        known = isinstance(observed, str) and bool(re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.@:-]{0,127}', observed))
        target = observed if known else ('<RULE_ID>' if operation == 'rule_show' else '<SECURITY_GROUP_ID>')
        command = shlex.join([*PREFIXES[operation], target])
        note = '' if known else ('원본 값 충돌로 대상 식별자를 확정할 수 없습니다. ' if observed is CONFLICT
                                else '원본에서 대상 식별자를 확인할 수 없습니다. ')
        if not known: note += '자리표시자를 실제 확인한 값으로 바꾼 후 사용해야 합니다. '
        text = f'{labels[operation]} ({path}):\n{note}```bash\n{command}\n```'
        facts.append({'id': 'readonly:' + operation, 'text': text, 'sources': ['raw_event:' + path, 'installed_openstack_cli:help']})
        commands.append({'operation': operation, 'target': target, 'known': known, 'source': path, 'command': command})
    facts.append({'id': 'readonly:not_executed', 'text': '읽기 전용 조회 명령이며 이번 답변에서 실행하지 않았습니다.',
                  'sources': ['execution:commands_not_run']})
    return {'kind': 'readonly_command_facts', 'strict': True, 'facts': facts,
            'required_fact_ids': [f['id'] for f in facts], 'commands': commands}


def command_errors(answer, plan):
    if not plan or plan.get('kind') != 'readonly_command_facts':
        return []
    text = str(answer).replace('\\\n', ' ')
    lines = re.findall(r'(?m)(?:^\s*(?:\$\s*)?|`)(openstack\s+[^\n`]+)', text)
    expected = {row['operation']: row for row in plan['commands']}
    found, errors = {}, []
    for line in lines:
        try: tokens = shlex.split(line)
        except ValueError:
            errors.append('명령어의 따옴표가 닫히지 않았습니다.'); continue
        if any(x in line for x in (';', '&&', '||', '$(', '`')) or any(x in tokens for x in ('|', '>', '>>')):
            errors.append('요청된 단일 읽기 전용 조회 명령만 제시해야 합니다.'); continue
        operation = next((key for key, prefix in PREFIXES.items() if tuple(tokens[:len(prefix)]) == prefix), None)
        if operation not in expected:
            errors.append('요청한 조회 대상/작업과 다른 명령입니다: ' + line); continue
        args = tokens[len(PREFIXES[operation]):]
        positional, i = [], 0
        # Accept common presentation flags, not invented command-specific flags.
        while i < len(args):
            arg = args[i]
            if arg in ('-f', '--format', '-c', '--column', '--max-width', '--prefix'):
                if i + 1 == len(args): errors.append('명령 옵션 값이 빠졌습니다: ' + arg); break
                i += 2
            elif arg in ('--fit-width', '--print-empty', '--noindent'):
                i += 1
            elif operation == 'rule_list' and arg == '--long':
                i += 1
            elif arg.startswith('-'):
                errors.append('지원하는 조회 명령에 없는 옵션입니다: ' + arg); i += 1
            else:
                positional.append(arg); i += 1
        if positional != [expected[operation]['target']]:
            errors.append(f'{operation}의 대상은 실제 원본에서 확인한 {expected[operation]["target"]!r}여야 합니다.')
        found[operation] = found.get(operation, 0) + 1
    for operation, row in expected.items():
        if found.get(operation) != 1:
            errors.append('요청한 조회 명령을 정확히 한 번 포함해야 합니다: ' + row['command'])
    return errors
