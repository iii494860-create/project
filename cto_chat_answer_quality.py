"""Presentation and response quality support for the per-event Floating AI chat.

This module does NOT call Neo4j, alter data, fabricate citations, execute CLI, or
replace the existing Qwen/Graph RAG/citation validation path.
"""
from __future__ import annotations

import re

_ACTION = re.compile(r'(대응|조치|완화|방어|복구|차단|해결|명령어?|커맨드|취소|회수|삭제|\bCLI\b|어떻게\s*(?:해야|막|처리))', re.I)
_CHANGE = re.compile(r'(취소|회수|삭제|차단|해제|막(?:아|는)|변경|되돌리|복구|비활성)', re.I)
_FENCE = re.compile(r'^\s*(```|~~~)')
_HEADING = re.compile(r'^\s*#{1,6}\s')
_LIST = re.compile(r'^\s*(?:[-*+]\s+|\d+[.)]\s+|[①②③④⑤⑥⑦⑧⑨⑩]\s*)')
_SENTENCE = re.compile(r'(?<=[다요죠음]\.)\s+(?=[가-힣A-Za-z])')


def is_action(question: str) -> bool:
    return bool(_ACTION.search(str(question or '')))


def compact_previous(messages, *, max_items=6):
    """Keep the nearest user context without feeding entire prior AI answers back.

    Original chat records remain unchanged. Content is advisory, not evidence.
    """
    valid = [m for m in (messages or []) if isinstance(m, dict)
             and m.get('role') in ('user', 'assistant') and str(m.get('content') or '').strip()]
    recent = valid[-max_items:]
    compact = []
    for msg in recent:
        role = msg['role']
        text = str(msg['content']).strip().replace('\x00', '')
        cap = 1100 if role == 'user' else 750
        if len(text) > cap:
            text = text[:cap].rstrip() + '\n[이전 내용 생략 — 실제 사실은 다시 조회]'
        compact.append({'role': role, 'content': text})
    return compact


def _known_cli(event_type: str, question: str):
    """Documentation-confirmed OpenStack CLI syntax references, never live-state proof.

    These are NOT commands for unattended execution. Any changing command
    requires independent identification of IDs, authorization and operator approval.
    """
    et = str(event_type or '').lower()
    q = str(question or '')
    read = []
    change = []
    if et in ('image.member.create', 'image.member.delete', 'image.send', 'image.update'):
        read = ['openstack image show <IMAGE_ID> -f yaml',
                'openstack image member list <IMAGE_ID>']
        if _CHANGE.search(q):
            change = ['openstack image remove project <IMAGE_ID> <TARGET_PROJECT_ID>']
    elif et.startswith('identity.role_assignment.'):
        read = ['openstack role assignment list --user <USER_ID> --project <PROJECT_ID> --names']
        if _CHANGE.search(q):
            change = ['openstack role remove --user <USER_ID> --project <PROJECT_ID> <ROLE_ID>']
    elif 'security_group' in et or 'security.group' in et:
        read = ['openstack security group show <SECURITY_GROUP_ID>',
                'openstack security group rule list <SECURITY_GROUP_ID>']
        if _CHANGE.search(q):
            change = ['openstack security group rule delete <RULE_ID>']
    elif et.startswith('identity.authenticate'):
        read = ['openstack user show <USER_ID> -f yaml',
                'openstack role assignment list --user <USER_ID> --names']
    return read, change


def _cli_reference(event_type: str, question: str) -> str:
    read, change = _known_cli(event_type, question)
    if not read:
        return ''
    desc = '[OpenStackClient CLI 문법 참고 — 실제 실행 결과/자원 ID/권한은 미확인]\n'
    desc += '읽기 전용 확인 명령:\n' + '\n'.join('  '+x for x in read) + '\n'
    if change:
        desc += ('자원 변경 명령(명시적 승인·영향 평가·정확한 ID 검증 후에만 운영자 수동 실행):\n'
                 + '\n'.join('  '+x for x in change) + '\n')
    desc += ('실제 로그에 없는 ID를 추정하지 말고 <> 자리표시자를 유지하라. '
             '참고 명령을 현재 환경에서 실행했다고 주장하지 마라. '
             '이 이벤트에서 해당 조치가 필요한지 먼저 확인하라.\n')
    return desc


def contract_for(kind: str, question: str, event_type: str, alerts, raw=None) -> str:
    """Append a bounded answer-style contract; latest question is authoritative."""
    action = kind == 'question' and is_action(question)
    head = '\n\n[이 로그별 AI 챗봇의 일관된 답변 규칙 — 가장 최근 질문에만 적용]\n'
    head += (
        '한국어 Markdown으로 답하라. 제목은 ###, 항목은 - , 명령어는 ```bash 코드블록을 사용하고 '
        '제목·문단·목록·코드블록 사이에는 빈 줄을 한 줄 넣어라. 한 줄로 긴 문장을 이어 쓰지 마라. '
        '표와 장황한 서론 대신 요점과 근거를 분리하고 필요한 만큼만 설명하라. '
        '현재 이벤트는 실제 Neo4j Alert에 연결되어 선택된 로그다. '
        '이전 AI 답변은 대화 맥락이며 사실 검증 자료가 아니다. '
        '현재 이벤트·Alert·도구 조회 결과를 사실의 우선 근거로 사용하고, '
        '확인되지 않은 사용자/IP/자원 ID/실행 결과/침해 성공을 만들어내지 마라. '
        '기존 인용 검증 조건을 그대로 지키고, 검증되지 않은 ID는 검증됐다고 말하지 마라. '
        '질문 주제를 벗어난 대응책이나 장황한 요약을 덧붙이지 마라.\n'
    )
    if kind == 'deep':
        head += ('응답 구조: ### 핵심 판단, ### 확인된 로그·경보 근거, '
                 '### 가능한 공격 기법(추정과 확정 구분), ### 대응·완화 절차, '
                 '### 확인이 필요한 사항. 미확인 데이터는 명시하고 실제 대응은 수행하지 마라.\n')
    elif action:
        head += ('응답 구조: ### 핵심 대응, ### 1. 확인·조사, '
                 '### 2. 승인 후 조치, ### 3. 조치 후 검증·복구, ### 확인되지 않은 사항. '
                 '확인 명령과 변경 명령을 구분하여 필요한 구체적 OpenStack CLI를 Bash 코드블록에 제시하라. '
                 '도구 조회 또는 공식 CLI 문법으로 확인할 수 없는 명령은 지어내지 말고, '
                 '확인을 위해 필요한 자원 ID·설정·접근 권한을 설명하라. '
                 '실제 완화책/승인 여부/되돌리기 가능성을 확인하라.\n')
        head += _cli_reference(event_type, question)
    else:
        head += ('응답 구조: ### 답변, ### 근거·확인 사항(필요할 때만). '
                 '한두 문장으로 충분한 질문이면 불필요한 항목을 만들지 마라.\n')
    return head


def _split_plain_paragraph(line: str):
    """Readable paragraphs from unstructured prose, without inventing facts."""
    line = line.strip()
    if len(line) < 160 or re.search(r'https?://|\|', line):
        return [line]
    parts = _SENTENCE.split(line)
    if len(parts) < 2:
        return [line]
    return [' '.join(parts[i:i+2]).strip() for i in range(0, len(parts), 2)]


def display_markdown(text: str) -> str:
    """Normalize display only. Preserve source wording, code fences and IDs."""
    content = str(text or '').replace('\r\n','\n').replace('\r','\n').strip()
    if not content:
        return ''
    # Some model responses store literal backslash-n separators instead of
    # real newlines. Change only clearly structured escaped multi-line text.
    if ('```' not in content and '~~~' not in content and '\\n' in content
            and '\n' not in content and content.count('\\n') >= 2):
        content = content.replace('\\n', '\n')
    # Inline circled step labels are structural list markers, not prose.
    if not re.search(r'(?m)^\s*(?:```|~~~)', content):
        content = re.sub(r'(?<=\S)\s+(?=[②③④⑤⑥⑦⑧⑨⑩])', '\n', content)
    lines = content.split('\n')
    out = []
    in_fence = False
    fence_symbol = ''
    for raw in lines:
        line = raw.rstrip()
        match = _FENCE.match(line)
        if match:
            symbol = match.group(1)[:3]
            if not in_fence:
                if out and out[-1] != '':
                    out.append('')
                in_fence = True
                fence_symbol = symbol
            elif symbol == fence_symbol:
                in_fence = False
            out.append(line)
            if not in_fence:
                out.append('')
            continue
        if in_fence:
            out.append(line)
            continue
        if not line.strip():
            if out and out[-1] != '':
                out.append('')
            continue
        is_structure = bool(_HEADING.match(line) or _LIST.match(line) or line.startswith('>'))
        if _HEADING.match(line):
            if out and out[-1] != '':
                out.append('')
            out.append(line)
            out.append('')
        elif is_structure:
            out.append(line)
        else:
            for part in _split_plain_paragraph(line):
                if out and out[-1] != '':
                    # Single newline in markdown disappears, so preserve prose breaks.
                    if not (_LIST.match(out[-1]) or out[-1].startswith('>')):
                        out.append('')
                out.append(part)
    result = '\n'.join(out).strip()
    # Normalize trailing accidentally blank line before fenced code, no semantic rewrite.
    return result


def format_answer(text: str, kind: str, question: str='', event_type: str='', *, command_block_owned: bool=False) -> str:
    answer = display_markdown(text)
    if not answer:
        return ''
    if not re.search(r'^#{1,6}\s', answer, re.M):
        heading = '### 핵심 분석' if kind == 'deep' else '### 대응 안내' if is_action(question) else '### 답변'
        answer = heading + '\n\n' + answer
    # A narrow, explicit last-resort CLI syntax appendix when the model only
    # gave generic advice. This is documentation-based, NOT a live finding,
    # and only offered for a small list of known OpenStack event families.
    if not command_block_owned and kind == 'question' and is_action(question) and not re.search(r'\bopenstack\s+\w+', answer, re.I):
        read, change = _known_cli(event_type, question)
        if read:
            answer += ('\n\n### 확인용 OpenStack CLI (문법 참고)\n\n```bash\n'
                       + '\n'.join(read) + '\n```')
            if change:
                answer += ('\n\n### 승인 후 조치 예시 (운영자 수동 실행)\n\n```bash\n'
                           + '\n'.join(change) + '\n```')
            answer += ('\n\n**주의:** 위 명령은 실행된 결과가 아니며, 현재 환경에서 '
                       '자원 ID·권한·영향을 확인한 뒤 사용해야 합니다. '
                       '승인 전에는 변경 명령을 실행하지 마세요.')
    return answer
