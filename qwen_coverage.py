"""Complete explicitly requested technique facts from actual typed CTO results."""
import re

from qwen_evidence import task_question


def complete_requested_techniques(answer, question, evidence):
    question = task_question(question)
    request = re.search(r'ATT(?:&|A)?CK|MITRE|공격\s*기법|기법\s*(?:ID|아이디|명칭|이름)', question, re.I)
    if not request or re.search(r'[^,.?!\n]{0,12}(?:빼고|빼줘|제외|생략|언급하지|필요\s*없)',
                                question[request.end():request.end()+25]):
        return answer, {'requested': False, 'added_ids': []}

    lookups = [item for item in evidence if item.get('tool') == 'lookup_technique']
    candidates = []
    if lookups:
        # An explicit missing ID must never be replaced with a nearby technique.
        for item in lookups:
            result = item.get('result', {})
            if result.get('found') is True:
                candidates.append((result, item['tool']))
    else:
        for item in evidence:
            result, tool = item.get('result', {}), item.get('tool')
            if tool in ('get_alert', 'get_incident', 'summarize_incident') and result.get('found') is True:
                candidates.extend((t, tool) for t in result.get('techniques', []))
        if not candidates:
            for item in evidence:
                result = item.get('result', {})
                if item.get('tool') == 'explain_log_event' and result.get('matched') is True:
                    for event in result.get('results', []):
                        for behavior in event.get('behaviors', []):
                            candidates.extend((t, item['tool']) for t in behavior.get('suggested_techniques', []))

    facts = {}
    for row, source in candidates:
        if not isinstance(row, dict):
            continue
        ident, name = row.get('id'), row.get('name')
        if (isinstance(ident, str) and re.fullmatch(r'T\d{4}(?:\.\d{3})?', ident)
                and isinstance(name, str) and 0 < len(name.strip()) <= 200):
            facts.setdefault(ident, {'id': ident, 'name': name.strip(), 'source_tool': source})
    plain = re.sub(r'[`*_]', '', answer)
    missing = [fact for ident, fact in sorted(facts.items())
               if not re.search(r'(?<![A-Za-z0-9_.])'+re.escape(ident)+r'(?![A-Za-z0-9_.])', plain)
               or fact['name'].casefold() not in plain.casefold()]
    audit = {'requested': True, 'available': list(facts.values()),
             'added_ids': [fact['id'] for fact in missing]}
    if not facts:
        audit['status'] = 'no_grounded_mapping'
        return answer, audit
    audit['status'] = 'completed_from_evidence' if missing else 'already_present'
    if not missing:
        return answer, audit
    block = '조회된 관련 ATT&CK 기법: ' + '; '.join(f"**{f['id']} — {f['name']}**" for f in missing)
    block += '. 로그·경보와의 연결 정보이며, 실제 공격 성공을 확정하는 뜻은 아닙니다.'
    return block + '\n\n' + answer, audit
