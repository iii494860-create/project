"""Evidence handling shared by the Qwen worker and its regression tests.

No expected answers, case IDs or benchmark files are used here.
"""
from __future__ import annotations

import json
import re
import threading

from cto_citation_scope import extract_techniques_from_rag, merge_scope

# ASCII identifier boundaries allow Korean particles, without backtracking a
# subtechnique into its parent. A malformed suffix remains a whole invalid ID.
CITATION_RE = re.compile(
    r'(?<![A-Za-z0-9_:])(?:TA\d{4}|T\d{4}(?:\.\d+)?|M\d{4}(?:\.\d+)?'
    r'|D3-[A-Za-z0-9-]+|DET\d{4}|AN\d{4}|CVE-\d{4}-\d+'
    r'|OSSA-\d{4}-\d+|OSSN-\d+|(?:al|in)-[0-9a-f]{24})(?![A-Za-z0-9_.])'
)
TECH_RE = re.compile(r'T\d{4}(?:\.\d{3})?\Z')
ABSENT_RE = re.compile(
    r'미발견|미등록|등록되지\s*않|존재하지\s*않|찾지\s*못|찾을\s*수\s*없|조회되지\s*않|발견되지\s*않'
    r'|(?:기록|등록|수록|등재)(?:되(?:어|지)|돼)?\s*(?:있지\s*)?않'
    r'|(?:존재|등록|기록|수록|등재|검색|조회|온톨로지|문서).{0,16}없|exists\s*[:=]\s*false'
    r'|not[ _-]found|does not exist|not registered', re.I)


def unwrap(value):
    for _ in range(8):
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except ValueError:
                return {}
        elif isinstance(value, dict) and 'result' in value:
            value = value['result']
        else:
            return value if isinstance(value, dict) else {}
    return {}


def task_question(question):
    """The dashboard appends log/evidence sections after the actual question."""
    task = str(question).rsplit('[이번 질문]', 1)[-1].lstrip()
    boundary = re.search(r'\n\[[^\]\n]{1,100}\]', task)
    return task[:boundary.start()].strip() if boundary else task.strip()


def requested_keys(question):
    # Read the user's requested names, never the evaluation rubric or log text.
    task = task_question(question)
    return list(dict.fromkeys(re.findall(r'\(([a-z][a-z0-9_]{2,})(?=\s*[:)])', task)))


def live_lookup_allowed(question):
    prefix = question.rsplit('[이번 질문]', 1)[0] if '[이번 질문]' in question else ''
    prefix = prefix.split('[이전 대화]', 1)[0]
    trusted_request = prefix + '\n' + task_question(question)
    # Authorization is taken only from the current user request and trusted
    # envelope, never raw fields or previous conversation. Korean negative
    # imperatives include 말고/말아/마세요, not just the stem "마".
    operation = r'(?:조회|질의|API\s*호출|실시간\s*확인|현재\s*상태\s*확인)'
    negative = r'(?:하지\s*(?:마|말|않)|요청하지\s*않|금지|불필요|필요\s*없|없이|생략|제외)'
    for match in re.finditer(operation + r'(?P<scope>[^.!?\n]{0,120}?)' + negative,
                             trusted_request, re.I):
        # "조회해줘, 변경은 하지 마" prohibits the change, not the lookup.
        # A coordinated list without a positive imperative remains prohibited.
        if not re.search(r'해\s*(?:줘|주|라)|하(?:고|되)|한\s*(?:뒤|후)', match['scope']):
            return False
    return not bool(re.search(r'(?:로그|기록|원문)(?:만|으로만).{0,35}(?:판단|답|분석|알려)',
                             trusted_request, re.I)
                    or re.search(r"(?:do\s+not|don't|without|no)\s+(?:live\s+)?(?:query|lookup|API|call)",
                                 trusted_request, re.I))


def evidence_targets(context):
    """Only typed event fields and explicit user-requested technique IDs seed retrieval."""
    events, ids = [], []
    def visit(node, depth=0):
        if depth > 5:
            return
        if isinstance(node, str) and len(node) <= 64000 and node.lstrip().startswith(('{', '[')):
            try:
                node = json.loads(node)
            except ValueError:
                return
        if isinstance(node, list):
            for child in node[:16]:
                visit(child, depth + 1)
            return
        if not isinstance(node, dict):
            return
        payload = node.get('payload') if isinstance(node.get('payload'), dict) else {}
        event = node.get('event_type') or node.get('eventTypeName') or payload.get('event_type')
        outcome = node.get('outcome') or payload.get('outcome')
        if isinstance(event, str) and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.:-]{1,160}', event):
            pair = (event, outcome if outcome in ('success', 'failure', 'pending', 'unknown') else None)
            if pair not in events:
                events.append(pair)
        ident = node.get('requested_technique_id')
        if isinstance(ident, str) and TECH_RE.fullmatch(ident):
            ids.append(ident)
        for key in ('events', 'records', 'logs'):
            if isinstance(node.get(key), list):
                for child in node[key][:16]:
                    visit(child, depth + 1)
        for key in ('raw_event', 'event', 'notification', 'log', 'source'):
            visit(node.get(key), depth + 1)
    visit(context)
    # IDs in log messages/user_agent are deliberately excluded.
    question = task_question(str(context.get('question') or ''))
    if events:
        ids = []  # A log's requested-ID field cannot widen an event's evidence scope.
    ids.extend(x for x in CITATION_RE.findall(question) if TECH_RE.fullmatch(x))
    # A routing hint without an outcome must not cause a duplicate broad lookup
    # when the actual nested log supplies the same event's precise outcome.
    specific = {event for event, outcome in events if outcome not in (None, 'unknown')}
    events = [(event, outcome) for event, outcome in events
              if outcome not in (None, 'unknown') or event not in specific]
    return events[:8], sorted(set(ids))[:8]


def compact_evidence(name, body):
    if name.endswith('explain_log_event') and isinstance(body.get('results'), list):
        return {**body, 'results': [{k: v for k, v in row.items() if k != 'fields'}
                                  for row in body['results'] if isinstance(row, dict)]}
    return body


class EvidenceLedger:
    def __init__(self, run_id, context, merge=merge_scope):
        self.run_id = run_id
        self.events, requested = evidence_targets(context)
        self.requested_ids = set(requested)
        self.requested_refs = {ident for ident in CITATION_RE.findall(task_question(str(context.get('question') or '')))
                               if ident.startswith(('al-', 'in-'))}
        # Supplied separately by the dashboard's actual TRIGGERED_BY lookup.
        # Never discover these from arbitrary raw log fields or previous prose.
        related = context.get('related_alert_ids')
        if isinstance(related, list):
            self.requested_refs.update(x for x in related[:8]
                                       if isinstance(x, str) and re.fullmatch(r'al-[0-9a-f]{24}', x))
        self.techniques = set()
        self.absent = set()
        self.calls = []
        self.merge = merge
        self.lock = threading.RLock()

    def record(self, name, args, raw):
        """Consume an actual dispatch result, before the model can reinterpret it."""
        body = unwrap(raw)
        with self.lock:
            self.calls.append({'name': name, 'arguments': args, 'ok': bool(body) and not body.get('error')})
            if not body or body.get('error'):
                return
            short = name.removeprefix('mcp__cto__').removeprefix('cto__')
            ids = set()
            event_ok = not self.events or (args.get('event_type'), args.get('outcome')) in self.events or any(
                e == args.get('event_type') and args.get('outcome') is None for e, _ in self.events)
            if short == 'lookup_technique' and body.get('id') == args.get('technique_id'):
                ident = body['id']
                if body.get('found') is False:
                    self.absent.add(ident)
                elif body.get('found') is True and ident in self.requested_ids | self.techniques:
                    ids.add(ident)
                    self.absent.discard(ident)
            elif short == 'validate_citations':
                # Existence rows are independently observed negative evidence,
                # even when an ID first appeared in a quoted hostile log. They
                # do not create a positive context scope.
                requested = set(args.get('ids') or [])
                for row in body.get('results', []):
                    if not isinstance(row, dict) or row.get('id') not in requested:
                        continue
                    if row.get('exists') is False:
                        self.absent.add(row['id'])
                    elif row.get('exists') is True:
                        self.absent.discard(row['id'])
            elif short in ('get_alert', 'get_incident', 'summarize_incident') and body.get('found') is True:
                ref = args.get('alert_id') or args.get('incident_id')
                if ref in self.requested_refs and ref in (body.get('alert_id'), body.get('incident_id')):
                    ids.update(t.get('id') if isinstance(t, dict) else t for t in body.get('techniques', []))
            elif short == 'explain_log_event' and body.get('matched') is True and event_ok:
                for event in body.get('results', []):
                    for behavior in event.get('behaviors', []):
                        ids.update(t.get('id') for t in behavior.get('suggested_techniques', []) if isinstance(t, dict))
            elif short == 'retrieve_log_context' and event_ok:
                ids.update(extract_techniques_from_rag(body))
            elif short == 'search_knowledge' and not self.events and not self.requested_ids:
                ids.update(extract_techniques_from_rag(body))
                ids.update(r.get('id') for r in body.get('results', [])
                           if isinstance(r, dict) and r.get('kind') == 'Technique')
            grounded = {x for x in ids if isinstance(x, str) and TECH_RE.fullmatch(x)}
            if grounded:
                self.techniques.update(grounded)
                self.merge(self.run_id, sorted(self.techniques))

    def classify_citations(self, answer):
        """Exclude only independently confirmed, explicitly negative mentions.

        An input ID echo can be neutral. A technique mapping or a positive claim
        still goes through the normal existence/context gate, even after lookup
        returned not_found. Each occurrence is checked independently.
        """
        positive, negative = set(), set()
        try:
            obj = json.loads(answer)
        except ValueError:
            obj = None
        answers = obj.get('answers', {}) if isinstance(obj, dict) else {}
        if not isinstance(answers, dict):
            answers = {}
        positive_lookup_claim = (
            answers.get('exists_in_ontology') is True
            or answers.get('lookup_status') in ('found', 'available')
            or any(answers.get(k) is not None for k in ('official_name', 'response_command'))
        )
        negative_lookup_id = answers.get('requested_id') or answers.get('requested_technique_id')
        negative_lookup_contract = (
            isinstance(negative_lookup_id, str)
            and negative_lookup_id in self.requested_ids & self.absent
            and answers.get('exists_in_ontology') is False
            and answers.get('lookup_status') == 'not_found'
            and not positive_lookup_claim
        )

        def scan(text, neutral=False):
            for clause in re.split(r'(?<=[.!?。])\s+|\n', text):
                for ident in CITATION_RE.findall(clause):
                    # A requested ID can be introduced in one sentence and
                    # reported absent in the next. Only accept a whole-clause
                    # input label, backed by an actual negative lookup; a later
                    # adopted mapping or positive claim still wins below.
                    input_echo = (ident in self.requested_ids and not positive_lookup_claim
                        and re.fullmatch(
                            r'(?:입력(?:된|한)?|요청(?:된|한)?|제공(?:된|한)?|원문(?:에|의)?)'
                            r'[^\n.!?]{0,100}(?:ID|식별자)(?:\s*값)?(?:은|는|이|가|:)\s*'
                            r'[\x60\x27\x22]?' + re.escape(ident)
                            + r'[\x60\x27\x22]?\s*(?:입니다|이다|다|임)?[.!?]?',
                            clause.strip(), re.I) is not None)
                    # Reporting that a supplied ID was checked is not claiming
                    # that it exists. Require both the structured negative
                    # verdict and actual tool evidence. Do not accept statements
                    # about existence, official names, classification or mapping.
                    lookup_note = (negative_lookup_contract and ident == negative_lookup_id
                        and re.search(r'(?:입력|요청|제공)', clause) is not None
                        and re.search(r'(?:조회|검색|검증|확인)', clause) is not None
                        and re.search(r'존재|등록|공식|공격|매핑|분류|해당|기법명|명칭|유효|기법(?:으로|이다|입니다|임)', clause) is None
                        and re.search(r'(?:조회|검색|검증|확인)(?:했습니다|했다|하였다|함|합니다)[.!?]?$',
                                      clause.strip()) is not None)
                    is_negative = bool(ABSENT_RE.search(clause)) and not re.search(
                        r'없는\s*것.{0,3}아니|않는\s*것.{0,3}아니|not\s+not', clause, re.I)
                    if ident in self.absent and (neutral or input_echo or lookup_note or is_negative):
                        negative.add(ident)
                    else:
                        positive.add(ident)

        def walk(value, key=''):
            if isinstance(value, dict):
                for k, v in value.items():
                    walk(v, k)
            elif isinstance(value, list):
                for v in value:
                    walk(v, key)
            elif isinstance(value, str):
                # Only an explicitly requested ID may be echoed without being
                # treated as an adopted technique. Never suppress mapping fields.
                if (key in ('requested_id', 'requested_technique_id')
                        and value in self.requested_ids & self.absent and not positive_lookup_claim):
                    scan(value, neutral=True)
                elif key in ('explanation', 'summary', 'note'):
                    scan(value)
                else:
                    positive.update(CITATION_RE.findall(value))
        if isinstance(obj, dict):
            walk(obj)
        else:
            scan(answer)
        return sorted(positive), sorted(negative - positive)


def final_citation_checks(ledger, answer, probes):
    """Separate adopted citations from negative claims after actual existence probes.

    Original probe responses are preserved by the worker. Positive checks below
    contain the original rows for adopted IDs, never invented successful rows.
    Unreturned IDs fail closed, and a nonexistent positive claim remains a failure.
    """
    ids, negative = ledger.classify_citations(answer)
    observed = {row['id']: row for probe in probes for row in probe.get('results', [])
                if isinstance(row, dict) and isinstance(row.get('id'), str)}
    if not ids:
        return ids, negative, []
    rows = [observed.get(ident, {'id': ident, 'exists': None, 'in_context': None}) for ident in ids]
    body = {'results': rows, 'all_exist': all(r.get('exists') is True for r in rows),
            'all_in_context': (None if any(r.get('in_context') is None for r in rows)
                               else all(r.get('in_context') is True for r in rows)),
            'source': 'actual_validate_citations_rows_for_adopted_ids'}
    return ids, negative, [body]


def output_errors(answer, keys):
    if not keys:
        return []
    try:
        obj = json.loads(answer)
    except ValueError:
        return ['코드펜스나 앞뒤 설명 없이 JSON 객체 하나만 반환해야 합니다.']
    if not isinstance(obj, dict) or not isinstance(obj.get('answers'), dict):
        return ['answers 객체와 explanation 문자열이 있는 JSON 객체가 필요합니다.']
    got = set(obj['answers'])
    errors = []
    if set(keys) - got:
        errors.append('요청된 키 누락: ' + ', '.join(sorted(set(keys) - got)))
    if got - set(keys):
        errors.append('요청하지 않은 키: ' + ', '.join(sorted(got - set(keys))))
    if not isinstance(obj.get('explanation'), str):
        errors.append('explanation은 한국어 문자열이어야 합니다.')
    return errors
