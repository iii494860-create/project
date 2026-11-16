"""Read-only CTO backend used directly, without Hermes or an MCP runtime."""
import json
import os
import re
from pathlib import Path

CTO_READ_TOOLS = frozenset({'lookup_technique', 'explain_log_event', 'next_attack_steps',
    'get_defenses', 'find_vulnerabilities', 'validate_citations', 'summarize_incident',
    'list_recent_alerts', 'get_alert', 'get_incident', 'related_activity',
    'search_knowledge', 'retrieve_log_context', 'lookup_named_tactics'})
RULE_FIELDS = ('uri', 'label_ko', 'ruleType', 'groupBy', 'threshold', 'windowSeconds',
               'distinctField', 'distinctMin', 'filter', 'condition_ko', 'severity', 'verificationStatus')


def live_lookup_plan(question, context):
    """Only explicit current-state requests may trigger existing read-only APIs."""
    from qwen_evidence import live_lookup_allowed, task_question
    from qwen_rules import records
    q = task_question(question)
    if not live_lookup_allowed(question) or not re.search(r'현재|지금|활성\s*(?:상태|여부)|실시간', q):
        return []
    nodes = records(context)
    raw = context.get('raw_event') or {}
    if isinstance(raw, dict): nodes.append(raw)
    def identifier(keys):
        for node in nodes:
            for key in keys:
                value = node.get(key)
                if isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_.@:-]{1,128}', value): return value
        return None
    action, ident = None, None
    if re.search(r'사용자|계정|유저', q):
        action = 'get_openstack_user_roles' if re.search(r'역할|권한', q) else 'get_openstack_user'
        ident = identifier(('user_id', 'user'))
    elif re.search(r'보안\s*그룹', q):
        action, ident = 'get_openstack_security_group', identifier(('security_group_id',))
    elif re.search(r'서버|가상\s*머신|\bVM\b', q, re.I):
        action, ident = 'get_openstack_server', identifier(('server_id', 'instance_id'))
    return [(action, ident)] if action and ident else []


def load_config(path=None):
    source = Path(path or os.environ.get('QWEN_API_CONFIG') or Path(__file__).with_name('qwen_api_config.json'))
    config = json.loads(source.read_text())
    for env, key in [('QWEN_API_MODEL', 'model'), ('QWEN_API_BASE_URL', 'base_url'), ('QWEN_POLICY_PATH', 'policy_path')]:
        if os.environ.get(env): config[key] = os.environ[env]
    if not isinstance(config.get('policy_path'), str) or not config['policy_path'].strip():
        raise ValueError('Qwen policy_path에 전용 지침 파일을 지정해야 합니다.')
    policy = Path(config['policy_path']).expanduser()
    config['policy_path'] = str((policy if policy.is_absolute() else source.resolve().parent / policy).resolve())
    config['base_url'] = str(config['base_url']).rstrip('/')
    if not config['base_url'].startswith(('http://', 'https://')) or not config['base_url'].endswith('/v1'):
        raise ValueError('Qwen base_url은 http(s) /v1 주소여야 합니다.')
    return config


class CTOBackend:
    def __init__(self, graph=None):
        self.graph, self.driver = graph, None
        self.observed_record_refs = set()
        self.observed_incident_links = {}
        self.observed_named_tactics = set()

    def connect(self):
        if self.graph is None:
            from neo4j import GraphDatabase
            from cto_tools import Neo4jGraph
            password = os.environ.get('NEO4J_PASSWORD')
            if not password:
                password = Path(os.environ.get('CTO_NEO4J_PASSWORD_FILE', '~/.cto_neo4j_password')).expanduser().read_text().strip()
            self.driver = GraphDatabase.driver(os.environ.get('NEO4J_URI', 'bolt://127.0.0.1:7687'),
                auth=(os.environ.get('NEO4J_USER', 'neo4j'), password), connection_timeout=10)
            self.driver.verify_connectivity()
            self.graph = Neo4jGraph(self.driver, os.environ.get('NEO4J_DATABASE', 'neo4j'))
        return self.graph

    def call(self, name, arguments):
        if name not in CTO_READ_TOOLS:
            raise ValueError('허용되지 않은 CTO 조회입니다.')
        import cto_tools
        graph = self.connect()
        if name == 'lookup_named_tactics':
            query = str(arguments.get('query') or '').strip()
            if not query or len(query) > 2000:
                raise ValueError('전술 명칭 조회는 이번 사용자 질문 1~2000자가 필요합니다.')
            normalized = re.sub(r'\s+', ' ', query).casefold()
            rows = []
            for node in graph.all_of('Tactic'):
                ident, canonical = node.get('externalId'), node.get('label_en') or node.get('label')
                if not isinstance(ident, str) or not re.fullmatch(r'TA\d{4}', ident) or not isinstance(canonical, str):
                    continue
                labels = [v for k in ('label_en', 'label_ko', 'label') if isinstance(v := node.get(k), str) and v.strip()]
                matches = [label for label in labels if re.search(
                    r'(?<![A-Za-z0-9_])' + re.escape(re.sub(r'\s+', ' ', label).casefold()) + r'(?![A-Za-z0-9_])', normalized)]
                if matches or re.search(r'(?<![A-Za-z0-9_])' + re.escape(ident.casefold()) + r'(?![A-Za-z0-9_])', normalized):
                    rows.append({'id': ident, 'name': canonical, 'matched_labels': sorted(set(matches)),
                                 'description': str(node.get('comment_en') or node.get('comment_ko') or '')[:1800]})
            rows = sorted({r['id']: r for r in rows}.values(), key=lambda r: r['id'])
            self.observed_named_tactics.update(r['id'] for r in rows)
            return {'query': query, 'results': rows, 'no_match': not rows,
                    'note': '질문에 명시된 전술의 실제 정식 ID·명칭 조회다. 사건 발생이나 특정 기법의 소속 관계를 증명하지 않는다.'}
        result = cto_tools.call(graph, name, os.path.expanduser(os.environ.get('CTO_TOOL_LOG', '~/.cto_tool_calls.jsonl')), **arguments)
        if name in ('get_alert', 'get_incident', 'summarize_incident') and result.get('found') is True:
            ref = arguments.get('alert_id') or arguments.get('incident_id')
            if ref and ref in (result.get('alert_id'), result.get('incident_id')):
                self.observed_record_refs.add(ref)
        if name == 'get_alert' and result.get('found') is True and not result.get('error'):
            alert_id, incident_id = arguments.get('alert_id'), result.get('incident_id')
            if (isinstance(alert_id, str) and re.fullmatch(r'al-[0-9a-f]{24}', alert_id)
                    and result.get('alert_id') == alert_id and isinstance(incident_id, str)
                    and re.fullmatch(r'in-[0-9a-f]{24}', incident_id)):
                # get_alert derives this top-level field from the actual
                # GROUPED_INTO edge. Authorize that reference only, not nested
                # raw-log IDs or the incident's unqueried details/other records.
                self.observed_incident_links.setdefault(incident_id, set()).add(alert_id)
        if name == 'validate_citations' and not result.get('error'):
            knowledge_ids = [row['id'] for row in result.get('results', [])
                             if row.get('exists') is True and re.fullmatch(
                                 r'TA\d{4}|T\d{4}(?:\.\d{3})?|M\d{4}|D3-[A-Z][A-Z0-9-]*', row.get('id', ''))]
            names = graph.names_for_external_ids(knowledge_ids) if knowledge_ids else {}
            if names:
                result = {**result, 'results': [dict(row, canonical_name=names[row['id']])
                          if row.get('id') in names else dict(row) for row in result.get('results', [])]}
            # Legacy CTO scope is technique-only. A record is grounded by an
            # actual successful preflight lookup plus this fresh existence check.
            # Preserve the original rows so both decisions remain auditable.
            old_rows = result.get('results', [])
            rows = [dict(row, in_context=True, context_source='actual_requested_record_lookup')
                    if row.get('id') in self.observed_record_refs and row.get('exists') is True
                    else dict(row) for row in old_rows]
            rows = [dict(row, in_context=True, context_source='actual_alert_incident_link',
                         context_alert_ids=sorted(self.observed_incident_links[row['id']]),
                         context_scope='linked_incident_reference')
                    if row.get('id') in self.observed_incident_links
                    and row.get('id') not in self.observed_record_refs and row.get('exists') is True
                    else row for row in rows]
            rows = [dict(row, in_context=True, context_source='actual_requested_tactic_name_lookup')
                    if row.get('id') in self.observed_named_tactics and row.get('exists') is True else row
                    for row in rows]
            if rows != old_rows:
                result = {**result, 'technique_scope_result': result, 'results': rows,
                          'all_in_context': all(row.get('in_context') is True for row in rows)}
        if name == 'explain_log_event' and result.get('matched') is True:
            rules = {}
            event_type, outcome = arguments.get('event_type'), arguments.get('outcome')
            for event in graph.all_of('LogEventType'):
                names = event.get('eventTypeName', [])
                if isinstance(names, str): names = [names]
                if event_type not in names or outcome is not None and event.get('outcome') not in (None, outcome):
                    continue
                found = graph.inn(event['uri'], 'USES_EVENT', 'DetectionRule')
                for behavior in graph.out(event['uri'], 'CLASSIFIED_AS', 'BehaviorClass'):
                    found += graph.inn(behavior['uri'], 'USES_BEHAVIOR', 'DetectionRule')
                for rule in found:
                    rules[rule['uri']] = {k: rule[k] for k in RULE_FIELDS if k in rule}
            result = {**result, 'rule_definitions': list(rules.values())}
        return result

    def close(self):
        if self.driver is not None: self.driver.close()
