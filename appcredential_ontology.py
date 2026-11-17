"""Persistent Keystone application credential mappings, included by gen_mapping."""
import json

MARKER = '# CTO_APPLICATION_CREDENTIAL_V1'


def mapping_ttl():
    lines = [MARKER]
    def literal(value):
        return json.dumps(value, ensure_ascii=False)
    def node(uri, kind, label, properties):
        parts = [('a', 'cto:' + kind), ('rdfs:label', literal(label) + '@ko')] + properties
        lines.append(uri + ' ' + ' ;\n    '.join(p + ' ' + v for p, v in parts) + ' .')
    node('kb:doc_appcredential', 'SourceDocument', 'Keystone Application Credentials', [
        ('cto:url', literal('https://docs.openstack.org/keystone/latest/user/application_credentials.html') + '^^xsd:anyURI'),
        ('rdfs:comment', literal('2026-11-17 cto-test 실제 생성·삭제 CADF 알림과 설치된 CLI 도움말 확인. 사용 인증 로그 연결은 미확인.') + '@ko')])
    node('kb:res_application_credential', 'ResourceType', 'Application Credential', [
        ('cto:providedBy', 'kb:Keystone'), ('cto:apiResourceName', literal('application_credential')),
        ('cto:typeURI', literal('data/security/credential')), ('cto:sensitivity', literal('high')),
        ('cto:derivedFrom', 'kb:doc_appcredential'), ('cto:verificationStatus', literal('공식문서확인'))])
    for name, label, paths, target, correlate in [
        ('user', '자격증명 작업 수행자', ['payload.initiator.user_id', 'payload.initiator.id'], 'kb:res_user', True),
        ('project', '자격증명 발급 프로젝트', ['payload.initiator.project_id', '_context_project_id'], 'kb:res_project', True),
        # target.id is also a shared Keystone service target in auth events;
        # making it a global correlation key would merge unrelated incidents.
        ('id', 'Application Credential ID', ['payload.resource_info', 'payload.target.id'], 'kb:res_application_credential', False),
    ]:
        node('kb:field_appcredential_' + name, 'LogField', label, [
            ('cto:fieldPath', ' , '.join(map(literal, paths))),
            ('cto:refersTo', target), ('cto:isCorrelationKey', str(correlate).lower()),
            ('cto:derivedFrom', 'kb:doc_appcredential'), ('cto:verificationStatus', literal('공식문서확인'))])
    for operation, word, action in [('create', '생성', 'create'), ('delete', '삭제', 'delete')]:
        node('kb:bc_appcredential_' + operation, 'BehaviorClass', 'Application Credential ' + word, [
            ('cto:riskScore', '0'), ('cto:matchesAction', 'kb:act_' + action),
            ('cto:matchesResourceType', 'kb:res_application_credential'),
            ('cto:derivedFrom', 'kb:doc_appcredential'), ('cto:verificationStatus', literal('팀설계')),
            ('rdfs:comment', literal('성공·실패 생성/삭제 기록을 보존한다. 단독 발급은 공격 판정이 아니며 자격증명 사용 성공도 뜻하지 않는다.') + '@ko')]
            + ([('cto:suggestsTechnique', 'kb:T1098_001')] if operation == 'create' else []))
        node('kb:ev_appcredential_' + operation, 'LogEventType', 'Keystone Application Credential ' + word, [
            ('cto:eventTypeName', literal('identity.application_credential.' + ('created' if operation == 'create' else 'deleted'))),
            ('cto:emittedBy', 'kb:Keystone'), ('cto:viaChannel', 'kb:ch_keystone_cadf'),
            ('cto:hasAction', 'kb:act_' + action), ('cto:onResourceType', 'kb:res_application_credential'),
            ('cto:classifiedAs', 'kb:bc_appcredential_' + operation),
            ('cto:hasField', ' , '.join(['kb:field_appcredential_user', 'kb:field_appcredential_project',
                'kb:field_appcredential_id', 'kb:f_ks_src_ip', 'kb:f_ks_request_id',
                'kb:f_ks_outcome', 'kb:f_ks_target_type', 'kb:f_ks_initiator_username', 'kb:f_ks_agent'])),
            ('cto:derivedFrom', 'kb:doc_appcredential'), ('cto:verificationStatus', literal('공식문서확인'))])
    node('kb:param_application_credential', 'CommandParameter', '확인된 Application Credential ID', [
        ('cto:placeholder', literal('<application-credential>')), ('cto:valueFrom', 'kb:field_appcredential_id')])
    node('kb:inv_appcredential_show', 'InvestigationQuery', 'Application Credential 속성 확인', [
        ('cto:command', literal('openstack application credential show <application-credential>')),
        ('cto:hasParameter', 'kb:param_application_credential'),
        ('cto:purpose', literal('자격증명 소유자 계정의 적절한 인증 문맥에서 프로젝트·역할·만료 확인. ID만으로 소유 계정을 바꿀 수 없으며 404는 삭제 또는 접근 범위 차이일 수 있다.') + '@ko'),
        ('cto:derivedFrom', 'kb:doc_appcredential'), ('cto:verificationStatus', literal('공식문서확인'))])
    node('kb:resp_appcredential_delete', 'ResponseAction', '확인된 비승인 Application Credential 폐기', [
        ('cto:command', literal('openstack application credential delete <application-credential>')),
        ('cto:hasParameter', 'kb:param_application_credential'), ('cto:requiresApproval', 'true'),
        ('rdfs:comment', literal('소유 계정·프로젝트·업무 영향 확인 후 승인된 사용자 인증 문맥에서 실행. 기존 secret 복원 불가. 삭제 이벤트에는 재삭제를 권고하지 않는다.') + '@ko'),
        ('cto:derivedFrom', 'kb:doc_appcredential'), ('cto:verificationStatus', literal('공식문서확인'))])
    for operation in ('create', 'delete'):
        lines.append(f'kb:bc_appcredential_{operation} cto:investigateWith kb:inv_appcredential_show .')
    node('kb:rule_appcredential_after_takeover', 'DetectionRule', '의심 로그인 후 Application Credential 발급', [
        ('cto:ruleType', literal('appcredential_sequence')), ('cto:alertTier', 'kb:tier_chain'),
        ('cto:usesEvent', 'kb:ev_appcredential_create'), ('cto:usesBehavior', 'kb:bc_appcredential_create'),
        ('cto:detects', 'kb:T1098_001'), ('cto:severity', literal('high')), ('cto:windowSeconds', '3600'),
        ('cto:groupBy', literal('@user')), ('cto:sequenceStep', literal('1:rule_fail_then_success') + ' , ' + literal('2:bc_appcredential_create')),
        ('cto:condition', literal('실패 반복 후 성공 경보에 포함된 성공 로그인과 동일 사용자·출발지 IP에서 3600초 이내 자격증명 생성 성공. 발급 프로젝트·자격증명 ID 필수, 알려진 프로젝트 불일치·승인 자격증명 제외. 단순 신규 IP는 제외. 발급 의심이며 자격증명 사용·침해 확정 아님.') + '@ko'),
        ('cto:ruleResponse', 'kb:resp_appcredential_delete'),
        ('cto:derivedFrom', 'kb:doc_team_scenario'), ('cto:verificationStatus', literal('팀설계'))])
    # T1098.001 has different response actions for Nova keys and Keystone credentials.
    lines.append('kb:rule_keypair_after_takeover cto:ruleResponse kb:resp_keypair_delete .')
    return '\n\n'.join(lines) + '\n'
