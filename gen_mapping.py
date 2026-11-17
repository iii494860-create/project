# openstack_mapping.ttl 생성기 (검증된 사실을 데이터로 정리 → Turtle 출력)
OK, TEAM, LOG, CMD = "공식문서확인", "팀설계", "실로그확인필요", "명령확인필요"
out = []
def lit(s, lang=None):
    s = str(s).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{s}"@{lang}' if lang else f'"{s}"'
def node(subj, pairs):
    body = " ;\n    ".join(f"{p} {o}" for p, o in pairs)
    out.append(f"{subj} {body} .\n")
def objs(*xs): return " , ".join(xs)

out.append('''@prefix cto:  <https://3k1h.example.org/cto#> .
@prefix kb:   <https://3k1h.example.org/kb#> .
@prefix d3f:  <http://d3fend.mitre.org/ontologies/d3fend.owl#> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
@prefix xsd:  <http://www.w3.org/2001/XMLSchema#> .

# =====================================================================
#  OpenStack 전용 매핑 v0.5 (Keystone · Nova · Neutron · Glance)
#  generate: gen_mapping.py 로 생성. 직접 고칠 때는 gen_mapping.py 를 고치고 다시 생성 권장
#
#  검증 상태(cto:verificationStatus)
#    공식문서확인   : 공식 문서/소스에서 직접 확인
#    팀설계         : 팀의 설계 가정 (근거를 발표·보고서에 제시)
#    실로그확인필요 : 우리 OpenStack 클러스터의 실제 로그로 확인 후 공식문서확인으로 변경
#    명령확인필요   : openstack <명령> --help 로 확인 후 공식문서확인으로 변경
#
#  자동 생성되어 여기 쓰지 않는 것: ATT&CK 기법·전술·완화책·탐지전략·동시사용, D3FEND 매핑, OSSA/OSSN
# =====================================================================
''')

# ---------------- 출처 문서
docs = [
 ("doc_keystone_notif", "Keystone Event Notifications", "https://docs.openstack.org/keystone/latest/admin/event_notifications.html"),
 ("doc_nova_notif", "Nova Notifications", "https://docs.openstack.org/nova/latest/reference/notifications.html"),
 ("doc_nova_samples", "Nova notification samples (doc/notification_samples)", "https://opendev.org/openstack/nova/src/branch/master/doc/notification_samples"),
 ("doc_neutron_notif", "Neutron Notification events", "https://docs.openstack.org/neutron/latest/reference/notifications.html"),
 ("doc_glance_notif", "Glance Notifications", "https://docs.openstack.org/glance/latest/admin/notifications.html"),
 ("doc_nova_keypair", "Nova keypair versioned notification (keypair.create/import/delete, KeypairPayload)", "https://opendev.org/openstack/nova/commit/ad56be6d225ef67892ecd29c0fff0b197c01c43a"),
 ("doc_audit_mw", "keystonemiddleware Audit middleware", "https://docs.openstack.org/keystonemiddleware/latest/audit.html"),
 ("doc_pycadf_taxonomy", "pyCADF cadftaxonomy (CADF action taxonomy)", "https://docs.openstack.org/pycadf/latest/_modules/pycadf/cadftaxonomy.html"),
 ("doc_pycadf_auditmap", "pyCADF api_audit_map.conf (nova/neutron)", "https://opendev.org/openstack/pycadf"),
 ("doc_osc", "python-openstackclient command reference", "https://docs.openstack.org/python-openstackclient/latest/"),
 ("doc_osc_help", "python-openstackclient 10.0.0 --help 출력으로 명령·인자 확인 (2026-09-27, 팀 VM)", None),
 ("doc_team_scenario", "3K1H 설계 문서 (팀)", None),
]
out.append("# ---------------- 출처 문서\n")
for n, label, url in docs:
    pairs = [("a", "cto:SourceDocument"), ("rdfs:label", lit(label))]
    if url: pairs.append(("cto:url", f"{lit(url)}^^xsd:anyURI"))
    elif n == "doc_team_scenario": pairs.append(("rdfs:comment", lit("공식 문서가 아닌 팀 설계 가정. 발표·보고서에 설계 근거를 함께 제시", "ko")))
    else: pairs.append(("rdfs:comment", lit("공식 명령 도구의 내장 도움말로 직접 확인한 기록", "ko")))
    node(f"kb:{n}", pairs)

# ---------------- 서비스, 채널
out.append("# ---------------- 서비스와 로그 채널\n")
for s, c in [("Keystone", "Identity"), ("Nova", "Compute"), ("Neutron", "Networking"), ("Glance", "Image")]:
    node(f"kb:{s}", [("a", "cto:OpenStackService"), ("rdfs:label", lit(s)), ("rdfs:comment", lit(c + " 서비스", "ko"))])
chans = [
 ("ch_keystone_cadf", "Keystone CADF 알림", "keystone.conf: notification_format = cadf. 인증 이벤트는 기본 억제(notification_opt_out 조정 필요)", "doc_keystone_notif", OK),
 ("ch_nova_versioned", "Nova versioned 알림", "nova.conf [notifications] notification_format = versioned 로 고정 권장(필드 경로가 versioned 기준)", "doc_nova_notif", OK),
 ("ch_neutron_notif", "Neutron 알림", "legacy(unversioned) 알림. payload는 API 리소스 스키마. 요청 사용자 정보 없음 → audit 로그와 연결 필요", "doc_neutron_notif", OK),
 ("ch_glance_notif", "Glance 알림", "glance 알림 driver 기본값은 noop(알림 없음) → 설정 필수. 이미지 생성·변경 이벤트의 필드 목록은 문서에 없음(실로그 확인)", "doc_glance_notif", OK),
 ("ch_audit", "keystonemiddleware audit (CADF)", "각 서비스 api-paste.ini 에 audit 필터 추가. 모든 API 요청을 CADF로 기록. 이벤트 이름·필드는 실로그 확인 필요", "doc_audit_mw", LOG),
]
for n, label, cmt, d, st in chans:
    node(f"kb:{n}", [("a", "cto:LogChannel"), ("rdfs:label", lit(label, "ko")), ("rdfs:comment", lit(cmt, "ko")),
                     ("cto:derivedFrom", f"kb:{d}"), ("cto:verificationStatus", lit(st))])

# ---------------- 행위 유형 (pyCADF ACTION_TAXONOMY, 확인됨)
out.append("# ---------------- 행위 유형 (CADF)\n")
ACTIONS = ["create", "read", "read/list", "update", "delete", "authenticate", "start", "stop", "enable", "disable", "send", "capture"]
def an(a): return "kb:act_" + a.replace("/", "_")
for a in ACTIONS:
    node(an(a), [("a", "cto:ActionType"), ("rdfs:label", lit(a)), ("cto:cadfAction", lit(a)),
                 ("cto:derivedFrom", "kb:doc_pycadf_taxonomy"), ("cto:verificationStatus", lit(OK))])

# ---------------- 자원 유형
out.append("# ---------------- 자원 유형\n")
RES = [
 # id, label, service, apiName, typeURI, sensitivity, source, status
 ("user", "사용자", "Keystone", "user", "data/security/account/user", "high", "doc_keystone_notif", OK),
 ("role_assignment", "역할 할당", "Keystone", "role_assignment", "data/security/account/user", "high", "doc_keystone_notif", OK),
 ("role", "역할 정의", "Keystone", "role", "data/security/role", "high", "doc_keystone_notif", OK),
 ("trust", "위임(trust)", "Keystone", "trust", "data/security/trust", "high", "doc_keystone_notif", OK),
 ("policy", "정책", "Keystone", "policy", "data/security/policy", "high", "doc_keystone_notif", OK),
 ("endpoint", "엔드포인트", "Keystone", "endpoint", "data/security/endpoint", "high", "doc_keystone_notif", OK),
 ("service", "서비스 카탈로그", "Keystone", "service", "data/security/service", "high", "doc_keystone_notif", OK),
 ("domain", "도메인", "Keystone", "domain", "data/security/domain", "high", "doc_keystone_notif", OK),
 ("region", "리전", "Keystone", "region", "data/security/region", "medium", "doc_keystone_notif", OK),
 ("project", "프로젝트", "Keystone", "project", "data/security/project", "medium", "doc_keystone_notif", OK),
 ("group", "그룹", "Keystone", "group", "data/security/group", "medium", "doc_keystone_notif", OK),
 ("instance", "인스턴스", "Nova", "instance", None, "medium", "doc_nova_notif", OK),
 ("keypair", "키페어", "Nova", "keypair", None, "high", "doc_nova_keypair", OK),
 ("image", "이미지", "Glance", "image", None, "high", "doc_glance_notif", OK),
 ("image_member", "이미지 공유", "Glance", "image_member", None, "high", "doc_glance_notif", OK),
 ("security_group_rule", "보안그룹 규칙", "Neutron", "security_group_rule", "service/network", "high", "doc_neutron_notif", OK),
 ("security_group", "보안그룹", "Neutron", "security_group", "service/network", "high", "doc_neutron_notif", OK),
 ("floatingip", "Floating IP", "Neutron", "floatingip", "service/network", "high", "doc_neutron_notif", OK),
 ("port", "포트", "Neutron", "port", "service/network", "medium", "doc_neutron_notif", OK),
 ("router", "라우터", "Neutron", "router", "service/network", "medium", "doc_neutron_notif", OK),
 ("network", "네트워크", "Neutron", "network", "service/network", "low", "doc_neutron_notif", OK),
 ("subnet", "서브넷", "Neutron", "subnet", "service/network", "low", "doc_neutron_notif", OK),
]
def rn(r): return f"kb:res_{r}"
for rid, label, svc, api, turi, sens, src, st in RES:
    pairs = [("a", "cto:ResourceType"), ("rdfs:label", lit(label, "ko")), ("cto:providedBy", f"kb:{svc}"),
             ("cto:apiResourceName", lit(api)), ("cto:sensitivity", lit(sens))]
    if turi: pairs.append(("cto:typeURI", lit(turi)))
    pairs += [("cto:derivedFrom", f"kb:{src}"), ("cto:verificationStatus", lit(st))]
    node(rn(rid), pairs)

# ---------------- 로그 필드
out.append("# ---------------- 로그 필드\n")
F = [
 # id, label, path(s), refersTo, corrKey, source, status
 ("ks_initiator_id", "행위자 사용자 ID", ["payload.initiator.id"], "user", True, "doc_keystone_notif", OK),
 ("ks_initiator_user_id", "행위자 user_id", ["payload.initiator.user_id"], "user", True, "doc_keystone_notif", OK),
 ("ks_initiator_username", "행위자 사용자명", ["payload.initiator.username"], None, False, "doc_keystone_notif", OK),
 ("ks_src_ip", "출발지 IP", ["payload.initiator.host.address"], None, True, "doc_keystone_notif", OK),
 ("ks_agent", "클라이언트 에이전트", ["payload.initiator.host.agent"], None, False, "doc_keystone_notif", OK),
 ("ks_request_id", "요청 ID", ["payload.initiator.request_id"], None, True, "doc_keystone_notif", OK),
 ("ks_action", "CADF 행위", ["payload.action"], None, False, "doc_keystone_notif", OK),
 ("ks_outcome", "결과", ["payload.outcome"], None, False, "doc_keystone_notif", OK),
 ("ks_target_id", "대상 ID", ["payload.target.id"], None, False, "doc_keystone_notif", OK),
 ("ks_target_type", "대상 typeURI", ["payload.target.typeURI"], None, False, "doc_keystone_notif", OK),
 ("ks_resource_info", "생성·변경된 자원 ID", ["payload.resource_info"], None, False, "doc_keystone_notif", OK),
 ("ks_reason_code", "사유 코드", ["payload.reason.reasonCode"], None, False, "doc_keystone_notif", OK),
 ("ks_pw_hash", "비밀번호 부분 해시", ["payload.attachments[name=partial_password_hash].content"], None, False, "doc_keystone_notif", OK),
 ("ks_ra_role", "할당 역할 ID", ["payload.role"], "role", False, "doc_keystone_notif", OK),
 ("ks_ra_project", "할당 대상 프로젝트", ["payload.project"], "project", True, "doc_keystone_notif", OK),
 ("ks_ra_domain", "할당 대상 도메인", ["payload.domain"], "domain", False, "doc_keystone_notif", OK),
 ("ks_ra_user", "역할 받은 사용자", ["payload.user"], "user", True, "doc_keystone_notif", OK),
 ("ks_ra_group", "역할 받은 그룹", ["payload.group"], "group", False, "doc_keystone_notif", OK),
 ("nova_uuid", "인스턴스 ID", ["payload.nova_object.data.uuid"], "instance", True, "doc_nova_samples", OK),
 ("nova_user", "요청 사용자 ID", ["payload.nova_object.data.user_id"], "user", True, "doc_nova_samples", OK),
 ("nova_tenant", "프로젝트 ID", ["payload.nova_object.data.tenant_id"], "project", True, "doc_nova_samples", OK),
 ("nova_host", "컴퓨트 호스트", ["payload.nova_object.data.host"], None, False, "doc_nova_samples", OK),
 ("nova_image", "이미지 ID", ["payload.nova_object.data.image_uuid"], None, False, "doc_nova_samples", OK),
 ("nova_flavor", "사양 이름", ["payload.nova_object.data.flavor.nova_object.data.name"], None, False, "doc_nova_samples", OK),
 ("nova_vcpus", "vCPU 수", ["payload.nova_object.data.flavor.nova_object.data.vcpus"], None, False, "doc_nova_samples", OK),
 ("nova_port", "연결 포트 ID", ["payload.nova_object.data.ip_addresses[].nova_object.data.port_uuid"], "port", True, "doc_nova_samples", OK),
 ("nova_ip", "고정 IP", ["payload.nova_object.data.ip_addresses[].nova_object.data.address"], None, False, "doc_nova_samples", OK),
 ("nova_key_name", "키페어 이름", ["payload.nova_object.data.key_name"], "keypair", False, "doc_nova_samples", LOG),
 ("nt_sgr_id", "보안그룹 규칙 ID", ["payload.security_group_rule.id", "payload.security_group_rule_id"], "security_group_rule", False, "doc_neutron_notif", OK),
 ("nt_sgr_sg", "소속 보안그룹 ID", ["payload.security_group_rule.security_group_id"], "security_group", True, "doc_neutron_notif", OK),
 ("nt_sgr_remote_ip", "허용 대상 IP 대역", ["payload.security_group_rule.remote_ip_prefix"], None, False, "doc_neutron_notif", OK),
 ("nt_sgr_remote_group", "허용 대상 보안그룹", ["payload.security_group_rule.remote_group_id"], "security_group", False, "doc_neutron_notif", OK),
 ("nt_sgr_direction", "방향", ["payload.security_group_rule.direction"], None, False, "doc_neutron_notif", OK),
 ("nt_sgr_protocol", "프로토콜", ["payload.security_group_rule.protocol"], None, False, "doc_neutron_notif", OK),
 ("nt_sgr_port_min", "시작 포트", ["payload.security_group_rule.port_range_min"], None, False, "doc_neutron_notif", OK),
 ("nt_sgr_port_max", "끝 포트", ["payload.security_group_rule.port_range_max"], None, False, "doc_neutron_notif", OK),
 ("nt_sgr_project", "프로젝트 ID", ["payload.security_group_rule.project_id"], "project", True, "doc_neutron_notif", OK),
 ("nt_fip_id", "Floating IP ID", ["payload.floatingip.id", "payload.floatingip_id"], "floatingip", False, "doc_neutron_notif", OK),
 ("nt_fip_port", "Floating IP 연결 포트", ["payload.floatingip.port_id"], "port", True, "doc_neutron_notif", OK),
 ("nt_fip_addr", "Floating IP 주소", ["payload.floatingip.floating_ip_address"], None, False, "doc_neutron_notif", OK),
 ("nt_fip_project", "프로젝트 ID", ["payload.floatingip.project_id"], "project", True, "doc_neutron_notif", OK),
 ("nt_port_id", "포트 ID", ["payload.port.id", "payload.port_id"], "port", True, "doc_neutron_notif", OK),
 ("nt_port_device", "포트가 붙은 장치(인스턴스) ID", ["payload.port.device_id"], "instance", True, "doc_neutron_notif", OK),
 ("nt_port_owner", "장치 소유 유형", ["payload.port.device_owner"], None, False, "doc_neutron_notif", OK),
 ("nt_port_sgs", "포트 적용 보안그룹", ["payload.port.security_groups"], "security_group", False, "doc_neutron_notif", LOG),
 ("nt_port_project", "프로젝트 ID", ["payload.port.project_id"], "project", True, "doc_neutron_notif", OK),
 # Nova 키페어 (KeypairPayload, 공식 알림 예시)
 ("nova_kp_user", "키페어 소유 사용자", ["payload.nova_object.data.user_id"], "user", True, "doc_nova_keypair", OK),
 ("nova_kp_name", "키페어 이름", ["payload.nova_object.data.name"], "keypair", False, "doc_nova_keypair", OK),
 ("nova_kp_fp", "키 지문", ["payload.nova_object.data.fingerprint"], None, False, "doc_nova_keypair", OK),
 ("nova_kp_type", "키 유형", ["payload.nova_object.data.type"], None, False, "doc_nova_keypair", OK),
 # Glance 이미지 전송(image.send) · 공유(image.member.*) (공식 문서에 필드 명시)
 ("gl_image_id", "이미지 ID", ["payload.image_id"], "image", True, "doc_glance_notif", OK),
 ("gl_owner", "이미지 소유자(프로젝트 또는 사용자)", ["payload.owner_id"], "project", True, "doc_glance_notif", OK),
 ("gl_recv_tenant", "받는 쪽 프로젝트", ["payload.receiver_tenant_id"], "project", True, "doc_glance_notif", OK),
 ("gl_recv_user", "받는 쪽 사용자", ["payload.receiver_user_id"], "user", True, "doc_glance_notif", OK),
 ("gl_dest_ip", "받는 쪽 IP", ["payload.destination_ip"], None, True, "doc_glance_notif", OK),
 ("gl_bytes", "전송 바이트", ["payload.bytes_sent"], None, False, "doc_glance_notif", OK),
 ("gl_member_id", "공유받은 프로젝트", ["payload.member_id"], "project", True, "doc_glance_notif", OK),
 ("gl_member_status", "공유 상태", ["payload.status"], None, False, "doc_glance_notif", OK),
 # Keystone 연동 로그인 (공식 문서 예시: initiator.credential)
 ("ks_cred_type", "연동 인증 유형(SAML 등)", ["payload.initiator.credential.type"], None, False, "doc_keystone_notif", OK),
 ("ks_cred_idp", "ID 제공자", ["payload.initiator.credential.identity_provider"], None, True, "doc_keystone_notif", OK),
 ("ks_cred_groups", "연동 그룹", ["payload.initiator.credential.groups"], None, False, "doc_keystone_notif", OK),
 # legacy 알림 봉투의 요청 컨텍스트 (Neutron 요청자 식별용 후보. 실로그로 존재 여부 확인)
 ("ctx_user", "요청 사용자 ID(컨텍스트)", ["_context_user_id"], "user", True, "doc_team_scenario", LOG),
 ("ctx_project", "요청 프로젝트 ID(컨텍스트)", ["_context_project_id", "_context_tenant_id"], "project", True, "doc_team_scenario", LOG),
 ("ctx_request_id", "요청 ID(컨텍스트)", ["_context_request_id"], None, True, "doc_team_scenario", LOG),
]
FIELD_NOTES = {
 "ks_pw_hash": "Keystone 2025.1 이후 기능(report_invalid_password_hash). 이전 버전이면 필드가 없음 → 무차별 대입 규칙은 건수만으로 판단",
 "ks_initiator_username": "최신 문서 예시(2025)에 있음. 구버전 Keystone 에서는 없을 수 있음",
 "ks_request_id": "최신 문서 예시(2025)에 있음. 구버전 Keystone 에서는 없을 수 있음",
}
def fn(f): return f"kb:f_{f}"
for fid, label, paths, ref, corr, src, st in F:
    pairs = [("a", "cto:LogField"), ("rdfs:label", lit(label, "ko")), ("cto:fieldPath", objs(*[lit(p) for p in paths]))]
    if fid in FIELD_NOTES: pairs.append(("rdfs:comment", lit(FIELD_NOTES[fid], "ko")))
    if ref: pairs.append(("cto:refersTo", rn(ref)))
    if corr: pairs.append(("cto:isCorrelationKey", "true"))
    pairs += [("cto:derivedFrom", f"kb:{src}"), ("cto:verificationStatus", lit(st))]
    node(fn(fid), pairs)

# ---------------- 행위 분류 (팀설계) : id, label, actions, resources, outcome, risk, techniques
out.append("# ---------------- 행위 분류 (행위 × 자원, 팀설계. 점수는 초기값)\n")
BC = [
 ("auth_failure", "인증 실패", ["authenticate"], ["user"], "failure", 3, ["T1110"]),
 ("auth_success", "인증 성공", ["authenticate"], ["user"], "success", 1, ["T1078_004"]),
 ("privilege_grant", "권한 부여", ["create"], ["role_assignment"], None, 20, ["T1098_003"]),
 ("privilege_revoke", "권한 회수", ["delete"], ["role_assignment"], None, 10, ["T1531"]),
 ("account_create", "계정 생성", ["create"], ["user"], None, 15, ["T1136_003"]),
 ("account_modify", "계정 변경", ["update"], ["user"], None, 10, ["T1098"]),
 ("account_delete", "계정 삭제", ["delete"], ["user"], None, 10, ["T1531"]),
 ("delegation", "권한 위임 생성·삭제", ["create", "delete"], ["trust"], None, 15, []),
 ("identity_infra_change", "인증 인프라 설정 변경", ["create", "update", "delete"], ["policy", "endpoint", "service", "domain", "region", "role"], None, 25, []),
 ("tenant_change", "프로젝트·그룹 변경", ["create", "update", "delete"], ["project", "group"], None, 5, []),
 ("compute_create", "인스턴스 생성", ["create"], ["instance"], None, 3, ["T1578_002", "T1496_001"]),
 ("compute_delete", "인스턴스 삭제", ["delete"], ["instance"], None, 3, ["T1578_003"]),
 ("compute_state", "인스턴스 정지", ["stop"], ["instance"], None, 2, []),
 ("credential_add", "키페어 등록", ["create"], ["keypair"], None, 10, ["T1098_001"]),
 ("credential_remove", "키페어 삭제", ["delete"], ["keypair"], None, 2, []),
 ("snapshot_create", "스냅샷 생성", ["capture"], ["instance"], None, 10, ["T1578_001"]),
 ("compute_start", "인스턴스 시작·재개", ["start"], ["instance"], None, 1, []),
 ("compute_modify", "인스턴스 크기 변경", ["update"], ["instance"], None, 2, []),
 ("image_register", "이미지 등록·변경", ["create", "update"], ["image"], None, 5, ["T1525"]),
 ("image_delete", "이미지 삭제", ["delete"], ["image"], None, 5, []),
 ("image_transfer", "이미지 전송", ["send"], ["image"], None, 3, ["T1537"]),
 ("image_share", "이미지 공유", ["create"], ["image_member"], None, 20, ["T1537"]),
 ("image_share_change", "이미지 공유 변경·해제", ["update", "delete"], ["image_member"], None, 2, []),
 ("firewall_rule_add", "방화벽 규칙 추가", ["create"], ["security_group_rule"], None, 10, ["T1686_001"]),
 ("firewall_change", "방화벽 변경", ["update", "delete"], ["security_group_rule", "security_group"], None, 5, ["T1686_001"]),
 ("firewall_group_create", "보안그룹 생성", ["create"], ["security_group"], None, 3, []),
 ("external_exposure", "외부 노출(Floating IP 연결)", ["create", "update"], ["floatingip"], None, 10, []),
 ("network_change", "네트워크 구성 변경", ["create", "update", "delete"], ["network", "subnet", "port", "router"], None, 1, []),
 ("floatingip_release", "Floating IP 해제", ["delete"], ["floatingip"], None, 1, []),
 ("discovery", "자원 조회·탐색", ["read", "read/list"], ["instance", "security_group", "security_group_rule", "port", "network", "floatingip", "user", "project", "role_assignment"], None, 1, ["T1580", "T1526", "T1087_004"]),
]
def bn(b): return f"kb:bc_{b}"
for bid, label, acts, ress, oc, risk, techs in BC:
    pairs = [("a", "cto:BehaviorClass"), ("rdfs:label", lit(label, "ko")),
             ("cto:matchesAction", objs(*[an(a) for a in acts])),
             ("cto:matchesResourceType", objs(*[rn(r) for r in ress]))]
    if oc: pairs.append(("cto:matchesOutcome", lit(oc)))
    pairs.append(("cto:riskScore", str(risk)))
    if techs: pairs.append(("cto:suggestsTechnique", objs(*[f"kb:{t}" for t in techs])))
    pairs += [("cto:derivedFrom", "kb:doc_team_scenario"), ("cto:verificationStatus", lit(TEAM))]
    node(bn(bid), pairs)

# ---------------- 로그 이벤트 유형
out.append("# ---------------- 로그 이벤트 유형\n")
KS_F_BASE = ["ks_initiator_id", "ks_initiator_user_id", "ks_src_ip", "ks_agent", "ks_request_id", "ks_action", "ks_outcome", "ks_target_id", "ks_target_type"]
EV = []  # id, label, names, outcome, service, channel, action, resource, bc, fields, source, status, comment
EV.append(("ks_auth_failure", "Keystone 인증 실패", ["identity.authenticate"], "failure", "Keystone", "ch_keystone_cadf", "authenticate", "user", "auth_failure",
           KS_F_BASE + ["ks_initiator_username", "ks_reason_code", "ks_pw_hash", "ks_cred_type", "ks_cred_idp", "ks_cred_groups"], "doc_keystone_notif", OK,
           "기본 억제 이벤트. report_invalid_password_hash = event 설정 시 비밀번호 해시 첨부"))
EV.append(("ks_auth_success", "Keystone 인증 성공", ["identity.authenticate"], "success", "Keystone", "ch_keystone_cadf", "authenticate", "user", "auth_success",
           KS_F_BASE + ["ks_initiator_username", "ks_cred_type", "ks_cred_idp", "ks_cred_groups"], "doc_keystone_notif", OK, "단독으로는 정상. 실패 반복 직후·처음 보는 IP일 때 의미"))
EV.append(("ks_ra_created", "Keystone 역할 부여", ["identity.role_assignment.created"], None, "Keystone", "ch_keystone_cadf", "create", "role_assignment", "privilege_grant",
           KS_F_BASE + ["ks_ra_role", "ks_ra_project", "ks_ra_domain", "ks_ra_user", "ks_ra_group"], "doc_keystone_notif", OK, None))
EV.append(("ks_ra_deleted", "Keystone 역할 회수", ["identity.role_assignment.deleted"], None, "Keystone", "ch_keystone_cadf", "delete", "role_assignment", "privilege_revoke",
           KS_F_BASE + ["ks_ra_role", "ks_ra_project", "ks_ra_domain", "ks_ra_user", "ks_ra_group"], "doc_keystone_notif", LOG, "이름은 identity.<resource>.<operation> 규칙으로 추정. 실로그 확인 필요"))
# Keystone CRUD (문서 표: identity.<resource_type>.<operation>)
KS_CRUD = {"user": ("사용자", ["create", "update", "delete"]), "project": ("프로젝트", ["create", "update", "delete"]),
           "group": ("그룹", ["create", "update", "delete"]), "role": ("역할 정의", ["create", "update", "delete"]),
           "domain": ("도메인", ["create", "update", "delete"]), "trust": ("위임", ["create", "delete"]),
           "region": ("리전", ["create", "update", "delete"]), "endpoint": ("엔드포인트", ["create", "update", "delete"]),
           "service": ("서비스 카탈로그", ["create", "update", "delete"]), "policy": ("정책", ["create", "update", "delete"])}
OPWORD = {"create": ("created", "생성"), "update": ("updated", "변경"), "delete": ("deleted", "삭제")}
def bc_for(action, res):
    for bid, _, acts, ress, oc, _, _ in BC:
        if action in acts and res in ress and oc is None:
            return bid
    raise SystemExit(f"행위 분류 없음: {action} x {res}")
for res, (klabel, ops) in KS_CRUD.items():
    for op in ops:
        w, kop = OPWORD[op]
        EV.append((f"ks_{res}_{w}", f"Keystone {klabel} {kop}", [f"identity.{res}.{w}"], None, "Keystone", "ch_keystone_cadf", op, res, bc_for(op, res),
                   KS_F_BASE + ["ks_resource_info"], "doc_keystone_notif", OK, None))
# Nova versioned
NOVA_F = ["nova_uuid", "nova_user", "nova_tenant", "nova_host", "nova_image", "nova_flavor", "nova_vcpus", "nova_port", "nova_ip", "nova_key_name"]
EV.append(("nova_instance_create", "Nova 인스턴스 생성 완료", ["instance.create.end"], None, "Nova", "ch_nova_versioned", "create", "instance", "compute_create", NOVA_F, "doc_nova_samples", OK, None))
EV.append(("nova_instance_delete", "Nova 인스턴스 삭제 완료", ["instance.delete.end"], None, "Nova", "ch_nova_versioned", "delete", "instance", "compute_delete", NOVA_F[:4], "doc_nova_samples", OK, None))
EV.append(("nova_instance_shutdown", "Nova 인스턴스 종료 완료", ["instance.shutdown.end"], None, "Nova", "ch_nova_versioned", "stop", "instance", "compute_state", NOVA_F[:4], "doc_nova_samples", OK, None))
NOVA_KP_F = ["nova_kp_user", "nova_kp_name", "nova_kp_fp", "nova_kp_type"]
EV.append(("nova_keypair_create", "Nova 키페어 생성·등록", ["keypair.create.end", "keypair.import.end"], None, "Nova", "ch_nova_versioned", "create", "keypair", "credential_add", NOVA_KP_F, "doc_nova_keypair", OK, None))
EV.append(("nova_keypair_delete", "Nova 키페어 삭제", ["keypair.delete.end"], None, "Nova", "ch_nova_versioned", "delete", "keypair", "credential_remove", NOVA_KP_F, "doc_nova_keypair", OK, None))
EV.append(("nova_instance_snapshot", "Nova 인스턴스 스냅샷 완료", ["instance.snapshot.end"], None, "Nova", "ch_nova_versioned", "capture", "instance", "snapshot_create", NOVA_F[:4], "doc_nova_samples", OK, "스냅샷으로 만들어진 이미지 ID 필드는 실로그 확인 필요"))
EV.append(("nova_instance_stop", "Nova 인스턴스 전원 끔·일시정지·중단", ["instance.power_off.end", "instance.pause.end", "instance.suspend.end"], None, "Nova", "ch_nova_versioned", "stop", "instance", "compute_state", NOVA_F[:4], "doc_nova_samples", OK, None))
EV.append(("nova_instance_start", "Nova 인스턴스 전원 켬·재개", ["instance.power_on.end", "instance.unpause.end"], None, "Nova", "ch_nova_versioned", "start", "instance", "compute_start", NOVA_F[:4], "doc_nova_samples", OK, None))
EV.append(("nova_instance_resize", "Nova 인스턴스 크기 변경 완료", ["instance.resize.end"], None, "Nova", "ch_nova_versioned", "update", "instance", "compute_modify", NOVA_F[:4], "doc_nova_samples", OK, None))
# Glance (공식 문서의 이벤트 목록. 생성·변경 이벤트는 '이미지 메타데이터'라고만 되어 있어 필드는 실로그 확인 후 추가)
GL_NOTE = "payload 는 이미지 메타데이터라고만 문서에 있음. 이미지 ID·소유자·공개 여부 필드는 실로그 확인 후 추가"
EV.append(("gl_image_register", "Glance 이미지 생성·업로드·활성화", ["image.create", "image.upload", "image.activate"], None, "Glance", "ch_glance_notif", "create", "image", "image_register", [], "doc_glance_notif", OK, GL_NOTE))
EV.append(("gl_image_update", "Glance 이미지 변경", ["image.update"], None, "Glance", "ch_glance_notif", "update", "image", "image_register", [], "doc_glance_notif", OK, GL_NOTE))
EV.append(("gl_image_delete", "Glance 이미지 삭제", ["image.delete"], None, "Glance", "ch_glance_notif", "delete", "image", "image_delete", [], "doc_glance_notif", OK, "INFO 이벤트의 payload 는 이미지 ID (문서)"))
EV.append(("gl_image_send", "Glance 이미지 전송", ["image.send"], None, "Glance", "ch_glance_notif", "send", "image", "image_transfer",
           ["gl_image_id", "gl_owner", "gl_recv_tenant", "gl_recv_user", "gl_dest_ip", "gl_bytes"], "doc_glance_notif", OK, None))
EV.append(("gl_image_member_create", "Glance 이미지 공유 생성", ["image.member.create"], None, "Glance", "ch_glance_notif", "create", "image_member", "image_share",
           ["gl_image_id", "gl_member_id", "gl_member_status"], "doc_glance_notif", OK, "공유 이벤트에는 이미지 소유자 필드가 없음 (문서)"))
EV.append(("gl_image_member_change", "Glance 이미지 공유 변경·해제", ["image.member.update", "image.member.delete"], None, "Glance", "ch_glance_notif", "update", "image_member", "image_share_change",
           ["gl_image_id", "gl_member_id", "gl_member_status"], "doc_glance_notif", OK, None))
# Neutron CRUD (문서: <resource>.<op>.end)
CTX = ["ctx_user", "ctx_project", "ctx_request_id"]
NT_F = {"security_group_rule": CTX + ["nt_sgr_id", "nt_sgr_sg", "nt_sgr_remote_ip", "nt_sgr_remote_group", "nt_sgr_direction", "nt_sgr_protocol", "nt_sgr_port_min", "nt_sgr_port_max", "nt_sgr_project"],
        "floatingip": CTX + ["nt_fip_id", "nt_fip_port", "nt_fip_addr", "nt_fip_project"],
        "port": CTX + ["nt_port_id", "nt_port_device", "nt_port_owner", "nt_port_sgs", "nt_port_project"]}
NT_RES = {"security_group_rule": ("보안그룹 규칙", ["create", "delete"]), "security_group": ("보안그룹", ["create", "update", "delete"]),
          "floatingip": ("Floating IP", ["create", "update", "delete"]), "port": ("포트", ["create", "update", "delete"]),
          "router": ("라우터", ["create", "update", "delete"]), "network": ("네트워크", ["create", "update", "delete"]),
          "subnet": ("서브넷", ["create", "update", "delete"])}
NOP = {"create": "생성", "update": "변경", "delete": "삭제"}
for res, (rl, ops) in NT_RES.items():
    for op in ops:
        bid = "floatingip_release" if (res == "floatingip" and op == "delete") else ("firewall_group_create" if (res == "security_group" and op == "create") else bc_for(op, res))
        EV.append((f"nt_{res}_{op}", f"Neutron {rl} {NOP[op]}", [f"{res}.{op}.end"], None, "Neutron", "ch_neutron_notif", op, res, bid,
                   NT_F.get(res, CTX), "doc_neutron_notif", OK, None))
EV.append(("nt_router_interface", "Neutron 라우터 인터페이스 추가·삭제", ["router.interface.create", "router.interface.delete"], None, "Neutron", "ch_neutron_notif", "update", "router", "network_change", [], "doc_neutron_notif", OK, None))
# audit (범용 조회)
EV.append(("audit_read", "API 조회 요청 (audit)", ["audit.http.request"], None, None, "ch_audit", "read/list", None, "discovery", [], "doc_audit_mw", LOG,
           "audit 미들웨어가 기록하는 조회(GET) 요청. 이벤트 이름·필드는 실로그로 확인 필요. 대상 자원은 target.typeURI로 판별"))

def en(e): return f"kb:ev_{e}"
for eid, label, names, oc, svc, ch, act, res, bid, fields, src, st, cmt in EV:
    pairs = [("a", "cto:LogEventType"), ("rdfs:label", lit(label, "ko")), ("cto:eventTypeName", objs(*[lit(n) for n in names]))]
    if oc: pairs.append(("cto:outcome", lit(oc)))
    if svc: pairs.append(("cto:emittedBy", f"kb:{svc}"))
    pairs += [("cto:viaChannel", f"kb:{ch}"), ("cto:hasAction", an(act))]
    if res: pairs.append(("cto:onResourceType", rn(res)))
    pairs.append(("cto:classifiedAs", bn(bid)))
    if fields: pairs.append(("cto:hasField", objs(*[fn(f) for f in fields])))
    pairs += [("cto:derivedFrom", f"kb:{src}"), ("cto:verificationStatus", lit(st))]
    if cmt: pairs.append(("rdfs:comment", lit(cmt, "ko")))
    node(en(eid), pairs)

# ---------------- 공격 순서 (팀설계)
out.append("# ---------------- 공격 순서 precedes (팀설계. 데이터 기반 coOccursWith 는 자동 생성)\n")
PRE = {"T1110": ["T1078_004"], "T1110_001": ["T1078_004"], "T1110_003": ["T1078_004"],
       "T1578_001": ["T1537"], "T1525": ["T1204_003"],
       "T1078_004": ["T1580", "T1526", "T1087_004", "T1098_003", "T1136_003", "T1578_002", "T1098_001", "T1578_001"],
       "T1087_004": ["T1098_003"], "T1580": ["T1578_002", "T1686_001"], "T1526": ["T1578_002"],
       "T1098_003": ["T1578_002"], "T1136_003": ["T1578_002"], "T1578_002": ["T1686_001", "T1496_001", "T1578_003"],
       "T1686_001": ["T1496_001"]}
for a, bs in PRE.items():
    out.append(f"kb:{a} cto:precedes {objs(*[f'kb:{b}' for b in bs])} .\n")

# ---------------- 경보 등급
out.append("\n# ---------------- 경보 등급\n")
for t, l, c in [("immediate", "즉시", "고위험 단일 행위"), ("chain", "체인", "공격 체인 성립"), ("score", "점수", "행위자 누적 위험 점수 초과"), ("info", "정보", "기록·점수 누적만")]:
    node(f"kb:tier_{t}", [("a", "cto:AlertTier"), ("rdfs:label", lit(l, "ko")), ("rdfs:comment", lit(c, "ko"))])

# ---------------- 탐지 규칙 (팀설계)
out.append("# ---------------- 탐지 규칙 (팀설계. 임계값은 초기값, 정상·공격 로그 실측으로 조정)\n")
RULES = [
 # id, label, tier, events, behaviors, techniques, severity, threshold, window, condition(설명),
 #   ruleType, filters, groupBy, steps, minCount
 ("sg_open_world", "보안그룹 전체 개방", "immediate", ["nt_security_group_rule_create"], ["firewall_rule_add"], ["T1686_001"], "critical", None, None,
  "direction=ingress 이고 (remote_ip_prefix 가 0.0.0.0/0 또는 ::/0 이거나, remote_ip_prefix 와 remote_group_id 가 모두 비어 있음) 이며 포트 범위가 전체이거나 22·3389 를 포함",
  "filter", ["payload.security_group_rule.direction == ingress",
             "payload.security_group_rule.remote_ip_prefix in 0.0.0.0/0|::/0|__empty__",
             "payload.security_group_rule.remote_group_id empty",
             "payload.security_group_rule.port_range_min covers_port 22|3389|any"], None, [], None),
 ("admin_role_grant", "관리자 역할 부여", "immediate", ["ks_ra_created"], ["privilege_grant"], ["T1098_003"], "high", None, None,
  "payload.role 이 admin 역할 ID 이고 행위자가 허용 목록에 없음",
  "filter", ["payload.role in_allowlist admin_role_id", "@user not_in_allowlist service_account|automation_account"], None, [], None),
 ("identity_infra_change", "인증 인프라 설정 변경", "immediate", [], ["identity_infra_change"], [], "high", None, None,
  "정책·엔드포인트·서비스·도메인·리전·역할 정의 변경을 허용 목록 밖 행위자가 수행",
  "filter", ["@user not_in_allowlist service_account|automation_account"], None, [], None),
 ("bruteforce", "Keystone 무차별 대입", "immediate", ["ks_auth_failure"], ["auth_failure"], ["T1110"], "medium", 10, 300,
  "같은 출발지 IP 에서 300초 안에 인증 실패 10회 이상. partial_password_hash 가 계속 바뀌면 공격, 같으면 설정 오류로 분류",
  "threshold", [], "@ip", [], None),
 ("mass_create", "인스턴스 대량 생성", "score", ["nova_instance_create"], ["compute_create"], ["T1578_002", "T1496_001"], "medium", 10, 600,
  "허용 목록 밖 프로젝트에서 600초 안에 인스턴스 10개 이상 (임계값은 정상 운영 로그로 조정 필요). 단독 경보 대신 사건 맥락·점수로 사용",
  "threshold", ["@project not_in_allowlist protected_resource"], "@project", [], None),
 ("fail_then_success", "실패 반복 후 로그인 성공", "chain", ["ks_auth_failure", "ks_auth_success"], ["auth_failure", "auth_success"], ["T1078_004"], "high", None, 600,
  "무차별 대입 경보가 난 IP 에서 600초 안에 인증 성공",
  "sequence", [], "@ip", ["1:rule_bruteforce|rule_password_guessing|rule_password_spraying", "2:bc_auth_success"], None),
 ("takeover_then_privilege", "의심 로그인 후 권한 확대", "chain", [], ["auth_success", "privilege_grant", "account_create"], ["T1098_003", "T1136_003"], "critical", None, 3600,
  "의심 로그인(실패 반복 후 성공 또는 처음 보는 IP) 이후 3600초 안에 같은 사용자가 역할 부여 또는 계정 생성",
  "sequence", [], "@user", ["1:rule_fail_then_success|bc_auth_success@new_source", "2:bc_privilege_grant|bc_account_create"], None),
 ("privilege_then_compute", "권한 확대 후 자원 생성", "chain", [], ["privilege_grant", "compute_create"], ["T1578_002"], "high", 3, 3600,
  "역할 부여 이후 3600초 안에 같은 사용자가 인스턴스 3개 이상 생성",
  "sequence", [], "@user", ["1:bc_privilege_grant", "2:bc_compute_create"], 3),
 ("compute_then_exposure", "생성 자원의 외부 노출", "chain", [], ["compute_create", "firewall_rule_add", "external_exposure"], ["T1686_001"], "critical", None, 3600,
  "같은 프로젝트에서 인스턴스 생성 후 3600초 안에 보안그룹 개방(sg_open_world) 또는 Floating IP 연결",
  "sequence", [], "@project", ["1:bc_compute_create", "2:rule_sg_open_world|bc_external_exposure"], None),
 ("password_guessing", "비밀번호 추측", "immediate", ["ks_auth_failure"], ["auth_failure"], ["T1110_001"], "medium", 10, 300,
  "같은 계정에 300초 안에 인증 실패 10회 이상, 비밀번호 부분 해시가 3종류 이상(비밀번호를 바꿔 가며 시도). 해시 필드가 없는 버전이면 건수만으로 판단",
  "threshold", [], "@user", [], None),
 ("password_spraying", "비밀번호 스프레이", "immediate", ["ks_auth_failure"], ["auth_failure"], ["T1110_003"], "medium", 5, 300,
  "같은 출발지 IP 에서 300초 안에 서로 다른 계정 5개 이상 인증 실패",
  "threshold", [], "@ip", [], None),
 ("image_share_external", "이미지 외부 프로젝트 공유", "immediate", ["gl_image_member_create"], ["image_share"], ["T1537"], "high", None, None,
  "이미지가 다른 프로젝트에 공유됨. 공유 이벤트에는 소유자 필드가 없어 모든 공유를 외부 공유로 보고, 신뢰 프로젝트만 제외",
  "filter", ["payload.member_id not_in_allowlist trusted_project"], None, [], None),
 ("image_send_cross_project", "이미지 다른 프로젝트로 전송", "immediate", ["gl_image_send"], ["image_transfer"], ["T1537"], "medium", None, None,
  "받는 쪽 프로젝트가 이미지 소유자와 다르고 신뢰 이미지가 아님. 공개 이미지로 다른 프로젝트가 인스턴스를 만들 때도 발생하므로 신뢰 이미지 목록을 채워야 오탐이 줄어듦",
  "filter", ["payload.receiver_tenant_id ne_field payload.owner_id", "payload.image_id not_in_allowlist trusted_image"], None, [], None),
 ("keypair_after_takeover", "의심 로그인 후 키페어 등록", "chain", [], ["auth_success", "credential_add"], ["T1098_001"], "high", None, 3600,
  "의심 로그인(실패 반복 후 성공 또는 처음 보는 IP) 이후 3600초 안에 같은 사용자가 키페어 생성·등록",
  "sequence", [], "@user", ["1:rule_fail_then_success|bc_auth_success@new_source", "2:bc_credential_add"], None),
 ("risk_accumulation", "누적 위험 점수 초과", "score", [], [], [], "medium", 50, 3600,
  "행위자(사용자 또는 IP)별로 3600초 동안 행위 분류 riskScore 합이 50 이상",
  "score", ["@actor not_in_allowlist service_account|automation_account|admin_ip"], "@actor", [], None),
]
RULE_EXTRA = {"password_guessing": {"distinctField": "payload.attachments[name=partial_password_hash].content", "distinctMin": 3},
              "password_spraying": {"distinctField": "payload.initiator.id", "distinctMin": 5}}
for rid, label, tier, evs, bcs, techs, sev, th, win, cond, rtype, filters, gby, steps, minc in RULES:
    pairs = [("a", "cto:DetectionRule"), ("rdfs:label", lit(label, "ko")), ("cto:alertTier", f"kb:tier_{tier}"), ("cto:ruleType", lit(rtype))]
    for f in filters: pairs.append(("cto:filter", lit(f)))
    if gby: pairs.append(("cto:groupBy", lit(gby)))
    for st_ in steps: pairs.append(("cto:sequenceStep", lit(st_)))
    if minc: pairs.append(("cto:minCount", str(minc)))
    for k, v in RULE_EXTRA.get(rid, {}).items():
        pairs.append((f"cto:{k}", lit(v) if isinstance(v, str) else str(v)))
    if evs: pairs.append(("cto:usesEvent", objs(*[en(e) for e in evs])))
    if bcs: pairs.append(("cto:usesBehavior", objs(*[bn(b) for b in bcs])))
    if techs: pairs.append(("cto:detects", objs(*[f"kb:{t}" for t in techs])))
    pairs += [("cto:condition", lit(cond, "ko")), ("cto:severity", lit(sev))]
    if th: pairs.append(("cto:threshold", str(th)))
    if win: pairs.append(("cto:windowSeconds", str(win)))
    pairs += [("cto:derivedFrom", "kb:doc_team_scenario"), ("cto:verificationStatus", lit(TEAM))]
    node(f"kb:rule_{rid}", pairs)

# ---------------- 명령 인자
out.append("# ---------------- 명령 인자 (자리표시자 ← 로그 필드. LLM이 값을 만들지 않음)\n")
PARAMS = {"user": ["ks_initiator_id", "ks_ra_user", "nova_user", "nova_kp_user"], "created_user": ["ks_resource_info"],
          "image": ["gl_image_id"], "member-project": ["gl_member_id", "gl_recv_tenant"], "keypair": ["nova_kp_name"],
          "project": ["ks_ra_project", "nova_tenant", "nt_sgr_project", "nt_fip_project", "nt_port_project"],
          "role": ["ks_ra_role"], "server": ["nova_uuid", "nt_port_device"], "rule": ["nt_sgr_id"],
          "security-group": ["nt_sgr_sg"], "floating-ip": ["nt_fip_id"], "port": ["nt_fip_port", "nt_port_id", "nova_port"]}
for p, fs in PARAMS.items():
    node(f"kb:param_{p.replace('-', '_')}", [("a", "cto:CommandParameter"), ("cto:placeholder", lit(f"<{p}>")), ("cto:valueFrom", objs(*[fn(f) for f in fs]))])

# ---------------- 자동 조사 (읽기 전용)
out.append("# ---------------- 자동 조사 항목 (읽기 전용, 에이전트 자동 실행)\n")
INV = [
 ("user_show", "계정 정보 조회", "openstack user show <user>", ["user"], "계정 상태·도메인·활성 여부 확인", CMD),
 ("role_list", "계정의 역할 목록", "openstack role assignment list --user <user> --names", ["user"], "보유 권한·최근 추가 역할 확인", OK),
 ("server_by_user", "계정이 만든 인스턴스", "openstack server list --all-projects --user <user>", ["user"], "탈취 계정으로 생성된 인스턴스 파악", OK),
 ("server_by_project", "프로젝트 인스턴스", "openstack server list --all-projects --project <project>", ["project"], "대량 생성 여부 확인", OK),
 ("server_show", "인스턴스 상세", "openstack server show <server>", ["server"], "사양·이미지·보안그룹·네트워크 확인", CMD),
 ("sg_rule_list", "보안그룹 규칙 목록", "openstack security group rule list <security-group>", ["security-group"], "전체 개방 규칙·개방 포트 확인", CMD),
 ("fip_list", "프로젝트 Floating IP", "openstack floating ip list --project <project>", ["project"], "외부 노출 인스턴스 확인", OK),
 ("image_show", "이미지 상세", "openstack image show <image>", ["image"], "소유자·공개 여부·생성 시각 확인", OK),
 ("image_member_list", "이미지 공유 대상 목록", "openstack image member list <image>", ["image"], "어느 프로젝트에 공유됐는지 확인", OK),
 ("keypair_list_user", "사용자의 키페어 목록", "openstack keypair list --user <user>", ["user"], "공격자가 등록한 키페어 확인", OK),
 ("server_by_image", "이미지로 만든 인스턴스", "openstack server list --all-projects --image <image>", ["image"], "해당 이미지로 실행된 인스턴스 파악", OK),
]
VERIFIED_BY_HELP = {"user_show", "server_show", "sg_rule_list", "disable_user", "disable_created_user", "stop_server", "delete_sg_rule",
                    "image_show", "image_member_list", "keypair_list_user", "server_by_image", "image_unshare", "image_deactivate", "keypair_delete"}
def cmd_src(i): return objs("kb:doc_osc", "kb:doc_osc_help") if i in VERIFIED_BY_HELP else "kb:doc_osc"
for iid, label, cmd, ps, purpose, st in INV:
    if iid in VERIFIED_BY_HELP: st = OK
    node(f"kb:inv_{iid}", [("a", "cto:InvestigationQuery"), ("rdfs:label", lit(label, "ko")), ("cto:command", lit(cmd)),
                           ("cto:hasParameter", objs(*[f"kb:param_{p.replace('-', '_')}" for p in ps])), ("cto:purpose", lit(purpose, "ko")),
                           ("cto:derivedFrom", cmd_src(iid)), ("cto:verificationStatus", lit(st))])
INV_LINK = {"auth_failure": ["user_show", "role_list"], "auth_success": ["user_show", "role_list", "server_by_user"],
            "privilege_grant": ["role_list", "user_show"], "account_create": ["user_show", "role_list"],
            "account_modify": ["user_show", "role_list"], "compute_create": ["server_show", "server_by_project"],
            "firewall_rule_add": ["sg_rule_list"], "firewall_change": ["sg_rule_list"], "external_exposure": ["fip_list"],
            "identity_infra_change": ["user_show", "role_list"], "discovery": ["user_show", "role_list"],
            "credential_add": ["keypair_list_user", "user_show"], "snapshot_create": ["server_show"],
            "image_register": ["image_show"], "image_transfer": ["image_show", "server_by_image"], "image_share": ["image_show", "image_member_list"]}
for b, invs in INV_LINK.items():
    out.append(f"{bn(b)} cto:investigateWith {objs(*[f'kb:inv_{i}' for i in invs])} .\n")

# ---------------- 대응 권고 (승인 후 실행)
out.append("\n# ---------------- 대응 권고 (관리자 승인 후 실행)\n")
out.append("# 참고: 토큰 폐기(openstack token revoke <token>)는 로그에 토큰 값이 없어 인자를 채울 수 없으므로 제외\n")
RESP = [
 ("disable_user", "사용자 비활성화", "openstack user set --disable <user>", "openstack user set --enable <user>", ["user"], "AccountLocking", CMD),
 ("disable_created_user", "새로 생성된 계정 비활성화", "openstack user set --disable <created_user>", "openstack user set --enable <created_user>", ["created_user"], "AccountLocking", CMD),
 ("remove_role", "부여된 역할 회수", "openstack role remove --user <user> --project <project> <role>", "openstack role add --user <user> --project <project> <role>", ["user", "project", "role"], "UserAccountPermissions", OK),
 ("stop_server", "의심 인스턴스 정지", "openstack server stop <server>", "openstack server start <server>", ["server"], None, CMD),
 ("delete_sg_rule", "개방된 보안그룹 규칙 삭제", "openstack security group rule delete <rule>", None, ["rule"], "InboundTrafficFiltering", CMD),
 ("unset_fip", "Floating IP 연결 해제", "openstack floating ip unset --port <floating-ip>", "openstack floating ip set --port <port> <floating-ip>", ["floating-ip", "port"], "InboundTrafficFiltering", OK),
 ("image_unshare", "이미지 공유 취소", "openstack image remove project <image> <member-project>", None, ["image", "member-project"], None, OK),
 ("image_deactivate", "의심 이미지 비활성화", "openstack image set --deactivate <image>", "openstack image set --activate <image>", ["image"], None, OK),
 ("keypair_delete", "공격자 키페어 삭제", "openstack keypair delete --user <user> <keypair>", None, ["user", "keypair"], None, OK),
]
RESP_NOTE = {"image_unshare": "되돌리기 명령(공유 다시 추가)은 아직 공식 확인 안 함",
             "keypair_delete": "되돌리기 없음. 로그의 공개키로 재등록할 수 있는지는 확인 안 함"}
for rid, label, cmd, rb, ps, d3, st in RESP:
    if rid in VERIFIED_BY_HELP: st = OK
    pairs = [("a", "cto:ResponseAction"), ("rdfs:label", lit(label, "ko")), ("cto:command", lit(cmd)), ("cto:requiresApproval", "true")]
    pairs.append(("cto:rollbackCommand", lit(rb)) if rb else ("rdfs:comment", lit(RESP_NOTE.get(rid, "되돌리기 명령 없음. 실행 전 규칙 내용을 조사 결과로 보관해 재생성 가능하게 할 것"), "ko")))
    pairs.append(("cto:hasParameter", objs(*[f"kb:param_{p.replace('-', '_')}" for p in ps])))
    if d3: pairs.append(("cto:implements", f"d3f:{d3}"))
    pairs += [("cto:derivedFrom", cmd_src(rid)), ("cto:verificationStatus", lit(st))]
    node(f"kb:resp_{rid}", pairs)
RESP_LINK = {"T1110": ["disable_user"], "T1078_004": ["disable_user"], "T1098_003": ["remove_role"], "T1136_003": ["disable_created_user"],
             "T1578_002": ["stop_server"], "T1496_001": ["stop_server"], "T1686_001": ["delete_sg_rule", "unset_fip"],
             "T1537": ["image_unshare", "image_deactivate"], "T1525": ["image_deactivate"],
             "T1110_001": ["disable_user"]}
for t, rs in RESP_LINK.items():
    out.append(f"kb:{t} cto:recommendedResponse {objs(*[f'kb:resp_{r}' for r in rs])} .\n")

# ---------------- 허용 목록 (값은 배포 환경에서 채움)
out.append("\n# ---------------- 허용 목록 (예시. 실제 값은 클러스터에서 확인해 채움)\n")
AL = [("svc_nova", "service_account", "nova"), ("svc_neutron", "service_account", "neutron"), ("svc_placement", "service_account", "placement"),
      ("admin_ip", "admin_ip", "<관리자 IP>"), ("admin_role", "admin_role_id", "<admin 역할 ID>"),
      ("trusted_image", "trusted_image", "<신뢰 이미지 ID>"), ("trusted_project", "trusted_project", "<신뢰 프로젝트 ID>")]
for aid, kind, val in AL:
    node(f"kb:allow_{aid}", [("a", "cto:AllowlistEntry"), ("cto:entryKind", lit(kind)), ("cto:entryValue", lit(val)),
                             ("cto:verificationStatus", lit(LOG)), ("rdfs:comment", lit("클러스터의 실제 서비스 계정·관리자 IP·admin 역할 ID 로 교체 (allowlist.json 으로도 지정 가능)", "ko"))])

from appcredential_ontology import mapping_ttl
out.append(mapping_ttl())
from pathlib import Path
out.append(Path(__file__).with_name("cinder_mapping.ttl").read_text(encoding="utf-8"))

open("openstack_mapping.ttl", "w", encoding="utf-8").write("\n".join(out))
print("events", len(EV), "fields", len(F), "behaviors", len(BC), "rules", len(RULES))
