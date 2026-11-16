#!/usr/bin/env bash
# 보안 문서 일괄 다운로드 v0.4 (3K1H 캡스톤, 범위: Keystone·Nova·Neutron)
# 사용법: bash download_docs.sh   → docs/ 폴더 생성, docs/sources.csv 에 출처 기록
# 필요: git, curl
set -u
BASE="docs"; TODAY=$(date +%F)
mkdir -p $BASE/{attack,defense,openstack,logs/{keystone,nova,neutron,common},tools}
echo "name,url,collected,format,purpose" > $BASE/sources.csv
ok()   { echo "[완료] $1"; echo "$1,$2,$TODAY,$3,$4" >> $BASE/sources.csv; }
fail() { echo "[실패] $1 → $2 (브라우저로 열어 확인 후 같은 위치에 수동 저장)"; }
get()   { if curl -fsSL "$2" -o "$3"; then ok "$1" "$2" "$4" "$5"; else fail "$1" "$2"; fi; }
clone() { if git clone --depth 1 -q "$2" "$3"; then ok "$1" "$2" "$4" "$5"; else fail "$1" "$2"; fi; }

# ---------- 공격 지식 (필수) ----------
get "attack-enterprise" "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json" \
    "$BASE/attack/enterprise-attack.json" "JSON(STIX 2.1)" "기법·전술·완화책·탐지전략·그룹별 기법 사용"

# ---------- 방어 지식 (참고용, D3FEND 1.6.0 고정) ----------
# 완화책→D3FEND 매핑은 작업 폴더의 d3fend_mitigation_map.csv 를 사용 (D3FEND 공식 매핑표를 옮긴 것)
get "d3fend-ontology" "https://d3fend.mitre.org/ontologies/d3fend/1.6.0/d3fend.ttl" \
    "$BASE/defense/d3fend.ttl" "TTL" "D3FEND 전체 온톨로지(Protégé 참고)"
get "d3fend-techniques" "https://d3fend.mitre.org/ontologies/d3fend/1.6.0/d3fend.csv" \
    "$BASE/defense/d3fend.csv" "CSV" "D3FEND 기법 목록·정의"

# ---------- OpenStack 로그 형식 (필수) ----------
get "keystone-notifications" "https://docs.openstack.org/keystone/latest/admin/event_notifications.html" \
    "$BASE/logs/keystone/event_notifications.html" "HTML" "Keystone CADF 이벤트 이름·필드"
get "nova-notifications" "https://docs.openstack.org/nova/latest/reference/notifications.html" \
    "$BASE/logs/nova/notifications.html" "HTML" "Nova versioned 알림 목록·예시"
get "neutron-notifications" "https://docs.openstack.org/neutron/latest/reference/notifications.html" \
    "$BASE/logs/neutron/notifications.html" "HTML" "Neutron 알림 이름 규칙·payload"
get "keystonemiddleware-audit" "https://docs.openstack.org/keystonemiddleware/latest/audit.html" \
    "$BASE/logs/common/audit.html" "HTML" "모든 API 요청 CADF 감사 로그 설정"
clone "pycadf" "https://opendev.org/openstack/pycadf" \
    "$BASE/tools/pycadf" "Python/conf" "CADF 행위 분류(cadftaxonomy.py), nova/neutron api_audit_map.conf"

# ---------- 조사·대응 명령 (필수) ----------
get "osc-floating-ip" "https://docs.openstack.org/python-openstackclient/latest/command-objects/floating-ip.html" \
    "$BASE/logs/common/osc-floating-ip.html" "HTML" "Floating IP 조회·해제 명령"
get "osc-role-assignment" "https://docs.openstack.org/python-openstackclient/latest/command-objects/role-assignment.html" \
    "$BASE/logs/common/osc-role-assignment.html" "HTML" "역할 할당 조회 명령"

# ---------- OpenStack 취약점 맥락 (보조) ----------
clone "ossa" "https://opendev.org/openstack/ossa" "$BASE/openstack/ossa" "YAML" "OpenStack 보안 권고"
clone "security-doc" "https://opendev.org/openstack/security-doc" "$BASE/openstack/security-doc" "YAML/RST" "OSSN(형식 미확인)"

echo; echo "끝. 출처 기록: $BASE/sources.csv"
echo "다음: python build_ontology.py"
