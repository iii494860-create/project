#!/usr/bin/env python3
"""
보안 문서 → 온톨로지(TTL) 변환 스크립트 v0.3 (3K1H 캡스톤)
범위: OpenStack Keystone · Nova · Neutron

사용법:
    pip install pyyaml
    python build_ontology.py                      # 기본: docs/ 읽고 out/ 에 생성
    python build_ontology.py --min-cooccur 3      # 기법 동시 사용 기준 조정

입력 (download_docs.sh 로 받은 docs/ 폴더 + 작업 폴더 파일):
    docs/attack/enterprise-attack.json    → 기법·전술·완화책·탐지 전략·기법 동시 사용
    d3fend_mitigation_map.csv             → ATT&CK 완화책 → D3FEND 방어 기법 (D3FEND 공식 매핑표)
    docs/openstack/ossa/                  → OSSA (Keystone·Nova·Neutron 관련만)
    docs/openstack/security-doc/          → OSSN (형식 미확인, 방어적으로 처리)
    schema.ttl, openstack_mapping.ttl     → 스키마와 팀 매핑 (합치기 대상)

출력 (out/):
    kb_attack.ttl, kb_d3fend.ttl, kb_openstack_vuln.ttl
    ontology_all.ttl   ← 최종 온톨로지 (스키마 + 매핑 + 자동 생성 전부)
    build_report.txt   ← 데이터 버전, 개수, 검증 결과
"""
import argparse, csv, glob, itertools, json, os, re, sys
from collections import Counter

import yaml

PREFIXES = """@prefix cto:  <https://3k1h.example.org/cto#> .
@prefix kb:   <https://3k1h.example.org/kb#> .
@prefix d3f:  <http://d3fend.mitre.org/ontologies/d3fend.owl#> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
@prefix xsd:  <http://www.w3.org/2001/XMLSchema#> .

"""
SERVICES = {"Keystone": ["keystone", "keystonemiddleware"], "Nova": ["nova"], "Neutron": ["neutron"]}
REPORT = []
ATTACK_STATUS = {"revoked": {}, "deprecated": set()}


def log(msg):
    print(msg)
    REPORT.append(msg)


def lit(text, lang=None):
    s = str(text).replace("\\", "\\\\").replace('"', '\\"')
    s = s.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    return f'"{s}"@{lang}' if lang else f'"{s}"'


def local(ext_id):
    """T1078.004 → T1078_004 (openstack_mapping.ttl 과 같은 규칙)"""
    return re.sub(r"[^A-Za-z0-9_]", "_", ext_id)


class TTL:
    def __init__(self):
        self.subjects = {}

    def add(self, s, p, o):
        lst = self.subjects.setdefault(s, [])
        if (p, o) not in lst:
            lst.append((p, o))

    def write(self, path, header):
        with open(path, "w", encoding="utf-8") as f:
            f.write(PREFIXES + header + "\n")
            for s, pos in self.subjects.items():
                f.write(f"{s} " + " ;\n    ".join(f"{p} {o}" for p, o in pos) + " .\n\n")


def add_doc(ttl, node, label, url):
    ttl.add(node, "a", "cto:SourceDocument")
    ttl.add(node, "rdfs:label", lit(label))
    ttl.add(node, "cto:url", f"{lit(url)}^^xsd:anyURI")


def clean(text):
    text = re.sub(r"\(Citation:[^)]*\)", "", text or "")
    text = re.sub(r"\[([^\]]+)\]\(https://attack\.mitre\.org[^)]*\)", r"\1", text)
    return re.sub(r"\s+", " ", text).strip()


def ext_id_of(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return None


# ---------------------------------------------------------------- 1. ATT&CK
def build_attack(path, platforms, min_cooccur):
    with open(path, encoding="utf-8") as f:
        objs = json.load(f)["objects"]
    alive = [o for o in objs if not o.get("revoked") and not o.get("x_mitre_deprecated")]
    by_id = {o["id"]: o for o in alive}
    ttl = TTL()
    add_doc(ttl, "kb:doc_attack", "MITRE ATT&CK Enterprise", "https://attack.mitre.org")
    status = lit("공식문서확인")
    version = next((o.get("x_mitre_version") for o in objs if o["type"] == "x-mitre-collection"), "?")

    order = {}
    for o in alive:
        if o["type"] == "x-mitre-matrix":
            for i, ref in enumerate(o.get("tactic_refs", []), 1):
                order[ref] = i
    tactic_by_short = {}
    for o in alive:
        if o["type"] == "x-mitre-tactic":
            node = f"kb:{local(ext_id_of(o))}"
            tactic_by_short[o.get("x_mitre_shortname")] = node
            ttl.add(node, "a", "cto:Tactic")
            ttl.add(node, "rdfs:label", lit(o["name"], "en"))
            ttl.add(node, "cto:externalId", lit(ext_id_of(o)))
            if o["id"] in order:
                ttl.add(node, "cto:tacticOrder", str(order[o["id"]]))

    techs = {}
    for o in alive:
        if o["type"] != "attack-pattern" or not set(o.get("x_mitre_platforms", [])) & platforms:
            continue
        tid = ext_id_of(o)
        if not tid:
            continue
        node = f"kb:{local(tid)}"
        techs[o["id"]] = node
        ttl.add(node, "a", "cto:Technique")
        ttl.add(node, "rdfs:label", lit(o["name"], "en"))
        ttl.add(node, "cto:externalId", lit(tid))
        desc = clean(o.get("description"))
        if desc:
            ttl.add(node, "rdfs:comment", lit(desc, "en"))
        for ph in o.get("kill_chain_phases", []):
            if ph.get("kill_chain_name") == "mitre-attack" and ph["phase_name"] in tactic_by_short:
                ttl.add(node, "cto:belongsToTactic", tactic_by_short[ph["phase_name"]])
        ttl.add(node, "cto:derivedFrom", "kb:doc_attack")
        ttl.add(node, "cto:verificationStatus", status)

    n_mit = 0
    users = {}  # 그룹·캠페인 → 사용 기법 집합
    det_targets = {}
    for r in alive:
        if r["type"] != "relationship":
            continue
        src, tgt, rt = r.get("source_ref", ""), r.get("target_ref", ""), r["relationship_type"]
        if rt == "subtechnique-of" and src in techs and tgt in techs:
            ttl.add(techs[src], "cto:subTechniqueOf", techs[tgt])
        elif rt == "mitigates" and tgt in techs and src in by_id:
            m = by_id[src]
            mid = ext_id_of(m)
            if not mid or not mid.startswith("M"):
                continue
            mnode = f"kb:{local(mid)}"
            ttl.add(mnode, "a", "cto:Mitigation")
            ttl.add(mnode, "rdfs:label", lit(m["name"], "en"))
            ttl.add(mnode, "cto:externalId", lit(mid))
            mdesc = clean(m.get("description"))
            if mdesc:
                ttl.add(mnode, "rdfs:comment", lit(mdesc, "en"))
            ttl.add(mnode, "cto:derivedFrom", "kb:doc_attack")
            ttl.add(techs[tgt], "cto:mitigatedBy", mnode)
            n_mit += 1
        elif rt == "uses" and tgt in techs and (src.startswith("intrusion-set--") or src.startswith("campaign--")):
            users.setdefault(src, set()).add(techs[tgt])
        elif rt == "detects" and tgt in techs and src.startswith("x-mitre-detection-strategy--"):
            det_targets.setdefault(src, []).append(techs[tgt])

    # 탐지 전략·분석 로직 (ATT&CK v18+)
    n_det = n_an = 0
    for sid, targets in det_targets.items():
        d = by_id.get(sid)
        if not d:
            continue
        did = ext_id_of(d) or sid.split("--")[1][:8]
        dnode = f"kb:{local(did)}"
        ttl.add(dnode, "a", "cto:DetectionStrategy")
        ttl.add(dnode, "rdfs:label", lit(d.get("name", did), "en"))
        ttl.add(dnode, "cto:externalId", lit(did))
        ttl.add(dnode, "cto:derivedFrom", "kb:doc_attack")
        for t in targets:
            ttl.add(dnode, "cto:detects", t)
        n_det += 1
        for aref in d.get("x_mitre_analytic_refs", []):
            a = by_id.get(aref)
            if not a:
                continue
            aplat = set(a.get("x_mitre_platforms", []))
            if aplat and not (aplat & platforms):
                continue
            aid = ext_id_of(a) or aref.split("--")[1][:8]
            anode = f"kb:{local(aid)}"
            ttl.add(anode, "a", "cto:Analytic")
            ttl.add(anode, "cto:externalId", lit(aid))
            ttl.add(anode, "rdfs:label", lit(a.get("name", aid), "en"))
            desc = clean(a.get("description"))
            logs = [f"{x.get('name', '')}:{x.get('channel', '')}" for x in a.get("x_mitre_log_source_references", []) or []]
            if logs:
                desc += " [log sources: " + "; ".join(logs) + "]"
            if aplat:
                desc += " [platforms: " + ", ".join(sorted(aplat)) + "]"
            if desc:
                ttl.add(anode, "rdfs:comment", lit(desc, "en"))
            ttl.add(dnode, "cto:hasAnalytic", anode)
            n_an += 1

    # 기법 동시 사용 (공격 그룹·캠페인 기준)
    pair = Counter()
    for used in users.values():
        for a, b in itertools.combinations(sorted(used), 2):
            pair[(a, b)] += 1
    n_co = 0
    for (a, b), c in pair.items():
        if c < min_cooccur:
            continue
        cn = f"kb:co_{a[3:]}__{b[3:]}"
        ttl.add(cn, "a", "cto:CoOccurrence")
        ttl.add(cn, "cto:techniqueA", a)
        ttl.add(cn, "cto:techniqueB", b)
        ttl.add(cn, "cto:coOccurrenceCount", str(c))
        ttl.add(cn, "cto:derivedFrom", "kb:doc_attack")
        ttl.add(a, "cto:coOccursWith", b)
        ttl.add(b, "cto:coOccursWith", a)
        n_co += 1

    # 폐기(revoked)된 기법 → 대체 기법 (매핑 검증 시 안내용)
    all_ext = {o["id"]: ext_id_of(o) for o in objs if o.get("type") == "attack-pattern"}
    revoked = {}
    for r in objs:
        if r.get("type") == "relationship" and r.get("relationship_type") == "revoked-by" and r.get("source_ref") in all_ext:
            old_id, new_id = all_ext.get(r["source_ref"]), all_ext.get(r.get("target_ref"))
            if old_id and new_id:
                revoked.setdefault(local(old_id), []).append(new_id)
    deprecated = {local(all_ext[o["id"]]) for o in objs if o.get("type") == "attack-pattern" and o.get("x_mitre_deprecated") and all_ext.get(o["id"])}
    ATTACK_STATUS["revoked"], ATTACK_STATUS["deprecated"] = revoked, deprecated

    log(f"[ATT&CK v{version}] 기법 {len(techs)}, 전술 {len(tactic_by_short)}, 완화 관계 {n_mit}, "
        f"탐지 전략 {n_det}, 분석 로직 {n_an}, 동시사용 쌍 {n_co} (기준 {min_cooccur}회 이상, 그룹·캠페인 {len(users)}개)")
    return ttl, {n[3:] for n in techs.values()}, version


# ---------------------------------------------------------------- 2. D3FEND
def build_d3fend(csv_path):
    ttl = TTL()
    add_doc(ttl, "kb:doc_d3fend_map", "D3FEND: ATT&CK Mitigations to D3FEND Technique Mappings",
            "https://d3fend.mitre.org/mappings/attack-mitigations")
    classes, n = set(), 0
    with open(csv_path, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            d = f"d3f:{row['d3fend_class']}"
            classes.add(row["d3fend_class"])
            ttl.add(d, "a", "cto:DefensiveTechnique")
            ttl.add(d, "rdfs:label", lit(row["d3fend_label"], "en"))
            ttl.add(d, "cto:externalId", lit(row["d3fend_id"]))
            ttl.add(d, "rdfs:comment", lit(row["definition"], "en"))
            ttl.add(d, "cto:derivedFrom", "kb:doc_d3fend_map")
            ttl.add(d, "cto:verificationStatus", lit("공식문서확인"))
            ttl.add(f"kb:{row['mitigation_id']}", "cto:mappedToD3FEND", d)
            n += 1
    log(f"[D3FEND] 매핑 {n}, 방어 기법 {len(classes)}")
    return ttl, classes


# ---------------------------------------------------------------- 3. OSSA / OSSN
def detect_services(text):
    t = text.lower()
    return [n for n, kws in SERVICES.items() if any(re.search(rf"\b{k}\b", t) for k in kws)]


def load_any(path):
    raw = open(path, encoding="utf-8", errors="ignore").read()
    if path.endswith((".yaml", ".yml")):
        try:
            doc = yaml.safe_load(raw)
            if isinstance(doc, dict):
                return doc, raw
        except Exception:
            pass
    return {}, raw


def unique_files(pattern, keep=None):
    """재귀 검색 결과에서 같은 실제 파일은 한 번만 (링크 폴더를 따라가 같은 파일을 두 번 찾는 문제 방지).
    OSSA 저장소에는 doc/source/ossa -> ../../ossa 링크 폴더가 있어 같은 파일이 두 경로로 발견됨 (2026-09-28 확인)"""
    found = [f for f in sorted(glob.glob(pattern, recursive=True))
             if os.path.isfile(f) and (keep is None or keep(f))]   # 폴더와 대상이 아닌 파일은 세지 않음
    seen, files = set(), []
    for f in found:
        rp = os.path.realpath(f)
        if rp not in seen:
            seen.add(rp)
            files.append(f)
    return files, len(found) - len(files)


def build_vulns(ossa_dir, secdoc_dir):
    ttl = TTL()
    add_doc(ttl, "kb:doc_ossa", "OpenStack Security Advisories", "https://security.openstack.org/ossalist.html")
    add_doc(ttl, "kb:doc_ossn", "OpenStack Security Notes", "https://opendev.org/openstack/security-doc")
    cnt = Counter()

    def add(kind, ext, title, desc, scope_text, doc_node, status):
        svcs = detect_services(scope_text)
        if not svcs:
            return
        node = f"kb:{local(ext)}"
        ttl.add(node, "a", "cto:Vulnerability")
        ttl.add(node, "cto:externalId", lit(ext))
        ttl.add(node, "rdfs:label", lit(title or ext, "en"))
        if desc:
            ttl.add(node, "rdfs:comment", lit(re.sub(r"\s+", " ", desc)[:2000], "en"))
        for s in svcs:
            ttl.add(node, "cto:affects", f"kb:{s}")
        ttl.add(node, "cto:derivedFrom", doc_node)
        ttl.add(node, "cto:verificationStatus", lit(status))
        cnt[kind] += 1

    ossa_files, ossa_dup = unique_files(os.path.join(ossa_dir, "**", "OSSA-*.yaml"))
    ossa_seen = set()
    for path in ossa_files:
        oid = os.path.splitext(os.path.basename(path))[0]
        if oid in ossa_seen:
            ossa_dup += 1
            continue
        ossa_seen.add(oid)
        doc, raw = load_any(path)
        prods = " ".join(str(p.get("product", "")) for p in doc.get("affected-products", []) or [] if isinstance(p, dict))
        cves = [str(v.get("cve-id")) for v in doc.get("vulnerabilities", []) or [] if isinstance(v, dict) and v.get("cve-id")]
        desc = str(doc.get("description", "")) + (" (CVE: " + ", ".join(cves) + ")" if cves else "")
        # 영향 제품 필드로만 판별 (본문 언급만으로 포함하지 않음)
        add("OSSA", os.path.splitext(os.path.basename(path))[0], str(doc.get("title", "")), desc, prods, "kb:doc_ossa", "공식문서확인")

    seen = set()
    is_ossn = lambda f: re.search(r"OSSN-(\d{4})", os.path.basename(f), re.I) is not None
    secdoc_files, secdoc_dup = unique_files(os.path.join(secdoc_dir, "**", "*"), keep=is_ossn)
    for path in secdoc_files:
        m = re.search(r"OSSN-(\d{4})", os.path.basename(path), re.I)
        if not m or os.path.isdir(path) or f"OSSN-{m.group(1)}" in seen:
            continue
        oid = f"OSSN-{m.group(1)}"
        seen.add(oid)
        doc, raw = load_any(path)
        title = str(doc.get("title") or next((l.strip() for l in raw.splitlines()
                                              if l.strip() and not re.fullmatch(r"[=\-~#*^`'\"]+", l.strip())), ""))
        add("OSSN", oid, title, str(doc.get("summary") or doc.get("description") or ""), title + " " + raw[:3000],
            "kb:doc_ossn", "실로그확인필요")
    log(f"[OpenStack 취약점] OSSA 파일 {len(ossa_seen)}개(중복 경로 {ossa_dup}개 제외) 중 범위 해당 {cnt['OSSA']}개, "
        f"OSSN 파일 {len(secdoc_files)}개(중복 경로 {secdoc_dup}개 제외, 번호 기준 {len(seen)}건) 중 범위 해당 {cnt['OSSN']}건 → 취약점 노드 {cnt['OSSA'] + cnt['OSSN']}개 "
        "(OSSN은 파일 형식 미확인 → 결과 직접 확인 필요)")
    return ttl


# ---------------------------------------------------------------- 4. 매핑 검증
def validate_mapping(path, tech_ids, d3f_classes):
    text = re.sub(r"#[^\n]*", "", open(path, encoding="utf-8").read())
    used_t = set(re.findall(r"kb:(T\d{4}(?:_\d{3})?)\b", text))
    used_m = set(re.findall(r"kb:(M\d{4})\b", text))
    used_d = set(re.findall(r"d3f:([A-Za-z0-9\-]+)", text))
    log(f"\n[검증] {os.path.basename(path)}: 기법 {len(used_t)}, 완화책 {len(used_m)}, D3FEND {len(used_d)} 참조")
    bad_t = sorted(used_t - tech_ids) if tech_ids else sorted(used_t)
    bad_d = sorted(used_d - d3f_classes) if d3f_classes else sorted(used_d)
    ok = True
    if bad_t:
        ok = False
        log("  ⚠ ATT&CK 데이터(플랫폼 필터 후)에 없는 기법: " + ", ".join(bad_t))
        for t in bad_t:
            if t in ATTACK_STATUS["revoked"]:
                log(f"    - {t}: 이 버전에서 폐기됨 → 대체 기법 {', '.join(ATTACK_STATUS['revoked'][t])} (gen_mapping.py 에서 교체 후 재생성)")
            elif t in ATTACK_STATUS["deprecated"]:
                log(f"    - {t}: 이 버전에서 사용 중단됨 → 매핑에서 제거 검토")
            else:
                log(f"    - {t}: ID 오타이거나 --platforms 범위 밖 (데이터에서 직접 확인 필요)")
    if bad_d:
        ok = False
        log("  ⚠ D3FEND 매핑표에 없는 방어 기법: " + ", ".join(bad_d))
    if ok:
        log("  ✓ 참조한 모든 ID가 실제 데이터에 존재")
    st = Counter(re.findall(r'cto:verificationStatus\s+"([^"]+)"', text))
    log("  검증 상태: " + ", ".join(f"{k} {v}" for k, v in st.items()))
    if st.get("실로그확인필요") or st.get("명령확인필요"):
        log("  → 클러스터 실제 로그로 확인 대상을 하나씩 확정하세요 (python check_queries.py --check 로 목록 확인).")
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--docs", default="docs")
    ap.add_argument("--out", default="out")
    ap.add_argument("--platforms", default="IaaS,Identity Provider")
    ap.add_argument("--min-cooccur", type=int, default=2, help="기법 동시 사용 최소 그룹·캠페인 수")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    for need in ("schema.ttl", "openstack_mapping.ttl", "d3fend_mitigation_map.csv"):
        if not os.path.exists(need):
            sys.exit(f"작업 폴더에 {need} 가 없습니다.")
    outputs, tech_ids, version = [], set(), "?"

    attack_json = os.path.join(a.docs, "attack", "enterprise-attack.json")
    if os.path.exists(attack_json):
        ttl, tech_ids, version = build_attack(attack_json, {p.strip() for p in a.platforms.split(",")}, a.min_cooccur)
        outputs.append(os.path.join(a.out, "kb_attack.ttl"))
        ttl.write(outputs[-1], f"# 자동 생성: MITRE ATT&CK v{version} (플랫폼: {a.platforms})")
    else:
        log(f"[오류] {attack_json} 없음 - download_docs.sh 를 먼저 실행하세요")

    ttl, d3f_classes = build_d3fend("d3fend_mitigation_map.csv")
    outputs.append(os.path.join(a.out, "kb_d3fend.ttl"))
    ttl.write(outputs[-1], "# 자동 생성: D3FEND 공식 매핑 (ATT&CK Mitigation → D3FEND)")

    ttl = build_vulns(os.path.join(a.docs, "openstack", "ossa"), os.path.join(a.docs, "openstack", "security-doc"))
    outputs.append(os.path.join(a.out, "kb_openstack_vuln.ttl"))
    ttl.write(outputs[-1], "# 자동 생성: OSSA / OSSN (Keystone·Nova·Neutron)")

    parts = ["schema.ttl", "openstack_mapping.ttl"] + outputs
    merged = os.path.join(a.out, "ontology_all.ttl")
    with open(merged, "w", encoding="utf-8") as f:
        for p in parts:
            f.write(f"\n# ===== {os.path.basename(p)} =====\n" + open(p, encoding="utf-8").read() + "\n")
    log(f"\n최종 온톨로지: {merged}")
    ok = validate_mapping("openstack_mapping.ttl", tech_ids, d3f_classes)
    with open(os.path.join(a.out, "build_report.txt"), "w", encoding="utf-8") as f:
        f.write(f"ATT&CK version: {version}\nD3FEND mapping: d3fend_mitigation_map.csv (D3FEND 1.6.0 기준 공식 매핑표)\n\n" + "\n".join(REPORT))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
