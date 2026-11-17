#!/usr/bin/env python3
"""
load_neo4j.py - 온톨로지(.ttl)를 Neo4j 에 적재 (3K1H 캡스톤)

원칙
  - out/ontology_all.ttl 이 원본. Neo4j 는 언제든 다시 만들 수 있는 사본.
  - 전체 재적재(지식층만 비우고 새로 만듦)를 트랜잭션 하나로 수행 → 적재 중에도 다른 질의는 이전 상태를 봄.
  - 기록층(:Record)·에이전트 보고서(:AgentReport)는 지우지 않음. 이들과 지식층 사이의 연결은
    지우기 직전에 기억해 두었다가 같은 트랜잭션 안에서 복원. 사라진 지식을 가리키던 연결은 보고.
  - 확정(커밋) 직전에 같은 트랜잭션 안에서 개수를 검증하고, 어긋나면 전체 취소 → 이전 상태 유지.
  - 질의는 모두 매개변수 방식, DB 이름 지정, 목록 단위 묶음 처리 (Neo4j 공식 드라이버 권고).
  - 라벨·관계 이름은 스키마에서 온 값만 쓰고, 형식 검사 후에만 질의에 넣음.

사용법
  python load_neo4j.py --dry-run          # DB 없이 변환·사전 검사만
  python load_neo4j.py                    # 적재 + 적재 후 검증
  python load_neo4j.py --verify-only      # 적재 없이 검증만
  python load_neo4j.py --test-rollback    # 실패 시 전체 취소가 실제로 되는지 확인 (첫 적재 후 1회)
접속 정보: 환경 변수 NEO4J_URI(기본 neo4j://localhost:7687), NEO4J_USER(기본 neo4j),
          NEO4J_PASSWORD(없으면 실행 중에 입력받음. 화면·기록에 남지 않음)
"""
import argparse, getpass, hashlib, os, re, sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from cto_store import Store, Literal

KNOWLEDGE, ONTO_CLASS = "Knowledge", "OntologyClass"
RECORD, REPORT, LOADINFO = "Record", "AgentReport", "LoadInfo"
SAFE_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
# 정의되지 않은 대상을 참조하면 적재를 멈춰야 하는 클래스 (에이전트 분석 경로에 있는 것들)
ANALYSIS_PATH = {"Technique", "Tactic", "Mitigation", "LogEventType", "LogField", "BehaviorClass", "DetectionRule",
                 "InvestigationQuery", "ResponseAction", "CommandParameter", "ResourceType", "ActionType",
                 "LogChannel", "OpenStackService", "AlertTier", "AllowlistEntry"}
BATCH = 500


def local(name):
    return name.split(":", 1)[-1]


def rel_type(prop):
    """cto:mappedToD3FEND -> MAPPED_TO_D3FEND"""
    return re.sub(r"([a-z])([A-Z])", r"\1_\2", local(prop)).upper()


def safe(name):
    if not SAFE_NAME.match(name):
        raise ValueError(f"질의에 넣을 수 없는 이름: {name!r}")
    return name


# ------------------------------------------------------------------ 변환
class Plan:
    def __init__(self, onto_path, schema_path):
        self.onto_path = onto_path
        self.attack_version = None
        self.s = Store.load(onto_path)
        self.sch = Store.load(schema_path)
        self.errors, self.notes = [], []
        self.classes = {c for c in self.sch.of_type("owl:Class")}
        self.obj_props = set(self.sch.of_type("owl:ObjectProperty"))
        self.dat_props = set(self.sch.of_type("owl:DatatypeProperty"))
        self._build()

    def _labels(self, n):
        return sorted(local(t) for t in self.s.types(n) if t in self.classes)

    def _build(self):
        s = self.s
        inst = {n for n in s.spo if self._labels(n)}
        cooc = {n for n in inst if "CoOccurrence" in self._labels(n)}
        self.instances = inst - cooc
        self.nodes, self.rels, self.skipped = {}, defaultdict(list), []
        unknown_attr, unknown_rel = Counter(), Counter()
        direct_cooc = set()

        for n in sorted(self.instances):
            labels = self._labels(n)
            props = defaultdict(list)
            for p, vals in s.spo[n].items():
                if p == "a":
                    continue
                for v in vals:
                    if type(v) is str:                                  # 다른 노드를 가리킴 → 관계
                        if p == "cto:coOccursWith":                    # 동시 사용 기록 노드와 중복 → 아래에서 처리
                            direct_cooc.add(frozenset((n, v)))
                            continue
                        if p not in self.obj_props:
                            unknown_rel[p] += 1
                        elif v in self.instances:
                            self.rels[rel_type(p)].append({"s": n, "o": v, "props": {}})
                        else:
                            self.skipped.append((n, p, v, labels))
                    else:                                               # 값 → 속성
                        if p in ("rdfs:label", "rdfs:comment"):
                            key = local(p)
                        elif p in self.dat_props:
                            key = local(p)
                        else:
                            unknown_attr[p] += 1
                            continue
                        lang = getattr(v, "lang", None)
                        key = f"{key}_{lang}" if lang else key
                        val = str(v) if isinstance(v, Literal) else v
                        if val is not None:
                            props[key].append(val)
            clean = {"uri": n}
            for k, vs in props.items():
                if len({type(x) for x in vs}) > 1:                     # 목록은 같은 자료형이어야 함 (공식 문서)
                    vs = [str(x) for x in vs]
                clean[k] = vs[0] if len(vs) == 1 else vs
            self.nodes[n] = {"labels": labels, "props": clean}

        # 정의되지 않은 주어가 분석 경로의 노드를 가리키는 경우도 확인
        for n in s.spo:
            if n in inst or not s.spo[n] or n.startswith(("cto:", "owl:", "rdfs:", "rdf:", "xsd:")):
                continue
            for p, vals in s.spo[n].items():
                for v in vals:
                    if type(v) is str and v in self.instances and p != "a":
                        self.skipped.append((n, p, v, ["(정의 없음)"]))

        # 기법 동시 사용 기록 → 관계 속성으로 변환 (빌드는 같은 쌍을 기록 노드 1개 + 직접 관계 양방향 2개로 남김.
        #  같은 관계 이름으로 세 번 적재되던 문제를 막기 위해 쌍마다 관계 1개만 만든다)
        covered = set()
        for c in sorted(cooc):
            a, b = s.val(c, "cto:techniqueA"), s.val(c, "cto:techniqueB")
            if a in self.instances and b in self.instances:
                src = s.val(c, "cto:derivedFrom")
                props = {"count": int(s.val(c, "cto:coOccurrenceCount", 0) or 0)}
                if src:
                    props["source"] = str(src)
                self.rels["CO_OCCURS_WITH"].append({"s": a, "o": b, "props": props})
                covered.add(frozenset((a, b)))
            else:
                self.skipped.append((c, "cto:techniqueA/B", f"{a},{b}", ["CoOccurrence"]))

        orphan = sorted(tuple(sorted(pr)) for pr in direct_cooc - covered
                        if len(pr) == 2 and all(x in self.instances for x in pr))
        for a, b in orphan:                                             # 기록 노드 없이 직접 관계만 있는 쌍: 횟수 없이 1개
            self.rels["CO_OCCURS_WITH"].append({"s": a, "o": b, "props": {}})
        self.cooc_note = (f"기법 동시 사용: 쌍 {len(covered) + len(orphan)}개 (횟수 있음 {len(covered)}, 직접 관계만 {len(orphan)}), "
                          f"중복 직접 관계 {len(direct_cooc & covered)}쌍은 적재하지 않음")

        if unknown_rel:
            self.errors.append(f"스키마에 없는 관계 사용: {dict(unknown_rel)}")
        if unknown_attr:
            self.errors.append(f"스키마에 없는 속성 사용: {dict(unknown_attr)}")
        bad = [x for x in self.skipped if set(x[3]) & ANALYSIS_PATH]
        if bad:
            self.errors.append("분석 경로의 노드가 정의되지 않은 대상을 참조함 (적재 중단): "
                               + "; ".join(f"{a} -{local(p)}-> {o}" for a, p, o, _ in bad[:10]))
        for lbls in {tuple(v["labels"]) for v in self.nodes.values()}:
            for l in lbls:
                safe(l)
        for t in self.rels:
            safe(t)
        self._build_schema()

    def _build_schema(self):
        sch = self.sch
        self.onto_classes = []
        for c in sorted(self.classes):
            d = {"name": local(c)}
            for lg in ("ko", "en"):
                for p, key in (("rdfs:label", "label"), ("rdfs:comment", "comment")):
                    v = next((x for x in sch.objs(c, p) if getattr(x, "lang", None) == lg), None)
                    if v:
                        d[f"{key}_{lg}"] = str(v)
            attrs = sorted(local(p) for p in self.dat_props if sch.val(p, "rdfs:domain") == c)
            if attrs:
                d["datatypeProperties"] = attrs
            self.onto_classes.append(d)
        self.sub_class = [{"s": local(c), "o": local(sup)} for c in self.classes
                          for sup in sch.objs(c, "rdfs:subClassOf") if sup in self.classes]
        self.schema_rels, self.schema_rel_skipped = [], []
        for p in sorted(self.obj_props):
            d, r = sch.val(p, "rdfs:domain"), sch.val(p, "rdfs:range")
            if d in self.classes and r in self.classes:
                self.schema_rels.append({"s": local(d), "o": local(r), "props": {
                    "name": local(p), "relType": rel_type(p), "label_ko": sch.label(p, ("ko",))}})
            else:
                self.schema_rel_skipped.append(local(p))

    # 적재 후 비교할 기대값
    def expected(self):
        return {"labels": Counter(l for v in self.nodes.values() for l in v["labels"]),
                "nodes": len(self.nodes),
                "rels": {t: len(v) for t, v in self.rels.items()},
                "onto_classes": len(self.onto_classes),
                "schema_rels": len(self.schema_rels)}

    def summary(self):
        e = self.expected()
        print(f"원본: {self.onto_path} (트리플 {self.s.n})")
        print(f"지식 노드 {e['nodes']}개, 관계 {sum(e['rels'].values())}개 ({len(e['rels'])}종), "
              f"설계도 클래스 {e['onto_classes']}개, 설계도 관계 {e['schema_rels']}개")
        print("  라벨별:", dict(sorted(e["labels"].items())))
        print("  관계별:", dict(sorted(e["rels"].items())))
        print(self.cooc_note)
        by_rel = Counter(local(p) for _, p, _, _ in self.skipped)
        print(f"제외한 참조(정의되지 않은 대상) {len(self.skipped)}건: {dict(by_rel)}")
        if self.schema_rel_skipped:
            print(f"설계도에서 제외한 관계(정의역·치역 없음) {len(self.schema_rel_skipped)}개: {', '.join(self.schema_rel_skipped)}")
        for m in self.errors:
            print("❌", m)


# ------------------------------------------------------------------ 적재
class LoadVerificationError(Exception):
    pass


def batches(rows):
    for i in range(0, len(rows), BATCH):
        yield rows[i:i + BATCH]


def reload_tx(tx, plan, force_fail=False):
    """트랜잭션 하나 안에서: 연결 기억 → 지식층·설계도 삭제 → 생성 → 연결 복원 → 적재 기록"""
    # 1) 기록층·보고서와 지식층 사이의 연결 기억
    links = [dict(r) for r in tx.run(
        "// q:snapshot_links\n"
        f"MATCH (x)-[r]-(k:{KNOWLEDGE}) WHERE NOT x:{KNOWLEDGE} AND NOT x:{ONTO_CLASS} "
        "RETURN elementId(x) AS xid, type(r) AS t, startNode(r) = x AS outgoing, k.uri AS uri, properties(r) AS props")]
    # 2) 삭제 (지식층과 설계도만)
    tx.run(f"// q:delete\nMATCH (n:{KNOWLEDGE}) DETACH DELETE n")
    tx.run(f"// q:delete\nMATCH (c:{ONTO_CLASS}) DETACH DELETE c")
    # 3) 지식 노드 생성 (라벨 조합별)
    groups = defaultdict(list)
    for v in plan.nodes.values():
        groups[tuple(v["labels"])].append({"props": v["props"]})
    for labels, rows in groups.items():
        lbl = ":".join(safe(l) for l in (KNOWLEDGE,) + labels)
        for b in batches(rows):
            tx.run(f"// q:create_nodes\nUNWIND $rows AS row CREATE (n:{lbl}) SET n = row.props", rows=b)
    # 4) 지식 관계 생성 (종류별)
    for t, rows in plan.rels.items():
        for b in batches(rows):
            tx.run(f"// q:create_rels\nUNWIND $rows AS row "
                   f"MATCH (a:{KNOWLEDGE} {{uri: row.s}}) MATCH (b:{KNOWLEDGE} {{uri: row.o}}) "
                   f"CREATE (a)-[r:{safe(t)}]->(b) SET r = row.props", rows=b)
    # 5) 설계도
    tx.run(f"// q:create_classes\nUNWIND $rows AS row CREATE (c:{ONTO_CLASS}) SET c = row", rows=plan.onto_classes)
    tx.run(f"// q:create_subclass\nUNWIND $rows AS row MATCH (a:{ONTO_CLASS} {{name: row.s}}) "
           f"MATCH (b:{ONTO_CLASS} {{name: row.o}}) CREATE (a)-[:SUBCLASS_OF]->(b)", rows=plan.sub_class)
    tx.run(f"// q:create_schema_rels\nUNWIND $rows AS row MATCH (a:{ONTO_CLASS} {{name: row.s}}) "
           f"MATCH (b:{ONTO_CLASS} {{name: row.o}}) CREATE (a)-[r:SCHEMA_RELATION]->(b) SET r = row.props",
           rows=plan.schema_rels)
    # 6) 연결 복원
    alive = set(plan.nodes)
    restore, broken = defaultdict(list), []
    for l in links:
        (restore[(l["t"], l["outgoing"])] if l["uri"] in alive else broken).append(l)
    restored = 0
    for (t, outgoing), rows in restore.items():
        pattern = f"(x)-[r:{safe(t)}]->(k)" if outgoing else f"(x)<-[r:{safe(t)}]-(k)"
        for b in batches(rows):
            res = tx.run(f"// q:restore_links\nUNWIND $rows AS row MATCH (x) WHERE elementId(x) = row.xid "
                         f"MATCH (k:{KNOWLEDGE} {{uri: row.uri}}) CREATE {pattern} SET r = row.props "
                         "RETURN count(r) AS c", rows=b)
            restored += res.single()["c"]
    # 7) 적재 기록
    e = plan.expected()
    info = {"loadedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "ontologyFile": os.path.basename(plan.onto_path),
            "ontologySha256": hashlib.sha256(open(plan.onto_path, "rb").read()).hexdigest(),
            "tripleCount": plan.s.n, "nodeCount": e["nodes"], "relCount": sum(e["rels"].values()),
            "skippedRefs": len(plan.skipped), "linksBefore": len(links), "linksRestored": restored,
            "linksBroken": len(broken)}
    if plan.attack_version:
        info["attackVersion"] = plan.attack_version
    # 8) 확정 전 검증: 하나라도 어긋나면 예외 → 트랜잭션 전체 취소 → 이전 상태 유지
    bad = [f"{n} (DB {g} / 기대 {w})" for n, g, w in verify_tx(tx, plan) if g != w]
    if bad:
        raise LoadVerificationError("적재 검증 실패로 전체 취소(이전 상태 유지): " + "; ".join(bad))
    if force_fail:
        raise LoadVerificationError("취소 시험용 강제 실패")
    tx.run(f"// q:loadinfo\nCREATE (i:{LOADINFO}) SET i = $info", info=info)
    return {"links": len(links), "restored": restored,
            "broken": [f"{b['t']} -> {b['uri']}" for b in broken]}


def verify_tx(tx, plan):
    e = plan.expected()
    got_labels = Counter()
    for r in tx.run(f"// q:verify_labels\nMATCH (n:{KNOWLEDGE}) RETURN labels(n) AS ls"):
        for l in r["ls"]:
            if l != KNOWLEDGE:
                got_labels[l] += 1
    got_nodes = tx.run(f"// q:verify_nodes\nMATCH (n:{KNOWLEDGE}) RETURN count(n) AS c").single()["c"]
    got_rels = {r["t"]: r["c"] for r in tx.run(
        f"// q:verify_rels\nMATCH (:{KNOWLEDGE})-[r]->(:{KNOWLEDGE}) RETURN type(r) AS t, count(r) AS c")}
    got_classes = tx.run(f"// q:verify_classes\nMATCH (c:{ONTO_CLASS}) RETURN count(c) AS c").single()["c"]
    got_schema = tx.run(f"// q:verify_schema\nMATCH (:{ONTO_CLASS})-[r:SCHEMA_RELATION]->() RETURN count(r) AS c").single()["c"]
    dup = tx.run(f"// q:verify_dup\nMATCH (n:{KNOWLEDGE}) WITH n.uri AS u, count(*) AS c WHERE c > 1 RETURN count(u) AS c").single()["c"]
    # 기대값과 무관하게 DB 안에서 직접 찾는 중복 (기대값 자체가 틀린 경우도 잡기 위해)
    dup_rel = tx.run(f"// q:verify_dup_rel\nMATCH (a:{KNOWLEDGE})-[r]->(b:{KNOWLEDGE}) WITH a, b, type(r) AS t, count(r) AS c "
                     "WHERE c > 1 RETURN count(*) AS c").single()["c"]
    dup_cooc = tx.run(f"// q:verify_dup_cooc\nMATCH (a:{KNOWLEDGE})-[r:CO_OCCURS_WITH]-(b:{KNOWLEDGE}) "
                      "WHERE elementId(a) < elementId(b) WITH a, b, count(r) AS c WHERE c > 1 RETURN count(*) AS c").single()["c"]
    checks = [("지식 노드 수", got_nodes, e["nodes"]),
              ("라벨별 노드 수", dict(got_labels), dict(e["labels"])),
              ("관계 종류별 수", got_rels, e["rels"]),
              ("설계도 클래스 수", got_classes, e["onto_classes"]),
              ("설계도 관계 수", got_schema, e["schema_rels"]),
              ("uri 중복", dup, 0),
              ("같은 두 노드 사이 같은 관계 중복", dup_rel, 0),
              ("기법 쌍마다 동시 사용 관계 1개", dup_cooc, 0)]
    return checks


def rollback_test(driver, plan, args):
    """실제 Neo4j 에서 '실패하면 이전 상태 유지'를 확인: 일부러 확정 직전에 실패시키고, 전후 상태를 비교"""
    def state(tx):
        return {"nodes": tx.run(f"MATCH (n:{KNOWLEDGE}) RETURN count(n) AS c").single()["c"],
                "rels": tx.run(f"MATCH (:{KNOWLEDGE})-[r]->() RETURN count(r) AS c").single()["c"],
                "loadinfo": tx.run(f"MATCH (i:{LOADINFO}) RETURN count(i) AS c").single()["c"]}
    with driver.session(database=args.database, default_access_mode="READ") as s:
        before = s.execute_read(state)
    if before["nodes"] == 0:
        print("먼저 한 번 정상 적재한 뒤에 실행하세요 (비교할 이전 상태가 필요함).")
        return False
    with driver.session(database=args.database) as s:
        try:
            s.execute_write(reload_tx, plan, True)
            print("✗ 강제 실패가 일어나지 않음")
            return False
        except LoadVerificationError:
            pass
    with driver.session(database=args.database, default_access_mode="READ") as s:
        after = s.execute_read(state)
    ok = before == after
    print(f"이전 {before}\n이후 {after}")
    print("✓ 실패 시 전체 취소 확인 (이전 상태 유지)" if ok else "✗ 상태가 바뀜 - 취소가 동작하지 않음")
    return ok


def run_db(plan, args):
    from neo4j import GraphDatabase, RoutingControl
    uri = os.environ.get("NEO4J_URI", "neo4j://localhost:7687")
    user = os.environ.get("NEO4J_USER", "neo4j")
    pw = os.environ.get("NEO4J_PASSWORD") or getpass.getpass(f"{user} 비밀번호: ")
    with GraphDatabase.driver(uri, auth=(user, pw)) as driver:
        driver.verify_connectivity()
        info = driver.get_server_info()
        print(f"접속: {info.agent}, Bolt {info.protocol_version}")
        if args.test_rollback:
            return rollback_test(driver, plan, args)
        if not args.verify_only:
            # 제약 조건은 데이터 변경과 같은 트랜잭션에 넣을 수 없어 먼저 따로 생성
            for name, lbl, prop in (("knowledge_uri", KNOWLEDGE, "uri"), ("ontology_class_name", ONTO_CLASS, "name"),
                                    ("record_id", RECORD, "recordId"), ("agent_report_id", REPORT, "reportId")):
                driver.execute_query(f"CREATE CONSTRAINT {safe(name)} IF NOT EXISTS FOR (n:{safe(lbl)}) "
                                     f"REQUIRE n.{safe(prop)} IS UNIQUE", database_=args.database)
            with driver.session(database=args.database) as session:
                try:
                    res = session.execute_write(reload_tx, plan)
                except LoadVerificationError as ex:
                    print("❌", ex)
                    return False
            print(f"적재 완료. 기록층 연결: 이전 {res['links']}개 → 복원 {res['restored']}개, 끊김 {len(res['broken'])}개")
            for b in res["broken"][:20]:
                print("   끊긴 연결:", b)
        with driver.session(database=args.database, default_access_mode="READ") as session:
            checks = session.execute_read(verify_tx, plan)
    ok = True
    print("\n[적재 후 검증]")
    for name, got, want in checks:
        good = got == want
        ok &= good
        print(f"  {'✓' if good else '✗'} {name}" + ("" if good else f"  (DB {got} / 기대 {want})"))
    print("\n전체 통과" if ok else "\n검증 실패 - 위 항목 확인")
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ontology", default="out/ontology_all.ttl")
    ap.add_argument("--schema", default="schema.ttl")
    ap.add_argument("--build-report", default="out/build_report.txt")
    ap.add_argument("--database", default=os.environ.get("NEO4J_DATABASE", "neo4j"))
    ap.add_argument("--dry-run", action="store_true", help="DB 없이 변환과 사전 검사만")
    ap.add_argument("--verify-only", action="store_true", help="적재 없이 검증만")
    ap.add_argument("--test-rollback", action="store_true", help="일부러 실패시켜 이전 상태가 유지되는지 확인 (첫 적재 후)")
    args = ap.parse_args()

    # 사전 검사 1: 빌드 보고서에 경고가 없어야 함 (ID 검증 통과)
    if not os.path.exists(args.build_report):
        sys.exit(f"{args.build_report} 이 없습니다. python build_ontology.py 를 먼저 실행하세요.")
    warn = [l.strip() for l in open(args.build_report, encoding="utf-8") if "⚠" in l]
    if warn:
        sys.exit("빌드 보고서에 경고가 있어 적재하지 않습니다:\n  " + "\n  ".join(warn))
    # 사전 검사 2: 변환과 구조 검사
    plan = Plan(args.ontology, args.schema)
    plan.attack_version = next((l.split(":", 1)[1].strip() for l in open(args.build_report, encoding="utf-8")
                                if l.startswith("ATT&CK version:")), None)
    plan.summary()
    if plan.errors:
        sys.exit("\n사전 검사 실패로 적재하지 않습니다.")
    print("\n사전 검사 통과")
    if args.dry_run:
        return
    sys.exit(0 if run_db(plan, args) else 1)


if __name__ == "__main__":
    main()
