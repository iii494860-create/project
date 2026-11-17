#!/usr/bin/env python3
"""
record_writer.py - 분석 엔진 결과를 Neo4j 기록층에 저장 (3K1H 캡스톤)

원칙
  - 엔진(프로그램)만 기록층에 쓴다. 에이전트는 읽기만 한다.
  - 지식층(:Knowledge)은 절대 수정하지 않는다. 쓰기 전후 지식층 개수를 같은 트랜잭션 안에서 비교해 달라지면 전체 취소.
  - 노드·관계 이름은 온톨로지 스키마 정의를 그대로 쓴다 (ObservedEvent, Alert, Incident, User, IPAddress, Project /
    hasEventType, performedBy, fromIP, inProject, triggeredBy, matchedRule, suspectedTechnique, groupedInto).
  - 같은 로그를 다시 넣어도 중복이 생기지 않는다: ID 는 내용의 해시, 저장은 MERGE.
  - 모든 수신 이벤트를 보존한다. 미분류는 경보가 아니라 관측 기록으로 저장한다.

사용법
  python record_writer.py --log attack_logs.jsonl --dry-run          # DB 없이 저장할 내용만 요약
  python record_writer.py --log attack_logs.jsonl [--baseline b.json --allowlist a.json]
접속 정보: NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD 또는 CTO_NEO4J_PASSWORD_FILE(기본 ~/.cto_neo4j_password)
"""
import argparse, getpass, hashlib, json, os, sys
from collections import defaultdict
from datetime import datetime, timezone
from cto_store import Store
import engine as E
from engine_t1537_verified import VerifiedEngine

RAW_MAX = 8000
FIELD_MAX, FIELD_VALUE_MAX = 12, 100     # 온톨로지 필드 요약: 필드 최대 12개, 값 최대 100자
BATCH = 500


def _h(prefix, text):
    return prefix + hashlib.sha256(text.encode("utf-8")).hexdigest()[:24]


def iso(ts):
    # 엔진은 로그에 시각이 없으면 순번을 시각 대신 씀 → 실제 시각이 아니면 저장하지 않음
    return datetime.fromtimestamp(float(ts), timezone.utc).isoformat(timespec="seconds") if ts and ts > 1e9 else None


def tech_uri(ext):
    return "kb:" + str(ext).replace(".", "_")


def event_id(e):
    raw = e["raw"]
    # Receipt times change on broker redelivery; publisher message identity does not.
    identity = {k: v for k, v in raw.items() if k != "received_at"}
    if raw.get("message_id"):
        identity = {"message_id": raw["message_id"], "publisher_id": raw.get("publisher_id", "")}
    return _h("ev-", json.dumps(identity, ensure_ascii=False, sort_keys=True))


def run_engine(log, ontology="out/ontology_all.ttl", allowlist=None, baseline=None):
    store = Store.load(ontology)
    allow = json.load(open(allowlist, encoding="utf-8")) if allowlist else None
    base = [tuple(x) for x in json.load(open(baseline, encoding="utf-8"))] if baseline else None
    eng = VerifiedEngine(store, allow, base, os.environ.get("CTO_NORMAL_EVIDENCE_FILE"))
    seen = set()
    with open(log, encoding="utf-8") as source:
        for line in source:
            msg = E.extract_json(line)
            if isinstance(msg, dict) and "event_type" in msg:
                key = event_id({"raw": msg})
                if key not in seen:
                    eng.process(msg)
                    seen.add(key)
    return eng


# ------------------------------------------------------------------ 저장할 행 만들기 (파이썬만)
def build_rows(eng):
    by_n = {e["n"]: e for e in eng.events}
    keep = sorted(by_n)
    nodes, rels = defaultdict(dict), defaultdict(set)
    ev_rid = {}
    for n in keep:
        e = by_n[n]
        rid = ev_rid[n] = event_id(e)
        raw = json.dumps(e["raw"], ensure_ascii=False, sort_keys=True)
        outcome = E.get_path(e["raw"], "payload.outcome")
        # 온톨로지가 이 이벤트 유형에서 읽으라고 정한 필드의 값 (엔진이 이미 뽑아 둔 것). 에이전트에게 원문 대신 기본으로 보여 줌
        fields = [[str(k), (v if isinstance(v, str) else json.dumps(v, ensure_ascii=False))[:FIELD_VALUE_MAX]]
                  for k, v in list(e["fields"].items())[:FIELD_MAX]]
        p = {"recordId": rid, "eventTypeName": e["event_type"], "observedAt": iso(e["ts"]),
             "outcome": outcome if isinstance(outcome, str) else None, "requestId": e["request_id"],
             "user": e["user"], "ip": e["ip"], "project": e["project"], "classification": e["how"],
             "eventTypeUri": e["ev"], "behaviorUri": e["bc"],
             "fieldsJson": json.dumps(fields, ensure_ascii=False) if fields else None,
             "rawLog": raw[:RAW_MAX], "rawTruncated": len(raw) > RAW_MAX}
        nodes["ObservedEvent"][rid] = {k: v for k, v in p.items() if v is not None}
        if e["ev"]:
            rels["HAS_EVENT_TYPE"].add((rid, e["ev"]))
        for label, rel, val, key in (("User", "PERFORMED_BY", e["user"], "name"), ("IPAddress", "FROM_IP", e["ip"], "address"),
                                     ("Project", "IN_PROJECT", e["project"], "projectId")):
            if not val:
                continue
            ent = f"{label.lower()}:{val}"
            cur = nodes[label].setdefault(ent, {"recordId": ent, key: str(val)})
            t = p["observedAt"]
            if t:
                cur["firstSeen"] = min(cur.get("firstSeen", t), t)
                cur["lastSeen"] = max(cur.get("lastSeen", t), t)
            rels[rel].add((rid, ent))

    al_rid = {}
    for i, a in enumerate(eng.alerts):
        ev_ids = sorted({ev_rid[x["n"]] for x in a["events"]})
        rid = al_rid[i] = _h("al-", a["rule"] + "|" + ",".join(ev_ids))
        p = {"recordId": rid, "ruleUri": a["rule"], "ruleLabel": a["rule_label"], "tier": a["tier"],
             "severity": a["severity"], "condition": a["condition"], "key": str(a["key"]),
             "keys": [str(k) for k in a["keys"]], "detectedAt": iso(a["ts"]),
             "techniqueIds": [t["id"] for t in a["techniques"]], "behaviors": list(a["behaviors"]),
             "investigateJson": json.dumps(a["investigate"], ensure_ascii=False),
             "respondJson": json.dumps(a["respond"], ensure_ascii=False),
             "nextStepsJson": json.dumps(a["next_steps"], ensure_ascii=False),
             "sources": list(a["sources"]), "eventCount": len(ev_ids)}
        nodes["Alert"][rid] = {k: v for k, v in p.items() if v is not None and v != []}
        rels["TRIGGERED_BY"] |= {(rid, x) for x in ev_ids}
        rels["MATCHED_RULE"].add((rid, a["rule"]))
        rels["SUSPECTED_TECHNIQUE"] |= {(rid, tech_uri(t["id"])) for t in a["techniques"]}

    for inc in eng.incidents.values():
        members = sorted(inc["alert_idx"])
        first = min(members, key=lambda i: (eng.alerts[i]["ts"], al_rid[i]))
        rid = al_rid[first].replace("al-", "in-", 1)        # 사건 ID = 가장 먼저 발생한 경보의 ID
        times = [iso(eng.alerts[i]["ts"]) for i in members if iso(eng.alerts[i]["ts"])]
        p = {"recordId": rid, "accumulatedRisk": int(inc["risk"]), "keys": sorted(str(k) for k in inc["ids"]),
             "alertCount": len(members), "techniqueIds": sorted(inc["techniques"]),
             "firstDetectedAt": min(times) if times else None, "lastDetectedAt": max(times) if times else None,
             "status": "active"}
        nodes["Incident"][rid] = {k: v for k, v in p.items() if v is not None and v != []}
        rels["GROUPED_INTO"] |= {(al_rid[i], rid) for i in members}
    return {k: v for k, v in nodes.items()}, {k: sorted(v) for k, v in rels.items()}


# 관계별 끝점: (시작 라벨, 끝 라벨 또는 None=지식층 노드)
REL_ENDS = {"HAS_EVENT_TYPE": ("ObservedEvent", None), "PERFORMED_BY": ("ObservedEvent", "User"),
            "FROM_IP": ("ObservedEvent", "IPAddress"), "IN_PROJECT": ("ObservedEvent", "Project"),
            "TRIGGERED_BY": ("Alert", "ObservedEvent"), "MATCHED_RULE": ("Alert", None),
            "SUSPECTED_TECHNIQUE": ("Alert", None), "GROUPED_INTO": ("Alert", "Incident")}
ENTITY = {"User", "IPAddress", "Project"}


def batches(rows):
    for i in range(0, len(rows), BATCH):
        yield rows[i:i + BATCH]


# ------------------------------------------------------------------ Neo4j 에 쓰기 (한 트랜잭션)
class KnowledgeChanged(Exception):
    pass


def write_tx(tx, nodes, rels):
    count = lambda: (tx.run("MATCH (n:Knowledge) RETURN count(n) AS c").single()["c"],
                     tx.run("MATCH (:Knowledge)-[r]->(:Knowledge) RETURN count(r) AS c").single()["c"])
    before = count()
    for label, items in nodes.items():
        rows = list(items.values())
        for b in batches(rows):
            if label in ENTITY:      # 여러 실행에 걸쳐 처음·마지막으로 본 시각을 갱신
                tx.run(f"UNWIND $rows AS row MERGE (n:Record:{label} {{recordId: row.recordId}}) "
                       "SET n.name = coalesce(row.name, n.name), n.address = coalesce(row.address, n.address), "
                       "n.projectId = coalesce(row.projectId, n.projectId), "
                       "n.firstSeen = CASE WHEN row.firstSeen IS NULL THEN n.firstSeen "
                       "  WHEN n.firstSeen IS NULL OR row.firstSeen < n.firstSeen THEN row.firstSeen ELSE n.firstSeen END, "
                       "n.lastSeen = CASE WHEN row.lastSeen IS NULL THEN n.lastSeen "
                       "  WHEN n.lastSeen IS NULL OR row.lastSeen > n.lastSeen THEN row.lastSeen ELSE n.lastSeen END",
                       rows=b)
            else:                    # 이벤트·경보·사건: 같은 입력이면 같은 내용 → 덮어써도 결과 동일
                tx.run(f"UNWIND $rows AS row MERGE (n:Record:{label} {{recordId: row.recordId}}) SET n += row", rows=b)
    made = {}
    for rel, pairs in rels.items():
        src, dst = REL_ENDS[rel]
        dst_pat = "(b:Knowledge {uri: row[1]})" if dst is None else f"(b:Record:{dst} {{recordId: row[1]}})"
        c = 0
        for b in batches([list(p) for p in pairs]):
            c += tx.run(f"UNWIND $rows AS row MATCH (a:Record:{src} {{recordId: row[0]}}) MATCH {dst_pat} "
                        f"MERGE (a)-[:{rel}]->(b) RETURN count(*) AS c", rows=b).single()["c"]
        made[rel] = c
    # 이번 실행에서 사건이 합쳐졌으면 경보의 예전 사건 연결을 지우고, 경보가 없어진 사건은 '병합됨'으로 표시
    grp = [list(p) for p in rels.get("GROUPED_INTO", [])]
    for b in batches(grp):
        tx.run("UNWIND $rows AS row MATCH (a:Record:Alert {recordId: row[0]})-[g:GROUPED_INTO]->(i:Record:Incident) "
               "WHERE i.recordId <> row[1] DELETE g", rows=b)
    superseded = tx.run("MATCH (i:Record:Incident) WHERE NOT EXISTS { (i)<-[:GROUPED_INTO]-() } AND i.status <> 'superseded' "
                        "SET i.status = 'superseded' RETURN count(i) AS c").single()["c"]
    after = count()
    if after != before:
        raise KnowledgeChanged(f"지식층이 바뀌어 전체 취소: 전 {before} / 후 {after}")
    return {"made": made, "superseded": superseded, "knowledge": after}


def password():
    if os.environ.get("NEO4J_PASSWORD"):
        return os.environ["NEO4J_PASSWORD"]
    p = os.path.expanduser(os.environ.get("CTO_NEO4J_PASSWORD_FILE", "~/.cto_neo4j_password"))
    return open(p, encoding="utf-8").read().strip() if os.path.exists(p) else getpass.getpass("neo4j 비밀번호: ")


def summary(nodes, rels):
    print("저장할 노드:", {k: len(v) for k, v in nodes.items()})
    print("저장할 관계:", {k: len(v) for k, v in rels.items()})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", required=True)
    ap.add_argument("--ontology", default="out/ontology_all.ttl")
    ap.add_argument("--allowlist"); ap.add_argument("--baseline")
    ap.add_argument("--database", default=os.environ.get("NEO4J_DATABASE", "neo4j"))
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    eng = run_engine(a.log, a.ontology, a.allowlist, a.baseline)
    nodes, rels = build_rows(eng)
    print(f"엔진: 이벤트 {len(eng.events)}건, 경보 {len(eng.alerts)}건, 사건 {len(eng.incidents)}건")
    summary(nodes, rels)
    if a.dry_run:
        return
    from neo4j import GraphDatabase
    with GraphDatabase.driver(os.environ.get("NEO4J_URI", "neo4j://localhost:7687"),
                              auth=(os.environ.get("NEO4J_USER", "neo4j"), password())) as d:
        d.verify_connectivity()
        with d.session(database=a.database) as s:
            s.run("CREATE CONSTRAINT record_id IF NOT EXISTS FOR (r:Record) REQUIRE r.recordId IS UNIQUE").consume()
            try:
                res = s.execute_write(write_tx, nodes, rels)
            except KnowledgeChanged as ex:
                sys.exit(f"❌ {ex}")
    short = {k: (v, len(rels[k])) for k, v in res["made"].items() if v != len(rels[k])}
    print("관계 연결:", "모두 연결됨" if not short else f"연결 안 된 것 있음 (실제, 기대) {short}")
    print(f"병합되어 비게 된 사건: {res['superseded']}개, 지식층 변화 없음 (노드·관계 {res['knowledge']})")


if __name__ == "__main__":
    main()
