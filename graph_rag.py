#!/usr/bin/env python3
"""graph_rag.py - 개발자가 직접 제어하는 Graph RAG 검색 파이프라인 (3K1H 캡스톤) v4

입력 두 종류 → ① 시드 선별 → ② 관계 확장(1~2-hop, 화이트리스트) → ③ 맥락 압축(문자 예산)

  [질문 모드] retrieve(g, 질문)
    ① 벡터 색인에서 top_k×4 후보 → floor 0.82 이상 & 1위와 gap 0.06 이내 → 종류별 SEED_KIND_CAP(기본 2, Technique 3, Analytic 1)
       → 전술(Tactic) 제외 → 최대 top_k. 버린 후보는 dropped_seeds 에 이유와 함께. 1위가 floor 미만이면 no_match
    ② EXPAND1(시드 종류별 1-hop) / EXPAND2(1-hop 노드 종류별 2-hop)
  [로그 모드] retrieve_for_event(g, 알림 JSON 또는 event_type)
    ① 벡터를 쓰지 않는다. 이벤트 유형(eventTypeName·outcome)과 일치하는 LogEventType → CLASSIFIED_AS → BehaviorClass 가 시드.
       입력 이벤트 유형 자체는 '입력 이벤트' 줄로 맥락 맨 앞에. 일치하는 이벤트 유형이 없으면 no_match(온톨로지에 매핑 없음)
    ② EVENT_EXPAND1(행위 분류 → 기법·탐지 규칙·조사 질의·같은 행위의 이벤트) / EVENT_EXPAND2(기법 → 전술·완화책·권고 대응)
  ③ 공통: fact = {id, kind, name, hop, path, text}. (hop, 관계 우선순위, 시드 순위) 순으로 채워 budget 에서 멈춤. 같은 노드는 한 번만
  확장은 Neo4jGraph.out/inn 만 쓰므로 표에 없는 관계(CO_OCCURS_WITH, DERIVED_FROM, HAS_FIELD, Record 계층)는 따라갈 수 없음
  임계값 보정(2026-10-03, qwen3-embedding:8b): 관련 질문 1위 0.85~0.87, 무관 질문 1위 0.74~0.80 → floor 0.82

사용:
  python graph_rag.py "질문" [--kind Technique] [--top-k 6] [--hops 2] [--gap 0.06] [--floor 0.82] [--budget 3000] [--json 파일]
  python graph_rag.py --event-type identity.authenticate --outcome failure
  python graph_rag.py --event-file real_logs/real_2026-10-01.jsonl --event-index 0     # JSONL 의 N번째 알림
접속: NEO4J_PASSWORD 또는 ~/.cto_neo4j_password (embed_knowledge.connect), 임베딩은 embed_knowledge.query_vector
"""
import argparse, collections, json, sys, time
from cto_tools import Neo4jGraph, _name, _t, RE_CITE, _as_list, OUTCOMES, RE_EVENT

SEED_KIND_CAP = {"Technique": 3, "Analytic": 1}   # 시드 종류별 상한, 없는 종류는 2 (Analytic·Vulnerability 가 상위를 독점하지 않게)
SEED_EXCLUDE = {"Tactic"}                          # 전술은 팬아웃이 커서 시드가 아니라 1-hop 으로만 닿게 함
TEXT_LEN = {0: 180, 1: 110, 2: 80}
# (방향, 관계, 대상 라벨, 상한, 표시 이름) — 순서가 곧 관계 우선순위
EXPAND1 = {
    "Technique": [("out", "BELONGS_TO_TACTIC", "Tactic", 3, "전술"),
                  ("out", "SUB_TECHNIQUE_OF", "Technique", 1, "상위 기법"),
                  ("in",  "SUB_TECHNIQUE_OF", "Technique", 3, "하위 기법"),
                  ("in",  "DETECTS", "DetectionRule", 3, "OpenStack 탐지 규칙"),
                  ("out", "MITIGATED_BY", "Mitigation", 4, "완화책"),
                  ("in",  "DETECTS", "DetectionStrategy", 2, "ATT&CK 탐지 전략"),
                  ("in",  "SUGGESTS_TECHNIQUE", "BehaviorClass", 3, "관련 행위 분류"),
                  ("out", "INVESTIGATE_WITH", "InvestigationQuery", 3, "조사 질의"),
                  ("out", "RECOMMENDED_RESPONSE", "ResponseAction", 3, "권고 대응"),
                  ("out", "PRECEDES", "Technique", 3, "다음 가능한 기법"),
                  ("in",  "PRECEDES", "Technique", 2, "앞선 기법")],
    "Tactic": [("in", "BELONGS_TO_TACTIC", "Technique", 8, "소속 기법")],
    "Mitigation": [("in", "MITIGATED_BY", "Technique", 5, "완화 대상 기법"),
                   ("out", "MAPPED_TO_D3FEND", "DefensiveTechnique", 3, "D3FEND")],
    "DefensiveTechnique": [("in", "MAPPED_TO_D3FEND", "Mitigation", 3, "대응 완화책"),
                           ("in", "IMPLEMENTS", "ResponseAction", 3, "구현 대응 조치")],
    "DetectionStrategy": [("out", "DETECTS", "Technique", 3, "탐지 대상 기법"),
                          ("out", "HAS_ANALYTIC", "Analytic", 3, "분석 로직")],
    "Analytic": [("in", "HAS_ANALYTIC", "DetectionStrategy", 2, "소속 탐지 전략")],
    "DetectionRule": [("out", "DETECTS", "Technique", 3, "탐지 대상 기법"),
                      ("out", "USES_BEHAVIOR", "BehaviorClass", 3, "사용 행위 분류")],
    "BehaviorClass": [("out", "SUGGESTS_TECHNIQUE", "Technique", 5, "시사 기법"),
                      ("in", "CLASSIFIED_AS", "LogEventType", 3, "로그 이벤트 유형"),
                      ("in", "USES_BEHAVIOR", "DetectionRule", 3, "탐지 규칙")],
    "LogEventType": [("out", "CLASSIFIED_AS", "BehaviorClass", 3, "행위 분류")],
    "InvestigationQuery": [("in", "INVESTIGATE_WITH", "Technique", 3, "대상 기법")],
    "ResponseAction": [("in", "RECOMMENDED_RESPONSE", "Technique", 3, "대상 기법"),
                       ("out", "IMPLEMENTS", "DefensiveTechnique", 2, "D3FEND")],
    "Vulnerability": [("out", "AFFECTS", "OpenStackService", 3, "영향 서비스")],
}
EXPAND2 = {
    "DetectionStrategy": [("out", "HAS_ANALYTIC", "Analytic", 2, "분석 로직")],
    "Mitigation": [("out", "MAPPED_TO_D3FEND", "DefensiveTechnique", 2, "D3FEND")],
    "BehaviorClass": [("in", "USES_BEHAVIOR", "DetectionRule", 2, "탐지 규칙"),
                      ("in", "CLASSIFIED_AS", "LogEventType", 2, "로그 이벤트 유형")],
    "DetectionRule": [("out", "USES_BEHAVIOR", "BehaviorClass", 2, "사용 행위 분류")],
    "DefensiveTechnique": [("in", "IMPLEMENTS", "ResponseAction", 2, "구현 대응 조치")],
    "Technique": [("out", "BELONGS_TO_TACTIC", "Tactic", 2, "전술")],
}
# 로그 모드: 시드 = 행위 분류(BehaviorClass). 분석가가 로그 한 건에서 알고 싶은 순서대로
EVENT_EXPAND1 = {
    "BehaviorClass": [("out", "SUGGESTS_TECHNIQUE", "Technique", 5, "시사 기법"),
                      ("in", "USES_BEHAVIOR", "DetectionRule", 3, "이 행위를 보는 탐지 규칙"),
                      ("out", "INVESTIGATE_WITH", "InvestigationQuery", 3, "조사 질의"),
                      ("in", "CLASSIFIED_AS", "LogEventType", 3, "같은 행위로 분류되는 이벤트")],
}
EVENT_EXPAND2 = {
    "Technique": [("out", "BELONGS_TO_TACTIC", "Tactic", 2, "전술"),
                  ("out", "MITIGATED_BY", "Mitigation", 2, "완화책"),
                  ("out", "RECOMMENDED_RESPONSE", "ResponseAction", 2, "권고 대응")],
    "DetectionRule": [("out", "DETECTS", "Technique", 2, "탐지 대상 기법")],
}
# search_knowledge 의 related 가 쓰던 키 이름으로 1-hop 을 묶기 위한 표: (관계, 방향[, 대상 라벨]) → 키
REL_KEYS = {
    ("BELONGS_TO_TACTIC", "out"): "tactics",
    ("SUB_TECHNIQUE_OF", "out"): "parent", ("SUB_TECHNIQUE_OF", "in"): "subtechniques",
    ("MITIGATED_BY", "out"): "mitigations", ("MITIGATED_BY", "in"): "techniques",
    ("DETECTS", "in", "DetectionStrategy"): "detection_strategies", ("DETECTS", "in", "DetectionRule"): "detection_rules",
    ("DETECTS", "out"): "techniques",
    ("SUGGESTS_TECHNIQUE", "in"): "behaviors", ("SUGGESTS_TECHNIQUE", "out"): "suggested_techniques",
    ("INVESTIGATE_WITH", "out"): "investigate", ("INVESTIGATE_WITH", "in"): "techniques",
    ("RECOMMENDED_RESPONSE", "out"): "responses", ("RECOMMENDED_RESPONSE", "in"): "techniques",
    ("PRECEDES", "out"): "next_techniques", ("PRECEDES", "in"): "previous_techniques",
    ("MAPPED_TO_D3FEND", "out"): "d3fend", ("MAPPED_TO_D3FEND", "in"): "mitigations",
    ("IMPLEMENTS", "in"): "responses", ("IMPLEMENTS", "out"): "d3fend",
    ("HAS_ANALYTIC", "out"): "analytics", ("HAS_ANALYTIC", "in"): "strategies",
    ("USES_BEHAVIOR", "out"): "behaviors", ("USES_BEHAVIOR", "in"): "detection_rules",
    ("CLASSIFIED_AS", "out"): "behaviors", ("CLASSIFIED_AS", "in"): "events",
    ("AFFECTS", "out"): "services",
}
TEXT_FIELDS = ("comment_en", "comment_ko", "condition_ko", "purpose_ko", "command")
EN_LABEL_KINDS = {"Technique", "Mitigation", "DefensiveTechnique", "DetectionStrategy", "Analytic", "Vulnerability", "Tactic"}
NOTE = "context 의 사실은 전부 온톨로지 관계를 따라간 결과다. allowed_ids 밖의 ID 는 인용하지 말 것. no_match 면 온톨로지에 없는 주제다."


def _id(p):
    return p.get("externalId") or str(p.get("uri", "")).split("#")[-1].split("/")[-1]

def _label(p, kind):
    return (p.get("label_en") or _name(p)) if kind in EN_LABEL_KINDS else _name(p)

def _text(p, n):
    for f in TEXT_FIELDS:
        v = p.get(f)
        if v:
            return _t(str(v), n)
    return ""

def _fact(p, kind, hop, seed_rank, seed_id, path, rel_shown, rel_type, direction, spec_idx, order, score=None):
    return {"id": _id(p), "kind": kind, "name": _label(p, kind), "hop": hop, "seed_rank": seed_rank, "seed": seed_id,
            "rel": rel_shown, "rel_type": rel_type, "dir": direction, "path": path, "text": _text(p, TEXT_LEN[hop]),
            "spec_idx": spec_idx, "order": order,
            "citable": bool(p.get("externalId")) and bool(RE_CITE.match(str(p.get("externalId")))),
            **({"score": round(float(score), 3)} if score is not None else {})}


# ---------------------------------------------------------------- ① 시드 (질문 모드)
def select_seeds(g, vec, kind, top_k, gap, floor):
    """floor·gap·종류별 상한·전술 제외를 차례로 적용. 버린 이유를 남긴다"""
    cands = g.vector_search(vec, min(top_k * 4, 50), kind)
    seeds, dropped, per_kind = [], [], collections.Counter()
    top = float(cands[0][1]) if cands else None
    for p, s in cands:
        s, k = float(s), p.get("kind")
        row = {"id": _id(p), "kind": k, "name": _label(p, k), "score": round(s, 3)}
        if s < floor:
            dropped.append({**row, "why": f"하한 {floor} 미만"})
        elif s < top - gap:
            dropped.append({**row, "why": f"1위({top:.3f})와 격차 {gap} 초과"})
        elif kind is None and k in SEED_EXCLUDE:
            dropped.append({**row, "why": "전술은 시드에서 제외(1-hop 으로 도달)"})
        elif kind is None and per_kind[k] >= SEED_KIND_CAP.get(k, 2):
            dropped.append({**row, "why": f"종류별 상한 {SEED_KIND_CAP.get(k, 2)} 초과"})
        elif len(seeds) >= top_k:
            dropped.append({**row, "why": f"top_k {top_k} 초과"})
        else:
            seeds.append((p, s)); per_kind[k] += 1
    return seeds, dropped


# ---------------------------------------------------------------- ② 확장 (공통)
def expand(g, seeds, hops, stat, table1=None, table2=None, seen=None):
    """표에 적힌 관계만 따라 fact 를 모은다. 같은 노드는 처음 닿은 경로로 한 번만"""
    table1, table2 = table1 or EXPAND1, table2 or EXPAND2
    facts, seen = [], set(seen or ())

    def step(uri, spec):
        d, rel, label, cap, shown = spec
        stat["queries"] += 1
        rows = g.out(uri, rel, label) if d == "out" else g.inn(uri, rel, label)
        return rows[:cap], (f"-{rel}->" if d == "out" else f"<-{rel}-"), label, shown, rel, d

    for rank, (p, score) in enumerate(seeds, 1):
        kind, sid = p.get("kind") or "?", _id(p)
        seen.add(sid)
        facts.append(_fact(p, kind, 0, rank, sid, "시드", "시드", "SEED", "", 0, len(facts), score))
        hop1 = []
        for i, spec in enumerate(table1.get(kind, [])):
            rows, arrow, label, shown, rel, d = step(p["uri"], spec)
            for q in rows:
                qid = _id(q)
                if qid in seen:
                    continue
                seen.add(qid); hop1.append((q, label))
                facts.append(_fact(q, label, 1, rank, sid, f"{sid} {arrow} {qid}", shown, rel, d, i, len(facts)))
        if hops >= 2:
            for q, label in hop1:
                for j, spec in enumerate(table2.get(label, [])):
                    rows, arrow, lab2, shown, rel, d = step(q["uri"], spec)
                    for r in rows:
                        rid = _id(r)
                        if rid in seen:
                            continue
                        seen.add(rid)
                        facts.append(_fact(r, lab2, 2, rank, sid, f"{_id(q)} {arrow} {rid}", shown, rel, d, j, len(facts)))
    return facts


# ---------------------------------------------------------------- ③ 압축 (공통)
def render(f):
    if f["rel_type"] == "EVENT":
        return f"[입력 이벤트] {f['id']} {f['name']} ({f['kind']}): {f['text']}"
    if f["hop"] == 0:
        tag = f"유사도 {f['score']}" if "score" in f else "로그 분류"
        return f"[시드 {f['seed_rank']}] {f['id']} {f['name']} ({f['kind']}, {tag}): {f['text']}"
    return f"  [{f['hop']}-hop {f['rel']}] {f['path']} | {f['name']} ({f['kind']}): {f['text']}"


def compress(facts, budget):
    """(hop, 관계 우선순위, 시드 순위) 순으로 채워 시드마다 고르게 들어가게 하고 budget 에서 멈춘다"""
    kept, lines, used, dropped = [], [], 0, 0
    for f in sorted(facts, key=lambda x: (x["hop"], x["spec_idx"], x["seed_rank"], x["order"])):
        line = render(f)
        if used + len(line) + 1 > budget:
            dropped += 1
            continue
        kept.append(f); lines.append(line); used += len(line) + 1
    return "\n".join(lines), kept, dropped


def _package(query, kind, seeds, dropped_seeds, facts, kept, text, dropped_facts, stat, t_embed, t_graph, extra=None):
    return {"query": query, "kind": kind,
            "seeds": [{"id": _id(p), "kind": p.get("kind"), "name": _label(p, p.get("kind")),
                       **({"score": round(s, 3)} if s is not None else {}),
                       "verificationStatus": p.get("verificationStatus"), "summary": _text(p, TEXT_LEN[0])} for p, s in seeds],
            "dropped_seeds": dropped_seeds, "no_match": not seeds,
            "context": kept, "facts_all": facts, "context_text": text,
            "allowed_ids": sorted({f["id"] for f in kept if f["citable"]}),
            "stats": {"candidates": len(seeds) + len(dropped_seeds), "seeds": len(seeds),
                      "seed_kinds": dict(collections.Counter(p.get("kind") for p, _ in seeds)),
                      "hop1": sum(1 for f in facts if f["hop"] == 1), "hop2": sum(1 for f in facts if f["hop"] == 2),
                      "facts_kept": len(kept), "facts_dropped": dropped_facts, "chars": len(text),
                      "embed_ms": t_embed, "graph_ms": t_graph, "graph_queries": stat["queries"]},
            "note": NOTE, **(extra or {})}


# ---------------------------------------------------------------- 질문 모드
def retrieve(g, query, kind=None, top_k=6, hops=2, gap=0.06, floor=0.82, budget=3000, vec=None):
    """vec 를 주면 임베딩을 건너뛴다 (호출자가 임베딩 오류를 따로 처리할 때)"""
    t0 = time.time()
    if vec is None:
        from embed_knowledge import query_vector
        vec = query_vector(query)
    t1 = time.time()
    stat = {"queries": 0}
    seeds, dropped_seeds = select_seeds(g, vec, kind, top_k, gap, floor)
    facts = expand(g, seeds, hops, stat) if seeds else []
    t2 = time.time()
    text, kept, dropped_facts = compress(facts, budget)
    return _package(query, kind, seeds, dropped_seeds, facts, kept, text, dropped_facts, stat,
                    int((t1 - t0) * 1000), int((t2 - t1) * 1000))


# ---------------------------------------------------------------- 로그 모드
def event_fields(event):
    """알림 JSON(dict) 또는 event_type 문자열 → (event_type, outcome|None)"""
    if isinstance(event, str):
        return event.strip(), None
    ev = str(event.get("event_type") or "").strip()
    outcome = (event.get("payload") or {}).get("outcome")
    return ev, (outcome if outcome in OUTCOMES else None)


def retrieve_for_event(g, event, outcome=None, hops=2, budget=3000):
    """로그 한 건 → 일치하는 LogEventType 의 BehaviorClass 를 시드로 (벡터 없음, 결정적) → 로그 모드 표로 확장 → 압축"""
    ev, oc = event_fields(event)
    oc = outcome if outcome is not None else oc
    if not RE_EVENT.match(ev):
        raise ValueError(f"이벤트 이름 형식이 아닙니다 (예: identity.authenticate): {ev[:40]!r}")
    t0 = time.time(); stat = {"queries": 1}
    events = sorted([e for e in g.all_of("LogEventType") if ev in _as_list(e.get("eventTypeName"))
                     and (oc is None or e.get("outcome") in (None, oc))], key=lambda x: x["uri"])
    seeds, seen_uri = [], set()
    for e in events:
        stat["queries"] += 1
        for b in g.out(e["uri"], "CLASSIFIED_AS", "BehaviorClass"):
            if b["uri"] not in seen_uri:
                seen_uri.add(b["uri"]); seeds.append((b, None))
    anchors = [_fact(e, "LogEventType", 0, 0, _id(e), "입력 이벤트", "입력 이벤트", "EVENT", "", 0, i) for i, e in enumerate(events)]
    facts = expand(g, seeds, hops, stat, EVENT_EXPAND1, EVENT_EXPAND2, seen={a["id"] for a in anchors}) if seeds else []
    for f in facts:                                               # 시드 줄에 위험 점수 표기
        if f["hop"] == 0:
            risk = next((p.get("riskScore") for p, _ in seeds if _id(p) == f["id"]), None)
            if risk is not None:
                f["text"] = f"riskScore {risk}. {f['text']}"
    for i, a in enumerate(anchors):
        a["order"] = -len(anchors) + i
    facts = anchors + facts
    t1 = time.time()
    text, kept, dropped_facts = compress(facts, budget)
    extra = {"event_type": ev, "outcome": oc,
             "matched_events": [{"id": _id(e), "name": _name(e), "outcome": e.get("outcome"),
                                 "verificationStatus": e.get("verificationStatus")} for e in events],
             "note": NOTE + (" 로그 모드: 시드는 벡터가 아니라 이벤트 유형의 행위 분류다." if seeds else
                             " 등록되지 않은 이벤트(온톨로지에 매핑 없음). 규칙 기반 탐지 대상이 아님")}
    return _package(ev, "event", seeds, [], facts, kept, text, dropped_facts, stat, 0, int((t1 - t0) * 1000), extra)


# ---------------------------------------------------------------- search_knowledge 연결용 보조
def rel_key(rel, direction, label):
    return REL_KEYS.get((rel, direction, label)) or REL_KEYS.get((rel, direction)) or rel.lower()


def related_by_seed(r):
    """시드별 1-hop 사실을 search_knowledge 의 related 가 쓰던 키 이름으로 묶는다 (예산과 무관하게 1-hop 전부, 값은 ID 목록)"""
    out = {s["id"]: {} for s in r["seeds"]}
    for f in r["facts_all"]:
        if f["hop"] != 1:
            continue
        out.setdefault(f["seed"], {}).setdefault(rel_key(f["rel_type"], f["dir"], f["kind"]), []).append(
            f["id"])                                        # 이름·설명은 context_text 가 담당 (중복 제거)
    for s in r["seeds"]:
        rel = out[s["id"]]
        if s["kind"] == "Technique":
            n_rules, n_beh = len(rel.get("detection_rules", [])), len(rel.get("behaviors", []))
            rel["openstack_detection"] = {"detectable": n_rules + n_beh > 0, "rules": n_rules, "behaviors": n_beh,
                                          "note": "1-hop 상한 안에서 센 값. 정확한 목록은 lookup_technique"}
        if s["kind"] == "Vulnerability":
            rel.setdefault("services", []); rel["note"] = "취약점은 공격 기법과 연결되어 있지 않음 (서비스 기준)"
    return out


def cite_ids(r):
    """인용 가능 ID: 시드 + 1-hop 전부 + 예산 안에 채택된 2-hop 중 공식 ID 형식"""
    ids = {f["id"] for f in r["facts_all"] if f["hop"] <= 1 and f["citable"]}
    ids |= {f["id"] for f in r["context"] if f["citable"]}
    return sorted(ids)


# ---------------------------------------------------------------- CLI
def _summary(r):
    s = r["stats"]
    seeds = [(x["id"], x.get("score", "분류")) for x in r["seeds"]]
    return (f"요약 | 시드 {seeds} {s['seed_kinds']} | 버린 후보 {len(r['dropped_seeds'])} "
            f"| 1-hop {s['hop1']} 2-hop {s['hop2']} | 채택 {s['facts_kept']} 버림 {s['facts_dropped']} | {s['chars']}자 "
            f"| 임베딩 {s['embed_ms']}ms 그래프 {s['graph_ms']}ms({s['graph_queries']}질의) | no_match={r['no_match']}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("query", nargs="?"); ap.add_argument("--kind"); ap.add_argument("--top-k", type=int, default=6)
    ap.add_argument("--hops", type=int, default=2); ap.add_argument("--gap", type=float, default=0.06)
    ap.add_argument("--floor", type=float, default=0.82); ap.add_argument("--budget", type=int, default=3000)
    ap.add_argument("--event-type"); ap.add_argument("--outcome")
    ap.add_argument("--event-file"); ap.add_argument("--event-index", type=int, default=0)
    ap.add_argument("--json"); ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args()
    event = None
    if a.event_file:
        with open(a.event_file, encoding="utf-8") as fh:
            lines = [l for l in fh if l.strip()]
        event = json.loads(lines[a.event_index])
    elif a.event_type:
        event = a.event_type
    elif not a.query:
        ap.error("질문 또는 --event-type / --event-file 중 하나가 필요합니다")
    import embed_knowledge as E
    d = E.connect()
    try:
        g = Neo4jGraph(d)
        r = retrieve_for_event(g, event, a.outcome, a.hops, a.budget) if event is not None else \
            retrieve(g, a.query, a.kind, a.top_k, a.hops, a.gap, a.floor, a.budget)
    finally:
        d.close()
    if event is not None:
        print(f"이벤트 {r['event_type']} / outcome {r['outcome']} → 일치 이벤트 유형 {[m['id'] for m in r['matched_events']]}")
    print(_summary(r))
    for x in r["dropped_seeds"]:
        print(f"  버림: {x['id']} {x['name']} ({x['kind']}) {x['score']} — {x['why']}")
    if not a.quiet:
        print(r["context_text"])
    if a.json:
        json.dump(r, open(a.json, "w", encoding="utf-8"), ensure_ascii=False, indent=1)


if __name__ == "__main__":
    main()
