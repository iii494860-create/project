#!/usr/bin/env python3
"""
embed_knowledge.py - 온톨로지 지식 노드를 벡터화해 Neo4j 벡터 색인을 만든다 (3K1H 캡스톤)

흐름: 지식 노드 읽기 → 종류별 문장 틀로 문장 생성 → Ollama /api/embed (32개씩, truncate=false) → 노드에 embedding·kind 저장
      → 벡터 색인 knowledge_embedding (4096차원, cosine, kind 로 거르기) → 캐시 파일에 벡터 보관

원칙
  - 지식 노드의 다른 속성·관계는 절대 건드리지 않는다 (추가하는 속성: embedding, kind, embedText, embedTextHash, embedModel, embedTruncated)
  - 문장은 정해진 틀로 프로그램이 만든다. 같은 노드는 항상 같은 문장.
  - 캐시(embeddings_cache.jsonl): uri + 문장 지문 + 모델이 같으면 Ollama 를 부르지 않는다. 지식층을 다시 적재한 뒤 --restore 로 복원.
  - Ollama 요청은 truncate=false: 문맥을 넘으면 조용히 잘리지 않고 오류로 멈춘다.
  - Cypher 는 Neo4j Cypher 25 공식 문법 (CREATE VECTOR INDEX ... WITH [...] OPTIONS {...}, db.create.setNodeVectorProperty).

사용법
  python embed_knowledge.py --dry-run                 # Neo4j 에서 읽어 문장·개수만 출력 (벡터화·저장 안 함)
  python embed_knowledge.py --dry-run --ttl out/ontology_all.ttl   # Neo4j 없이 .ttl 로 문장 확인
  python embed_knowledge.py                           # 벡터화 + 저장 + 색인
  python embed_knowledge.py --restore                 # 캐시만으로 복원 (Ollama 호출 없음)
환경 변수: NEO4J_URI(기본 neo4j://localhost:7687), NEO4J_USER, NEO4J_PASSWORD 또는 CTO_NEO4J_PASSWORD_FILE(~/.cto_neo4j_password),
          CTO_EMBED_URL(기본 http://127.0.0.1:11434), CTO_EMBED_MODEL(기본 qwen3-embedding:8b)
"""
import argparse, getpass, hashlib, json, os, sys, time, urllib.error, urllib.request

EMBED_URL = os.environ.get("CTO_EMBED_URL", "http://127.0.0.1:11434")
EMBED_MODEL = os.environ.get("CTO_EMBED_MODEL", "qwen3-embedding:8b")
DIM, BATCH, TEXT_MAX, INDEX = 4096, 32, 4000, "knowledge_embedding"   # 문장 상한 4000자 ≈ 영어 1000토큰
CACHE = "embeddings_cache.jsonl"
KINDS = ["Technique", "Mitigation", "DefensiveTechnique", "DetectionStrategy", "Analytic", "LogEventType",
         "BehaviorClass", "DetectionRule", "InvestigationQuery", "ResponseAction", "Vulnerability", "Tactic"]

# 종류별로 노드와 문장에 쓸 이웃 정보를 함께 읽는 질의 (읽기 전용, 코드 상수)
KIND_QUERIES = {
    "Technique": ("MATCH (n:Knowledge:Technique) OPTIONAL MATCH (n)-[:BELONGS_TO_TACTIC]->(t:Tactic) "
                  "RETURN properties(n) AS p, collect(DISTINCT coalesce(t.label_en, t.label)) AS x1, [] AS x2"),
    "LogEventType": ("MATCH (n:Knowledge:LogEventType) OPTIONAL MATCH (n)-[:EMITTED_BY]->(s:OpenStackService) "
                     "OPTIONAL MATCH (n)-[:CLASSIFIED_AS]->(b:BehaviorClass) "
                     "RETURN properties(n) AS p, collect(DISTINCT coalesce(s.label, s.label_ko)) AS x1, collect(DISTINCT b.label_ko) AS x2"),
}
KIND_QUERIES["Tactic"] = (                          # 전술: 소속 기법 이름을 함께 (전술 단독 질문의 검색 입구)
    "MATCH (n:Knowledge:Tactic) OPTIONAL MATCH (t:Technique)-[:BELONGS_TO_TACTIC]->(n) "
    "RETURN properties(n) AS p, collect(DISTINCT (coalesce(t.externalId, '') + ' ' + coalesce(t.label_en, ''))) AS x1, [] AS x2")
KIND_QUERIES["BehaviorClass"] = (
    "MATCH (n:Knowledge:BehaviorClass) OPTIONAL MATCH (n)-[:MATCHES_ACTION]->(a:ActionType) "
    "OPTIONAL MATCH (n)-[:SUGGESTS_TECHNIQUE]->(t:Technique) "
    "RETURN properties(n) AS p, collect(DISTINCT coalesce(a.label_ko, a.label)) AS x1, "
    "collect(DISTINCT (coalesce(t.externalId, '') + ' ' + coalesce(t.label_en, ''))) AS x2")
for _k in KINDS:
    KIND_QUERIES.setdefault(_k, f"MATCH (n:Knowledge:{_k}) RETURN properties(n) AS p, [] AS x1, [] AS x2")


def _s(v):
    if v is None:
        return ""
    return ", ".join(str(x) for x in v) if isinstance(v, list) else str(v)


def _clean(text):
    return " ".join(text.split())


def build_text(kind, p, x1=(), x2=()):
    """종류별 문장 틀. 속성이 없으면 그 부분을 비운다. 반환: (문장, 잘렸는지)"""
    # 이웃 목록(x1, x2)은 Cypher collect() 가 순서를 보장하지 않아 재적재 뒤 순서가 바뀔 수 있다.
    # 같은 노드는 항상 같은 문장이어야 캐시(--restore)가 맞으므로 정렬해서 쓴다.
    x1 = sorted(str(x) for x in (x1 or ()) if x)
    x2 = sorted(str(x) for x in (x2 or ()) if x)
    ext, en, ko = _s(p.get("externalId")), _s(p.get("label_en") or p.get("label")), _s(p.get("label_ko"))
    cen, cko = _s(p.get("comment_en")), _s(p.get("comment_ko"))
    if kind == "Technique":
        t = f"ATT&CK technique {ext} {en}. Tactics: {', '.join(x for x in x1 if x)}. {cen}"
    elif kind == "Mitigation":
        t = f"ATT&CK mitigation {ext} {en}. {cen}"
    elif kind == "DefensiveTechnique":
        t = f"D3FEND technique {ext} {en}. {cen}"
    elif kind in ("DetectionStrategy", "Analytic"):
        t = f"ATT&CK detection {ext} {en}. {cen}"
    elif kind == "LogEventType":
        t = f"OpenStack {', '.join(x for x in x1 if x)} log event {ko} ({_s(p.get('eventTypeName'))}). Behavior: {', '.join(x for x in x2 if x)}"
    elif kind == "BehaviorClass":                       # 행위 분류: CADF 행위와 연결된 기법을 함께 (검색의 다리 역할)
        t = (f"{ko or en}. {cko or cen}. Actions: {', '.join(x for x in x1 if x)}. "
             f"Related ATT&CK techniques: {', '.join(x.strip() for x in x2 if x and x.strip())}")
    elif kind == "DetectionRule":
        t = f"{ko or en}. {_s(p.get('condition_ko')) or cko or cen}"
    elif kind in ("InvestigationQuery", "ResponseAction"):
        t = f"{ko or en}. {_s(p.get('purpose_ko')) or cko or cen}. Command: {_s(p.get('command'))}"
    elif kind == "Vulnerability":
        t = f"OpenStack advisory {ext} {en}. {cen}"
    elif kind == "Tactic":
        t = f"ATT&CK tactic {ext} {en}. Techniques: {', '.join(x.strip() for x in x1 if x and x.strip())}"
    else:
        raise ValueError(kind)
    t = _clean(t).replace(" .", ".").replace("..", ".")
    return (t[:TEXT_MAX], True) if len(t) > TEXT_MAX else (t, False)


def text_hash(text, model=EMBED_MODEL):
    return hashlib.sha256((model + "\n" + text).encode("utf-8")).hexdigest()


# ------------------------------------------------------------------ 입력 (Neo4j 또는 .ttl)
class Neo4jSource:
    def __init__(self, driver, database="neo4j"):
        self.d, self.db = driver, database

    def rows(self, kind):
        from neo4j import RoutingControl
        recs, _, _ = self.d.execute_query(KIND_QUERIES[kind], database_=self.db, routing_=RoutingControl.READ)
        return [(dict(r["p"]), list(r["x1"]), list(r["x2"])) for r in recs]


class TtlSource:
    """Neo4j 없이 .ttl 로 문장을 확인할 때 (적재 스크립트와 같은 변환 규칙 사용)"""
    def __init__(self, ttl, schema="schema.ttl"):
        from load_neo4j import Plan
        plan = Plan(ttl, schema)
        self.nodes, self.rels = plan.nodes, plan.rels

    def _out(self, uri, rel, label):
        return [self.nodes[r["o"]]["props"] for r in self.rels.get(rel, []) if r["s"] == uri and label in self.nodes[r["o"]]["labels"]]

    def rows(self, kind):
        out = []
        for uri, v in self.nodes.items():
            if kind not in v["labels"]:
                continue
            x1, x2 = [], []
            if kind == "Technique":
                x1 = [t.get("label_en") or t.get("label") for t in self._out(uri, "BELONGS_TO_TACTIC", "Tactic")]
            elif kind == "LogEventType":
                x1 = [s.get("label") or s.get("label_ko") for s in self._out(uri, "EMITTED_BY", "OpenStackService")]
                x2 = [b.get("label_ko") for b in self._out(uri, "CLASSIFIED_AS", "BehaviorClass")]
            elif kind == "BehaviorClass":
                x1 = [a.get("label_ko") or a.get("label") for a in self._out(uri, "MATCHES_ACTION", "ActionType")]
                x2 = [f"{t.get('externalId', '')} {t.get('label_en', '')}" for t in self._out(uri, "SUGGESTS_TECHNIQUE", "Technique")]
            out.append((dict(v["props"]), x1, x2))
        return out


def collect_targets(source, kinds):
    targets, truncated = [], 0
    for kind in kinds:
        for p, x1, x2 in source.rows(kind):
            text, cut = build_text(kind, p, x1, x2)
            truncated += cut
            targets.append({"uri": p["uri"], "kind": kind, "text": text, "hash": text_hash(text), "truncated": cut})
    targets.sort(key=lambda t: (t["kind"], t["uri"]))
    return targets, truncated


# ------------------------------------------------------------------ Ollama
def embed(texts, tries=3):
    body = json.dumps({"model": EMBED_MODEL, "input": texts, "truncate": False, "keep_alive": "10m"}).encode("utf-8")
    req = urllib.request.Request(EMBED_URL.rstrip("/") + "/api/embed", data=body, headers={"Content-Type": "application/json"})
    for i in range(tries):
        try:
            with urllib.request.urlopen(req, timeout=600) as r:
                d = json.load(r)
            vecs = d.get("embeddings")
            if not vecs or len(vecs) != len(texts):
                raise RuntimeError(f"임베딩 개수 불일치: 요청 {len(texts)} / 응답 {len(vecs or [])}")
            bad = [i for i, v in enumerate(vecs) if len(v) != DIM]
            if bad:
                raise RuntimeError(f"차원이 {DIM}이 아닌 벡터: {len(bad)}개 (예: {len(vecs[bad[0]])})")
            return vecs
        except urllib.error.HTTPError as e:
            msg = e.read().decode("utf-8", "ignore")[:300]
            if e.code >= 500 and i < tries - 1:
                time.sleep(2 ** i); continue
            raise RuntimeError(f"임베딩 서버 오류 {e.code}: {msg}") from None
        except (urllib.error.URLError, TimeoutError) as e:
            if i < tries - 1:
                time.sleep(2 ** i); continue
            raise RuntimeError(f"임베딩 서버에 연결할 수 없음 ({EMBED_URL}): {e}") from None


def query_vector(question):
    """검색용: 공식 권고대로 질문에만 영어 지시문을 붙임 (Query: 뒤 공백 없음)"""
    task = ("Given a question about an OpenStack cloud security event or attack, retrieve relevant ATT&CK techniques, "
            "defenses, detection knowledge and OpenStack log events")
    return embed([f"Instruct: {task}\nQuery:{question}"])[0]


# ------------------------------------------------------------------ 캐시
def load_cache(path=CACHE):
    cache = {}
    if os.path.exists(path):
        for line in open(path, encoding="utf-8"):
            if line.strip():
                r = json.loads(line)
                if r.get("model") == EMBED_MODEL:
                    cache[(r["uri"], r["hash"])] = r["vec"]
    return cache


def append_cache(rows, path=CACHE):
    with open(path, "a", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps({"uri": r["uri"], "hash": r["hash"], "model": EMBED_MODEL, "vec": r["vec"]}) + "\n")


# ------------------------------------------------------------------ Neo4j 쓰기 (추가 속성만)
WRITE_Q = ("UNWIND $rows AS row MATCH (n:Knowledge {uri: row.uri}) "
           "SET n.kind = row.kind, n.embedText = row.text, n.embedTextHash = row.hash, n.embedModel = $model, "
           "n.embedTruncated = row.truncated "
           "WITH n, row CALL db.create.setNodeVectorProperty(n, 'embedding', row.vec) RETURN count(n) AS c")
INDEX_Q = (f"CREATE VECTOR INDEX {INDEX} IF NOT EXISTS FOR (n:Knowledge) ON (n.embedding) WITH [n.kind] "
           "OPTIONS {indexConfig: {`vector.dimensions`: $dim, `vector.similarity_function`: $sim}}")


WRITE_Q_FALLBACK = WRITE_Q.replace("WITH n, row CALL db.create.setNodeVectorProperty(n, 'embedding', row.vec) ",
                                   "SET n.embedding = row.vec ")


def write_vectors(driver, rows, database="neo4j", batch=50):
    """공식 프로시저(db.create.setNodeVectorProperty)로 저장. 문법 오류가 나면 일반 SET 으로 전환 (둘 다 벡터 색인에 유효)"""
    written, q = 0, WRITE_Q
    for i in range(0, len(rows), batch):
        params = {"rows": rows[i:i + batch], "model": EMBED_MODEL}
        try:
            recs, _, _ = driver.execute_query(q, params, database_=database)
        except Exception as e:
            if q is WRITE_Q and "Syntax" in type(e).__name__ + str(e):
                print(f"  프로시저 문장이 거부되어 SET 방식으로 전환: {str(e)[:120]}", file=sys.stderr)
                q = WRITE_Q_FALLBACK
                recs, _, _ = driver.execute_query(q, params, database_=database)
            else:
                raise
        written += recs[0]["c"]
    return written


def ensure_index(driver, database="neo4j", wait=60):
    driver.execute_query(INDEX_Q, {"dim": DIM, "sim": "cosine"}, database_=database)
    for _ in range(wait):
        recs, _, _ = driver.execute_query("SHOW VECTOR INDEXES YIELD name, state WHERE name = $n RETURN state",
                                          {"n": INDEX}, database_=database)
        if recs and recs[0]["state"] == "ONLINE":
            return "ONLINE"
        time.sleep(1)
    return recs[0]["state"] if recs else "없음"


def password():
    if os.environ.get("NEO4J_PASSWORD"):
        return os.environ["NEO4J_PASSWORD"]
    p = os.path.expanduser(os.environ.get("CTO_NEO4J_PASSWORD_FILE", "~/.cto_neo4j_password"))
    return open(p, encoding="utf-8").read().strip() if os.path.exists(p) else getpass.getpass("neo4j 비밀번호: ")


def connect():
    from neo4j import GraphDatabase
    d = GraphDatabase.driver(os.environ.get("NEO4J_URI", "neo4j://localhost:7687"),
                             auth=(os.environ.get("NEO4J_USER", "neo4j"), password()))
    d.verify_connectivity()
    return d


# ------------------------------------------------------------------ 실행
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true", help="문장·개수만 출력 (벡터화·저장 없음)")
    ap.add_argument("--ttl", help="Neo4j 대신 .ttl 로 문장 확인 (--dry-run 전용)")
    ap.add_argument("--restore", action="store_true", help="캐시만으로 복원 (Ollama 호출 없음)")
    ap.add_argument("--limit", type=int, default=0, help="시험용: 앞 N개만")
    ap.add_argument("--kinds", default=",".join(KINDS))
    ap.add_argument("--database", default="neo4j")
    a = ap.parse_args()
    kinds = [k for k in a.kinds.split(",") if k in KINDS]

    driver = None
    if a.ttl:
        if not a.dry_run:
            sys.exit("--ttl 은 --dry-run 과 함께만 쓸 수 있습니다")
        source = TtlSource(a.ttl)
    else:
        driver = connect()
        source = Neo4jSource(driver, a.database)
    targets, truncated = collect_targets(source, kinds)
    if a.limit:
        targets = targets[:a.limit]
    from collections import Counter
    print(f"대상 노드 {len(targets)}개: {dict(Counter(t['kind'] for t in targets))}")
    print(f"{TEXT_MAX}자 초과로 잘린 문장 {truncated}개, 모델 {EMBED_MODEL}, 차원 {DIM}")
    if a.dry_run:
        for kind in kinds:
            ex = next((t for t in targets if t["kind"] == kind), None)
            if ex:
                print(f"  [{kind}] {ex['text'][:160]}{'…' if len(ex['text']) > 160 else ''}")
        return

    cache = load_cache()
    todo = [t for t in targets if (t["uri"], t["hash"]) not in cache]
    print(f"캐시에서 재사용 {len(targets) - len(todo)}개, 새로 벡터화 {len(todo)}개")
    if todo and a.restore:
        sys.exit(f"--restore 인데 캐시에 없는 노드가 {len(todo)}개 있습니다 (문장이 바뀌었거나 처음 실행). --restore 없이 실행하세요.")
    t0 = time.time()
    for i in range(0, len(todo), BATCH):
        chunk = todo[i:i + BATCH]
        vecs = embed([t["text"] for t in chunk])
        for t, v in zip(chunk, vecs):
            t["vec"] = v
            cache[(t["uri"], t["hash"])] = v
        append_cache(chunk)
        print(f"  벡터화 {min(i + BATCH, len(todo))}/{len(todo)} ({time.time() - t0:.0f}초)", file=sys.stderr)
    for t in targets:
        t["vec"] = cache[(t["uri"], t["hash"])]

    written = write_vectors(driver, targets, a.database)
    state = ensure_index(driver, a.database)
    recs, _, _ = driver.execute_query(
        "MATCH (n:Knowledge) WHERE n.embedding IS NOT NULL RETURN count(n) AS c, min(size(n.embedding)) AS lo, max(size(n.embedding)) AS hi",
        database_=a.database)
    c, lo, hi = recs[0]["c"], recs[0]["lo"], recs[0]["hi"]
    print(f"벡터 저장 {written}/{len(targets)}, DB 에 벡터가 있는 노드 {c}개, 차원 {lo}~{hi}, 색인 {INDEX} {state}, "
          f"소요 {time.time() - t0:.0f}초")
    ok = written == len(targets) and c >= len(targets) and lo == hi == DIM and state == "ONLINE"
    print("전체 통과" if ok else "확인 필요")
    driver.close()
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
