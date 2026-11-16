"""Bounded, read-only Neo4j exploration. No Streamlit or operational side effects."""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
import re
import time
from typing import Any

from neo4j import READ_ACCESS
from neo4j.exceptions import AuthError, ServiceUnavailable, SessionExpired

KNOWN_LABELS = (
    "Technique", "DetectionStrategy", "DetectionRule", "LogEventType",
    "ObservedEvent", "Alert", "Incident",
)
COLORS = dict(zip(KNOWN_LABELS, (
    "#609dff", "#43d4cf", "#68d997", "#f0cf66", "#ffa461", "#ff707e", "#b98bff",
)))
OTHER_COLOR = "#a3adbe"
# Includes the existing loader/dashboard's externalId, ruleLabel and recordId.
# Missing properties are legal in Cypher; no inferred relationships are introduced.
SEARCH_KEYS = (
    "id", "name", "uri", "title", "eventTypeName", "ruleId", "techniqueId",
    "recordId", "externalId", "external_id", "alertId", "incidentId", "uuid",
    "ruleLabel", "label", "label_ko", "label_en", "name_ko", "name_en", "eventId", "reportId",
)
PREVIEW_KEYS = SEARCH_KEYS + ("severity", "status", "detectedAt", "description")
IDENTITY_KEYS = ("recordId", "externalId", "external_id", "techniqueId", "ruleId",
                 "alertId", "incidentId", "id", "uri", "uuid")
NAME_KEYS = ("name", "name_ko", "name_en", "title", "ruleLabel", "label_ko", "label_en", "label", "eventTypeName")
MAX_RESULTS = 50
MAX_EDGES = 8000
QUERY_SECONDS = 4.0
OPERATION_SECONDS = 12.0
LABEL_LIMIT = 256
SECRET_KEY = re.compile(r"password|passwd|secret|token|credential|private.?key|authorization", re.I)

# Projection deliberately excludes rawLog, fieldsJson, embeddings and arbitrary values.
NODE_PROJECTION = """{element_id: elementId(n), labels: labels(n), preview:
 [k IN $preview_keys WHERE n[k] IS NOT NULL | {key: k, value:
 CASE WHEN toStringOrNull(n[k]) IS NOT NULL THEN left(toStringOrNull(n[k]), 240)
 ELSE [v IN n[k][..8] | left(toStringOrNull(v), 240)] END}]}"""
PING = "RETURN 1 AS ok"
LABELS = "CALL db.labels() YIELD label RETURN label LIMIT $limit"
INDEXES = """SHOW INDEXES YIELD type, entityType, labelsOrTypes, properties, state
 WHERE entityType = 'NODE' AND state = 'ONLINE' AND type IN ['RANGE', 'TEXT']
 RETURN type, labelsOrTypes, properties LIMIT $limit"""
PROPERTY_SAMPLE = """MATCH (n) WITH n LIMIT $sample
 UNWIND keys(n) AS property RETURN DISTINCT property LIMIT $limit"""
SEARCH = """MATCH (n)
 WHERE ($label IS NULL OR $label IN labels(n))
 AND any(k IN $search_keys WHERE any(v IN
   CASE WHEN toStringOrNull(n[k]) IS NOT NULL THEN [n[k]] ELSE coalesce(n[k], []) END
   WHERE toLower(toStringOrNull(v)) CONTAINS $term))
 AND NOT elementId(n) IN $exclude
 RETURN """ + NODE_PROJECTION + " AS node LIMIT $limit"
BROWSE = """MATCH (n)
 WHERE ($label IS NULL OR $label IN labels(n))
 AND ($after IS NULL OR elementId(n) > $after)
 WITH n ORDER BY elementId(n) LIMIT $limit
 RETURN """ + NODE_PROJECTION + " AS node ORDER BY node.element_id"
# Log-only browsing can use a label scan without changing any DB indexes.
BROWSE_LOGS = BROWSE.replace("MATCH (n)", "MATCH (n:ObservedEvent)", 1)
ROOT = "MATCH (n) WHERE elementId(n) = $id RETURN " + NODE_PROJECTION + " AS node LIMIT 1"
EXPAND = """UNWIND $frontier AS fid
 MATCH (a) WHERE elementId(a) = fid
 CALL {
   WITH a
   MATCH (a)-[r]-(n)
   RETURN r, n LIMIT $per_parent
 }
 RETURN """ + NODE_PROJECTION + """ AS node,
 {id: elementId(r), source: elementId(startNode(r)),
  target: elementId(endNode(r)), type: type(r)} AS edge
 LIMIT $limit"""
INTERNAL_EDGES = """UNWIND $ids AS aid
 MATCH (a) WHERE elementId(a) = aid
 MATCH (a)-[r]->(b)
 WHERE elementId(b) IN $ids AND NOT elementId(r) IN $exclude
 RETURN {id: elementId(r), source: elementId(a), target: elementId(b), type: type(r)} AS edge
 LIMIT $limit"""
# All property names can be inspected, but large values are bounded on the server.
PROPERTIES = """MATCH (n) WHERE elementId(n) = $id
 RETURN [k IN keys(n) | {key: k,
 value: CASE WHEN toStringOrNull(n[k]) IS NOT NULL THEN left(toStringOrNull(n[k]), $chars)
 ELSE [v IN n[k][..100] | left(toStringOrNull(v), $chars)] END,
 truncated: CASE WHEN toStringOrNull(n[k]) IS NOT NULL THEN size(toStringOrNull(n[k])) > $chars
 ELSE size(n[k]) > 100 OR any(v IN n[k] WHERE size(toStringOrNull(v)) > $chars) END}]
 AS entries LIMIT 1"""


class GraphError(Exception):
    """Only fixed, credential-free messages cross the UI boundary."""


def safe_error(exc: Exception) -> str:
    if isinstance(exc, GraphError):
        return str(exc)
    if isinstance(exc, AuthError):
        return "Neo4j 인증에 실패했습니다. 서버의 연결 계정 설정을 확인하세요."
    code = str(getattr(exc, "code", ""))
    if "Forbidden" in code or "Unauthorized" in code:
        return "Neo4j 읽기 권한이 부족합니다. 연결 계정의 조회 권한을 확인하세요."
    if "TimedOut" in code or "Terminated" in code or isinstance(exc, TimeoutError):
        return "조회 제한 시간을 초과했습니다. 노드 유형을 지정하거나 검색 범위를 줄이세요."
    if isinstance(exc, (ServiceUnavailable, SessionExpired, OSError)):
        return "Neo4j에 연결할 수 없습니다. 서버의 연결 주소와 네트워크 상태를 확인하세요."
    return "Neo4j 조회를 완료하지 못했습니다. 연결 상태와 서버 버전·조회 권한을 확인하세요."


def _identifier(value: str) -> str:
    """Only DB-reported metadata, never search input, is passed here."""
    return "`" + value.replace("`", "``") + "`"


def node_dict(raw: dict) -> dict:
    props = {p["key"]: p.get("value") for p in raw.get("preview", [])
             if p.get("key") in PREVIEW_KEYS}
    labels = list(raw.get("labels") or [])
    kind = next((x for x in KNOWN_LABELS if x in labels), labels[0] if labels else "기타")
    def text(keys: tuple) -> str:
        for k in keys:
            v = props.get(k)
            if v:
                return ", ".join(map(str, v)) if isinstance(v, list) else str(v)
        return ""
    identity = text(IDENTITY_KEYS) or str(raw["element_id"])
    name = text(NAME_KEYS) or identity
    return {"id": str(raw["element_id"]), "labels": labels, "kind": kind,
            "identifier": identity, "name": name, "color": COLORS.get(kind, OTHER_COLOR),
            "properties": props}


@dataclass
class Schema:
    labels: list[str] = field(default_factory=list)
    properties: list[str] = field(default_factory=list)
    indexes: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


class GraphStore:
    def __init__(self, driver: Any, database: str):
        self.driver = driver
        self.database = database

    def _read(self, query: str, params: dict | None = None, *, deadline: float | None = None) -> list[dict]:
        remaining = QUERY_SECONDS if deadline is None else min(QUERY_SECONDS, deadline - time.monotonic())
        if remaining <= 0:
            raise GraphError("조회 제한 시간을 초과했습니다. 노드 유형을 지정하거나 검색 범위를 줄이세요.")
        try:
            # Explicit transaction: no automatic retry; timeout covers the entire query.
            # No caller-provided Cypher is accepted by any public operation.
            with self.driver.session(database=self.database, default_access_mode=READ_ACCESS,
                                     fetch_size=128) as session:
                with session.begin_transaction(timeout=remaining) as tx:
                    rows = tx.run(query, params or {}).data()
                    # Explicitly close with ROLLBACK even for successful reads.
                    tx.rollback()
                    return rows
        except Exception as exc:
            raise GraphError(safe_error(exc)) from None

    def inspect(self) -> Schema:
        deadline = time.monotonic() + OPERATION_SECONDS
        self._read(PING, deadline=deadline)
        labels = self._read(LABELS, {"limit": LABEL_LIMIT + 1}, deadline=deadline)
        schema = Schema(labels=sorted({r["label"] for r in labels[:LABEL_LIMIT]}))
        if len(labels) > LABEL_LIMIT:
            schema.notes.append("노드 유형 목록은 256개까지 표시합니다. '전체' 검색은 모든 유형을 포함합니다.")
        try:
            schema.indexes = self._read(INDEXES, {"limit": 128}, deadline=deadline)
        except GraphError:
            schema.notes.append("인덱스 메타데이터를 읽지 못해 제한 시간 내 일반 검색을 사용합니다.")
        try:
            schema.properties = [r["property"] for r in self._read(
                PROPERTY_SAMPLE, {"sample": 256, "limit": 256}, deadline=deadline)]
        except GraphError:
            schema.notes.append("속성 표본 조회를 완료하지 못했습니다. 기존 스키마의 검색 속성을 사용합니다.")
        return schema

    def browse(self, label: str | None, schema: Schema, after: str | None = None) -> dict:
        """Visit every matching node in bounded pages, without a keyword."""
        if label is not None and label not in set(schema.labels).union(KNOWN_LABELS):
            raise GraphError("허용되지 않은 노드 유형입니다. 목록에서 다시 선택하세요.")
        if after is not None and (not isinstance(after, str) or not after or len(after) > 512):
            raise GraphError("목록 위치가 올바르지 않습니다. 새로고침 후 다시 조회하세요.")
        rows = self._read(BROWSE_LOGS if label == "ObservedEvent" else BROWSE,
                          {"label": label, "after": after, "limit": MAX_RESULTS + 1,
                           "preview_keys": list(PREVIEW_KEYS)})
        nodes = [node_dict(row["node"]) for row in rows[:MAX_RESULTS]]
        has_more = len(rows) > MAX_RESULTS
        return {"nodes": nodes, "limited": False,
                "next_cursor": nodes[-1]["id"] if has_more and nodes else None}

    def search(self, term: str, label: str | None, schema: Schema, *, after: str | None = None) -> dict:
        term = term.strip()
        if not term:
            return self.browse(label, schema, after)
        if len(term) > 200:
            raise GraphError("검색어는 200자 이하로 입력하세요.")
        if label is not None and label not in set(schema.labels).union(KNOWN_LABELS):
            raise GraphError("허용되지 않은 노드 유형입니다. 목록에서 다시 선택하세요.")
        deadline = time.monotonic() + OPERATION_SECONDS
        result: dict[str, dict] = {}
        # Prefer exact, indexed identifiers before a bounded substring fallback.
        # Limit fast-path requests as well as result size for predictable latency.
        plans = []
        for index in schema.indexes:
            props = index.get("properties") or []
            if len(props) != 1 or props[0] not in SEARCH_KEYS:
                continue
            for index_label in index.get("labelsOrTypes") or []:
                if index_label not in schema.labels:
                    continue
                if label and index_label != label:
                    continue
                plans.append((index_label, props[0]))
        for ilabel, prop in sorted(set(plans), key=lambda x: (x[1] not in IDENTITY_KEYS, x))[:6]:
            q = ("MATCH (n:" + _identifier(ilabel) + ") WHERE n." + _identifier(prop)
                 + " = $exact RETURN " + NODE_PROJECTION + " AS node LIMIT $limit")
            rows = self._read(q, {"exact": term, "limit": MAX_RESULTS + 1,
                                  "preview_keys": list(PREVIEW_KEYS)}, deadline=deadline)
            for row in rows:
                n = node_dict(row["node"]); result[n["id"]] = n
            if len(result) > MAX_RESULTS:
                break
        if len(result) <= MAX_RESULTS:
            rows = self._read(SEARCH, {"label": label, "term": term.casefold(),
                "search_keys": list(SEARCH_KEYS), "preview_keys": list(PREVIEW_KEYS),
                "exclude": list(result), "limit": MAX_RESULTS + 1 - len(result)}, deadline=deadline)
            for row in rows:
                n = node_dict(row["node"]); result[n["id"]] = n
        return {"nodes": list(result.values())[:MAX_RESULTS], "limited": len(result) > MAX_RESULTS}

    def graph(self, root_id: str, depth: int = 1, max_nodes: int = 50) -> dict:
        if depth not in (1, 2) or max_nodes not in (20, 50, 100, 200, 500, 1000, 1500, 3000):
            raise GraphError("탐색 깊이와 표시 노드 수를 목록에서 선택하세요.")
        deadline = time.monotonic() + OPERATION_SECONDS
        rows = self._read(ROOT, {"id": root_id, "preview_keys": list(PREVIEW_KEYS)}, deadline=deadline)
        if not rows:
            raise GraphError("선택한 노드가 더 이상 존재하지 않습니다. 다시 검색하세요.")
        root = node_dict(rows[0]["node"])
        nodes = {root["id"]: root}; edges: dict[str, dict] = {}
        frontier = [root_id]; limited = False
        for _ in range(depth):
            if not frontier:
                break
            # At most 301 rows per hop, including a sentinel to detect truncation.
            rows = self._read(EXPAND, {"frontier": frontier, "per_parent": MAX_EDGES + 1,
                "limit": MAX_EDGES + 1, "preview_keys": list(PREVIEW_KEYS)}, deadline=deadline)
            if len(rows) > MAX_EDGES:
                limited = True
            next_frontier = []
            for row in rows[:MAX_EDGES]:
                edge = row["edge"]; n = node_dict(row["node"])
                if edge["id"] in edges:
                    continue
                if len(edges) >= MAX_EDGES or (n["id"] not in nodes and len(nodes) >= max_nodes):
                    limited = True; continue
                # Every admitted node has a real retained path back to the root.
                if n["id"] not in nodes:
                    nodes[n["id"]] = n; next_frontier.append(n["id"])
                if edge["source"] in nodes and edge["target"] in nodes:
                    edges[edge["id"]] = edge
            frontier = next_frontier
        if len(edges) < MAX_EDGES:
            remaining = MAX_EDGES - len(edges)
            rows = self._read(INTERNAL_EDGES, {"ids": list(nodes), "exclude": list(edges),
                                               "limit": remaining + 1}, deadline=deadline)
            limited = limited or len(rows) > remaining
            for row in rows[:remaining]:
                edge = row["edge"]
                if edge["source"] in nodes and edge["target"] in nodes:
                    edges[edge["id"]] = edge
        graph = {"root": root_id, "nodes": list(nodes.values()), "edges": list(edges.values()),
                 "depth": depth, "max_nodes": max_nodes, "limited": limited}
        distances = paths_from(graph, root_id, 2)
        for n in graph["nodes"]:
            n["hop"] = len(distances.get(n["id"], []))
        return graph

    def properties(self, node_id: str) -> dict:
        rows = self._read(PROPERTIES, {"id": node_id, "chars": 65536})
        if not rows:
            raise GraphError("선택한 노드가 더 이상 존재하지 않습니다. 다시 검색하세요.")
        entries = rows[0]["entries"]
        values = {p["key"]: "[비공개]" if SECRET_KEY.search(p["key"]) else p["value"] for p in entries}
        return {"values": values, "limited": any(p.get("truncated") for p in entries)}


def paths_from(graph: dict, node_id: str, max_depth: int = 2) -> dict[str, list[dict]]:
    """Shortest paths in the DISPLAYED subgraph, retaining real edge directions."""
    adjacency: dict[str, list[tuple[str, dict]]] = {}
    for e in graph["edges"]:
        adjacency.setdefault(e["source"], []).append((e["target"], e))
        adjacency.setdefault(e["target"], []).append((e["source"], e))
    paths: dict[str, list[dict]] = {node_id: []}; queue = deque([node_id])
    while queue:
        src = queue.popleft()
        if len(paths[src]) >= max_depth:
            continue
        for dst, edge in adjacency.get(src, []):
            if dst in paths:
                continue
            paths[dst] = paths[src] + [{"from": src, "to": dst, "edge": edge}]
            queue.append(dst)
    return paths


def graph_payload(graph: dict, selected: str, view_key: str, revision: int) -> dict:
    """Only short, allowlisted labels reach the browser visualization."""
    return {"root": graph["root"], "selected": selected, "view_key": view_key, "revision": revision,
            "nodes": [{"id": n["id"], "label": n["name"][:45], "kind": n["kind"],
                       "identifier": n["identifier"][:100], "color": n["color"], "hop": n["hop"]}
                      for n in graph["nodes"]],
            "edges": graph["edges"]}
