"""Isolated 3K1H knowledge graph page; every session key belongs to this feature."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
import time
from uuid import uuid4
from zoneinfo import ZoneInfo

from neo4j import GraphDatabase
import streamlit as st
from streamlit.components.v2 import component

from cto_knowledge_graph_store import (
    COLORS, KNOWN_LABELS, OTHER_COLOR, GraphError, GraphStore, Schema,
    graph_payload, paths_from, safe_error,
)

STATE_KEY = "_cto_kg_state"
ASSETS = Path(__file__).with_name("cto_knowledge_graph_assets")


def new_state() -> dict:
    return {"term": "", "label": "전체", "depth": 1, "max_nodes": 50,
            "schema": None, "schema_at": 0.0, "status": "미확인", "checked": "",
            "error": "", "hits": [], "search_limited": False, "searched": False,
            "graph": None, "selected": None, "revision": 0, "details": {},
            "view_key": uuid4().hex, "result_conditions": None, "pending_root": None,
            "result_mode": None, "browse_page": 0, "browse_cursors": [None],
            "browse_next": None, "pending_page": None, "pending_all_logs": False,
            "whole_graph_mode": False}


@st.cache_resource(show_spinner=False)
def _driver(uri: str, user: str, password: str):
    # Same configuration/credential provider as dashboard, independent bounded pool.
    return GraphDatabase.driver(uri, auth=(user, password), connection_timeout=3,
                                connection_acquisition_timeout=4, max_transaction_retry_time=0,
                                max_connection_pool_size=4)


@st.cache_resource(show_spinner=False)
def _canvas_component():
    return component("cto_knowledge_graph_canvas_v1",
                     html=(ASSETS / "graph.html").read_text(encoding="utf-8"),
                     css=(ASSETS / "graph.css").read_text(encoding="utf-8"),
                     js=(ASSETS / "graph.js").read_text(encoding="utf-8"))


def _stamp(state: dict):
    state["status"] = "연결됨"
    state["checked"] = datetime.now(ZoneInfo("Asia/Seoul")).strftime("%Y-%m-%d %H:%M:%S KST")
    state["error"] = ""


def _failed(state: dict, exc: Exception):
    state["status"] = "조회 실패"
    state["error"] = safe_error(exc)
    # Never present stale results as current data after a failed refresh/search.
    state["graph"] = None
    state["hits"] = []
    state["selected"] = None
    state["details"] = {}
    state["browse_next"] = None
    state["pending_page"] = None


def _inspect(store: GraphStore, state: dict, force: bool = False):
    if force or state["schema"] is None or time.monotonic() - state["schema_at"] > 300:
        state["schema"] = store.inspect()
        state["schema_at"] = time.monotonic()
        _stamp(state)


def _load_graph(store: GraphStore, state: dict, root_id: str):
    state["whole_graph_mode"] = False
    state["graph"] = store.graph(root_id, state["depth"], state["max_nodes"])
    ids = {n["id"] for n in state["graph"]["nodes"]}
    if state["selected"] not in ids:
        state["selected"] = root_id
    state["revision"] += 1
    state["details"] = {}
    _stamp(state)


def _load_whole_graph(store: GraphStore, state: dict):
    """Wide overview mode: merge graphs from multiple current hit roots."""
    roots = []
    current = state["selected"] or (state["graph"] or {}).get("root")
    if current:
        roots.append(current)
    for node in state.get("hits") or []:
        nid = node.get("id")
        if nid and nid not in roots:
            roots.append(nid)
    if not roots:
        return

    max_nodes = max(20, int(state.get("max_nodes") or 50))
    # Keep the overview practical; many roots can produce a crowded canvas.
    max_roots = 8 if max_nodes >= 100 else 6 if max_nodes >= 50 else 4
    nodes_by_id = {}
    edges_by_id = {}
    limited = False
    used_roots = 0
    for rid in roots[:max_roots]:
        sub = store.graph(rid, state["depth"], max_nodes)
        used_roots += 1
        for node in sub.get("nodes", []):
            if node["id"] not in nodes_by_id:
                if len(nodes_by_id) >= max_nodes:
                    limited = True
                    break
                nodes_by_id[node["id"]] = node
        for edge in sub.get("edges", []):
            if edge["id"] not in edges_by_id and edge["source"] in nodes_by_id and edge["target"] in nodes_by_id:
                edges_by_id[edge["id"]] = edge
        limited = limited or bool(sub.get("limited"))
        if limited:
            break

    if used_roots < len(roots):
        limited = True
    state["whole_graph_mode"] = True
    state["graph"] = {
        "root": current or roots[0],
        "depth": state["depth"],
        "max_nodes": max_nodes,
        "limited": limited,
        "nodes": list(nodes_by_id.values()),
        "edges": list(edges_by_id.values()),
    }
    ids = {n["id"] for n in state["graph"]["nodes"]}
    if state["selected"] not in ids:
        state["selected"] = current if current in ids else (roots[0] if roots[0] in ids else next(iter(ids), None))
    state["revision"] += 1
    state["details"] = {}
    _stamp(state)


def _search(store: GraphStore, state: dict, refresh: bool = False, page: int | None = None):
    state["searched"] = True
    old_root = state["graph"]["root"] if state["graph"] else None
    state["graph"] = None
    state["hits"] = []
    state["search_limited"] = False
    state["pending_root"] = None
    state["details"] = {}
    state["result_conditions"] = (state["term"], state["label"])
    state["result_mode"] = "search" if state["term"].strip() else "browse"
    state["browse_next"] = None
    state["whole_graph_mode"] = False
    if page is None:
        state["browse_page"] = 0
        state["browse_cursors"] = [None]
    else:
        state["browse_page"] = page
    _inspect(store, state, force=refresh)
    label = None if state["label"] == "전체" else state["label"]
    if state["result_mode"] == "browse":
        result = store.search(state["term"], label, state["schema"],
                              after=state["browse_cursors"][state["browse_page"]])
        state["browse_next"] = result["next_cursor"]
    else:
        result = store.search(state["term"], label, state["schema"])
    state["hits"] = result["nodes"]
    state["search_limited"] = result["limited"]
    _stamp(state)
    if state["hits"]:
        ids = [n["id"] for n in state["hits"]]
        keep_root = refresh and old_root and (state["result_mode"] == "search" or old_root in ids)
        root = old_root if keep_root else ids[0]
        if not refresh:
            state["selected"] = root
        _load_graph(store, state, root)


def _widget_value(key: str, value):
    # Widget state can be removed on page navigation. Durable values stay in STATE_KEY.
    if st.session_state.get(key) != value:
        st.session_state[key] = value


def _reset():
    state = st.session_state.get(STATE_KEY, new_state())
    replacement = new_state()
    for key in ("schema", "schema_at", "status", "checked"):
        replacement[key] = state[key]
    st.session_state[STATE_KEY] = replacement
    for key in list(st.session_state):
        if key.startswith("cto_kg_"):
            del st.session_state[key]


def _remember(widget_key: str, state_key: str):
    st.session_state[STATE_KEY][state_key] = st.session_state[widget_key]


def _all_logs():
    state = st.session_state[STATE_KEY]
    state["term"] = ""
    state["label"] = "ObservedEvent"
    state["pending_all_logs"] = True
    state["pending_page"] = None


def _browse_step(delta: int):
    state = st.session_state[STATE_KEY]
    if state["result_mode"] != "browse" or state["result_conditions"] != (state["term"], state["label"]):
        return
    page = state["browse_page"]
    if delta == 1 and state["browse_next"] is not None:
        state["browse_cursors"] = state["browse_cursors"][:page + 1] + [state["browse_next"]]
        state["pending_page"] = page + 1
    elif delta == -1 and page > 0:
        state["pending_page"] = page - 1


def _canvas_selected():
    state = st.session_state.get(STATE_KEY)
    event = st.session_state.get("cto_kg_canvas", {}).get("selection")
    if not state or not state["graph"] or not isinstance(event, dict):
        return
    if event.get("revision") == state["revision"] and event.get("id") in {n["id"] for n in state["graph"]["nodes"]}:
        state["selected"] = event["id"]


def _detail_summary(store: GraphStore, state: dict):
    graph = state["graph"]
    by_id = {n["id"]: n for n in graph["nodes"]}
    node = by_id[state["selected"]]
    with st.container(border=True):
        st.subheader("선택 노드 상세 정보")
        st.text(node["name"])
        st.caption("노드 Label")
        st.text(", ".join(node["labels"]) or "(Label 없음)")
        st.caption("노드 식별자 / Neo4j elementId")
        st.code(node["identifier"], language=None)
        st.code(node["id"], language=None)
        if st.button("전체 그래프 보기", key="cto_kg_whole_graph", width="stretch"):
            with st.spinner("전체 그래프 개요를 조회합니다…"):
                _load_whole_graph(store, state)
            st.rerun()
        if st.button("선택 노드 중심으로 확장", key="cto_kg_expand", width="stretch"):
            with st.spinner("선택 노드의 실제 관계를 조회합니다…"):
                _load_graph(store, state, node["id"])
            st.rerun()
        with st.expander("주요 속성", expanded=False):
            st.json(node["properties"])
        with st.expander("전체 속성 확인"):
            st.caption("요청한 노드의 모든 속성명을 조회합니다. 큰 값은 속성당 65,536자·배열 100개까지 표시합니다.")
            if st.button("전체 속성 조회", key="cto_kg_properties"):
                with st.spinner("선택 노드 속성을 조회합니다…"):
                    state["details"][node["id"]] = store.properties(node["id"])
                    _stamp(state)
            detail = state["details"].get(node["id"])
            if detail:
                if detail["limited"]:
                    st.info("일부 대용량 속성 값은 표시 한도에서 잘렸습니다.")
                st.json(detail["values"])


def _detail_tables(state: dict):
    graph = state["graph"]
    by_id = {n["id"]: n for n in graph["nodes"]}
    node = by_id[state["selected"]]
    paths = paths_from(graph, node["id"])
    direct = []
    for edge in graph["edges"]:
        if node["id"] not in (edge["source"], edge["target"]):
            continue
        other = edge["target"] if edge["source"] == node["id"] else edge["source"]
        direct.append({"관계": edge["type"], "방향": "나가는 관계 →" if edge["source"] == node["id"] else "들어오는 관계 ←",
                       "연결 노드": by_id[other]["name"], "유형": by_id[other]["kind"]})

    related = []
    for target, path in paths.items():
        if not path:
            continue
        other = by_id[target]
        route = node["name"]
        for step in path:
            edge = step["edge"]
            if edge["source"] == step["from"]:
                route += " —[" + edge["type"] + "]→ "
            else:
                route += " ←[" + edge["type"] + "]— "
            route += by_id[step["to"]]["name"]
        related.append({"노드": other["name"], "유형": other["kind"],
                        "연결": "직접 · 1-hop" if len(path) == 1 else "간접 · 2-hop", "실제 경로": route})

    st.markdown("**연결된 관계와 노드**")
    if direct:
        st.dataframe(direct, hide_index=True, width="stretch")
    else:
        st.info("표시 범위에 연결된 관계가 없습니다.")

    st.markdown("**관련 공격 기법·탐지 규칙 및 보안 노드**")
    if related:
        st.dataframe(sorted(related, key=lambda r: (r["유형"] not in ("Technique", "DetectionRule"), r["연결"])),
                     hide_index=True, width="stretch")
    else:
        st.caption("표시 범위에서 관련 노드가 확인되지 않았습니다.")
    st.caption("위 목록과 직접·간접 구분은 현재 표시된 그래프 내 최단 경로 기준입니다. 화살표는 DB 관계 방향입니다.")


@st.fragment
def render_knowledge_graph(uri: str, user: str, database: str, password_provider, *, _store=None):
    """No automatic polling. _store is a dependency injection seam for isolated tests."""
    st.session_state.setdefault(STATE_KEY, new_state())
    state = st.session_state[STATE_KEY]
    # Existing live sessions can predate the browsing fields; keep all old values.
    for key, default in new_state().items():
        state.setdefault(key, default)
    st.subheader("Neo4j 지식 그래프")
    # V11: keep the filter controls close to the canvas without altering other pages.
    st.markdown("""<style>
    .st-key-cto_kg_filters { margin-bottom: -0.5rem !important; }
    .st-key-cto_kg_filters [data-testid="stCaptionContainer"] { margin-bottom: -0.4rem !important; }
    </style>""", unsafe_allow_html=True)
    st.caption("온톨로지에 저장된 공격 기법, 탐지 규칙, 로그 이벤트 및 보안 경보 간의 연결 관계를 탐색합니다.")
    cards = st.container()
    error_box = st.container()
    try:
        if _store is None:
            password = password_provider()
            if not password:
                raise GraphError("Neo4j 연결 자격 증명이 설정되지 않았습니다. 서버 설정을 확인하세요.")
            store = GraphStore(_driver(uri, user, password), database)
        else:
            store = _store
        if state["schema"] is None and not state["error"]:
            with st.spinner("Neo4j 연결과 노드 유형을 확인합니다…"):
                _inspect(store, state)
    except Exception as exc:
        _failed(state, exc)
        store = None
    schema = state["schema"] or Schema()
    labels = ["전체", *KNOWN_LABELS, *sorted(set(schema.labels) - set(KNOWN_LABELS))]
    if state["label"] not in labels:
        state["label"] = "전체"
    with st.container(border=True, key="cto_kg_filters"):
        for widget, field in (("cto_kg_label", "label"),
                              ("cto_kg_depth", "depth"), ("cto_kg_max_nodes", "max_nodes")):
            _widget_value(widget, state[field])
        a, b, c = st.columns([2, 1, 1])
        a.selectbox("노드 유형", labels, key="cto_kg_label", on_change=_remember, args=("cto_kg_label", "label"))
        b.selectbox("탐색 깊이", [1, 2], key="cto_kg_depth", format_func=lambda x: str(x) + "-hop",
                    on_change=_remember, args=("cto_kg_depth", "depth"))
        c.selectbox("최대 표시 노드 수", [20, 50, 100, 200, 500, 1000, 1500, 3000], key="cto_kg_max_nodes", format_func=lambda x: str(x) + "개",
                    on_change=_remember, args=("cto_kg_max_nodes", "max_nodes"))
        st.caption("선택한 노드 유형의 목록을 조회합니다. 로그를 보려면 노드 유형에서 ObservedEvent를 선택하세요.")
        a, c, d = st.columns([1, 1, 1])
        search = a.button("전체 불러오기", key="cto_kg_search", type="primary", width="stretch")
        c.button("초기화", key="cto_kg_reset", on_click=_reset, width="stretch")
        refresh = d.button("새로고침", key="cto_kg_refresh", width="stretch")
    try:
        all_logs = state.pop("pending_all_logs", False)
        page = state.pop("pending_page", None)
        if search or refresh or all_logs:
            if store is None:
                password = password_provider()
                if not password:
                    raise GraphError("Neo4j 연결 자격 증명이 설정되지 않았습니다. 서버 설정을 확인하세요.")
                store = GraphStore(_driver(uri, user, password), database)
            with st.spinner("Neo4j에서 그래프 대상을 조회합니다…"):
                _search(store, state, refresh=refresh)
        elif page is not None:
            with st.spinner("다음 목록을 조회합니다…"):
                _search(store, state, page=page)
        elif state["graph"] and (state["depth"], state["max_nodes"]) != (state["graph"]["depth"], state["graph"]["max_nodes"]):
            with st.spinner("탐색 범위를 변경합니다…"):
                if state.get("whole_graph_mode"):
                    _load_whole_graph(store, state)
                else:
                    _load_graph(store, state, state["graph"]["root"])
        if not state["searched"]:
            st.info("노드 유형을 선택한 뒤 '전체 불러오기'를 눌러 탐색을 시작하세요.")
        elif not state["hits"] and not state["error"]:
            st.info("조회된 노드가 없습니다. 조건을 변경하거나 새로고침하세요.")
        if state["search_limited"]:
            st.info("검색 결과는 최대 50개입니다. 노드 유형을 바꾸어 범위를 좁히세요.")
        if state["hits"] and not state["graph"]:
            hits = {n["id"]: n for n in state["hits"]}
            root = next(iter(hits), None)
            if root:
                with st.spinner("선택한 노드의 관계를 조회합니다…"):
                    state["selected"] = root
                    _load_graph(store, state, root)
        graph = state["graph"]
        if graph:
            if graph["limited"]:
                st.caption("표시 한도에 도달했습니다. 최대 " + str(graph["max_nodes"]) + "개 노드 범위에서 일부 관계만 표시됩니다. 다른 노드를 중심으로 탐색할 수 있습니다.")
            legend = " ".join('<span style="display:inline-block;margin:0 14px 8px 0"><span style="color:' + color + '">●</span> ' + name + '</span>'
                              for name, color in [*COLORS.items(), ("기타", OTHER_COLOR)])
            st.markdown(legend, unsafe_allow_html=True)
            by_id = {n["id"]: n for n in graph["nodes"]}
            selected = state.get("selected") if state.get("selected") in by_id else graph["root"] if graph["root"] in by_id else next(iter(by_id))
            state["selected"] = selected
            left, right = st.columns([1.85, 1], gap="large")
            with left:
                try:
                    result = _canvas_component()(key="cto_kg_canvas", height=570,
                        data=graph_payload(graph, selected, state["view_key"], state["revision"]),
                        on_selection_change=_canvas_selected)
                    event = result.get("selection")
                    if isinstance(event, dict) and event.get("revision") == state["revision"] and event.get("id") in by_id:
                        state["selected"] = event["id"]
                except Exception:
                    st.warning("그래프 화면을 표시하지 못했습니다. 아래 관계 표로 탐색할 수 있습니다.")
                    st.dataframe(graph["edges"], hide_index=True)
                st.caption("노드 클릭: 상세 정보 · 노드 드래그: 위치 이동 · 빈 공간 드래그: 화면 이동 · 휠 / + −: 확대·축소")
            with right:
                _detail_summary(store, state)
            _detail_tables(state)
        for note in schema.notes:
            st.caption(note)
    except Exception as exc:
        _failed(state, exc)
    with cards:
        a, b, c = st.columns(3)
        graph = state["graph"]
        a.metric("Neo4j 연결 상태", state["status"])
        b.metric("현재 결과 노드", len(graph["nodes"]) if graph else 0)
        c.metric("현재 결과 관계", len(graph["edges"]) if graph else 0)
        if state["checked"]:
            st.caption("마지막 조회 성공: " + state["checked"])
    if state["error"]:
        error_box.error(state["error"])
