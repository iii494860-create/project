#!/usr/bin/env python3
"""
engine.py - 온톨로지 기반 결정론적 위협 분석 엔진 v0.5 (3K1H 캡스톤)

역할 (LLM 없이 동작):
  로그(JSON 알림) → 이벤트 유형·행위 분류 → 탐지 규칙 실행 → 경보 → 사건 묶기
  → 자동 조사 명령 생성(인자는 로그 값으로 채움) → 대응 권고 → LLM 설명용 컨텍스트 생성
경보 여부는 이 엔진(규칙)이 결정한다. LLM 은 설명만 한다.

사용법:
  python engine.py --log sample_logs.jsonl                    # 경보를 한국어로 출력
  python engine.py --log sample_logs.jsonl --json alerts.json  # 경보를 JSON 으로 저장 (LLM 입력용)
  python engine.py --log normal_logs.jsonl --learn baseline.json   # 정상 로그로 기준선(사용자↔IP) 학습
  python engine.py --log x.jsonl --baseline baseline.json --allowlist allowlist.json

입력 로그 형식: 한 줄에 하나의 oslo 알림 JSON ({"event_type":..., "payload":..., "timestamp":...}).
  알림 driver 를 log 로 두면 로그 한 줄 안에 이 JSON 이 들어 있으므로, 줄에서 JSON 부분만 추출한다.
"""
import argparse, json, re, sys
from collections import defaultdict
from datetime import datetime, timezone

from cto_store import Store
import cto_appcredential

# 행위자 식별 우선순위 (온톨로지의 isCorrelationKey 필드 중, 행위자(initiator) 쪽 경로)
ACTOR_USER_PATHS = ["payload.initiator.id", "payload.initiator.user_id", "payload.nova_object.data.user_id", "_context_user_id",
                    "payload.receiver_user_id"]
ACTOR_IP_PATHS = ["payload.initiator.host.address", "payload.destination_ip"]
PROJECT_PATHS = ["payload.nova_object.data.tenant_id", "payload.project", "payload.security_group_rule.project_id",
                 "payload.floatingip.project_id", "payload.port.project_id", "_context_project_id", "_context_tenant_id",
                 "payload.receiver_tenant_id"]
REQUEST_PATHS = ["payload.initiator.request_id", "_context_request_id"]
KS_OP = {"created": "create", "updated": "update", "deleted": "delete"}
NOVA_OP = {"create": "create", "delete": "delete", "shutdown": "stop", "power_off": "stop", "update": "update"}


# ----------------------------------------------------------------- 유틸
def _split_path(path):
    """'.' 로 나누되, 리터럴 점 키('nova_object.data')를 우선 인식한다."""
    LITERAL = ("nova_object.data", "nova_object.name", "nova_object.namespace", "nova_object.version")
    toks, i = [], 0
    while i < len(path):
        for lk in LITERAL:
            if path.startswith(lk, i) and (i + len(lk) == len(path) or path[i + len(lk)] in ".["):
                toks.append(lk); i += len(lk); break
        else:
            j = path.find(".", i)
            j = len(path) if j == -1 else j
            toks.append(path[i:j]); i = j
        if i < len(path) and path[i] == ".":
            i += 1
    return toks


def get_path(obj, path):
    """'a.b[].c', 'a.b[name=x].c' 형태의 경로로 값 추출. 없으면 None, 배열이면 list"""
    cur = [obj]
    for tok in _split_path(path):
        m = re.fullmatch(r"([\w.-]+?)(\[\])?(?:\[(\w+)=([^\]]+)\])?", tok)
        if not m:
            return None
        key, arr, fk, fv = m.groups()
        nxt = []
        for c in cur:
            if not isinstance(c, dict) or key not in c:
                continue
            v = c[key]
            if arr:
                nxt += [x for x in v] if isinstance(v, list) else []
            elif fk:
                nxt += [x for x in (v if isinstance(v, list) else []) if isinstance(x, dict) and str(x.get(fk)) == fv]
            else:
                nxt.append(v)
        cur = nxt
        if not cur:
            return None
    return cur[0] if len(cur) == 1 else cur


def parse_ts(msg):
    for cand in (msg.get("timestamp"), get_path(msg, "payload.eventTime"), get_path(msg, "payload.nova_object.data.created_at")):
        if not cand:
            continue
        s = str(cand).replace("Z", "+00:00").replace(" ", "T")
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
            try:
                d = datetime.strptime(s, fmt)
                return d.replace(tzinfo=timezone.utc).timestamp() if d.tzinfo is None else d.timestamp()
            except ValueError:
                pass
    return None


def extract_json(line):
    """로그 한 줄에서 JSON 객체 부분만 추출"""
    line = line.strip()
    if not line:
        return None
    if line.startswith("{"):
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            pass
    i = line.find("{")
    while i != -1:
        try:
            return json.loads(line[i:])
        except json.JSONDecodeError:
            i = line.find("{", i + 1)
    return None


# ----------------------------------------------------------------- 엔진
class Engine:
    def __init__(self, store, allowlist=None, baseline=None):
        self.s = store
        self.events, self.alerts, self.incidents = [], [], {}
        self.seen_pairs = set(baseline or [])
        self._last_alert = {}
        # 이벤트 유형 색인
        self.ev_index = defaultdict(list)
        for ev in store.of_type("cto:LogEventType"):
            for name in store.objs(ev, "cto:eventTypeName"):
                self.ev_index[str(name)].append(ev)
        # 행위 분류 색인 (action, resource)
        self.bc_index = defaultdict(list)
        for bc in store.of_type("cto:BehaviorClass"):
            for a in store.objs(bc, "cto:matchesAction"):
                for r in store.objs(bc, "cto:matchesResourceType"):
                    self.bc_index[(str(store.val(a, "cto:cadfAction")), str(store.val(r, "cto:apiResourceName")))].append(bc)
        # 허용 목록: 온톨로지 항목 + 파일
        self.allow = defaultdict(set)
        for e in store.of_type("cto:AllowlistEntry"):
            v = str(store.val(e, "cto:entryValue", ""))
            if v and not v.startswith("<"):
                self.allow[str(store.val(e, "cto:entryKind"))].add(v)
        for k, vs in (allowlist or {}).items():
            self.allow[k] |= set(map(str, vs))
        self.rules = store.of_type("cto:DetectionRule")
        # 사건 묶기에 쓸 연결 키 필드 (온톨로지의 cto:isCorrelationKey)
        self.corr_paths = {str(p) for f in store.of_type("cto:LogField") if store.val(f, "cto:isCorrelationKey") is True
                           for p in store.objs(f, "cto:fieldPath")}

    # ---- 분류
    def classify(self, msg):
        et = msg.get("event_type", "")
        outcome = get_path(msg, "payload.outcome")
        for ev in self.ev_index.get(et, []):
            oc = self.s.val(ev, "cto:outcome")
            if oc is None or str(oc) == str(outcome):
                return ev, self.s.val(ev, "cto:classifiedAs"), "등록 이벤트"
        # 일반 분류: event_type 이름 규칙에서 행위·자원 추출
        action = res = None
        m = re.fullmatch(r"identity\.(\w+)\.(created|updated|deleted)", et)
        if m:
            res, action = m.group(1), KS_OP[m.group(2)]
        m = re.fullmatch(r"(\w+)\.(\w+)\.end", et)
        if m and not action:
            res, action = m.group(1), NOVA_OP.get(m.group(2), m.group(2))
        if et.startswith("audit.http"):
            a = str(get_path(msg, "payload.action") or "")
            action = "read/list" if a.startswith("read/list") else a.split("/")[0]
            turi = str(get_path(msg, "payload.target.typeURI") or "")
            res = turi.rstrip("/").split("/")[-1].replace("-", "_") if turi else None
        if action and res:
            bcs = self.bc_index.get((action, res), [])
            if bcs:
                return None, bcs[0], f"일반 분류({action} × {res})"
        return None, None, "미분류"

    def fields_of(self, ev, msg):
        out = {}
        nodes = self.s.objs(ev, "cto:hasField") if ev else []
        if not nodes:  # 일반 분류 이벤트: 모든 필드 노드 시도
            nodes = self.s.of_type("cto:LogField")
        for f in nodes:
            for p in self.s.objs(f, "cto:fieldPath"):
                v = get_path(msg, str(p))
                if v is not None and v != [] and v != "":
                    out[str(p)] = v
                    break
        return out

    def first(self, fields, paths):
        for p in paths:
            if p in fields:
                v = fields[p]
                return str(v[0] if isinstance(v, list) else v)
        return None

    # ---- 처리
    def process(self, msg, ts=None):
        if cto_appcredential.duplicate(self, msg):
            return []
        ev, bc, how = self.classify(msg)
        fields = self.fields_of(ev, msg)
        e = {"n": len(self.events), "ts": ts if ts is not None else (parse_ts(msg) or float(len(self.events))),
             "event_type": msg.get("event_type"), "ev": ev, "bc": bc, "how": how, "fields": fields, "raw": msg,
             "user": self.first(fields, ACTOR_USER_PATHS), "ip": self.first(fields, ACTOR_IP_PATHS),
             "project": self.first(fields, PROJECT_PATHS), "request_id": self.first(fields, REQUEST_PATHS),
             "risk": int(self.s.val(bc, "cto:riskScore", 0)) if bc else 0}
        cto_appcredential.normalize(e)
        e["actor"] = e["user"] or e["ip"] or e["project"]
        e["new_source"] = bool(e["user"] and e["ip"] and (e["user"], e["ip"]) not in self.seen_pairs)
        if e["user"] and e["ip"]:
            self.seen_pairs.add((e["user"], e["ip"]))
        self.events.append(e)
        if bc is None:
            return []
        new = []
        for r in self.rules:
            a = self.eval_rule(r, e)
            if a:
                new.append(a)
        return new

    def key_of(self, e, gby):
        if gby is None:
            return e["actor"]
        g = str(gby)
        return {"@user": e["user"], "@ip": e["ip"], "@project": e["project"], "@actor": e["actor"]}.get(g, self.first(e["fields"], [g]))

    def rule_applies(self, r, e):
        uses_bc, uses_ev = self.s.objs(r, "cto:usesBehavior"), self.s.objs(r, "cto:usesEvent")
        return (e["bc"] in uses_bc) or (e["ev"] in uses_ev) or (not uses_bc and not uses_ev)

    def check_filter(self, f, e):
        m = re.fullmatch(r"(\S+)\s+(==|!=|in|empty|notempty|covers_port|in_allowlist|not_in_allowlist|ne_field)(?:\s+(.*))?", str(f).strip())
        if not m:
            return False
        path, op, arg = m.groups()
        special = {"@user": e["user"], "@ip": e["ip"], "@project": e["project"], "@actor": e["actor"], "@new_source": str(e["new_source"]).lower()}
        v = special[path] if path in special else e["fields"].get(path)
        vals = [str(x) for x in v] if isinstance(v, list) else ([] if v is None or v == "" else [str(v)])
        args = (arg or "").split("|")
        if op == "ne_field":
            other = e["fields"].get(arg)
            ovals = [str(x) for x in other] if isinstance(other, list) else ([] if other in (None, "") else [str(other)])
            return bool(vals) and bool(ovals) and not (set(vals) & set(ovals))
        if op == "==": return arg in vals
        if op == "!=": return arg not in vals
        if op == "in": return any(a in vals for a in args) or ("__empty__" in args and not vals)
        if op == "empty": return not vals
        if op == "notempty": return bool(vals)
        if op == "in_allowlist": return any(x in self.allow[arg] for x in vals)
        if op == "not_in_allowlist":
            pool = set().union(*(self.allow[k] for k in args))
            return not any(x in pool for x in vals)
        if op == "covers_port":
            mn = e["fields"].get(path); mx = e["fields"].get(path.replace("port_range_min", "port_range_max"))
            if mn in (None, "") and mx in (None, ""):
                return True  # 포트 범위 없음 = 전체 포트
            try:
                mn, mx = int(mn), int(mx if mx not in (None, "") else mn)
            except (TypeError, ValueError):
                return False
            return any(a != "any" and mn <= int(a) <= mx for a in args)
        return False

    def step_matches(self, spec, x):
        """x: 이벤트 dict 또는 경보 dict. spec: 'bc_a|rule_b|bc_c@new_source'"""
        for alt in spec.split("|"):
            name, _, flag = alt.partition("@")
            if name.startswith("rule_"):
                if x.get("kind") == "alert" and x["rule"] == f"kb:{name}":
                    return True
            elif x.get("kind") != "alert" and x.get("bc") == f"kb:{name}" and (not flag or x.get(flag)):
                return True
        return False

    def eval_rule(self, r, e):
        s = self.s
        rtype = str(s.val(r, "cto:ruleType", "filter"))
        gby = s.val(r, "cto:groupBy")
        win = int(s.val(r, "cto:windowSeconds", 0) or 0)
        th = int(s.val(r, "cto:threshold", 0) or 0)
        key = self.key_of(e, gby)
        if rtype == "appcredential_sequence":
            return cto_appcredential.evaluate(self, r, e)
        if rtype == "filter":
            if not self.rule_applies(r, e):
                return None
            if all(self.check_filter(f, e) for f in s.objs(r, "cto:filter")):
                return self.alert(r, key, [e])
        elif rtype == "threshold":
            if not self.rule_applies(r, e) or key is None:
                return None
            hits = [x for x in self.events if self.rule_applies(r, x) and self.key_of(x, gby) == key and e["ts"] - x["ts"] <= win]
            dfield, dmin = s.val(r, "cto:distinctField"), int(s.val(r, "cto:distinctMin", 0) or 0)
            if dfield and dmin:
                distinct = set()
                for x in hits:
                    v = x["fields"].get(str(dfield))
                    if v is None:
                        v = get_path(x.get("raw", {}), str(dfield))
                    for one in (v if isinstance(v, list) else [v]):
                        if one not in (None, ""):
                            distinct.add(str(one))
                # 필수 구분 값이 없거나 최소 종류 수보다 적으면 이 규칙의 경보를 만들지 않는다.
                if len(distinct) < dmin:
                    return None
            if len(hits) >= th and self._fresh(r, key, e["ts"], win):
                return self.alert(r, key, hits)
        elif rtype == "sequence":
            steps = sorted((str(x) for x in s.objs(r, "cto:sequenceStep")), key=lambda x: int(x.split(":")[0]))
            specs = [x.split(":", 1)[1] for x in steps]
            if key is None or not self.step_matches(specs[-1], e):
                return None
            pool = [x for x in self.events if self.key_of(x, gby) == key and e["ts"] - x["ts"] <= win] + \
                   [a for a in self.alerts if key in a["keys"] and e["ts"] - a["ts"] <= win]
            chain, t = [], -1
            for spec in specs[:-1]:
                c = [x for x in pool if x["ts"] >= t and x["ts"] <= e["ts"] and self.step_matches(spec, x) and x is not e]
                if not c:
                    return None
                first = min(c, key=lambda x: x["ts"]); chain.append(first); t = first["ts"]
            last = [x for x in pool if x["ts"] >= t and self.step_matches(specs[-1], x) and x.get("kind") != "alert"] + [e]
            minc = int(s.val(r, "cto:minCount", 1) or 1)
            if len({x["n"] for x in last}) < minc or not self._fresh(r, key, e["ts"], win):
                return None
            return self.alert(r, key, [x for x in chain if x.get("kind") != "alert"] + [e], related_alerts=[x for x in chain if x.get("kind") == "alert"])
        elif rtype == "score":
            if key is None or not all(self.check_filter(f, e) for f in s.objs(r, "cto:filter")):
                return None
            hits = [x for x in self.events if x["actor"] == key and e["ts"] - x["ts"] <= win]
            total = sum(x["risk"] for x in hits)
            if total >= th and self._fresh(r, key, e["ts"], win):
                a = self.alert(r, key, hits); a["score"] = total
                return a
        return None

    def _fresh(self, r, key, ts, win):
        last = self._last_alert.get((r, key))
        return last is None or ts - last > win

    # ---- 경보 생성
    def alert(self, r, key, events, related_alerts=()):
        s = self.s
        self._last_alert[(r, key)] = events[-1]["ts"]
        techs = list(dict.fromkeys(s.objs(r, "cto:detects") + [t for e in events if e["bc"] for t in s.objs(e["bc"], "cto:suggestsTechnique")]))
        bcs = list(dict.fromkeys(e["bc"] for e in events if e["bc"]))
        allf = {}
        for e in events:
            allf.update(e["fields"])
        keys = {v for e in events for v in (e["user"], e["ip"], e["project"]) if v}
        for ev_ in events:  # 온톨로지에서 연결 키로 지정한 필드 값(이미지 ID, 소유 프로젝트 등)도 사건 연결에 사용
            for p_, v_ in ev_["fields"].items():
                if p_ in self.corr_paths:
                    for one in (v_ if isinstance(v_, list) else [v_]):
                        if isinstance(one, (str, int)) and str(one):
                            keys.add(str(one))
        if key is None:
            key = self.first({k: v for ev_ in events for k, v in ev_["fields"].items()},
                             ["payload.image_id", "payload.nova_object.data.uuid"]) or events[-1]["event_type"]
        a = {"kind": "alert", "rule": r, "rule_label": s.label(r), "tier": s.label(s.val(r, "cto:alertTier")),
             "severity": str(s.val(r, "cto:severity", "")), "key": key, "keys": sorted(keys), "ts": events[-1]["ts"],
             "condition": str(s.val(r, "cto:condition", "")),
             "events": [{"n": e["n"], "event_type": e["event_type"], "how": e["how"], "user": e["user"], "ip": e["ip"], "project": e["project"]} for e in events],
             "behaviors": [s.label(b) for b in bcs],
             "techniques": [self.tech_info(t) for t in techs],
             "next_steps": self.next_steps(techs),
             "investigate": self.fill_commands([q for b in bcs for q in s.objs(b, "cto:investigateWith")], allf),
             # 대응 권고는 규칙이 '탐지했다'고 판단한 기법 기준 (이벤트가 암시하는 후보 기법까지 넓히면 엉뚱한 대응이 나옴.
             #  예: 스프레이에서 피해 계정 비활성화). 규칙에 탐지 기법이 없으면(점수 규칙 등) 후보 기법 전체 사용
             "respond": self.fill_commands(s.objs(r, "cto:ruleResponse") or [x for t in (s.objs(r, "cto:detects") or techs) for x in s.objs(t, "cto:recommendedResponse")], allf, response=True),
             "related_alerts": [x["rule_label"] for x in related_alerts],
             "sources": sorted({str(s.val(d, "cto:url")) for n in [r] + techs for d in s.objs(n, "cto:derivedFrom") if s.val(d, "cto:url")})}
        a["llm_context"] = self.llm_context(a, techs, r)
        self.alerts.append(a)
        self.link_incident(a, sum(e["risk"] for e in events))
        return a

    def link_incident(self, a, risk):
        """경보의 keys(사용자·IP·프로젝트)를 공유하면 같은 사건으로 병합"""
        ids = {x for x in set(a["keys"]) | {a["key"]} if x}
        merged = {iid for iid, inc in self.incidents.items() if ids & inc["ids"]}
        inc = {"ids": set(ids), "alerts": [], "alert_idx": [], "risk": 0, "techniques": set()}
        for iid in merged:
            old = self.incidents.pop(iid)
            inc["ids"] |= old["ids"]; inc["risk"] += old["risk"]; inc["techniques"] |= old["techniques"]
            inc["alert_idx"] += old["alert_idx"]
        inc["risk"] += risk
        inc["alert_idx"].append(len(self.alerts) - 1)   # 기록층 저장용: 규칙 이름만으로는 같은 규칙의 경보를 구분 못함
        # 경보 흐름은 발생 순서대로. 병합할 사건을 집합(set) 순서로 이어 붙이면 실행마다 순서가 바뀌던 문제 수정
        inc["alert_idx"].sort()
        inc["alerts"] = [self.alerts[i]["rule_label"] for i in inc["alert_idx"]]
        inc["techniques"] |= {t["id"] for t in a["techniques"]}
        self.incidents[min(inc["ids"])] = inc

    def tech_info(self, t):
        s = self.s
        return {"id": s.ext(t), "name": s.label(t, ("en",)), "in_attack_data": "cto:Technique" in s.types(t),
                "tactics": [s.label(x, ("en",)) for x in s.objs(t, "cto:belongsToTactic")]}

    def next_steps(self, techs):
        s, out = self.s, []
        for t in techs:
            designed = sorted(s.ext(n) for n in s.closure(t, "cto:precedes") - {t})
            co = []
            for c in s.subs("cto:techniqueA", t) + s.subs("cto:techniqueB", t):
                other = s.val(c, "cto:techniqueB") if s.val(c, "cto:techniqueA") == t else s.val(c, "cto:techniqueA")
                co.append((int(s.val(c, "cto:coOccurrenceCount", 0)), s.ext(other)))
            out.append({"from": s.ext(t), "designed": designed, "cooccur_top": [i for _, i in sorted(co, reverse=True)[:5]]})
        return out

    def fill_commands(self, nodes, fields, response=False):
        s, out = self.s, []
        for q in dict.fromkeys(nodes):
            cmd = str(s.val(q, "cto:command", ""))
            rb = str(s.val(q, "cto:rollbackCommand", "") or "")
            missing = []
            for p in s.objs(q, "cto:hasParameter"):
                ph = str(s.val(p, "cto:placeholder"))
                val = next((fields[str(fp)] for f in s.objs(p, "cto:valueFrom") for fp in s.objs(f, "cto:fieldPath") if str(fp) in fields), None)
                if isinstance(val, list):
                    val = val[0]
                if val is None:
                    missing.append(ph)
                else:
                    cmd = cmd.replace(ph, str(val))
                    rb = rb.replace(ph, str(val))
            item = {"label": s.label(q), "command": cmd, "missing": missing, "status": str(s.val(q, "cto:verificationStatus", ""))}
            if response:
                item["requires_approval"] = True
                item["rollback"] = rb or None
                d = s.val(q, "cto:implements")
                item["d3fend"] = f"{s.ext(d)} {s.label(d, ('en',))}" if d else None
            else:
                item["purpose"] = str(s.val(q, "cto:purpose", ""))
            out.append(item)
        return out

    def llm_context(self, a, techs, r):
        s, facts = self.s, []
        for t in techs:
            facts.append({"id": s.ext(t), "type": "technique", "name": s.label(t, ("en",)),
                          "description": str(s.val(t, "rdfs:comment", ""))[:600]})
            for m in s.objs(t, "cto:mitigatedBy"):
                facts.append({"id": s.ext(m), "type": "mitigation", "name": s.label(m, ("en",)),
                              "d3fend": [f"{s.ext(d)} {s.label(d, ('en',))}" for d in s.objs(m, "cto:mappedToD3FEND")]})
            for d in s.subs("cto:detects", t):
                if "cto:DetectionStrategy" in s.types(d):
                    facts.append({"id": s.ext(d), "type": "attack_detection_strategy", "name": s.label(d, ("en",))})
        allowed = sorted({f["id"] for f in facts} | {x for f in facts for x in [y.split(" ")[0] for y in f.get("d3fend", [])]})
        return {"rule": {"label": a["rule_label"], "tier": a["tier"], "severity": a["severity"], "condition": a["condition"]},
                "facts": facts, "allowed_ids": allowed,
                "instruction": "위 facts 에 있는 ID 만 인용해 한국어로 설명. allowed_ids 밖의 ID·명령을 만들지 말 것."}


# ----------------------------------------------------------------- 출력
def print_alert(a):
    print(f"\n■ [{a['tier']}·{a['severity']}] {a['rule_label']}   대상: {a['key']}")
    print(f"  조건: {a['condition']}")
    print(f"  근거 이벤트 {len(a['events'])}건: " + ", ".join(f"#{e['n']} {e['event_type']}" for e in a["events"][-5:]))
    if a["related_alerts"]:
        print("  이어진 경보: " + ", ".join(a["related_alerts"]))
    for t in a["techniques"]:
        print(f"  공격 기법: {t['id']} {t['name']} [{'/'.join(t['tactics'])}]" + ("" if t["in_attack_data"] else "  ⚠ ATT&CK 데이터에 없음"))
    for n in a["next_steps"]:
        if n["designed"] or n["cooccur_top"]:
            print(f"  다음 단계({n['from']}): 설계 {n['designed']}  데이터 {n['cooccur_top']}")
    for q in a["investigate"]:
        print(f"  자동 조사: {q['command']}" + (f"  (인자 없음: {q['missing']})" if q["missing"] else "") + f"  [{q['status']}]")
    for x in a["respond"]:
        print(f"  대응 권고(승인 필요): {x['command']}" + (f"  (인자 없음: {x['missing']})" if x["missing"] else "") +
              (f"  / 되돌리기: {x['rollback']}" if x["rollback"] else "") + (f"  / {x['d3fend']}" if x["d3fend"] else ""))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ontology", default="out/ontology_all.ttl")
    ap.add_argument("--log", required=True)
    ap.add_argument("--allowlist"); ap.add_argument("--baseline"); ap.add_argument("--learn"); ap.add_argument("--json")
    a = ap.parse_args()
    store = Store.load(a.ontology)
    allow = json.load(open(a.allowlist, encoding="utf-8")) if a.allowlist else None
    base = [tuple(x) for x in json.load(open(a.baseline, encoding="utf-8"))] if a.baseline else None
    eng = Engine(store, allow, base)
    n = unclassified = 0
    for line in open(a.log, encoding="utf-8"):
        msg = extract_json(line)
        if not msg or "event_type" not in msg:
            continue
        n += 1
        if not a.learn:
            for al in eng.process(msg):
                print_alert(al)
        else:
            eng.process(msg)
    unclassified = [e["event_type"] for e in eng.events if e["bc"] is None]
    print(f"\n처리 {n}건, 분류 {n - len(unclassified)}건, 미분류 {len(unclassified)}건" + (f" {sorted(set(unclassified))}" if unclassified else ""))
    if a.learn:
        json.dump(sorted(eng.seen_pairs), open(a.learn, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        print(f"기준선 저장: {a.learn} (사용자↔IP {len(eng.seen_pairs)}쌍). 경보는 내지 않았습니다.")
        return
    print(f"경보 {len(eng.alerts)}건, 사건 {len(eng.incidents)}건")
    for inc in eng.incidents.values():
        print(f"  사건 [{', '.join(sorted(inc['ids']))}] 누적 위험 {inc['risk']}  기법 {sorted(inc['techniques'])}")
        print(f"      경보 흐름: " + " → ".join(inc["alerts"]))
    if a.json:
        incs = [{"ids": sorted(i["ids"]), "risk": i["risk"], "alerts": i["alerts"], "techniques": sorted(i["techniques"])} for i in eng.incidents.values()]
        json.dump({"alerts": eng.alerts, "incidents": incs}, open(a.json, "w", encoding="utf-8"), ensure_ascii=False, indent=1, default=str)
        print(f"JSON 저장: {a.json}")


if __name__ == "__main__":
    main()
