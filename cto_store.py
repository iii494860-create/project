"""
cto_store.py - 온톨로지(Turtle) 로더 (3K1H 캡스톤)
rdflib 없이 동작. build_ontology.py 가 생성하는 Turtle 부분집합을 읽어 메모리 그래프로 만든다.
(rdflib 로 out/ontology_all.ttl 을 여는 것도 가능. 이 로더는 엔진·점검 스크립트가 의존성 없이 돌기 위한 것)
"""
import re
from collections import defaultdict

TOK = re.compile(r'''
 (?P<ws>\s+)|(?P<comment>\#[^\n]*)|
 (?P<prefix>@prefix)|
 (?P<iri><[^<>"\s]*>)|
 (?P<str>"(?:[^"\\\n]|\\.)*")(?:(?P<lang>@[a-zA-Z]+(?:-[a-zA-Z0-9]+)*)|\^\^(?P<dt>[A-Za-z][\w-]*:[\w-]+))?|
 (?P<num>[+-]?\d+(?:\.\d+)?)(?=[\s;,.\]])|
 (?P<bool>true|false)(?=[\s;,.])|
 (?P<pname>[A-Za-z][\w-]*:(?:[A-Za-z0-9_](?:[\w.-]*[\w-])?)?)|
 (?P<a>a)(?=\s)|
 (?P<punct>[.;,])
''', re.X)


class Literal(str):
    """문자열 리터럴 (언어 태그 보관)"""
    def __new__(cls, value, lang=None):
        o = str.__new__(cls, value)
        o.lang = lang
        return o


def _unescape(s):
    if "\\" not in s:
        return s
    return re.sub(r'\\(["\\nrt])', lambda m: {'"': '"', '\\': '\\', 'n': '\n', 'r': '\r', 't': '\t'}[m.group(1)], s)


def parse_turtle(text):
    toks, pos = [], 0
    while pos < len(text):
        m = TOK.match(text, pos)
        if not m:
            raise SyntaxError(f"Turtle 토큰 오류 line {text.count(chr(10), 0, pos) + 1}: {text[pos:pos + 40]!r}")
        pos = m.end()
        k = m.lastgroup
        if k in ("ws", "comment"):
            continue
        if m.group("str") is not None:
            lang = m.group("lang")
            toks.append(("lit", Literal(_unescape(m.group("str")[1:-1]), lang[1:] if lang else None)))
        elif k == "num":
            v = m.group(0)
            toks.append(("lit", float(v) if "." in v else int(v)))
        elif k == "bool":
            toks.append(("lit", m.group(0) == "true"))
        else:
            toks.append((k, m.group(0)))
    triples, i = [], 0
    while i < len(toks):
        if toks[i][0] == "prefix":
            i += 4
            continue
        s = toks[i][1]; i += 1
        while True:
            p = "a" if toks[i][0] == "a" else toks[i][1]; i += 1
            while True:
                o = toks[i][1]; i += 1
                triples.append((s, p, o))
                if toks[i][1] == ",":
                    i += 1; continue
                break
            if toks[i][1] == ";":
                i += 1; continue
            if toks[i][1] == ".":
                i += 1; break
            raise SyntaxError(f"문장 종료 오류 near {s} {p}")
    return triples


class Store:
    def __init__(self, triples):
        self.spo = defaultdict(lambda: defaultdict(list))
        self.pos = defaultdict(lambda: defaultdict(list))
        for s, p, o in triples:
            if o not in self.spo[s][p]:
                self.spo[s][p].append(o)
            if isinstance(o, str) and s not in self.pos[p][o]:
                self.pos[p][o].append(s)
        self.n = len(triples)

    @classmethod
    def load(cls, *paths):
        t = []
        for p in paths:
            with open(p, encoding="utf-8") as f:
                t += parse_turtle(f.read())
        return cls(t)

    def objs(self, s, p):
        return list(self.spo.get(s, {}).get(p, []))

    def val(self, s, p, default=None):
        v = self.objs(s, p)
        return v[0] if v else default

    def subs(self, p, o):
        return list(self.pos.get(p, {}).get(o, []))

    def types(self, s):
        return self.objs(s, "a")

    def of_type(self, cls_name):
        return self.subs("a", cls_name)

    def has(self, s, p, o):
        return o in self.spo.get(s, {}).get(p, [])

    def label(self, s, langs=("ko", "en")):
        ls = self.objs(s, "rdfs:label")
        for lg in langs:
            for l in ls:
                if getattr(l, "lang", None) == lg:
                    return str(l)
        return str(ls[0]) if ls else s.split(":", 1)[-1]

    def ext(self, s):
        return str(self.val(s, "cto:externalId", s.split(":", 1)[-1]))

    def closure(self, s, p):
        seen, stack = set(), [s]
        while stack:
            x = stack.pop()
            for y in self.objs(x, p):
                if y not in seen:
                    seen.add(y); stack.append(y)
        return seen
