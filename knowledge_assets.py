#!/usr/bin/env python3
"""Install versioned public knowledge, independently of any operational database."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import tarfile

ROOT = Path(__file__).resolve().parent
ASSETS = ROOT / 'knowledge'


def manifest():
    data = json.loads((ASSETS / 'manifest.json').read_text())
    if data['format'] != 1:
        raise ValueError('Unknown knowledge format')
    for name, digest in data['files'].items():
        path = ASSETS / name
        if path.parent != ASSETS or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError(f'지식 자료 무결성 검사 실패: {name}')
    return data


def kisa_data():
    return json.loads(gzip.decompress((ASSETS / 'kisa_public.json.gz').read_bytes()))


def prepare():
    manifest()
    (ROOT / 'out').mkdir(exist_ok=True)
    for name in ('ontology_all.ttl', 'build_report.txt'):
        target = ROOT / 'out' / name
        if target.exists() and target.read_bytes() != (ASSETS / name).read_bytes():
            raise ValueError(f'{target.name}: 기존 자료가 배포본과 다릅니다. 별도 보관 후 다시 실행하세요.')
        shutil.copyfile(ASSETS / name, target)
    # Only regular files beneath docs/ are accepted; no links or traversal.
    with tarfile.open(ASSETS / 'public_docs.tar.gz', 'r:gz') as archive:
        for member in archive:
            parts = PurePosixPath(member.name).parts
            if not member.isfile() or not parts or parts[0] != 'docs' or '..' in parts:
                raise ValueError('Invalid public document archive member')
            target = ROOT.joinpath(*parts)
            if target.resolve() != target.absolute():
                raise ValueError('Document destination contains a symlink')
            if target.exists():
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.extractfile(member) as source, target.open('wb') as dest:
                shutil.copyfileobj(source, dest)
    print('배포 온톨로지와 공개 원문 문서 준비 완료')


def import_public(driver, database='neo4j'):
    manifest()
    data = kisa_data()
    with driver.session(database=database) as s:
        s.run('CREATE CONSTRAINT kisa_advisory_sourceid IF NOT EXISTS FOR (a:KISAAdvisory) REQUIRE a.sourceId IS UNIQUE').consume()
        s.run('CREATE CONSTRAINT cto_kisa_cve_unique IF NOT EXISTS FOR (v:KISACVE) REQUIRE v.cveId IS UNIQUE').consume()
        def write(tx):
            for start in range(0, len(data['advisories']), 100):
                tx.run('UNWIND $rows AS p MERGE(a:KISAAdvisory {sourceId:p.sourceId}) '
                       'ON CREATE SET a += p', rows=data['advisories'][start:start+100]).consume()
            for start in range(0, len(data['cves']), 500):
                tx.run('UNWIND $rows AS id MERGE(v:KISACVE {cveId:id}) '
                       "ON CREATE SET v.sourceBasis='KISA public advisory'",
                       rows=data['cves'][start:start+500]).consume()
            for start in range(0, len(data['mentions']), 500):
                tx.run('UNWIND $rows AS e MATCH(a:KISAAdvisory {sourceId:e[0]}) '
                       'WHERE coalesce(a.cveLinkBlocked,false) = false '
                       'MATCH(v:KISACVE {cveId:e[1]}) MERGE(a)-[:MENTIONS_CVE]->(v)',
                       rows=data['mentions'][start:start+500]).consume()
            for uri, labels in json.loads((ASSETS / 'extra_labels.json').read_text()).items():
                # Fixed, reviewed secondary label; do not interpolate file strings.
                if labels != ['CinderExtension']:
                    raise ValueError('Unexpected secondary label')
                tx.run('MATCH(n:Knowledge {uri:$uri}) SET n:CinderExtension', uri=uri).consume()
        s.execute_write(write)
    print(f"KISA 공지 {len(data['advisories'])}, CVE {len(data['cves'])}, 연결 {len(data['mentions'])} 적재 완료")


def verify_graph(driver, database='neo4j', vectors=True):
    from load_neo4j import Plan
    data = manifest()
    plan = Plan(str(ASSETS / 'ontology_all.ttl'), str(ROOT / 'schema.ttl'))
    if plan.errors:
        raise ValueError(plan.errors)
    with driver.session(database=database) as s:
        actual = {r['uri']: r for r in s.run('MATCH(n:Knowledge) RETURN n.uri AS uri,labels(n) AS labels,properties(n) AS p')}
        for uri, expected in plan.nodes.items():
            found = actual.get(uri)
            if not found or not set(expected['labels']).issubset(found['labels']):
                raise ValueError(f'온톨로지 노드/종류 누락: {uri}')
            for key, value in expected['props'].items():
                if found['p'].get(key) != value:
                    raise ValueError(f'온톨로지 속성 불일치: {uri}.{key}')
        extra = json.loads((ASSETS / 'extra_labels.json').read_text())
        for uri, labels in extra.items():
            if not set(labels).issubset(actual[uri]['labels']):
                raise ValueError(f'확장 분류 누락: {uri}')
        classes = {r['p']['name']: r['p'] for r in s.run('MATCH(n:OntologyClass) RETURN properties(n) AS p')}
        for cls in plan.onto_classes:
            if any(classes.get(cls['name'], {}).get(k) != v for k, v in cls.items()):
                raise ValueError('온톨로지 클래스 정의 누락: ' + cls['name'])
        schema_edges = {(r['a'], r['t'], r['b']) for r in s.run('MATCH(a:OntologyClass)-[r:SCHEMA_RELATION]->(b:OntologyClass) RETURN a.name AS a,r.relType AS t,b.name AS b')}
        if any((r['s'],r['props']['relType'],r['o']) not in schema_edges for r in plan.schema_rels):
            raise ValueError('온톨로지 스키마 관계 누락')
        subclasses = {(r['a'],r['b']) for r in s.run('MATCH(a:OntologyClass)-[:SUBCLASS_OF]->(b:OntologyClass) RETURN a.name AS a,b.name AS b')}
        if any((r['s'],r['o']) not in subclasses for r in plan.sub_class):
            raise ValueError('온톨로지 상속 관계 누락')
        edges = {(r['a'], r['t'], r['b']) for r in s.run(
            'MATCH(a:Knowledge)-[r]->(b:Knowledge) RETURN a.uri AS a,type(r) AS t,b.uri AS b')}
        for kind, rows in plan.rels.items():
            if any((r['s'], kind, r['o']) not in edges for r in rows):
                raise ValueError(f'온톨로지 관계 누락: {kind}')
        public = kisa_data()
        article_data = {r['p']['sourceId']:r['p'] for r in s.run('MATCH(a:KISAAdvisory) RETURN properties(a) AS p')}
        articles = set(article_data)
        cves = {r['id'] for r in s.run('MATCH(v:KISACVE) RETURN v.cveId AS id')}
        mentions = {(r['a'],r['v']) for r in s.run('MATCH(a:KISAAdvisory)-[:MENTIONS_CVE]->(v:KISACVE) RETURN a.sourceId AS a,v.cveId AS v')}
        required_mentions = {tuple(e) for e in public['mentions'] if not article_data.get(e[0], {}).get('cveLinkBlocked')}
        if (not {a['sourceId'] for a in public['advisories']} <= articles or
                not set(public['cves']) <= cves or not required_mentions <= mentions):
            raise ValueError('KISA 공지/CVE/관계 누락')
        for article in public['advisories']:
            found = article_data[article['sourceId']]
            for key in ('title','url','detailText','detailStatus'):
                if article.get(key) and not found.get(key):
                    raise ValueError('KISA 공지 내용 누락: ' + key)
        report = {'Knowledge': len(actual), 'OntologyClass': len(classes),
                  'KISAAdvisory': len(articles), 'KISACVE': len(cves),
                  'MENTIONS_CVE': len(mentions), 'knowledge_relationships': len(edges)}
        if vectors:
            from embed_knowledge import Neo4jSource, collect_targets, KINDS, DIM, EMBED_MODEL, INDEX
            targets, _ = collect_targets(Neo4jSource(driver, database), KINDS)
            for t in targets:
                p = actual[t['uri']]['p']
                if (len(p.get('embedding', [])) != DIM or p.get('embedModel') != EMBED_MODEL or p.get('embedTextHash') != t['hash']):
                    raise ValueError('임베딩 누락/모델/내용 불일치: ' + t['uri'])
            indexes = s.run('SHOW VECTOR INDEXES YIELD name,state WHERE name=$name RETURN state', name=INDEX).data()
            if not indexes or indexes[0]['state'] != 'ONLINE':
                raise ValueError('벡터 색인 준비 안 됨')
            report['embedded_nodes'] = len(targets)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return report


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('action', choices=['prepare', 'import', 'verify'])
    ap.add_argument('--without-vectors', action='store_true', help='Only for staged verification; does not mark setup complete')
    args = ap.parse_args()
    if args.action == 'prepare':
        prepare()
    else:
        import os
        from neo4j import GraphDatabase
        with GraphDatabase.driver(os.environ['NEO4J_URI'], auth=(os.environ['NEO4J_USER'], os.environ['NEO4J_PASSWORD'])) as driver:
            if args.action == 'import':
                import_public(driver, os.environ.get('NEO4J_DATABASE', 'neo4j'))
            else:
                verify_graph(driver, os.environ.get('NEO4J_DATABASE', 'neo4j'), not args.without_vectors)
