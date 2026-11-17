#!/usr/bin/env python3
"""Apply a pulled release while retaining site configuration and operational records."""
from collections import defaultdict
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import uuid

from knowledge_assets import ASSETS, manifest, import_public, verify_graph
from load_neo4j import Plan, batches, safe, rel_type
from runtime_env import ROOT, load, values


class KnowledgeFilesError(RuntimeError):
    """The graph committed but its matching engine input could not be installed."""


def configuration_changes(current, ask=input):
    """Only fill settings introduced after the first installer; preserve credentials."""
    changes = {}
    if current.get('CTO_EMBED_LOCAL') not in ('true', 'false'):
        choice = ask('임베딩 서버: 기존 주소 유지(k) / 이 PC에 자동 설치(l) [k]: ').strip().lower() or 'k'
        if choice not in ('k', 'l'):
            raise ValueError('k 또는 l을 입력하세요.')
        changes['CTO_EMBED_LOCAL'] = 'true' if choice == 'l' else 'false'
        if choice == 'l':
            changes.update(CTO_EMBED_URL='http://127.0.0.1:11435', CTO_EMBED_MODEL='qwen3-embedding:8b')
    if current.get('RABBIT_HOST'):
        if not current.get('RABBIT_USER') or not current.get('RABBIT_PASSWORD'):
            raise ValueError('.env에 RABBIT_USER와 RABBIT_PASSWORD를 입력하세요.')
        for key, default in {'RABBIT_PORT':'5672', 'RABBIT_VHOST':'/', 'RABBIT_TLS':'false',
                             'RABBIT_DECLARE_QUEUE':'true',
                             'RABBIT_ROUTING_KEYS':'notifications.info,notifications.warn,notifications.error,versioned_notifications.info,versioned_notifications.warn,versioned_notifications.error'}.items():
            if not current.get(key):
                changes[key] = default
        declared = current.get('RABBIT_DECLARE_QUEUE', 'true').lower() != 'false'
        if declared:
            if not current.get('RABBIT_EXCHANGES'):
                exchanges = ask('RabbitMQ 알림 exchange 이름 (쉼표 구분, 예: nova,neutron,keystone): ').strip()
                if not exchanges:
                    raise ValueError('수집 서비스를 활성화하려면 실제 알림 exchange 이름이 필요합니다.')
                changes['RABBIT_EXCHANGES'] = exchanges
            # An old queue-monitor setting does not authorize competing consumers.
            if not current.get('RABBIT_DECLARE_QUEUE') or not current.get('RABBIT_QUEUE'):
                changes['RABBIT_QUEUE'] = 'cto.dashboard.' + uuid.uuid4().hex[:12]
        elif not current.get('RABBIT_QUEUE'):
            raise ValueError('수동 구독 모드에는 RABBIT_QUEUE가 필요합니다.')
    return changes


def merge_tx(tx, plan):
    """Update release-owned knowledge; never delete nodes or record relationships."""
    uris = list(plan.nodes)
    before = tx.run('MATCH(n:Knowledge) RETURN count(n) AS c').single()['c']
    property_keys = set().union(*(set(n['props']) for n in plan.nodes.values())) - {'uri'}
    # Remove obsolete ontology properties, while retaining embeddings and site notes.
    groups = defaultdict(list)
    for uri, node in plan.nodes.items():
        properties = {k: None for k in property_keys}
        properties.update(node['props'])
        groups[tuple(node['labels'])].append({'uri': uri, 'props': properties})
    for labels, rows in groups.items():
        label_text = ':'.join(safe(v) for v in labels)
        for chunk in batches(rows):
            tx.run(f'UNWIND $rows AS row MERGE(n:Knowledge {{uri:row.uri}}) '
                   f'SET n:{label_text} SET n += row.props', rows=chunk).consume()
    managed = sorted({rel_type(p) for p in plan.obj_props} | {'HAS_TIER'})
    # Superseded package relationships are replaced. Outside knowledge and
    # ObservedEvent/Alert/Incident/Report links are untouched.
    tx.run('MATCH(a:Knowledge)-[r]->(b:Knowledge) '
           'WHERE a.uri IN $uris AND b.uri IN $uris AND type(r) IN $types DELETE r',
           uris=uris, types=managed).consume()
    for kind, rows in plan.rels.items():
        for chunk in batches(rows):
            tx.run('UNWIND $rows AS row MATCH(a:Knowledge {uri:row.s}), (b:Knowledge {uri:row.o}) '
                   f'MERGE(a)-[r:{safe(kind)}]->(b) SET r = row.props', rows=chunk).consume()
    tx.run('UNWIND $rows AS row MERGE(n:OntologyClass {name:row.name}) SET n += row', rows=plan.onto_classes).consume()
    names = [c['name'] for c in plan.onto_classes]
    tx.run('MATCH(a:OntologyClass)-[r:SCHEMA_RELATION|SUBCLASS_OF]->(b:OntologyClass) '
           'WHERE a.name IN $names AND b.name IN $names DELETE r', names=names).consume()
    tx.run('UNWIND $rows AS row MATCH(a:OntologyClass {name:row.s}), (b:OntologyClass {name:row.o}) '
           'MERGE(a)-[:SUBCLASS_OF]->(b)', rows=plan.sub_class).consume()
    tx.run('UNWIND $rows AS row MATCH(a:OntologyClass {name:row.s}), (b:OntologyClass {name:row.o}) '
           'MERGE(a)-[r:SCHEMA_RELATION {relType:row.props.relType}]->(b) SET r += row.props', rows=plan.schema_rels).consume()
    got = tx.run('MATCH(n:Knowledge) WHERE n.uri IN $uris RETURN count(n) AS c', uris=uris).single()['c']
    if got != len(plan.nodes):
        raise ValueError('업데이트 중 지식 노드 검사 실패')
    expected_edges = sum(map(len, plan.rels.values()))
    got_edges = tx.run('MATCH(a:Knowledge)-[r]->(b:Knowledge) WHERE a.uri IN $uris AND b.uri IN $uris '
                       'AND type(r) IN $types RETURN count(r) AS c', uris=uris, types=managed).single()['c']
    if got_edges != expected_edges:
        raise ValueError('업데이트 중 지식 관계 검사 실패')
    after = tx.run('MATCH(n:Knowledge) RETURN count(n) AS c').single()['c']
    tx.run('CREATE(n:LoadInfo) SET n.mode="release_update", n.loadedAt=$at, n.nodeCount=$count',
           at=datetime.now(timezone.utc).isoformat(), count=len(plan.nodes)).consume()
    return {'previous_knowledge': before, 'total_knowledge': after, 'release_knowledge': len(plan.nodes)}


def update_knowledge(driver, database='neo4j'):
    manifest()
    plan = Plan(str(ASSETS / 'ontology_all.ttl'), str(ROOT / 'schema.ttl'))
    if plan.errors:
        raise ValueError(plan.errors)
    output = ROOT / 'out'
    output.mkdir(exist_ok=True)
    previous = output / 'ontology_all.ttl'
    if previous.exists() and previous.read_bytes() != (ASSETS/'ontology_all.ttl').read_bytes():
        old = Plan(str(previous), str(ROOT/'schema.ttl'))
        engine_kinds = {'DetectionRule','LogEventType','BehaviorClass','LogField','InvestigationQuery','ResponseAction'}
        custom = [uri for uri,node in old.nodes.items() if uri not in plan.nodes and engine_kinds.intersection(node['labels'])]
        if old.errors or custom:
            raise ValueError('기존 온톨로지에 배포본 밖의 탐지 정의가 있습니다. 해당 정의를 먼저 통합해야 하므로 DB는 변경하지 않습니다.')
    # Stage complete files before changing the database; final replacements are atomic.
    with tempfile.TemporaryDirectory(prefix='.release-', dir=output) as staging:
        for name in ('ontology_all.ttl', 'build_report.txt'):
            (Path(staging)/name).write_bytes((ASSETS/name).read_bytes())
            old_file = output/name
            if old_file.exists() and old_file.read_bytes() != (ASSETS/name).read_bytes():
                history = output/'previous'
                history.mkdir(mode=0o700, exist_ok=True)
                digest = hashlib.sha256(old_file.read_bytes()).hexdigest()[:16]
                saved = history/(name+'.'+digest)
                saved.write_bytes(old_file.read_bytes())
                saved.chmod(0o600)
        for label, prop, name in [('Knowledge','uri','knowledge_uri'),('OntologyClass','name','ontology_class_name')]:
            driver.execute_query(f'CREATE CONSTRAINT {name} IF NOT EXISTS FOR(n:{label}) REQUIRE n.{prop} IS UNIQUE', database_=database)
        with driver.session(database=database) as session:
            report = session.execute_write(merge_tx, plan)
        try:
            for name in ('ontology_all.ttl', 'build_report.txt'):
                (Path(staging)/name).replace(output/name)
        except OSError as exc:
            raise KnowledgeFilesError('DB 갱신 후 온톨로지 파일 적용 실패. 파일 권한·디스크를 확인하고 ./update.sh를 다시 실행하세요.') from exc
    # prepare() now accepts the matching outputs and installs missing public documents.
    from knowledge_assets import prepare
    prepare()
    import_public(driver, database)
    verify_graph(driver, database, vectors=False)
    print('기존 기록 보존·지식 적용:', json.dumps(report, ensure_ascii=False))
    return report


def run(*args):
    subprocess.run(list(args), cwd=ROOT, check=True)


def main():
    os.umask(0o077)
    manifest()
    from install_runtime_services import check_ownership, unit_texts
    units = unit_texts()
    check_ownership(units)
    current = values()
    if not current:
        raise SystemExit('.env가 없습니다. 새 설치는 ./setup.sh를 사용하세요.')
    changes = configuration_changes(current)
    if changes:
        from configure import update_env
        update_env(changes)
    load()
    from neo4j import GraphDatabase
    driver = GraphDatabase.driver(os.environ['NEO4J_URI'], auth=(os.environ['NEO4J_USER'],os.environ['NEO4J_PASSWORD']))
    try:
        driver.verify_connectivity()
        run(sys.executable, str(ROOT/'sync_openstack_config.py'))
        run(sys.executable, str(ROOT/'check_connections.py'))
        run('bash', str(ROOT/'setup_embedding.sh'))
        if os.environ.get('RABBIT_HOST'):
            run(sys.executable, str(ROOT/'live_notification_consumer.py'), '--check')
        sudo = [] if os.geteuid() == 0 else ['sudo']
        installed = [n for n in units if (Path('/etc/systemd/system')/n).exists()]
        if not os.environ.get('RABBIT_HOST') and installed:
            raise ValueError('기존 수집 서비스가 있으나 RABBIT_HOST가 비어 있습니다. 설정을 확인하세요.')
        active = [n for n in installed if subprocess.run(['systemctl','is-active','--quiet',n]).returncode == 0]
        try:
            if installed:
                for suffix in ('.timer', '.service'):
                    group = [n for n in installed if n.endswith(suffix)]
                    if group:
                        run(*sudo, 'systemctl', 'stop', *group)
            update_knowledge(driver, os.environ.get('NEO4J_DATABASE','neo4j'))
            run(sys.executable, str(ROOT/'embed_knowledge.py'))
            verify_graph(driver, os.environ.get('NEO4J_DATABASE','neo4j'))
            run(sys.executable, str(ROOT/'install_runtime_services.py'))
        except BaseException as exc:
            # Preserve receiver availability on a recoverable embedding/API failure.
            # If files did not install, do not run a detector with a mismatched graph.
            restore = ([n for n in active if n == 'cto-openstack-consumer.service']
                       if isinstance(exc, KnowledgeFilesError) else active)
            if restore:
                subprocess.run(sudo+['systemctl','start',*restore], check=False)
            print('업데이트가 완료되지 않았습니다. 오류를 해결한 후 ./update.sh를 다시 실행하세요.', file=sys.stderr)
            raise
    finally:
        driver.close()
    print('업데이트 적용 완료. 기존 대시보드를 Ctrl+C로 종료한 뒤 ./run_dashboard.sh로 다시 실행하세요.')


if __name__ == '__main__':
    with (ROOT/'.update.lock').open('w') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SystemExit('다른 업데이트가 실행 중입니다.')
        try:
            main()
        except (ValueError, OSError, KnowledgeFilesError, subprocess.CalledProcessError) as exc:
            raise SystemExit(str(exc)) from None
