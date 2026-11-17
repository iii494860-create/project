#!/usr/bin/env python3
"""Validate an older graph update in a disposable Neo4j; never use a live database."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from neo4j import GraphDatabase
from load_neo4j import Plan, reload_tx
import knowledge_assets
import update_install

ROOT = Path(__file__).resolve().parents[1]


def main():
    uri = os.environ['NEO4J_URI']
    parsed = urlsplit(uri)
    if parsed.hostname != '127.0.0.1' or parsed.port == 7687:
        raise SystemExit('Use disposable localhost Neo4j on a non-default port')
    with tempfile.TemporaryDirectory(prefix='cto-update-check-') as folder:
        stage = Path(folder)
        for name in ('schema.ttl','openstack_mapping.ttl'):
            source = subprocess.check_output(['git','show','5145dcd:'+name], cwd=ROOT)
            (stage/name).write_bytes(source)
        shutil.copyfile(ROOT/'d3fend_mitigation_map.csv', stage/'d3fend_mitigation_map.csv')
        subprocess.run([sys.executable,str(ROOT/'build_ontology.py'),'--docs',str(ROOT/'docs')], cwd=stage, check=True, stdout=subprocess.DEVNULL)
        old_plan = Plan(str(stage/'out/ontology_all.ttl'),str(stage/'schema.ttl'))
        assert not old_plan.errors, old_plan.errors
        original_file = (stage/'out/ontology_all.ttl').read_bytes()
        shutil.copyfile(ROOT/'schema.ttl',stage/'schema.ttl')
        (stage/'.env').write_text('preserve-site-settings\n')
        (stage/'clouds.yaml').write_text('preserve-clouds\n')
        with GraphDatabase.driver(uri, auth=(os.environ['NEO4J_USER'],os.environ['NEO4J_PASSWORD'])) as driver:
            driver.verify_connectivity()
            rows,_,_=driver.execute_query('MATCH(n) RETURN count(n) AS c')
            assert rows[0]['c'] == 0, 'Test requires an empty disposable database'
            with driver.session() as session:
                session.execute_write(reload_tx, old_plan)
            driver.execute_query('''
                MATCH(t:Knowledge {uri:'kb:T1078_004'}), (e:Knowledge {uri:'kb:ev_ks_auth_failure'})
                CREATE(custom:Knowledge:Technique {uri:'kb:site_custom',label_en:'Site knowledge'})
                CREATE(custom)-[:SITE_REFERENCE]->(t)
                CREATE(event:Record:ObservedEvent {recordId:'ev-111111111111111111111111',rawLog:'synthetic'})
                CREATE(event)-[:HAS_EVENT_TYPE]->(e)
                CREATE(alert:Record:Alert {recordId:'al-111111111111111111111111'})
                CREATE(alert)-[:TRIGGERED_BY]->(event)
                CREATE(report:Report {reportId:'synthetic-report',body:'keep report'})
                CREATE(report)-[:CITES]->(t)
                SET t.siteNote='keep note', t.filter='obsolete package property'
            ''')
            public = knowledge_assets.kisa_data()
            blocked_id = public['mentions'][0][0]
            advisory = next(a for a in public['advisories'] if a['sourceId']==blocked_id)
            driver.execute_query('CREATE(a:KISAAdvisory) SET a=$p, a.cveLinkBlocked=true',p=advisory)
            def retained():
                rows,_,_=driver.execute_query('''
                    MATCH(a)-[r]->(b) WHERE a:Record OR a:Report OR a.uri='kb:site_custom'
                    RETURN elementId(a) AS a, type(r) AS t, elementId(b) AS b ORDER BY a,t,b
                ''')
                return [dict(r) for r in rows]
            before = retained()
            with patch.object(update_install,'ROOT',stage), patch.object(knowledge_assets,'ROOT',stage):
                first = update_install.update_knowledge(driver)
                saved_output = (stage/'out/ontology_all.ttl').read_bytes()
                with (stage/'out/ontology_all.ttl').open('a') as output:
                    output.write('\nkb:site_custom_event a cto:LogEventType ; cto:eventTypeName "custom.site.event" .\n')
                try:
                    update_install.update_knowledge(driver)
                except ValueError as error:
                    assert '탐지 정의' in str(error)
                else:
                    raise AssertionError('Custom runtime event mapping was silently replaced')
                assert before==retained()
                (stage/'out/ontology_all.ttl').write_bytes(saved_output)
                second = update_install.update_knowledge(driver)
            assert first['total_knowledge']==second['total_knowledge']==972, (first,second)
            assert before==retained(), 'Record/report/custom relationships changed'
            rows,_,_=driver.execute_query("MATCH(t:Knowledge {uri:'kb:T1078_004'}) RETURN properties(t) AS p")
            assert rows[0]['p']['siteNote']=='keep note'
            assert 'filter' not in rows[0]['p'], 'Obsolete ontology property remains'
            rows,_,_=driver.execute_query('MATCH(a:KISAAdvisory {sourceId:$id})-[:MENTIONS_CVE]->() RETURN count(*) AS c',id=blocked_id)
            assert rows[0]['c']==0, 'Blocked public CVE relationship restored'
            assert original_file!=(stage/'out/ontology_all.ttl').read_bytes()
            assert any(p.read_bytes()==original_file for p in (stage/'out/previous').iterdir())
            assert (stage/'out/ontology_all.ttl').read_bytes()==(ROOT/'knowledge/ontology_all.ttl').read_bytes()
            assert (stage/'.env').read_text()=='preserve-site-settings\n'
            assert (stage/'clouds.yaml').read_text()=='preserve-clouds\n'
            plan = Plan(str(ROOT/'knowledge/ontology_all.ttl'),str(ROOT/'schema.ttl'))
            try:
                with driver.session() as session:
                    def fail(tx):
                        update_install.merge_tx(tx,plan)
                        tx.run("MATCH(n:Knowledge {uri:'kb:T1078_004'}) SET n.siteNote='must rollback'").consume()
                        raise RuntimeError('forced transaction failure')
                    session.execute_write(fail)
            except RuntimeError:
                pass
            rows,_,_=driver.execute_query("MATCH(n:Knowledge {uri:'kb:T1078_004'}) RETURN n.siteNote AS note")
            assert rows[0]['note']=='keep note'
            assert before==retained()
            print(json.dumps({'old_knowledge':len(old_plan.nodes),'release_knowledge':971,'total_with_site_knowledge':972,
                              'preserved_links':len(before),'replay':'passed','rollback':'passed','config':'unchanged'},ensure_ascii=False))


if __name__=='__main__':
    main()
