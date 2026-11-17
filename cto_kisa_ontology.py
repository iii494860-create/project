#!/usr/bin/env python3
"""KISA RSS metadata -> evidence-scoped Neo4j CVE graph.

Safe graph edges ONLY: (KISAAdvisory)-[:MENTIONS_CVE]->(KISACVE).
Never claims that a product is affected or that an exploit happened.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re

CVE = re.compile(r'^CVE-[0-9]{4}-[0-9]{4,}$', re.I)


def valid_cves(raw):
    if not isinstance(raw, (list, tuple)):
        return []
    return sorted({str(v).strip().upper() for v in raw if CVE.fullmatch(str(v).strip())})


def graph_edges(records):
    edges = set()
    for record in records:
        source_id = str(record.get('sourceId') or '').strip()
        if not source_id.startswith('kisa-'):
            continue
        for cve_id in valid_cves(record.get('cveIds')):
            edges.add((source_id, cve_id))
    return [{'source_id': k, 'cve_id': v} for k, v in sorted(edges)]


def password():
    value = os.environ.get('NEO4J_PASSWORD')
    if value:
        return value
    p = Path.home()/'.cto_neo4j_password'
    if not p.is_file():
        raise RuntimeError('NEO4J_PASSWORD or ~/.cto_neo4j_password required')
    return p.read_text(encoding='utf-8').strip()


def connection():
    from neo4j import GraphDatabase
    driver = GraphDatabase.driver(
        os.environ.get('NEO4J_URI','bolt://127.0.0.1:7687'),
        auth=(os.environ.get('NEO4J_USER','neo4j'),password()),
    )
    driver.verify_connectivity()
    return driver, os.environ.get('NEO4J_DATABASE','neo4j')


def synchronize(session, dry_run=True):
    # The original KISA collector already maintains sourceId and cveIds.
    source = list(session.run('''
      MATCH (a:KISAAdvisory)
      WHERE a.sourceId IS NOT NULL AND coalesce(a.cveLinkBlocked,false) = false AND NOT (coalesce(a.url,'') CONTAINS 'bbsId=B0000302' AND coalesce(a.url,'') =~ '.*[?&]nttId=35350(&.*)?')
      RETURN a.sourceId AS sourceId, a.cveIds AS cveIds
    '''))
    edges = graph_edges(source)
    report = {'advisories':len(source), 'candidate_links':len(edges),
              'created_cve_nodes':0, 'created_relations':0, 'dry_run':bool(dry_run)}
    if dry_run or not edges:
        return report
    # Exact CVE identifiers are proved only by the RSS-derived cveIds field.
    # The dedicated KISACVE label prevents accidentally merging into an unrelated
    # generic CVE / Vulnerability ontology with different provenance.
    cypher = '''
      UNWIND $edges AS edge
      MATCH (a:KISAAdvisory {sourceId:edge.source_id})
      WHERE coalesce(a.cveLinkBlocked,false) = false AND NOT (coalesce(a.url,'') CONTAINS 'bbsId=B0000302' AND coalesce(a.url,'') =~ '.*[?&]nttId=35350(&.*)?')
      MERGE (v:KISACVE {cveId:edge.cve_id})
      ON CREATE SET v.createdAt = $now, v.sourceBasis = 'KISA RSS listed CVE'
      MERGE (a)-[:MENTIONS_CVE]->(v)
    '''
    now = datetime.now(timezone.utc).isoformat()
    # Single-property uniqueness makes concurrent/retried MERGE idempotent.
    session.run('''
      CREATE CONSTRAINT cto_kisa_cve_unique IF NOT EXISTS
      FOR (v:KISACVE) REQUIRE v.cveId IS UNIQUE
    ''').consume()
    # Bound batches keep one Neo4j query from growing unbounded.
    for start in range(0,len(edges),200):
        summary = session.run(cypher, edges=edges[start:start+200], now=now).consume()
        report['created_cve_nodes'] += summary.counters.nodes_created
        report['created_relations'] += summary.counters.relationships_created
    return report


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    g=p.add_mutually_exclusive_group()
    g.add_argument('--dry-run',action='store_true',help='No DB writes (default)')
    g.add_argument('--sync',action='store_true',help='Create ONLY KISA CVE nodes and MENTIONS_CVE edges')
    args=p.parse_args(argv)
    driver, database=connection()
    try:
        with driver.session(database=database) as session:
            result=synchronize(session,dry_run=not args.sync)
        print('KISA graph sync:',json.dumps(result,ensure_ascii=False))
    finally:
        driver.close()

if __name__=='__main__':
    main()

# KISA CVE review guard v1: B0000302:35350
