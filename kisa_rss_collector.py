#!/usr/bin/env python3
"""KISA public RSS -> separate Neo4j KISAAdvisory nodes.
Does not create Alert, Incident, DetectionRule or Technique relationships.
Python stdlib for RSS; neo4j driver needed only for writing.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import hashlib
from html import unescape
import json
import os
from pathlib import Path
import re
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
import xml.etree.ElementTree as ET

FEEDS = {
    'vulnerability': 'https://www.boho.or.kr/kr/rss.do?bbsId=B0000302',
    'security_notice': 'https://www.boho.or.kr/kr/rss.do?bbsId=B0000133',
}
MAX_BYTES = 2 * 1024 * 1024
ALLOWED_HOSTS = {'www.boho.or.kr', 'boho.or.kr', 'krcert.or.kr', 'www.krcert.or.kr'}
CVE_RE = re.compile(r'\bCVE-[0-9]{4}-[0-9]{4,}\b', re.I)


def _text(elem, tag):
    found = elem.find(tag)
    return ''.join(found.itertext()).strip() if found is not None else ''


def plain(value: str, limit: int = 1200) -> str:
    value = re.sub(r'<(script|style)\b[^>]*>.*?</\1\s*>', ' ', value, flags=re.I | re.S)
    value = re.sub(r'<[^>]+>', ' ', value)
    return re.sub(r'\s+', ' ', unescape(value)).strip()[:limit]


def safe_official_url(value: str) -> str:
    value = value.strip()
    p = urlsplit(value)
    return value if p.scheme == 'https' and (p.hostname or '').lower() in ALLOWED_HOSTS else ''


def date_string(value: str) -> str:
    if not value.strip():
        return ''
    try:
        dt = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        try:
            dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
        except ValueError:
            return ''
    if not dt.tzinfo:
        return ''
    return dt.astimezone(timezone.utc).isoformat()


def parse_feed(xml_data: bytes, kind: str):
    if len(xml_data) > MAX_BYTES:
        raise ValueError('RSS too large')
    if re.search(rb'<!\s*(DOCTYPE|ENTITY)', xml_data, re.I):
        raise ValueError('DTD/entities are disallowed')
    root = ET.fromstring(xml_data)
    candidates = root.findall('./channel/item')
    if not candidates:
        candidates = root.findall('./{*}entry')
    seen = set()
    for item in candidates:
        title = plain(_text(item, 'title') or _text(item, '{*}title'), 250)
        guid = _text(item, 'guid') or _text(item, '{*}id')
        link = _text(item, 'link')
        if not link:
            lnk = item.find('{*}link')
            if lnk is not None:
                link = lnk.get('href') or ''
        url = safe_official_url(link)
        published = date_string(_text(item, 'pubDate') or _text(item, '{*}published') or _text(item, '{*}updated'))
        description = plain(_text(item, 'description') or _text(item, '{*}summary'), 1600)
        if not title or not (guid or url):
            continue
        identifier = hashlib.sha256((kind + '\n' + (guid.strip() or url)).encode('utf-8')).hexdigest()
        if identifier in seen:
            continue
        seen.add(identifier)
        cve_ids = sorted({x.upper() for x in CVE_RE.findall(title + ' ' + description)})
        yield {'sourceId': 'kisa-' + identifier, 'sourceFeed': kind, 'sourceName': 'KISA 보호나라',
               'title': title, 'url': url, 'publishedAt': published,
               'summary': description, 'cveIds': cve_ids}


def fetch_rss(url: str) -> bytes:
    req = Request(url, headers={'User-Agent': '3K1H-KISA-RSS-Reader/1.0', 'Accept': 'application/rss+xml, application/xml, text/xml'})
    with urlopen(req, timeout=15) as response:
        length = response.headers.get('Content-Length')
        if length and int(length) > MAX_BYTES:
            raise ValueError('RSS response too large')
        data = response.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError('RSS response too large')
    return data


def load_password():
    password = os.environ.get('NEO4J_PASSWORD')
    if password:
        return password
    file = Path.home() / '.cto_neo4j_password'
    if not file.exists():
        raise RuntimeError('NEO4J_PASSWORD or ~/.cto_neo4j_password required')
    return file.read_text(encoding='utf-8').strip()


def save_to_neo4j(items):
    from neo4j import GraphDatabase
    uri = os.environ.get('NEO4J_URI', 'bolt://127.0.0.1:7687')
    user = os.environ.get('NEO4J_USER', 'neo4j')
    database = os.environ.get('NEO4J_DATABASE', 'neo4j')
    inserted = 0
    now = datetime.now(timezone.utc).isoformat()
    with GraphDatabase.driver(uri, auth=(user, load_password())) as driver:
        driver.verify_connectivity()
        with driver.session(database=database) as session:
            session.run('CREATE CONSTRAINT kisa_advisory_sourceid IF NOT EXISTS FOR (a:KISAAdvisory) REQUIRE a.sourceId IS UNIQUE').consume()
            for item in items:
                summary = session.run('''
                    MERGE (a:KISAAdvisory {sourceId:$sourceId})
                    ON CREATE SET a.firstSeenAt = $seen
                    SET a.sourceName = $sourceName,
                        a.sourceFeed = $sourceFeed,
                        a.title = $title,
                        a.url = $url,
                        a.publishedAt = $publishedAt,
                        a.summary = $summary,
                        a.cveIds = $cveIds,
                        a.lastSeenAt = $seen
                ''', **item, seen=now).consume()
                inserted += summary.counters.nodes_created
    return inserted


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--dry-run', action='store_true', help='Fetch/parse only; no Neo4j writes')
    p.add_argument('--fixture', type=Path, help='Read local RSS XML for offline test')
    p.add_argument('--feed', choices=list(FEEDS), default='vulnerability', help='Only used with --fixture')
    args = p.parse_args()
    all_items = []
    for kind, url in ([(args.feed, '')] if args.fixture else FEEDS.items()):
        try:
            payload = args.fixture.read_bytes() if args.fixture else fetch_rss(url)
            items = list(parse_feed(payload, kind))
            print(f'{kind}: {len(items)} RSS entries parsed')
            all_items.extend(items)
        except Exception as exc:
            raise SystemExit(f'RSS read failed for {kind}: {type(exc).__name__}: {exc}') from exc
    if args.dry_run:
        for item in all_items[:10]:
            print(json.dumps({k: item[k] for k in ('sourceFeed', 'title', 'publishedAt', 'cveIds', 'url')}, ensure_ascii=False))
        print(f'DRY-RUN: {len(all_items)} entries, 0 DB writes')
    else:
        print(f'Neo4j: {save_to_neo4j(all_items)} new nodes; {len(all_items)} checked')


if __name__ == '__main__':
    main()
