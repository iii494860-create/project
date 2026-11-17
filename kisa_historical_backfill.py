#!/usr/bin/env python3
"""KISA historical bulletin backfill (independent from existing RSS timers).

Read only unless --apply. Uses KISA's existing strict detail parser and Neo4j
KISAAdvisory model. Does not touch Alert/Incident/Technique/DetectionRule.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import sys
import time
from urllib.parse import urlencode, urlsplit, parse_qs
from urllib.request import Request, build_opener

from cto_kisa_detail import get_driver, official_page, parse_detail, NoRedirect

BOARDS = {
    'security_notice': ('B0000133', '205020'),
    'vulnerability': ('B0000302', '205023'),
}
BASE = 'https://www.boho.or.kr/kr/bbs/'
AGENT = '3K1H-KISA-Historical-Reader/1.0 (public pages, serial, respectful)'
MAX_LIST_BYTES = 1_500_000
CVE = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.I)


def list_url(board, page):
    bbsid, menu = BOARDS[board]
    return BASE + 'list.do?' + urlencode({'bbsId':bbsid,'menuNo':menu,'pageIndex':page})


def detail_url(board, nttid):
    bbsid, menu = BOARDS[board]
    return BASE + 'view.do?' + urlencode({'bbsId':bbsid,'menuNo':menu,'nttId':nttid,'pageIndex':1})


def key_of(url):
    p = urlsplit(url)
    if p.scheme != 'https' or p.hostname not in {'boho.or.kr','www.boho.or.kr'} or p.path != '/kr/bbs/view.do':
        return None
    q = parse_qs(p.query)
    b = q.get('bbsId',[''])[0]
    n = q.get('nttId',[''])[0]
    if b not in {x[0] for x in BOARDS.values()} or not n.isdigit():
        return None
    return f'{b}:{n}'


class Listing(HTMLParser):
    """Capture candidate bulletin anchors in listing table rows, not navigation."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack=[]; self.rows=[]; self.table_depth=0
        self.row=None; self.link=None; self.links=[]
        self.text=[]
    def handle_starttag(self,tag,attrs):
        tag=tag.lower(); attrs=dict(attrs)
        if tag=='table':self.table_depth+=1
        if tag=='tr' and self.table_depth and self.row is None:
            self.row={'links':[],'text':[],'attrs':attrs}
        if tag=='a' and self.row is not None:
            self.link={'attrs':attrs,'parts':[]}
        if tag not in {'input','img','br','hr','meta','link','source','wbr'}:
            self.stack.append(tag)
    def handle_data(self,data):
        if self.row is not None:self.row['text'].append(data)
        if self.link is not None:self.link['parts'].append(data)
        self.text.append(data)
    def handle_endtag(self,tag):
        tag=tag.lower()
        if tag=='a' and self.link is not None and self.row is not None:
            self.link['title']=re.sub(r'\s+',' ',''.join(self.link['parts'])).strip()
            self.row['links'].append(self.link); self.link=None
        if tag=='tr' and self.row is not None:
            self.rows.append(self.row);self.row=None
        if tag=='table' and self.table_depth:self.table_depth-=1
        if tag in self.stack:
            for i in range(len(self.stack)-1,-1,-1):
                if self.stack[i]==tag:
                    del self.stack[i:];break


def find_nttid(attrs):
    """Recognize explicit nttId and common view(number) onclick variants.

    Reject ambiguous or unknown link patterns rather than inventing ids.
    """
    for field in ('href','onclick','data-nttid','data-id'):
        value=str(attrs.get(field,'')).strip()
        if field in ('data-nttid','data-id') and value.isdigit():return value
        m=re.search(r'nttId(?:=|%3[Dd]|\s*[:=]\s*[\'\"]?)(\d{2,12})',value,re.I)
        if m:return m.group(1)
        m=re.search(r'(?:fn_?view|go_?view|view_?detail|fn_?detail|view)\s*\(\s*[\'\"]?(\d{2,12})[\'\"]?',value,re.I)
        if m:return m.group(1)
    return ''


def parse_listing(html,board):
    if isinstance(html,bytes):html=html.decode('utf-8-sig','replace')
    parser=Listing();parser.feed(html);parser.close()
    plain=re.sub(r'\s+',' ',''.join(parser.text))
    total_match=re.search(r'총\s*게시물\s*([\d,]+)\s*건',plain)
    total=int(total_match.group(1).replace(',','')) if total_match else None
    items=[];seen=set();unresolved=[]
    for row in parser.rows:
        for link in row['links']:
            title=link['title']
            attrs=link['attrs']
            val=' '.join(str(v) for v in attrs.values())
            # Exclude navigation links and file attachments.
            if len(title)<7 or title in {'목록으로','다음 페이지','이전 페이지'}:continue
            if not (('view' in val.lower() or 'nttId' in val or 'nttid' in val.lower() or 'detail' in val.lower())):
                continue
            nttid=find_nttid(attrs)
            if not nttid:
                unresolved.append({'title':title,'href':str(attrs.get('href',''))[:160],
                                   'onclick':str(attrs.get('onclick',''))[:160]})
                continue
            key=f'{BOARDS[board][0]}:{nttid}'
            if key in seen:continue
            seen.add(key)
            items.append({'key':key,'title':title,'url':detail_url(board,nttid),'board':board})
    samples=[{'title':link['title'][:80], 'attrs':{k:str(v)[:140] for k,v in link['attrs'].items()}}
             for row in parser.rows for link in row['links']][:6]
    return {'total':total,'items':items,'unresolved':unresolved[:10],
            'row_count':len(parser.rows),'samples':samples}


def fetch_listing(board,page):
    url=list_url(board,page)
    req=Request(url,headers={'User-Agent':AGENT,'Accept':'text/html'})
    with build_opener(NoRedirect()).open(req,timeout=20) as resp:
        if not resp.headers.get('Content-Type','').lower().startswith('text/html'):
            raise ValueError('KISA list response is not HTML')
        if resp.headers.get('Content-Length') and int(resp.headers['Content-Length'])>MAX_LIST_BYTES:
            raise ValueError('KISA listing HTML too large')
        data=resp.read(MAX_LIST_BYTES+1)
    if len(data)>MAX_LIST_BYTES:raise ValueError('KISA listing HTML too large')
    return data


def read_existing(session):
    # Key by official bbsId+nttId, never by title. Existing RSS ids are preserved.
    lookup={}
    for row in session.run('''MATCH (a:KISAAdvisory) WHERE a.url IS NOT NULL
         RETURN a.sourceId AS sourceId, a.url AS url, a.detailStatus AS detailStatus'''):
        key=key_of(row['url'])
        if key:
            lookup.setdefault(key,dict(row))
    return lookup


def safe_insert(session,item,detail):
    """Add ONLY new validated advisory; never update an existing sourceId."""
    now=datetime.now(timezone.utc).isoformat()
    source_id='kisa-backfill-'+hashlib.sha256(item['key'].encode()).hexdigest()
    # Source collision defense and reproducible page identity.
    bbsid,nttid=item['key'].split(':')
    params=dict(sourceId=source_id,title=item['title'],url=item['url'],
                sourceFeed=item['board'],sourceName='KISA 보호나라',
                publishedAt=detail['detailPublishedAt'] or '',
                summary='',cveIds=detail['detailCveIds'],seen=now,
                detailText=detail['detailText'],detailPublishedAt=detail['detailPublishedAt'],
                detailCveIds=detail['detailCveIds'],detailSha256=detail['detailSha256'],
                bulletinKey=item['key'])
    # One article in one explicit transaction; no Alert/Incident/Technique links.
    def txwork(tx):
        # A pre-existing RSS node can have a different sourceId for this bulletin.
        # Fail closed and skip if a bulletin with this key is already in DB.
        existing=tx.run('''MATCH (a:KISAAdvisory) WHERE a.url IS NOT NULL
             AND a.url CONTAINS $ident RETURN a.sourceId AS id, a.url AS url''',
             ident='nttId='+nttid).data()
        for match in existing:
            if key_of(match['url'])==item['key']:
                return False
        result=tx.run('''MERGE (a:KISAAdvisory {sourceId:$sourceId})
            ON CREATE SET a.firstSeenAt=$seen,
              a.sourceName=$sourceName, a.sourceFeed=$sourceFeed,
              a.title=$title, a.url=$url, a.publishedAt=$publishedAt,
              a.summary=$summary, a.cveIds=$cveIds,
              a.detailText=$detailText, a.detailPublishedAt=$detailPublishedAt,
              a.detailCveIds=$detailCveIds, a.detailSha256=$detailSha256,
              a.detailSourceUrl=$url, a.detailCheckedAt=$seen,
              a.detailStatus='verified_official_page',
              a.backfillBulletinKey=$bulletinKey,
              a.lastSeenAt=$seen
            RETURN a.sourceId AS id''',**params).single()
        if not result:raise RuntimeError('Insert failed')
        if detail['detailCveIds']:
            tx.run('''UNWIND $cves AS cve
                MATCH (a:KISAAdvisory {sourceId:$sourceId})
                MERGE (v:KISACVE {cveId:cve})
                ON CREATE SET v.sourceBasis='KISA official advisory', v.createdAt=$now
                MERGE (a)-[:MENTIONS_CVE]->(v)''',
                cves=detail['detailCveIds'],sourceId=source_id,now=now).consume()
        return True
    return session.execute_write(txwork)


def append_record(file,info):
    file.parent.mkdir(parents=True,exist_ok=True)
    with file.open('a',encoding='utf-8') as f:
        f.write(json.dumps(info,ensure_ascii=False)+'\n')


def checkpoint_path():
    return Path.home()/'ontology-project'/'real_logs'/'kisa_history_backfill_progress.json'


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--probe',action='store_true',help='Inspect first list page per feed; NO DB writes')
    p.add_argument('--apply',action='store_true',help='Explicitly save only successfully verified new articles')
    p.add_argument('--all',action='store_true',help='Traverse all pages. Otherwise one page per feed by default')
    p.add_argument('--max-pages',type=int,default=1,help='Pages per feed without --all (1..300)')
    p.add_argument('--delay',type=float,default=3.0,help='Minimum seconds between requests (>=2.0)')
    p.add_argument('--resume',action='store_true',help='Resume from checkpoint per feed')
    p.add_argument('--board',choices=['both',*BOARDS],default='both')
    p.add_argument('--max-items',type=int,default=0,help='Bound article requests per run (0 unlimited)')
    a=p.parse_args()
    if not 1<=a.max_pages<=300:p.error('--max-pages must be 1..300')
    if a.delay<2:p.error('--delay must be >= 2 seconds')
    if a.probe and a.apply:p.error('--probe and --apply are mutually exclusive')
    if a.resume and not a.apply:p.error('--resume requires --apply')
    if a.all and not a.apply:p.error('--all requires --apply after probe / small tests')
    if a.all and a.max_items:p.error('--all is not compatible with --max-items')
    boards=list(BOARDS) if a.board=='both' else [a.board]
    progress=checkpoint_path()
    try:state=json.loads(progress.read_text(encoding='utf-8')) if a.resume and progress.exists() else {}
    except json.JSONDecodeError:raise SystemExit('Corrupt checkpoint file; manual review needed')
    log=progress.with_name('kisa_history_backfill_events.jsonl')
    result={'boards':boards,'lists':0,'entries':0,'existing':0,'verified':0,
            'added':0,'failed':0,'unresolved':0,'dry_run':not a.apply}
    drv=None
    try:
        if not a.probe:
            drv=get_driver()
            with drv.session(database=os.environ.get('NEO4J_DATABASE','neo4j')) as sess:
                existing=read_existing(sess)
        else:existing={}
        for board in boards:
            start=int(state.get(board,1)) if a.resume else 1
            max_page=300 if a.all else min(start+a.max_pages-1,300)
            first_page_signature=None
            for page in range(start,max_page+1):
                try:
                    listing=parse_listing(fetch_listing(board,page),board)
                except Exception as exc:
                    result['failed']+=1
                    print('LIST ERROR',board,page,type(exc).__name__,str(exc)[:160]);break
                result['lists']+=1
                items=listing['items']
                result['unresolved']+=len(listing['unresolved'])
                print(f'LIST {board} page={page} rows={listing["row_count"]} '
                      f'identified={len(items)} total={listing["total"]} unresolved={len(listing["unresolved"])}')
                if a.probe:
                    for v in items[:4]:print(' FOUND',v['key'],v['title'][:70])
                    for v in listing['unresolved'][:3]:print(' UNKNOWN',v)
                    if not items:
                        for v in listing['samples'][:5]:print(' SAMPLE LINK',v)
                    sig=tuple(x['key'] for x in items)
                    if first_page_signature is not None and sig==first_page_signature:
                        print('PROBE ERROR: page returned identical bulletin IDs - pagination is not working')
                        result['failed']+=1
                        break
                    first_page_signature=sig
                    if not items or listing['unresolved']:
                        result['failed']+=1
                    if page < max_page:time.sleep(a.delay)
                    continue
                if not items:
                    print('STOP: list parsed zero entries. Template may differ; inspect --probe output.')
                    result['failed']+=1;break
                sig=tuple(x['key'] for x in items)
                if sig==first_page_signature:
                    print('STOP: pagination repeated same page - avoid infinite collection')
                    result['failed']+=1;break
                first_page_signature=sig
                result['entries']+=len(items)
                if listing['unresolved']:
                    print('STOP: links could not be identified safely; fix parser before saving')
                    result['failed']+=len(listing['unresolved']);break
                if listing['total'] is not None and page>1 and page>(listing['total']+9)//10:
                    break
                for item in items:
                    if item['key'] in existing:
                        result['existing']+=1;continue
                    if a.max_items and result['verified']>=a.max_items:
                        print('STOP: --max-items reached');return 0
                    time.sleep(a.delay)
                    try:
                        detail=parse_detail(official_page(item['url']),item['title'])
                        if not detail['detailText'] or not detail['detailPublishedAt']:
                            raise ValueError('Missing verified detail or date')
                        result['verified']+=1
                        print(' VERIFIED',item['key'],'chars',len(detail['detailText']),
                              'date',detail['detailPublishedAt'],'cves',len(detail['detailCveIds']))
                        if a.apply:
                            with drv.session(database=os.environ.get('NEO4J_DATABASE','neo4j')) as session:
                                if safe_insert(session,item,detail):
                                    result['added']+=1
                                    existing[item['key']]={'sourceId':'backfill','url':item['url']}
                                    print('  STORED',item['key'])
                                else:print('  SKIPPED pre-existing bulletin',item['key'])
                    except Exception as exc:
                        result['failed']+=1
                        print(' SKIP',item['key'],type(exc).__name__,str(exc)[:170])
                        append_record(log,{'at':datetime.now(timezone.utc).isoformat(),
                            'board':board,'page':page,'key':item['key'],'title':item['title'],
                            'error':type(exc).__name__+': '+str(exc)[:240]})
                if a.apply:
                    state[board]=page+1
                    progress.parent.mkdir(parents=True,exist_ok=True)
                    progress.write_text(json.dumps(state,indent=2),encoding='utf-8')
                if a.all and listing['total'] is not None and page >= (listing['total']+9)//10:
                    break
                time.sleep(a.delay)
    except KeyboardInterrupt:
        print('INTERRUPTED - existing successfully committed records remain in Neo4j')
    finally:
        if drv:drv.close()
        print('SUMMARY:',json.dumps(result,ensure_ascii=False))
    return 1 if result['failed'] else 0

if __name__=='__main__':raise SystemExit(main())
