#!/usr/bin/env python3
"""Read bounded KISA official advisory HTML, enrich ONLY KISAAdvisory and CVE mentions.

Never create alerts, product vulnerability assertions, attack detections or patch status.
No writes on --dry-run. Standard-library only, except the installed Neo4j client.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone, timedelta
import hashlib
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
from urllib.parse import urlsplit
from urllib.request import Request, urlopen, build_opener, HTTPRedirectHandler

from cto_kisa_rag import valid_url, CVE_RE

MAX_HTML = 3_000_000
MAX_TEXT = 10_000
MAX_RECORDS = 60
AGENT = '3K1H-KISA-Official-Advisory/1.0 (public pages only)'
BLOCKS = {'h1','h2','h3','h4','p','div','br','table','tr','td','th','section','article','li','ul','ol','strong'}
SKIP = {'script','style','svg','noscript','header','footer','nav','aside','form'}
DATE = re.compile(r'^(?:19|20)\d\d[-.]\d{1,2}[-.]\d{1,2}$')
STOP_MARKS = ('키워드', '이전 글', '다음 글', '목록으로', '개인정보처리방침', 'KISA 대국민서비스')
SECTION_MARKS = ('□ 개요','□ 설명','□ 영향','□ 참고', '영향받는 제품', '취약점', '해결 방안')

class PageText(HTMLParser):
    """Flatten visible body text; headings and table rows retain boundaries."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.lines = []
        self.buf = []
        self.skip = []
        self.in_body = False
        self.saw_body = False
    def handle_starttag(self,tag,attrs):
        tag=tag.lower()
        if tag=='body': self.in_body=True;self.saw_body=True
        if tag in SKIP:
            self.flush();self.skip.append(tag)
        elif tag in BLOCKS and not self.skip:
            self.flush()
    def handle_endtag(self,tag):
        tag=tag.lower()
        if self.skip:
            if tag==self.skip[-1]:self.skip.pop()
            return
        if tag in BLOCKS: self.flush()
        if tag=='body':self.in_body=False
    def handle_data(self,data):
        if not self.skip and self.in_body:
            self.buf.append(data)
    def flush(self):
        if self.buf:
            v=re.sub(r'\s+',' ',''.join(self.buf)).strip()
            if v:self.lines.append(v)
            self.buf=[]


def _normalise_title(value):
    """Use only for checking the identity of an advisory, never as evidence text."""
    value = re.sub(r'\s+', ' ', str(value or '')).strip()
    return re.sub(r'[^0-9a-z가-힣]+', '', value.casefold())


# Publication metadata is not the same as a product release date or a date
# mentioned in the advisory description. Accept ONLY explicit near-heading
# publication labels from the rendered official page.
PUBLISHED_LABEL = re.compile(r'(?:작성일자?|등록일자?|게시일자?|등록날짜|게시날짜|작성날짜|공고일)(?=$|\s|[:：\-])(?:\s*[:：\-]\s*|\s*)', re.I)
PUBLISHED_DATE = re.compile(r'(?<!\d)((?:19|20)\d{2})[.\-/년 ]+([01]?\d)[.\-/월 ]+([0-3]?\d)(?:일)?(?!\d)')


def _date_iso(value):
    match = PUBLISHED_DATE.search(str(value or ''))
    if not match:
        return ''
    try:
        result = datetime(int(match[1]), int(match[2]), int(match[3])).date()
    except ValueError:
        return ''
    # Published dates after the current local day are suspect (clock is KST).
    return result.isoformat() if result <= (datetime.now(timezone(timedelta(hours=9))).date()) else ''


def extract_official_date(lines, section_index, title):
    # Limit the search to article metadata before the first section, never the
    # product-version table, external references, or later advisory body.
    begin = max(0, section_index - 55)
    search = lines[begin:section_index]
    normalized = _normalise_title(title)
    cvem = {v.upper() for v in CVE_RE.findall(title)}
    title_indexes = [i for i, text in enumerate(search) if
                     (normalized and normalized in _normalise_title(text)) or
                     (cvem and any(cve in text.upper() for cve in cvem))]
    # A publication label must occur near the expected article heading.
    for i, line in enumerate(search):
        lm = PUBLISHED_LABEL.search(line)
        if not lm:
            continue
        if title_indexes and min(abs(i - j) for j in title_indexes) > 30:
            continue
        date = _date_iso(line[lm.end():])
        if not date and i + 1 < len(search):
            date = _date_iso(search[i + 1])
        if date:
            return date
    # Some KISA templates show the publication date next to the article
    # heading without a '작성일' label. Accept it ONLY on the matched heading
    # line or on its immediately following date-only line, before □ 개요.
    for idx in title_indexes:
        heading = search[idx]
        date = _date_iso(heading)
        if date:
            return date
        if idx + 1 < len(search):
            nextline = search[idx + 1].strip()
            if DATE.fullmatch(nextline):
                date = _date_iso(nextline)
                if date:
                    return date
    return ''



class BoardTitleDate(HTMLParser):
    """Extract an article publication date only from the official .b_title header."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.depth = 0
        self.capture = None
        self.heading_parts = []
        self.date_spans = []
        self.buf = []

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        attrs = dict(attrs)
        if self.depth:
            if tag == 'div':
                self.depth += 1
            if self.depth == 1 and tag in ('h2', 'span'):
                self.capture = tag
                self.buf = []
        elif tag == 'div' and 'b_title' in attrs.get('class', '').split():
            self.depth = 1

    def handle_data(self, data):
        if self.depth and self.capture:
            self.buf.append(data)

    def handle_endtag(self, tag):
        tag = tag.lower()
        if self.depth and self.capture == tag:
            value = re.sub(r'\\s+', ' ', ''.join(self.buf)).strip()
            if self.capture == 'h2':
                self.heading_parts.append(value)
            elif self.capture == 'span':
                self.date_spans.append(value)
            self.capture = None
            self.buf = []
        if tag == 'div' and self.depth:
            self.depth -= 1


def extract_board_header_date(html, expected_title):
    """Accept a date only when the nearby KISA board title identifies this notice."""
    parser = BoardTitleDate()
    parser.feed(html)
    parser.close()
    expected = _normalise_title(expected_title)
    expected_cves = {m.upper() for m in CVE_RE.findall(expected_title)}
    if not expected:
        return ''
    for heading in parser.heading_parts:
        normalized_heading = _normalise_title(heading)
        heading_cves = {m.upper() for m in CVE_RE.findall(heading)}
        if expected_cves:
            # A CVE alone is not sufficient if the heading names a different notice.
            matches = expected_cves == heading_cves and (
                normalized_heading == expected or
                (len(expected) >= 24 and (expected in normalized_heading or normalized_heading in expected))
            )
        else:
            matches = normalized_heading == expected
        if not matches:
            continue
        dates = [_date_iso(value) for value in parser.date_spans if DATE.fullmatch(value.strip())]
        dates = [value for value in dates if value]
        if len(set(dates)) == 1:
            return dates[0]
    return ''



class OfficialBoardContent(HTMLParser):
    """Extract a unique official board title and its content_html block.

    The KISA general-notice template can have b_title and content_html without
    an article.board parent. Validate the actual title, date, and content
    independently; never accept site navigation as advisory evidence.
    """
    BREAKS = {'div', 'p', 'br', 'section', 'h1', 'h2', 'h3',
              'tr', 'td', 'th', 'li', 'ul', 'ol', 'table'}
    IGNORE = {'script', 'style', 'svg', 'noscript', 'form', 'nav', 'footer'}
    VOID = {'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input',
            'link', 'meta', 'param', 'source', 'track', 'wbr'}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []
        self.header_parts = []
        self.text = []
        self.body_found = 0
        self.title_found = 0

    @staticmethod
    def _has_class(attrs, value):
        return value in (dict(attrs).get('class') or '').split()

    def _inside(self, tag, attr=None):
        return any(
            t == tag and (attr is None or self._has_class(attrs, attr))
            for t, attrs in self.stack
        )

    def _ignored(self):
        return any(t in self.IGNORE for t, _ in self.stack)

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        # Count exact official content markers independently of article.board.
        if tag == 'div' and self._has_class(attrs, 'content_html'):
            self.body_found += 1
        if tag == 'h2' and self._inside('div', 'b_title'):
            self.title_found += 1
        if self._inside('div', 'content_html') and not self._ignored() and tag in self.BREAKS:
            self.text.append('\n')
        if tag not in self.VOID:
            self.stack.append((tag, attrs))

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag.lower() not in self.VOID:
            self.handle_endtag(tag)

    def handle_data(self, data):
        if self._ignored():
            return
        if self._inside('h2') and self._inside('div', 'b_title'):
            self.header_parts.append(data)
        if self._inside('div', 'content_html'):
            self.text.append(data)

    def handle_endtag(self, tag):
        tag = tag.lower()
        if self._inside('div', 'content_html') and not self._ignored() and tag in self.BREAKS:
            self.text.append('\n')
        # Close the matching element, including stray unclosed inline tags.
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                del self.stack[i:]
                break

    def article(self, title):
        if self.title_found != 1 or self.body_found != 1:
            raise ValueError('Verified board title/content container not found')
        heading = re.sub(r'\s+', ' ', ''.join(self.header_parts)).strip()
        requested = re.sub(r'\s+', ' ', str(title or '')).strip()
        if not _normalise_title(requested):
            raise ValueError('RSS title too short for non-CVE verification')
        if _normalise_title(heading) != _normalise_title(requested):
            raise ValueError('Official board heading does not match RSS title')
        lines = [re.sub(r'\s+', ' ', line).strip()
                 for line in ''.join(self.text).split('\n')]
        lines = [line for line in lines if line]
        content = '\n'.join(lines).strip()
        if len(content) < 100:
            raise ValueError('Official non-CVE bulletin body too short')
        if len(content) > MAX_TEXT:
            content = content[:MAX_TEXT].rstrip()
        return content


def parse_non_cve_detail(html, title):
    """Validate the official board heading and substantive article body.

    This strict non-CVE route does not require a CVE or a vulnerability section,
    because general security notices can use a different content structure.
    """
    if isinstance(html, bytes):
        html = html.decode('utf-8-sig', 'replace')
    if CVE_RE.search(title or ''):
        raise ValueError('CVE notice must use the CVE verification route')
    board = OfficialBoardContent()
    board.feed(html)
    board.close()
    detail = board.article(title)
    posted = extract_board_header_date(html, title)
    if not posted:
        raise ValueError('Official non-CVE publication date missing')
    return {'detailText': detail, 'detailPublishedAt': posted,
            'detailCveIds': sorted({c.upper() for c in CVE_RE.findall(detail)}),
            'detailSha256': hashlib.sha256(detail.encode('utf-8')).hexdigest()}



def parse_detail(html, title):
    """Read a KISA page even if its on-page heading differs from the RSS title.

    A CVE-bearing RSS item must have the same CVE in the extracted *body*.
    A notice without a CVE needs matching substantive title text in the page.
    Page sections are required before any detail is accepted.
    """
    if not CVE_RE.search(str(title or '')):
        return parse_non_cve_detail(html, title)
    if isinstance(html, bytes):
        html = html.decode('utf-8-sig', 'replace')
    parser = PageText()
    parser.feed(html)
    parser.flush()
    lines = parser.lines
    title = re.sub(r'\s+', ' ', str(title or '')).strip()
    if not title:
        raise ValueError('Missing advisory title')
    if not lines:
        raise ValueError('Official page body is empty')

    # The old exact-title requirement rejected official pages whose visible
    # heading omitted the RSS prefix or split the advisory title across tags.
    index = next((i for i, line in enumerate(lines)
                  if line == title or (title in line and len(line) < len(title) + 35)), None)

    section_starts = ('□ 개요', '□ 설명', '□ 영향받는', '□ 영향',
                      '□ 취약점', '개요', '영향받는 제품 및 해결 방안')
    section = next((i for i, line in enumerate(lines)
                    if any(line.startswith(mark) for mark in section_starts)), None)
    if section is None:
        raise ValueError('Official advisory content sections not found')
    if index is not None and index < section:
        start = index + 1
    else:
        start = section

    body = []
    length = 0
    for line in lines[start:]:
        if any(line.startswith(mark) for mark in STOP_MARKS):
            break
        if length + len(line) > MAX_TEXT * 2:
            break
        body.append(line)
        length += len(line)
    detail = '\n'.join(body)[:MAX_TEXT].strip()
    if len(detail) < 100:
        raise ValueError('Official advisory body too short')
    # Do not trust menus, headers or footer boilerplate as an official body.
    if not any(mark in detail for mark in ('□ 개요', '□ 설명', '영향받는 제품', '해결 방안')):
        raise ValueError('Official advisory body sections not verified')
    if not any(mark in detail for mark in ('취약점', 'CVE-', '보안 업데이트', '보안 권고')):
        raise ValueError('Official advisory subject not verified')

    title_cves = {m.upper() for m in CVE_RE.findall(title)}
    body_cves = {m.upper() for m in CVE_RE.findall(detail)}
    if title_cves:
        if not title_cves.intersection(body_cves):
            raise ValueError('RSS CVE not found in official advisory body')
    else:
        normalized_title = _normalise_title(title)
        normalized_page = _normalise_title(' '.join(lines[:max(section + 1, 15)]))
        if len(normalized_title) < 12 or normalized_title not in normalized_page:
            raise ValueError('Official title not verified for non-CVE advisory')

    posted = extract_board_header_date(html, title) or extract_official_date(lines, section, title)
    return {'detailText':detail, 'detailPublishedAt':posted,
            'detailCveIds':sorted(body_cves),
            'detailSha256':hashlib.sha256(detail.encode('utf-8')).hexdigest()}


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*a,**kw):
        raise ValueError('Unexpected redirect; official URL must remain unchanged')


def official_page(url, opener=None):
    if not valid_url(url):raise ValueError('URL not on KISA HTTPS allowlist')
    u=urlsplit(url)
    if u.port not in (None,443):raise ValueError('Only HTTPS port 443 allowed')
    if u.path != '/kr/bbs/view.do' or not u.query or 'nttId=' not in u.query:
        raise ValueError('Not a supported KISA bulletin URL')
    op=opener or build_opener(NoRedirect())
    req=Request(url,headers={'User-Agent':AGENT,'Accept':'text/html'})
    with op.open(req, timeout=12) as res:
        if res.headers.get('Content-Length') and int(res.headers['Content-Length'])>MAX_HTML:
            raise ValueError('Response too large')
        if not res.headers.get('Content-Type','').lower().startswith('text/html'):
            raise ValueError('Not HTML')
        payload=res.read(MAX_HTML+1)
    if len(payload)>MAX_HTML:raise ValueError('HTML too large')
    return payload


def password():
    v=os.environ.get('NEO4J_PASSWORD')
    if v:return v
    p=Path.home()/'.cto_neo4j_password'
    if not p.is_file():raise RuntimeError('Missing Neo4j password')
    return p.read_text(encoding='utf8').strip()


def get_driver():
    from neo4j import GraphDatabase
    drv=GraphDatabase.driver(os.environ.get('NEO4J_URI','bolt://127.0.0.1:7687'),
                             auth=(os.environ.get('NEO4J_USER','neo4j'),password()))
    drv.verify_connectivity()
    return drv


def enrich(session,rows,*,dry_run=True,force=False,opener=None,now=None):
    now=now or datetime.now(timezone.utc)
    stats={'checked':0,'updated':0,'skipped':0,'failed':0,'new_relations':0,'dry_run':dry_run}
    for item in rows:
        url=str(item.get('url') or '')
        if not valid_url(url):stats['skipped']+=1;continue
        checked=str(item.get('detailCheckedAt') or '')
        if checked and not force:
            try:
                if now-datetime.fromisoformat(checked) < timedelta(hours=24):
                    stats['skipped']+=1;continue
            except (TypeError,ValueError):pass
        stats['checked']+=1
        try:
            detail=parse_detail(official_page(url,opener),item.get('title'))
        except Exception as exc:
            stats['failed']+=1
            print('DETAIL SKIP',str(item.get('sourceId') or '')[:80],type(exc).__name__,str(exc)[:120])
            continue
        print('DETAIL',str(item.get('sourceId') or '')[:64],
              'CVE',len(detail['detailCveIds']),'chars',len(detail['detailText']),
              'date',detail['detailPublishedAt'] or 'unknown')
        if dry_run:continue
        d={**detail,'sourceId':item['sourceId'],'url':url,'now':now.isoformat()}
        # Only bind to the exact already-stored advisory; never insert a new one.
        res=session.run('''
          MATCH (a:KISAAdvisory {sourceId:$sourceId})
          WHERE a.url = $url AND coalesce(a.cveLinkBlocked,false) = false AND NOT (coalesce(a.url,'') CONTAINS 'bbsId=B0000302' AND coalesce(a.url,'') =~ '.*[?&]nttId=35350(&.*)?')
          SET a.detailText=$detailText, a.detailPublishedAt=$detailPublishedAt,
              a.detailCveIds=$detailCveIds, a.detailSha256=$detailSha256,
              a.detailSourceUrl=$url, a.detailCheckedAt=$now,
              a.detailStatus='verified_official_page'
          RETURN a.sourceId AS sourceId
        ''',**d)
        if not res.single():raise RuntimeError('Advisory changed before detail save')
        stats['updated']+=1
        # Link only CVEs that occurred literally in the official page, no product/ATT&CK edges.
        if detail['detailCveIds']:
            links=session.run('''
              UNWIND $cves AS cve
              MATCH (a:KISAAdvisory {sourceId:$sourceId})
              WHERE coalesce(a.cveLinkBlocked,false) = false AND NOT (coalesce(a.url,'') CONTAINS 'bbsId=B0000302' AND coalesce(a.url,'') =~ '.*[?&]nttId=35350(&.*)?')
              MERGE (v:KISACVE {cveId:cve})
              ON CREATE SET v.sourceBasis='KISA official advisory', v.createdAt=$now
              MERGE (a)-[:MENTIONS_CVE]->(v)
            ''', sourceId=item['sourceId'],cves=detail['detailCveIds'],now=now.isoformat()).consume()
            stats['new_relations']+=links.counters.relationships_created
    return stats


def update_verified_dates(session, rows, *, dry_run=True, opener=None):
    # Read-only by default; match already verified records.
    # Require the saved detail digest to be identical.
    stats = {'checked': 0, 'ready': 0, 'updated': 0, 'missing_date': 0,
             'content_mismatch': 0, 'failed': 0, 'dry_run': dry_run}
    for row in rows:
        stats['checked'] += 1
        try:
            fresh = parse_detail(official_page(row['url'], opener), row['title'])
        except Exception as exc:
            stats['failed'] += 1
            print('DATE SKIP', row['sourceId'], type(exc).__name__, str(exc)[:120])
            continue
        date = fresh['detailPublishedAt']
        if not date:
            stats['missing_date'] += 1
            print('DATE MISSING', row['sourceId'], 'official publication metadata not verified')
            continue
        if fresh['detailSha256'] != row.get('detailSha256'):
            stats['content_mismatch'] += 1
            print('DATE SKIP', row['sourceId'], 'detail SHA256 changed; manual review needed')
            continue
        stats['ready'] += 1
        print('DATE VERIFIED', row['sourceId'], date)
        if dry_run:
            continue
        result = session.run('''
            MATCH (a:KISAAdvisory {sourceId:$sourceId})
            WHERE a.url=$url AND a.detailStatus='verified_official_page'
              AND a.detailSha256=$sha AND coalesce(a.detailPublishedAt,'')=''
            SET a.detailPublishedAt=$date
            RETURN a.sourceId AS sourceId
        ''', sourceId=row['sourceId'], url=row['url'], sha=row['detailSha256'], date=date)
        if result.single():
            stats['updated'] += 1
    return stats


def main(argv=None):
    arg=argparse.ArgumentParser()
    arg.add_argument('--dry-run',action='store_true')
    arg.add_argument('--force',action='store_true',help='Refresh verified detail even within 24h')
    arg.add_argument('--limit',type=int,default=30)
    arg.add_argument('--fixture',type=Path,help='Offline HTML fixture; requires --title')
    arg.add_argument('--title',default='')
    arg.add_argument('--dates-only', action='store_true', help='Check official dates for already verified advisories only')
    arg.add_argument('--non-cve-only', action='store_true',
                     help='Only unverified notices whose titles have no CVE')
    arg.add_argument('--apply-non-cve', action='store_true',
                     help='Save verified general notices (requires --non-cve-only)')

    arg.add_argument('--apply-dates', action='store_true', help='Explicitly save validated dates (requires --dates-only)')
    a=arg.parse_args(argv)
    if a.fixture:
        if not a.title:arg.error('--fixture requires --title')
        print(json.dumps(parse_detail(a.fixture.read_bytes(),a.title),ensure_ascii=False,indent=2))
        return 0
    if a.apply_dates and not a.dates_only: arg.error('--apply-dates requires --dates-only')
    if a.apply_non_cve and not a.non_cve_only:
        arg.error('--apply-non-cve requires --non-cve-only')
    if a.non_cve_only and (a.dates_only or a.apply_dates or a.force):
        arg.error('--non-cve-only cannot be combined with date or force modes')

    if not 1<=a.limit<=MAX_RECORDS:arg.error('--limit 1..60')
    drv=get_driver()
    try:
        with drv.session(database=os.environ.get('NEO4J_DATABASE','neo4j')) as s:
            if a.dates_only:
                rows=[dict(x) for x in s.run('''
                    MATCH (a:KISAAdvisory)
                    WHERE a.detailStatus='verified_official_page'
                      AND a.detailSha256 IS NOT NULL
                      AND coalesce(a.detailPublishedAt,'')=''
                      AND a.sourceId IS NOT NULL AND a.url IS NOT NULL
                    RETURN a.sourceId AS sourceId, a.title AS title,
                           a.url AS url, a.detailSha256 AS detailSha256
                    ORDER BY a.firstSeenAt DESC LIMIT $limit
                ''',limit=a.limit)]
                report=update_verified_dates(s,rows,dry_run=not a.apply_dates)
                print('KISA date verification:', json.dumps(report,ensure_ascii=False))
                return 0
            if a.non_cve_only:
                rows = [dict(x) for x in s.run('''
                    MATCH (a:KISAAdvisory)
                    WHERE a.sourceId IS NOT NULL AND a.url IS NOT NULL AND coalesce(a.cveLinkBlocked,false) = false AND NOT (coalesce(a.url,'') CONTAINS 'bbsId=B0000302' AND coalesce(a.url,'') =~ '.*[?&]nttId=35350(&.*)?')
                      AND a.title IS NOT NULL
                      AND NOT toUpper(a.title) CONTAINS 'CVE-'
                      AND coalesce(a.detailStatus,'') <> 'verified_official_page'
                    RETURN a.sourceId AS sourceId, a.title AS title,
                           a.url AS url, null AS detailCheckedAt
                    ORDER BY a.firstSeenAt DESC
                    LIMIT $limit
                ''', limit=a.limit)]
                print('KISA non-CVE candidates:', len(rows))
                result = enrich(s, rows, dry_run=not a.apply_non_cve)
                print('KISA non-CVE verification:', json.dumps(result, ensure_ascii=False))
                return 0
            # Most recent by firstSeen, not by missing publishedAt.
            rows=[dict(x) for x in s.run('''
              MATCH (a:KISAAdvisory)
              WHERE a.sourceId IS NOT NULL AND a.url IS NOT NULL AND coalesce(a.cveLinkBlocked,false) = false AND NOT (coalesce(a.url,'') CONTAINS 'bbsId=B0000302' AND coalesce(a.url,'') =~ '.*[?&]nttId=35350(&.*)?')
              RETURN a.sourceId AS sourceId, a.title AS title, a.url AS url,
                     a.detailCheckedAt AS detailCheckedAt
              ORDER BY coalesce(a.detailCheckedAt,'') ASC, a.firstSeenAt DESC
              LIMIT $limit
            ''',limit=a.limit)]
            result=enrich(s,rows,dry_run=a.dry_run,force=a.force)
            print('KISA detail sync:',json.dumps(result,ensure_ascii=False))
    finally:drv.close()
    return 0

if __name__=='__main__':raise SystemExit(main())

# KISA historical date/title repair v1

# KISA CVE review guard v1: B0000302:35350
