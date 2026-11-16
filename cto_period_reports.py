# CTO_PERIOD_COMPREHENSIVE_V8
"""KST daily/weekly SOC reports: independently verified Neo4j aggregation.

Do not confuse Alert count with event count, or inferred incidents with confirmed attacks.
No destructive response actions are performed.
"""
from __future__ import annotations

from collections import Counter
from math import ceil
from datetime import datetime, timedelta, timezone
from pathlib import Path
import re
import uuid

KST = timezone(timedelta(hours=9))
CAP = 10000


def periods(now=None):
    now = (now or datetime.now(KST)).astimezone(KST)
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    monday = today - timedelta(days=today.weekday())
    elapsed = now - monday
    return {
        'daily': (today, now),
        'weekly': (monday, now),
        'prev_week_same_elapsed': (monday - timedelta(days=7), monday - timedelta(days=7) + elapsed),
    }


def parse_time(value):
    if value is None or str(value).strip() == '':
        return None
    raw = str(value).strip().replace('Z', '+00:00')
    if raw.endswith(' KST'):
        raw = raw[:-4] + '+09:00'
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if dt.tzinfo is None:
        # Matches the existing dashboard's _format_kst convention.
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(KST)


def read_alerts(query):
    # This is intentionally an Alert-first query. Every Alert appears at most
    # once, no matter how many ObservedEvents, Techniques or Incidents it links.
    rows = query('''
    MATCH (a:Alert)
    OPTIONAL MATCH (a)-[:TRIGGERED_BY]-(e:ObservedEvent)
    OPTIONAL MATCH (a)-[:GROUPED_INTO]->(i:Incident)
    OPTIONAL MATCH (a)-[:SUSPECTED_TECHNIQUE]->(t:Technique)
    WITH a, collect(DISTINCT e) AS evs,
         collect(DISTINCT i) AS incs,
         collect(DISTINCT t) AS techs
    RETURN coalesce(toString(a.recordId),toString(a.id),elementId(a)) AS alert_id,
      coalesce(toString(a.detectedAt),toString(a.createdAt),'') AS alert_time,
      coalesce(a.ruleLabel,a.name,'미확인 탐지 규칙') AS rule,
      coalesce(a.severity,'UNKNOWN') AS severity,
      [ev IN evs WHERE ev IS NOT NULL |
        {id:coalesce(toString(ev.recordId),elementId(ev)),
         observed_at:coalesce(toString(ev.observedAt),toString(ev.timestamp),''),
         event_type:coalesce(ev.eventTypeName,ev.event_type,''),
         outcome:coalesce(ev.outcome,'')}] AS events,
      [inc IN incs WHERE inc IS NOT NULL |
        {id:coalesce(toString(inc.recordId),toString(inc.id),elementId(inc)),
         status:coalesce(inc.status,'미확인')}] AS incidents,
      [tech IN techs WHERE tech IS NOT NULL |
        {id:coalesce(tech.externalId,tech.id,''),name:coalesce(tech.name,'')}] AS techniques
    ORDER BY alert_time DESC
    LIMIT $limit
    ''', limit=CAP + 1)
    if len(rows) > CAP:
        raise RuntimeError('Alert 수가 안전 집계 상한을 초과했습니다. 잘린 데이터로 보고서를 만들지 않습니다.')
    return rows


def _record_time(row):
    t = parse_time(row.get('alert_time'))
    if t is not None:
        return t
    times = [parse_time(ev.get('observed_at')) for ev in row.get('events') or []]
    times = [x for x in times if x]
    return min(times) if times else None


def _in_window(date, bounds):
    return date is not None and bounds[0] <= date <= bounds[1]


def _counts(rows, window):
    from cto_period_professional import richer_alert_details
    selected = [r for r in rows if _in_window(_record_time(r),window)]
    severity, rules, techniques = Counter(), Counter(), Counter()
    ev, incident, event_types = set(), set(), Counter()
    per_day = Counter()
    details = []
    for a in selected:
        date = _record_time(a)
        per_day[date.strftime('%Y-%m-%d')] += 1
        severity[str(a.get('severity') or 'UNKNOWN').upper()] += 1
        rules[str(a.get('rule') or '미확인 탐지 규칙')] += 1
        for e in a.get('events') or []:
            eid=e.get('id')
            if eid and eid not in ev:
                ev.add(eid)
                event_types[str(e.get('event_type') or '미확인 이벤트')] += 1
        for i in a.get('incidents') or []:
            if i.get('id'):incident.add(i['id'])
        for t in a.get('techniques') or []:
            tid=str(t.get('id') or '')
            if re.fullmatch(r'T\d{4}(?:\.\d{3})?',tid): techniques[tid] += 1
        details.append(richer_alert_details(a,date))
    return {'alerts':len(selected),'events':len(ev),'incidents':len(incident),
            'severity':severity,'rules':rules,'techniques':techniques,
            'event_types':event_types,'per_day':per_day,'details':details[:30]}


def aggregate(query, kind, now=None):
    from cto_period_professional import operational_summary
    if now is None:now=datetime.now(KST)
    windows=periods(now)
    if kind not in ('daily','weekly'):
        raise ValueError('지원하지 않는 기간')
    # Two independently grounded sets: all ObservedEvents and Alert-linked cases.
    snapshot=read_period_logs(query,kind,now=now)
    records=read_alerts(query)
    no_timestamp=sum(_record_time(x) is None for x in records)
    current=_counts(records,windows[kind])
    previous=_counts(records,windows['prev_week_same_elapsed']) if kind=='weekly' else None
    return {'kind':kind,'start':windows[kind][0],'end':windows[kind][1],
            'current':current,'previous':previous,'undated_alerts':no_timestamp,
            'total_alerts_queried':len(records),
            'operations':operational_summary(snapshot)}


def _count_lines(counter, max_items=8):
    if not counter:return '- 해당 기간 확인된 데이터 없음'
    return '\n'.join(f'- {k}: {v}건' for k,v in counter.most_common(max_items))


def build_markdown(data, report_id):
    from cto_period_professional import form_model, build_markdown as make_markdown
    return make_markdown(form_model(data,report_id))


def save_report(query, data, body, report_id, model=None):
    from cto_period_professional import form_model
    import json
    model=model or form_model(data,report_id)
    model_json=json.dumps(model,ensure_ascii=False)
    op=data['operations']
    rows=query('''
      CREATE (r:Report {
        id:$id, title:$title, reportType:$report_type,
        content:$content, sourceType:'soc_period',
        periodStart:$start, periodEnd:$end, timezone:'Asia/Seoul',
        createdAt:$created_at, alertCount:$alert_count,
        eventCount:$event_count, incidentCount:$incident_count,
        totalCollectedEvents:$all_event_count,alertLinkedEvents:$alert_events,
        unlinkedEvents:$unlinked_events,
        reportDataJson:$structured_data,
        analystReview:'pending'
      }) RETURN r.id AS id
    ''', id=report_id,title=('일일' if data['kind']=='daily' else '주간')+' OpenStack 종합 보안관제 보고서',
       report_type='daily_soc' if data['kind']=='daily' else 'weekly_soc',
       content=body,start=data['start'].isoformat(),end=data['end'].isoformat(),
       created_at=datetime.now(timezone.utc).isoformat(),
       alert_count=data['current']['alerts'],event_count=data['current']['events'],
       incident_count=data['current']['incidents'],
       all_event_count=op['all_events'],alert_events=op['alert_linked_events'],
       unlinked_events=op['unlinked_events'],structured_data=model_json)
    if len(rows)!=1 or rows[0].get('id')!=report_id:
        raise RuntimeError('Neo4j 저장 응답을 확인하지 못했습니다. 재시도 전에 Report 노드 존재 여부를 검사하세요.')
    return report_id


def fetch_saved(query, kind=None, limit=60):
    if kind not in (None, 'daily', 'weekly'):
        raise ValueError('지원하지 않는 보고서 종류')
    report_types = [kind + '_soc'] if kind else ['daily_soc', 'weekly_soc']
    return query('''
      MATCH (r:Report)
      WHERE r.reportType IN $report_types
      RETURN r.id AS id, r.title AS title, r.reportType AS reportType,
             r.content AS content, r.createdAt AS createdAt,
             r.periodStart AS periodStart, r.periodEnd AS periodEnd,
             r.reportDataJson AS reportDataJson
      ORDER BY r.createdAt DESC LIMIT $limit
    ''',report_types=report_types, limit=limit)


def _render_downloads(st, report, key):
    from cto_period_professional import read_model
    if read_model(report):
        from cto_period_professional import generate_docx, generate_pdf
    else:
        # Legacy saved reports have no structured data; keep old downloads.
        from cto_period_documents import generate_docx, generate_pdf
    name='soc_'+('daily' if report['reportType']=='daily_soc' else 'weekly')+'_'+str(report['id'])[:10]
    content=str(report.get('content') or '')
    st.download_button('원문 (.md)',content.encode('utf-8-sig'),file_name=name+'.md',key=key+'_md')
    try:
        doc=generate_docx(report);pdf=generate_pdf(report)
    except (ImportError, OSError, ValueError) as exc:
        st.warning(f'PDF/Word 보고서 생성 확인 필요: {exc}')
        return
    c1,c2=st.columns(2)
    c1.download_button('Word (.docx)',doc,file_name=name+'.docx',mime='application/vnd.openxmlformats-officedocument.wordprocessingml.document',key=key+'_word',use_container_width=True)
    c2.download_button('PDF (.pdf)',pdf,file_name=name+'.pdf',mime='application/pdf',key=key+'_pdf',use_container_width=True)


def read_period_logs(query, kind, now=None, limit=20000):
    """A bounded, read-only snapshot of all ObservedEvents in the KST period.

    Unlike the report aggregate (Alert-first), this is an Event-first log view.
    Filter the retrieved timestamps in Python to support mixed historic ISO formats.
    Never silently truncate and misrepresent a complete period.
    """
    window=periods(now)
    if kind not in ('daily','weekly'):
        raise ValueError('지원하지 않는 기간')
    rows=query('''
      MATCH (e:ObservedEvent)
      OPTIONAL MATCH (a:Alert)-[:TRIGGERED_BY]-(e)
      WITH e,collect(DISTINCT a) AS alerts
      OPTIONAL MATCH (e)-[:PERFORMED_BY]-(u:User)
      WITH e,alerts,head(collect(DISTINCT u)) AS usr
      OPTIONAL MATCH (e)-[:FROM_IP]-(ip:IPAddress)
      WITH e,alerts,usr,head(collect(DISTINCT ip)) AS src
      RETURN
        coalesce(toString(e.recordId),toString(e.message_id),elementId(e)) AS event_id,
        coalesce(toString(e.observedAt),toString(e.timestamp),toString(e.received_at),'') AS observed_at,
        coalesce(e.eventTypeName,e.event_type,e.eventType,'') AS event_type,
        coalesce(e.outcome,e.result,'') AS outcome,
        coalesce(usr.username,usr.name,e.user,e.username,'') AS username,
        coalesce(src.address,src.ip,e.ip,e.source_ip,'') AS source_ip,
        [a IN alerts WHERE a IS NOT NULL |
          coalesce(toString(a.recordId),toString(a.id),elementId(a))] AS alert_ids,
        [a IN alerts WHERE a IS NOT NULL | coalesce(a.severity,'UNKNOWN')] AS severities
      ORDER BY observed_at DESC
      LIMIT $limit
    ''', limit=limit+1)
    if len(rows)>limit:
        raise RuntimeError(f'전체 수집 로그가 {limit:,}건을 넘어 안전 조회 상한에 도달했습니다. '
                           '일부만 표시해 기간 전체인 것처럼 보이게 하지 않습니다. '
                           '서버측 기간 인덱스 조회/페이지 분할이 필요합니다.')
    selected=[]
    undated=0
    for row in rows:
        stamp=parse_time(row.get('observed_at'))
        if stamp is None:
            undated += 1
            continue
        if not _in_window(stamp,window[kind]):
            continue
        alerts=sorted({str(a) for a in (row.get('alert_ids') or []) if a})
        selected.append({
            'event_id':str(row.get('event_id') or ''),
            'time':stamp.strftime('%Y-%m-%d %H:%M:%S KST'),
            'stamp':stamp,
            'event_type':str(row.get('event_type') or '-') or '-',
            'outcome':str(row.get('outcome') or '-') or '-',
            'username':str(row.get('username') or '-') or '-',
            'source_ip':str(row.get('source_ip') or '-') or '-',
            'alerts':alerts,
            'severity':', '.join(sorted({str(x).upper() for x in row.get('severities') or [] if x})) or '-',
            'is_threat':bool(alerts),
        })
    selected.sort(key=lambda r:(r['stamp'],r['event_id']),reverse=True)
    return {'kind':kind,'start':window[kind][0],'end':window[kind][1],
            'items':selected,'undated':undated,'scanned':len(rows)}


def pagination_window(page: int, total_pages: int, window_size: int = 10):
    """Return a valid page and a stable block of numbered navigation links."""
    if total_pages < 1 or window_size < 1:
        raise ValueError('페이지 수와 표시할 번호 수는 양수여야 합니다.')
    current = max(1, min(int(page), int(total_pages)))
    start = ((current - 1) // window_size) * window_size + 1
    return current, list(range(start, min(start + window_size, total_pages + 1)))


def _render_log_pagination(st, kind: str, scope: str, total_pages: int, current: int):
    """CTO_PERIOD_PAGER_ACTIVE_GREEN_V7: compact, centered, non-overlapping pager.

    A single non-wrapping flex row is used instead of three nested column groups.
    At most five page numbers are shown so the pager fits narrow screens; at
    smaller widths the pager scrolls horizontally instead of crushing numbers.
    All active/inactive page numbers stay the same button height.
    """
    page_key = f'cto_period_logs_page_{kind}_{scope}'
    if total_pages < 1:
        raise ValueError('페이지 수는 양수여야 합니다.')
    current = max(1, min(int(current), int(total_pages)))
    visible = min(5, int(total_pages))
    start = max(1, min(current - visible // 2, total_pages - visible + 1))
    numbers = list(range(start, start + visible))

    def select_page(target):
        st.session_state[page_key] = target

    # Restrict CSS to the daily/weekly log pagination only.
    st.markdown("""<style>
      [class*="st-key-cto_period_pagebar_"] {
        max-width: 100% !important;
        overflow-x: auto !important;
        overflow-y: hidden !important;
        margin-top: .22rem !important;
        padding: .12rem 0 !important;
        border: none !important;
        scrollbar-width: thin;
      }
      [class*="st-key-cto_period_pagebar_"] [data-testid="stHorizontalBlock"] {
        display: flex !important;
        flex-flow: row nowrap !important;
        justify-content: center !important;
        align-items: center !important;
        gap: .22rem !important;
        width: max-content !important;
        max-width: none !important;
        margin-inline: auto !important;
      }
      [class*="st-key-cto_period_pagebar_"] [data-testid="stColumn"] {
        flex: 0 0 1.85rem !important;
        width: 1.85rem !important;
        min-width: 1.85rem !important;
        max-width: 1.85rem !important;
        padding: 0 !important;
      }
      [class*="st-key-cto_period_pagebar_"] [data-testid="stVerticalBlock"] {
        gap: 0 !important;
      }
      [class*="st-key-cto_period_pagebar_"] button {
        min-height: 1.75rem !important;
        height: 1.75rem !important;
        width: 1.85rem !important;
        min-width: 1.85rem !important;
        max-width: 1.85rem !important;
        padding: 0 !important;
        border: none !important;
        box-shadow: none !important;
        border-radius: .28rem !important;
        background: transparent !important;
        color: inherit !important;
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
        font-size: .94rem !important;
        line-height: 1 !important;
        font-weight: 500 !important;
        transform: none !important;
      }
      [class*="st-key-cto_period_pagebar_"] button:hover:not(:disabled) {
        background: rgba(127,143,177,.12) !important;
      }
      [class*="st-key-cto_period_pagebar_"] button:disabled {
        color: rgba(145,154,171,.50) !important;
        background: transparent !important;
      }
    </style>""", unsafe_allow_html=True)
    # Stable selection: Streamlit gives the active page a primary button type.
    # The former CSS-only selection depended on key wrapper DOM structure;
    # primary's kind/data-testid is more reliable, and we explicitly color
    # its nested Markdown text instead of styling just the outer button.
    st.markdown("""<style>
      [class*="st-key-cto_period_pagebar_"] button:is([kind="primary"], [data-testid="stBaseButton-primary"]),
      [class*="st-key-cto_period_pagebar_"] button:is([kind="primary"], [data-testid="stBaseButton-primary"]) * {
        color: #22c55e !important;
        font-weight: 800 !important;
      }
      [class*="st-key-cto_period_pagebar_"] button:is([kind="primary"], [data-testid="stBaseButton-primary"]) {
        background: transparent !important;
        border: none !important;
        box-shadow: none !important;
      }
      [class*="st-key-cto_period_pagebar_"] button:is([kind="primary"], [data-testid="stBaseButton-primary"]):hover {
        color: #22c55e !important;
      }
    </style>""", unsafe_allow_html=True)

    with st.container(border=False, key=f'cto_period_pagebar_{kind}_{scope}'):
        cols = st.columns(len(numbers) + 2, gap='small')
        with cols[0]:
            st.button('‹', key=f'{page_key}_prev', help='이전 페이지',
                      disabled=current == 1, use_container_width=True,
                      on_click=select_page, args=(max(1, current - 1),))
        for index, number in enumerate(numbers):
            with cols[index + 1]:
                st.button(str(number), key=f'{page_key}_number_{number}',
                          type='primary' if number == current else 'secondary',
                          use_container_width=True, on_click=select_page,
                          args=(number,))
        with cols[-1]:
            st.button('›', key=f'{page_key}_next', help='다음 페이지',
                      disabled=current == total_pages, use_container_width=True,
                      on_click=select_page, args=(min(total_pages, current + 1),))
    return current

def render_period_logs(st, query, kind):
    """The log table and numbered navigation live at each report tab's bottom."""
    st.divider()
    label = '일일' if kind == 'daily' else '주간'
    st.subheader(f'{label} 수집 로그')
    st.caption('선택한 기간의 Neo4j ObservedEvent 전체 로그입니다. '
               'Alert와 연결된 위협 이벤트는 별도로 표시하며, 보고서 상단 통계는 Alert 기준입니다. '
               '표는 전체 수집 이벤트를 보여주며, 보고서도 전체 수집 통계와 Alert 위협 분석을 함께 집계합니다. 목록은 새로고침 전까지 고정됩니다.')
    key = 'cto_period_event_snapshot_' + kind
    today_start = periods()[kind][0].isoformat()
    if st.button('↻ 로그 목록 새로고침', key='cto_period_logs_refresh_' + kind):
        st.session_state.pop(key, None)
        st.session_state[f'cto_period_logs_page_{kind}_all'] = 1
        st.session_state[f'cto_period_logs_page_{kind}_threat'] = 1
    if key not in st.session_state or st.session_state[key].get('start_key') != today_start:
        try:
            with st.spinner('선택 기간 OpenStack 수집 로그를 조회하는 중...'):
                result = read_period_logs(query, kind)
                st.session_state[key] = {'start_key': today_start, 'result': result}
        except Exception as exc:
            st.error('기간별 로그 조회 실패: ' + str(exc))
            return
    snapshot = st.session_state[key]['result']
    all_rows = snapshot['items']
    threat_count = sum(int(r['is_threat']) for r in all_rows)
    c1, c2, c3 = st.columns(3)
    c1.metric('전체 수집 이벤트', len(all_rows))
    c2.metric('Alert 연결 이벤트', threat_count)
    c3.metric('그 외 이벤트', len(all_rows) - threat_count)
    st.caption(f"로그 스냅샷 집계: {snapshot['start']:%Y-%m-%d %H:%M} ~ "
               f"{snapshot['end']:%Y-%m-%d %H:%M} KST")
    if snapshot['undated']:
        st.warning(f"시각 확인이 어려운 이벤트 {snapshot['undated']}건은 기간 필터에서 제외되었습니다.")
    threats_only = st.checkbox('Alert가 연결된 위협 로그만 보기', value=False,
                               key='cto_period_threat_filter_' + kind)
    rows = [r for r in all_rows if r['is_threat']] if threats_only else all_rows
    if not rows:
        st.info('조건에 맞는 기간별 로그가 없습니다.')
        return

    scope = 'threat' if threats_only else 'all'
    page_key = f'cto_period_logs_page_{kind}_{scope}'
    total_pages = ceil(len(rows) / 100)
    current, _ = pagination_window(st.session_state.get(page_key, 1), total_pages)
    st.session_state[page_key] = current
    left = (current - 1) * 100
    shown = rows[left:left + 100]
    import pandas as pd
    st.dataframe(pd.DataFrame([{
        '탐지 시각(KST)': r['time'],
        '이벤트': r['event_type'],
        '결과': r['outcome'],
        '사용자': r['username'],
        '출발지 IP': r['source_ip'],
        '위협 여부': 'Alert 연결' if r['is_threat'] else '-',
        '심각도': r['severity'],
        'Alert 수': len(r['alerts']),
        '이벤트 ID': r['event_id'],
    } for r in shown]), use_container_width=True, hide_index=True, height=380)

    _render_log_pagination(st, kind, scope, total_pages, current)
    st.caption(f'표시: {left + 1:,}~{left + len(shown):,} / {len(rows):,}건 · '
               f'{current:,}/{total_pages:,} 페이지 · '
               '전체 조회는 Neo4j에 저장된 이벤트를 기준으로 합니다.')


def render_saved_for_kind(st,query,kind):
    """The saved list belongs in its own report type tab, not a separate menu."""
    label='일일' if kind=='daily' else '주간'
    st.divider()
    st.subheader(f'저장된 {label} 보고서')
    try:
        reports=fetch_saved(query,kind=kind)
    except Exception as exc:
        st.error('저장 보고서 조회 실패: '+str(exc))
        return
    valid={str(r['id']):r for r in reports if r.get('id')}
    if not valid:
        st.info(f'아직 저장된 {label} 보고서가 없습니다.')
        return
    rid=st.selectbox('저장 보고서 선택',list(valid),
        key='cto_period_saved_'+kind,
        format_func=lambda rid:f"{valid[rid].get('title') or label+' 보고서'} · "
                               f"{str(valid[rid].get('createdAt') or '')[:19]}")
    selected=valid[rid]
    st.caption('저장 당시의 원본 스냅샷이며, 현재 로그로 재집계하지 않습니다.')
    if selected.get('content'):
        with st.expander('보고서 전문 보기',expanded=False):
            st.markdown(selected['content'])
        _render_downloads(st,selected,'cto_period_saved_'+kind+'_'+re.sub('[^A-Za-z0-9_]','_',rid)[:24])
    else:
        st.warning('저장된 Report 노드에서 보고서 본문을 찾을 수 없습니다.')


def render(st, neo4j_query, kind, run_analysis=None):
    """Current tab only: all log activity + separately evidenced alerts."""
    from cto_period_professional import form_model, build_markdown as professional_markdown
    import json
    data_window=periods()[kind]
    label='일일' if kind=='daily' else '주간'
    st.subheader(f'{label} 종합 보안관제 보고서')
    start,end=data_window
    st.caption(f'집계 범위(KST): {start:%Y-%m-%d %H:%M}부터 생성 시각까지 · 날짜 입력 불필요')
    st.info('전체 수집 이벤트(정상 여부 미판정 포함)를 집계하고, Alert와 연결된 위협은 별도 상세 분석합니다. PDF·Word는 실무형 표 양식입니다.')
    if st.button(f'📄 {label} 보고서 생성 및 Neo4j 저장',key=f'cto_period_create_{kind}',type='primary',use_container_width=True):
        try:
            with st.spinner(f'{label} 전체 수집 로그와 위협 탐지 데이터를 집계하는 중...'):
                data=aggregate(neo4j_query,kind)
                rid=str(uuid.uuid4())
                model=form_model(data,rid)
                content=professional_markdown(model)
                save_report(neo4j_query,data,content,rid,model=model)
                report={'id':rid,'title':f'{label} OpenStack 종합 보안관제 보고서',
                        'reportType':kind+'_soc','content':content,
                        'reportDataJson':json.dumps(model,ensure_ascii=False),
                        'periodStart':data['start'].isoformat(),
                        'periodEnd':data['end'].isoformat()}
                st.session_state[f'cto_period_latest_{kind}']=report
            st.success('Neo4j Report 저장 완료 · ID: '+rid)
        except Exception as exc:
            st.error('보고서 생성/저장 실패: '+str(exc))
    current=st.session_state.get(f'cto_period_latest_{kind}')
    if current:
        st.markdown('### 방금 생성한 보고서')
        with st.expander('새 보고서 본문 보기',expanded=False):
            st.markdown(current['content'])
        _render_downloads(st,current,'cto_period_latest_'+kind)
    render_saved_for_kind(st,neo4j_query,kind)
    render_period_logs(st,neo4j_query,kind)


def render_saved(st, query):
    """Compatibility read API for older callers; new navigation does not use this."""
    st.subheader('저장된 정기 보고서')
    try:
        reports=fetch_saved(query)
    except Exception as exc:
        st.error('정기 보고서 조회 실패: '+str(exc));return
    if not reports:
        st.info('아직 저장된 일일·주간 보고서가 없습니다.');return
    names={str(r['id']):r for r in reports if r.get('id')}
    rid=st.selectbox('저장 보고서 선택',list(names),key='cto_period_saved_id',
                     format_func=lambda rid:f"{names[rid].get('title')} · {str(names[rid].get('createdAt') or '')[:19]}")
    current=names[rid]
    st.caption('과거 생성 시점의 스냅샷을 그대로 표시합니다. 현재 로그로 재집계하지 않습니다.')
    st.markdown(current.get('content') or '저장된 본문이 없습니다.')
    if current.get('content'):
        _render_downloads(st,current,'cto_period_saved_'+re.sub('[^A-Za-z0-9_]','_',rid)[:24])
