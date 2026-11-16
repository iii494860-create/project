"""Floating-chat report action for an exact Alert-linked OpenStack event.

Reuses the dashboard's verified report generation and Neo4j saving functions.
It never trusts a chat message or a model-generated ID as report provenance.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone

from cto_report_documents import build_fields, generate_docx, generate_pdf

EVENT_REF = re.compile(r'[A-Za-z0-9._:\-]{1,180}\Z')


def fetch_bound_event(env, event_id):
    """Fetch the event by a validated immutable reference and prove Alert link."""
    if not EVENT_REF.fullmatch(str(event_id or '')):
        raise ValueError('로그 ID 형식 오류')
    rows = env['neo4j_query']('''
        MATCH (e:ObservedEvent)
        WHERE $id IN [toString(e.recordId), toString(e.message_id),
                      toString(e.messageId), elementId(e)]
          AND EXISTS { MATCH (:Alert)-[:TRIGGERED_BY]-(e) }
        OPTIONAL MATCH (e)-[:PERFORMED_BY]-(u:User)
        WITH e, head(collect(DISTINCT u)) AS u
        OPTIONAL MATCH (e)-[:FROM_IP]-(ip:IPAddress)
        WITH e, u, head(collect(DISTINCT ip)) AS ip
        RETURN elementId(e) AS neo4j_node_id,
            coalesce(toString(e.recordId), toString(e.message_id),
                     toString(e.messageId), elementId(e)) AS event_id,
            coalesce(e.eventTypeName, e.event_type, e.eventType, '') AS event_type,
            coalesce(e.outcome, e.result, '') AS outcome,
            coalesce(toString(e.observedAt), toString(e.timestamp), '') AS event_time,
            coalesce(u.username, u.name, e.user, e.username, '') AS username,
            coalesce(ip.address, ip.ip, e.ip, e.source_ip, '') AS source_ip,
            toString(e.recordId) AS record_id,
            toString(e.message_id) AS message_id,
            properties(e) AS neo4j_properties
        LIMIT 2
    ''', id=event_id)
    if len(rows) > 1:
        raise ValueError('같은 로그 ID에 여러 이벤트가 일치해 보고서를 생성하지 않았습니다.')
    if not rows:
        raise ValueError('이벤트와 실제 Alert 연결이 확인되지 않습니다. 보고서를 생성하지 않았습니다.')
    ev = dict(rows[0])
    if not ev.get('neo4j_node_id'):
        raise RuntimeError('Neo4j 이벤트 내부 ID를 확인하지 못했습니다.')
    return ev


def _read_only_details(env, ev):
    details = env['_event_report_alert_details'](ev['neo4j_node_id'])
    if not details:
        raise ValueError('선택 이벤트를 근거로 하는 Alert가 없습니다.')
    ev['severities'] = [str(x.get('severity') or '') for x in details if x.get('severity')]
    ev['alert_ids'] = [str(x['alert_id']) for x in details if x.get('alert_id')]
    return details


def generate_and_save(env, event_id):
    """Use existing verified pipeline: event → Alert → GraphRAG → AI → Report."""
    required = ('neo4j_query','_event_report_alert_details','_event_report_grounding',
                '_event_report_prompt','_event_report_markdown','_event_report_save',
                'run_ontology_agent_analysis','run_graph_rag_event')
    missing = [key for key in required if not callable(env.get(key))]
    if missing:
        raise RuntimeError('대시보드 보고서 함수가 누락되었습니다: ' + ', '.join(missing))
    ev = fetch_bound_event(env, event_id)
    details = _read_only_details(env, ev)

    raw, match = None, 'none'
    if callable(env.get('_raw_event_detail')):
        raw, match = env['_raw_event_detail'](ev)
    rag, rag_error = None, ''
    if ev.get('event_type'):
        try:
            rag = env['run_graph_rag_event'](str(ev['event_type']),str(ev.get('outcome') or '') or None)
        except Exception as exc:
            rag_error = f'{type(exc).__name__}: {exc}'[:250]
    source = env['_event_report_grounding'](ev, details, raw, match, rag, rag_error)
    question = env['_event_report_prompt'](source)
    event_id = str(ev['event_id'])

    # Trusted record reference originates in the exact Neo4j match above. This
    # is not an arbitrary user-supplied or model-generated ID.
    minimal_verified_raw = {'recordId': event_id,
                            'event_type': str(ev.get('event_type') or ''),
                            'outcome': str(ev.get('outcome') or '')}
    result = env['run_ontology_agent_analysis'](
        question, event_type=str(ev.get('event_type') or ''),
        outcome=str(ev.get('outcome') or ''), raw_event=minimal_verified_raw,
        related_alert_ids=source['alert_ids'], timeout=660,
    )
    if not isinstance(result, dict):
        raise RuntimeError('AI 분석 결과가 올바르지 않습니다.')
    answer = str(result.get('answer') or '').strip()
    if not answer:
        raise RuntimeError('AI 분석 답변이 비어 있어 저장하지 않았습니다.')
    if result.get('citation_status') == 'fail':
        raise RuntimeError('Citation 검증 실패 — 검증되지 않은 내용을 보고서로 저장하지 않았습니다.')
    markdown = env['_event_report_markdown'](source, result)
    # Save only after all supported checks pass. Do not execute remediation.
    report_id = env['_event_report_save'](ev, source, markdown)
    if not isinstance(report_id, str) or not report_id.strip():
        raise RuntimeError('Neo4j Report 저장 확인 실패')
    ev['incident_ids'] = source['incident_ids']
    fields = build_fields(report_id, ev, source['alert_ids'], markdown,
                          citation_status=result.get('citation_status') or '결과 미기록')
    fields['rag_status'] = ('근거 조회 오류' if rag_error else '근거 없음' if source.get('rag_no_match') else '근거 확보')
    return {'id': report_id, 'event_id': event_id, 'markdown': markdown,
            'fields': fields, 'citation_status': fields['citation_status'],
            'created_at': datetime.now(timezone.utc).isoformat()}


def find_latest_saved(env, event_id):
    """Recover the last saved report on reopening the same event chat."""
    if not EVENT_REF.fullmatch(str(event_id or '')):
        return None
    if not callable(env.get('neo4j_query')):
        return None
    rows = env['neo4j_query']('''
        MATCH (r:Report)-[:ANALYZES_EVENT]->(e:ObservedEvent)
        WHERE $id IN [toString(e.recordId),toString(e.message_id),
                      toString(e.messageId),elementId(e)]
          AND r.reportType = 'threat_event'
          AND r.content IS NOT NULL
        RETURN r.id AS id, r.content AS markdown,
               r.createdAt AS created_at, r.sourceEventId AS source_event_id
        ORDER BY r.createdAt DESC LIMIT 1
    ''', id=event_id)
    if not rows:
        return None
    row = rows[0]
    if not row.get('id') or not str(row.get('markdown') or '').strip():
        return None
    ev = fetch_bound_event(env, event_id)
    details = _read_only_details(env, ev)
    ev['incident_ids'] = sorted({str(x.get('incident_id')) for x in details if x.get('incident_id')})
    return {
        'id': str(row['id']),
        'event_id': str(ev['event_id']),
        'markdown': str(row['markdown']),
        'fields': build_fields(str(row['id']), ev, ev['alert_ids'], str(row['markdown']),
                               citation_status='기존 저장 보고서 — 생성 당시 검증 기록 확인 필요',
                               created_at=row.get('created_at')),
        'created_at': str(row.get('created_at') or ''),
    }


def _download_controls(st, doc):
    fields = doc['fields']
    event_id = doc['event_id']
    rid = doc['id']
    key = hashlib.sha256((event_id+rid).encode('utf-8')).hexdigest()[:12]
    base = 'SOC_' + re.sub('[^A-Za-z0-9_-]', '_', event_id)[:36] + '_' + key
    st.success('Neo4j 보고서 저장 확인 · ID: ' + rid)
    st.caption('실무형 보고서: 기본 정보 · 탐지·침해 내용 · 대응 과정 · 증거자료 · 복구·재발 방지')
    with st.expander('보고서 내용 미리보기', expanded=False):
        st.markdown(doc['markdown'])
    # Only export content from the Report node or this successfully saved result.
    # Keep rendered bytes per report in the session to avoid repeating heavy
    # conversions during the existing 5-second Streamlit fragment refresh.
    rendered = st.session_state.setdefault('cto_fchat_report_bytes_v1', {})
    if not isinstance(rendered, dict):
        rendered = {}
        st.session_state['cto_fchat_report_bytes_v1'] = rendered
    if key not in rendered:
        rendered[key] = {}
        if len(rendered) > 20:
            rendered.pop(next(iter(rendered)))
        try:
            rendered[key]['pdf'] = generate_pdf(fields)
        except Exception as exc:
            rendered[key]['pdf_error'] = str(exc)
        try:
            rendered[key]['docx'] = generate_docx(fields)
        except Exception as exc:
            rendered[key]['docx_error'] = str(exc)
    pdf_bytes = rendered[key].get('pdf')
    docx_bytes = rendered[key].get('docx')
    for label in ('pdf', 'docx'):
        if rendered[key].get(label+'_error'):
            st.warning(label.upper()+' 변환 실패: '+rendered[key][label+'_error'])
    c1,c2,c3=st.columns(3)
    if pdf_bytes:
        c1.download_button('PDF 다운로드', pdf_bytes, file_name=base+'.pdf',
                           mime='application/pdf',key='cto_fchat_pdf_'+key,
                           use_container_width=True)
    if docx_bytes:
        c2.download_button('Word 다운로드', docx_bytes, file_name=base+'.docx',
                           mime='application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                           key='cto_fchat_docx_'+key,use_container_width=True)
    c3.download_button('원문 다운로드', doc['markdown'].encode('utf-8-sig'),
                       file_name=base+'.md', mime='text/markdown',
                       key='cto_fchat_md_'+key,use_container_width=True)


def render(st, env, event_id, generate_clicked=False, busy=False):
    """Called once inside the existing fixed Floating chat panel."""
    key = 'cto_fchat_report_by_event_v1'
    cache = st.session_state.setdefault(key,{})
    if not isinstance(cache,dict):
        cache={}
        st.session_state[key]=cache
    if generate_clicked:
        if busy:
            st.info('기존 AI 분석이 완료된 뒤 보고서를 생성해 주세요.')
        else:
            try:
                with st.spinner('선택 로그의 근거를 검증하고 실무형 AI 보고서를 생성·저장하는 중...'):
                    doc=generate_and_save(env,event_id)
                    cache[event_id]=doc
            except Exception as exc:
                st.error('보고서 생성/저장 실패: '+str(exc))
    current = cache.get(event_id)
    if current is None:
        # Negative-cache missing reports for 45 s to avoid a Neo4j query on
        # every fragment refresh. Successful saves appear immediately above.
        from time import monotonic
        polls = st.session_state.setdefault('cto_fchat_report_poll_v1', {})
        if monotonic() - polls.get(event_id, -1e6) >= 45:
            polls[event_id] = monotonic()
            try:
                current = find_latest_saved(env,event_id)
            except Exception:
                current = None
            if current:
                cache[event_id] = current
    if current:
        st.markdown('**📄 이 로그의 저장 보고서**')
        _download_controls(st,current)
