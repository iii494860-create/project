"""Additive SOC incident summary, sharing the existing per-event floating chat."""
from __future__ import annotations
import pandas as pd
import streamlit as st

try:
    from st_aggrid import AgGrid, GridOptionsBuilder, GridUpdateMode
except ImportError:
    AgGrid = GridOptionsBuilder = GridUpdateMode = None


def _name(row):
    labels = [str(x) for x in row.get('rule_names') or [] if x]
    return (labels[0] + (f' 외 {len(labels)-1}종' if len(labels)>1 else '')) if labels else '미확인 탐지 유형'


def _severity(row):
    vals = {str(v).lower() for v in (row.get('severities') or []) if v}
    for value, label in [('critical','긴급'),('high','높음'),('medium','보통'),('low','낮음'),('info','정보')]:
        if value in vals: return label
    return '미분류'


def _events(query, incident_id, limit=80):
    """Distinct original evidence linked via Incident<-GROUPED_INTO-Alert-TRIGGERED_BY-Event."""
    return query('''
        MATCH (i:Incident)
        WHERE coalesce(toString(i.recordId),toString(i.id),toString(i.incidentId),
            toString(i.incident_id),toString(i.uuid),elementId(i))=$incident_id
        MATCH (a:Alert)-[:GROUPED_INTO]->(i)
        MATCH (a)-[:TRIGGERED_BY]-(e:ObservedEvent)
        WITH DISTINCT e
        RETURN coalesce(toString(e.message_id), toString(e.messageId),
                        toString(e.recordId), elementId(e)) AS event_id,
               coalesce(toString(e.observedAt), toString(e.eventTime),
                 toString(e.timestamp), toString(e.receivedAt),'') AS observed_at,
               coalesce(e.eventTypeName,e.event_type,e.eventType,e.type,'') AS event_type,
               coalesce(e.outcome,e.result,'') AS outcome,
               coalesce(e.sourceIp,e.source_ip,e.ip,'') AS source_ip,
               coalesce(e.user,e.username,'') AS username
        ORDER BY observed_at DESC LIMIT $limit
    ''', incident_id=incident_id, limit=limit)


def _count_events(query, incident_id):
    rows=query('''
        MATCH (i:Incident)
        WHERE coalesce(toString(i.recordId),toString(i.id),toString(i.incidentId),
            toString(i.incident_id),toString(i.uuid),elementId(i))=$incident_id
        OPTIONAL MATCH (a:Alert)-[:GROUPED_INTO]->(i)
        OPTIONAL MATCH (a)-[:TRIGGERED_BY]-(e:ObservedEvent)
        RETURN count(DISTINCT e) AS event_count
    ''',incident_id=incident_id)
    return int(rows[0]['event_count'] or 0) if rows else 0


def render_soc_incident_panel(*, query, recent_incidents, format_time, neo4j_ok):
    """Called only from the live-monitoring page; no modifications to existing chat state."""
    st.markdown('### 사건 중심 관제')
    st.caption('왼쪽에서 사건을 선택하면 오른쪽에서 경보 요약과 근거 로그를 확인합니다. 아래 기존 위협 로그 표·AI 챗봇은 그대로 유지됩니다.')
    if not neo4j_ok():
        st.warning('Neo4j 연결을 확인할 수 없어 사건 목록을 표시하지 않습니다.')
        return
    rows = recent_incidents(40)
    if not rows:
        st.info('현재 조회되는 Incident가 없습니다. 아래 기존 위협 로그 표는 계속 사용할 수 있습니다.')
        return
    counts={}
    for row in rows:
        iid=str(row.get('id') or '')
        if not iid: continue
        try: counts[iid]=_count_events(query,iid)
        except Exception: counts[iid]=None
    valid=[r for r in rows if r.get('id')]
    if not valid: return
    current=st.session_state.get('cto_soc_selected_incident')
    if current not in {str(r['id']) for r in valid}:
        current=str(valid[0]['id'])
        st.session_state['cto_soc_selected_incident']=current
    left,right=st.columns([3,2],gap='medium')
    with left:
        st.markdown('**위협 사건 목록**')
        if AgGrid is None:
            st.error('실제 행 클릭 표에 필요한 streamlit-aggrid 패키지가 없습니다. '
                     '`python -m pip install streamlit-aggrid`로 설치하세요.')
            return

        # One actual, aligned data grid. Clicking anywhere in a row selects it;
        # no fake button columns, no row-selection checkboxes, and no ID column.
        table_rows = []
        for r in valid:
            iid = str(r['id'])
            timestamp = r.get('last_detected_at_kst') or format_time(r.get('last_detected_at')) or '-'
            table_rows.append({
                '탐지 시각': str(timestamp),
                '관련 로그 수': counts.get(iid),
                '위험도': _severity(r),
                '공격 유형': _name(r),
                '_incident_id': iid,
            })
        table_data = pd.DataFrame(table_rows)
        opts = GridOptionsBuilder.from_dataframe(table_data)
        # Same compact, border-lined visual language as the existing threat-log table.
        opts.configure_default_column(resizable=True, sortable=True, filter=False,
                                      suppressMenu=True)
        opts.configure_column('_incident_id', hide=True)
        opts.configure_column('탐지 시각', width=177, minWidth=155)
        opts.configure_column('관련 로그 수', width=102, minWidth=92,
                              type=['numericColumn'])
        opts.configure_column('위험도', width=76, minWidth=70)
        opts.configure_column('공격 유형', flex=1, minWidth=180,
                              tooltipField='공격 유형')
        opts.configure_selection(selection_mode='single', use_checkbox=False)
        options = opts.build()
        options['suppressRowClickSelection'] = False
        options['suppressCellFocus'] = True
        options['animateRows'] = False
        options['rowHeight'] = 42
        options['headerHeight'] = 43
        options['rowSelection'] = 'single'
        # No faux buttons, no AG Grid checkbox selector, no incident number column.
        options['suppressHorizontalScroll'] = False
        options['ensureDomOrder'] = True
        # Make an entire selected row visually distinct, exactly like expanded
        # rows in the existing OpenStack log table.
        custom_css = {
            '.ag-root-wrapper': {
                'border': '1px solid #354053 !important',
                'border-radius': '12px !important',
                'background-color': '#0d121a !important',
                'overflow': 'hidden !important',
            },
            '.ag-root-wrapper-body, .ag-root, .ag-body-viewport, .ag-center-cols-viewport, .ag-center-cols-container': {
                'background-color': '#0d121a !important',
            },
            '.ag-header, .ag-header-viewport, .ag-header-container, .ag-header-row': {
                'background-color': '#151b25 !important',
                'color': '#c7d0df !important',
                'font-weight': '700 !important',
                'border-bottom': '1px solid #354053 !important',
            },
            '.ag-header-cell': {
                'border-right': '1px solid #28303d !important',
                'padding-left': '10px !important',
                'padding-right': '10px !important',
            },
            '.ag-header-cell-text': {
                'color': '#c7d0df !important',
                'font-size': '13px !important',
                'font-weight': '700 !important',
            },
            '.ag-row': {
                'background-color': '#0e131c !important',
                'color': '#e6eaf2 !important',
                'border-bottom': '1px solid #293341 !important',
                'cursor': 'pointer !important',
                'font-family': 'system-ui, -apple-system, Malgun Gothic, sans-serif !important',
                'font-size': '13px !important',
            },
            '.ag-row-odd': {'background-color': '#101722 !important'},
            '.ag-row:hover, .ag-row-hover': {'background-color': '#202d43 !important'},
            '.ag-row-selected, .ag-row-selected.ag-row-odd, .ag-row-selected.ag-row-even': {
                'background-color': '#213d65 !important',
                'box-shadow': 'inset 3px 0 0 #68a6ff !important',
            },
            '.ag-cell': {
                'border-right': '1px solid #28303d !important',
                'padding-left': '10px !important',
                'padding-right': '10px !important',
                'color': '#e6eaf2 !important',
                'line-height': '42px !important',
                'font-size': '13px !important',
            },
            '.ag-cell:last-child': {'border-right': '0 !important'},
            '.ag-checkbox-input-wrapper, .ag-selection-checkbox': {'display': 'none !important'},
            '.ag-overlay-no-rows-center': {'color': '#aab7c9 !important'},
        }
        original_index = next((i for i, row in enumerate(table_rows)
                               if row['_incident_id'] == current), 0)
        result = AgGrid(
            table_data,
            gridOptions=options,
            update_mode=GridUpdateMode.SELECTION_CHANGED,
            data_return_mode='AS_INPUT',
            theme='streamlit',
            custom_css=custom_css,
            fit_columns_on_grid_load=False,
            height=min(514, 44 + len(table_rows) * 42 + 2),
            allow_unsafe_jscode=False,
            reload_data=False,
            pre_selected_rows=[original_index],
            key='cto_soc_incident_grid_v1_3',
        )
        selected_rows = result.get('selected_rows')
        if isinstance(selected_rows, pd.DataFrame):
            selected_rows = selected_rows.to_dict('records')
        if selected_rows is not None and len(selected_rows):
            selected_id = str(selected_rows[0].get('_incident_id') or '')
            if selected_id in {str(r['id']) for r in valid} and selected_id != current:
                st.session_state['cto_soc_selected_incident'] = selected_id
                current = selected_id
                st.rerun()
        st.caption('행 클릭으로 사건을 선택합니다. 동일 원본 로그는 1건으로 계산합니다.')
    incident=next((r for r in valid if str(r['id'])==current),valid[0])
    with right:
        st.markdown('**선택 사건 상세**')
        st.caption(str(incident['id']))
        st.markdown(f"**{_name(incident)}** · 위험도 {_severity(incident)}")
        a,b=st.columns(2)
        a.metric('관련 로그',counts.get(str(incident['id'])) if counts.get(str(incident['id'])) is not None else '-')
        b.metric('연결 경보',incident.get('alert_count') or 0)
        a,b=st.columns(2)
        a.metric('누적 위험 점수',incident.get('risk') if incident.get('risk') is not None else '-')
        b.metric('사건 상태',str(incident.get('status') or '미확인'))
        st.write('**최초 탐지:**',incident.get('created_at_kst') or '-')
        st.write('**최근 탐지:**',incident.get('last_detected_at_kst') or '-')
        tids=incident.get('technique_ids') or []
        st.write('**MITRE ATT&CK:**',', '.join(map(str,tids)) or '연결 없음')
        st.write('**탐지 유형:**',', '.join(map(str,incident.get('rule_names') or [])) or '미확인')
        try:
            events=_events(query,str(incident['id']))
            st.markdown('**연결된 원본 로그**')
            if events:
                # CTO_SOC_LOG_CHAT_LINK_V1: use the exact same stable event ID
                # as the bottom threat table and cto_floating_chat._chat_path.
                # A whole-row click opens the EXISTING chatbot. No AI work
                # starts merely from viewing or selecting an incident.
                from cto_floating_chat import EVENT_ID as _cto_chat_id_pattern
                records = []
                for e in events:
                    eid = str(e.get('event_id') or '').strip()
                    if not _cto_chat_id_pattern.fullmatch(eid):
                        continue
                    records.append({
                        '발생 시각':format_time(e.get('observed_at')),
                        '이벤트':e.get('event_type') or '-',
                        '결과':e.get('outcome') or '-',
                        '출발지 IP':e.get('source_ip') or '정보 없음',
                        '사용자':e.get('username') or '정보 없음',
                        '_event_id':eid,
                    })
                if records:
                    log_data = pd.DataFrame(records)
                    log_builder = GridOptionsBuilder.from_dataframe(log_data)
                    log_builder.configure_default_column(resizable=True, sortable=True,
                                                         filter=False, suppressMenu=True)
                    log_builder.configure_column('_event_id', hide=True)
                    log_builder.configure_column('발생 시각', minWidth=155, width=175)
                    log_builder.configure_column('이벤트', minWidth=150, width=170)
                    log_builder.configure_column('결과', minWidth=70, width=76)
                    log_builder.configure_column('출발지 IP', minWidth=125, width=140)
                    log_builder.configure_column('사용자', minWidth=115, width=130)
                    log_builder.configure_selection(selection_mode='single', use_checkbox=False)
                    log_options = log_builder.build()
                    log_options['suppressRowClickSelection'] = False
                    log_options['suppressCellFocus'] = True
                    log_options['animateRows'] = False
                    log_options['rowHeight'] = 42
                    log_options['headerHeight'] = 43
                    log_result = AgGrid(
                        log_data, gridOptions=log_options,
                        update_mode=GridUpdateMode.SELECTION_CHANGED,
                        data_return_mode='AS_INPUT', theme='streamlit',
                        custom_css=custom_css, fit_columns_on_grid_load=False,
                        height=min(280, 44 + 42 * len(records) + 2),
                        allow_unsafe_jscode=False,
                        # Recreate the widget after an open so clicking the
                        # same log again can reopen the popup without a checkbox.
                        key='cto_soc_linked_logs_' + str(incident['id']) + '_'
                            + str(st.session_state.get('cto_soc_log_grid_seq', 0)),
                    )
                    chosen_rows = log_result.get('selected_rows')
                    if isinstance(chosen_rows, pd.DataFrame):
                        chosen_rows = chosen_rows.to_dict('records')
                    if chosen_rows is not None and len(chosen_rows):
                        picked = str(chosen_rows[0].get('_event_id') or '').strip()
                        if picked in {r['_event_id'] for r in records}:
                            st.session_state['cto_float_chat_active_id'] = picked
                            st.session_state['cto_float_chat_from_bridge'] = True
                            st.session_state['cto_soc_log_grid_seq'] = (
                                int(st.session_state.get('cto_soc_log_grid_seq', 0)) + 1)
                            st.rerun()
                else:
                    st.info('유효한 로그 ID가 없어 AI 대화를 열 수 없습니다.')
                if counts.get(str(incident['id'])) is not None and counts[str(incident['id'])]>len(events):
                    st.caption('최근 80건만 표시합니다. 관련 로그 수는 전체 고유 이벤트 기준입니다.')
            else:
                st.info('이 사건에 연결된 근거 이벤트가 없습니다.')
        except Exception as exc:
            st.warning(f'사건 관련 로그 조회 실패: {exc}')
    st.caption('오른쪽 관련 로그의 행을 클릭하면 아래 기존 위협 로그 표와 같은 AI 챗봇이 열립니다. 질문 이력도 로그 ID로 공유합니다.')
    st.divider()
