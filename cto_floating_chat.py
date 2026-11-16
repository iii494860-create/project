# CTO_MULTISOURCE_UI_WINDOWS_AUTO_V2
# CTO_FLOATING_CHAT_QUALITY_V11
# CTO_FLOATING_REPORT_V1
# CTO_BG_PROGRESS_V3: status visualization patch.
"""Read-only, event-pinned floating chat for the existing 3K1H Streamlit dashboard.
All queries use parameters. Only events with related Alerts can be opened.
"""
from __future__ import annotations
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from cto_chat_jobs import submit as _cto_submit_job, get_status as _cto_job_status
from cto_chat_answer_quality import display_markdown as _cto_display_md
from cto_floating_report import render as _cto_report_render

EVENT_ID = re.compile(r"[A-Za-z0-9._:\-]{1,180}\Z")
CHAT_DIR = Path.home() / '.cto_event_ai_chats'


def launcher_html(event_id):
    """Only a static JS action inside the pre-existing HTML table iframe."""
    event_id = str(event_id or '').strip()
    if not EVENT_ID.fullmatch(event_id):
        return ''
    js_id = json.dumps(event_id, ensure_ascii=True)
    js = ("window.parent.postMessage({kind:'cto_float_chat_open',"
          "eventId:" + js_id + "},'*');return false;")
    return (
        '<div style="padding:10px 18px 12px;border-top:1px solid #354c6b;'
        'background:#151e2e">'
        '<a href="#" onclick="'+ escape(js, quote=True) +'" '
        'style="display:inline-block;padding:9px 14px;background:#565ad3;'
        'color:#fff;border-radius:7px;text-decoration:none;font-weight:700;'
        'font-size:13px">🤖 AI 챗봇 열기 (오른쪽 패널)</a></div>'
    )


def render_browser_bridge(st):
    # st.html JavaScript support was introduced in Streamlit 1.52.
    # Script is static (no untrusted data), and the backend validates IDs.
    import inspect
    if 'unsafe_allow_javascript' not in inspect.signature(st.html).parameters:
        return False
    st.html('''<script>
    (() => {
      if (window.__ctoFloatChatBound) return;
      window.__ctoFloatChatBound = true;
      window.addEventListener('message', (e) => {
        const v = e.data;
        if (!v || v.kind !== 'cto_float_chat_open' || typeof v.eventId !== 'string') return;
        if (!/^[A-Za-z0-9._:\\-]{1,180}$/.test(v.eventId)) return;
        // Accept messages only from a currently embedded table iframe.
        const frames = Array.from(document.querySelectorAll('iframe'));
        if (!frames.some(f => f.contentWindow === e.source)) return;
        // Open via a native Streamlit widget in a small fragment.
        // Never navigate or reload the host page; keep the table and scroll intact.
        const input = document.querySelector(
          '.st-key-cto_float_chat_open_bridge [data-testid="stTextInput"] input'
        );
        if (!input) return; // fail closed; do not fall back to page navigation.
        const payload = v.eventId + '|' + String(Date.now()) + '-' +
                        Math.random().toString(36).slice(2);
        const descriptor = Object.getOwnPropertyDescriptor(
          window.HTMLInputElement.prototype, 'value'
        );
        if (!descriptor || typeof descriptor.set !== 'function') return;
        input.focus({preventScroll: true});
        descriptor.set.call(input, payload);
        input.dispatchEvent(new Event('input', {bubbles: true}));
        // st.text_input commits on blur in supported Streamlit versions.
        input.dispatchEvent(new Event('change', {bubbles: true}));
        input.blur();
      });
    })();
    </script>''', unsafe_allow_javascript=True)
    return True


def _chat_path(event_id):
    return CHAT_DIR / (hashlib.sha256(event_id.encode('utf-8')).hexdigest()+'.jsonl')


def _chat_load(event_id):
    from hermes_dashboard import public_progress_steps
    path = _chat_path(event_id)
    if not path.exists():
        return []
    result = []
    for line in path.read_text(encoding='utf-8', errors='replace').splitlines()[-150:]:
        try:
            entry = json.loads(line)
        except (ValueError, TypeError):
            continue
        if entry.get('event_id') == event_id and entry.get('role') in ('user','assistant'):
            message = {'role': entry['role'], 'content': str(entry.get('content') or '')[:20000]}
            duration = entry.get('elapsed_sec')
            if isinstance(duration, (int, float)) and not isinstance(duration, bool) and 0 <= duration <= 7200:
                message['elapsed_sec'] = round(float(duration), 1)
            steps = public_progress_steps(entry.get('progress_steps'))
            if steps:
                message['progress_steps'] = steps
            result.append(message)
    return result


def _chat_append(event_id, role, content, *, elapsed_sec=None, progress_steps=None):
    from hermes_dashboard import public_progress_steps
    CHAT_DIR.mkdir(parents=True,exist_ok=True,mode=0o700)
    os.chmod(CHAT_DIR,0o700)
    target = _chat_path(event_id)
    rec = {'event_id':event_id,'role':role,'content':str(content)[:20000],
           'time':datetime.now(timezone.utc).isoformat()}
    if isinstance(elapsed_sec, (int, float)) and not isinstance(elapsed_sec, bool) and elapsed_sec >= 0:
        rec['elapsed_sec'] = round(float(elapsed_sec), 1)
    steps = public_progress_steps(progress_steps)
    if role == 'assistant' and steps:
        rec['progress_steps'] = steps
    fd=os.open(str(target),os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600)
    with os.fdopen(fd,'a',encoding='utf-8') as file:
        os.fchmod(file.fileno(),0o600)
        file.write(json.dumps(rec,ensure_ascii=False)+'\n')


def _event_fetch(env, event_id):
    fn=env['neo4j_query']
    rows = fn('''
    MATCH (a:Alert)-[:TRIGGERED_BY]-(e:ObservedEvent)
    WHERE $id IN [toString(e.recordId),toString(e.message_id),
                  toString(e.messageId),elementId(e)]
    WITH e,collect(DISTINCT a) AS alerts
    RETURN e{.*} AS event,
           [a IN alerts | {
             rule:coalesce(a.ruleName,a.ruleLabel,a.name,''),
             severity:coalesce(a.severity,a.level,''),
             id:coalesce(toString(a.recordId),toString(a.id),elementId(a))
           }] AS alerts
    LIMIT 1
    ''', id=event_id)
    return rows[0] if rows else None


def _event_fields(event_id, fields):
    detail = fields.get('fieldsJson') or fields.get('fields_json')
    if isinstance(detail,str):
        try:detail=json.loads(detail)
        except (ValueError,TypeError):detail=None
    # The recorder also stores fields as JSON [name, value] pairs.
    # Preserve their names so the chat can see payload.status/image_id etc.
    if isinstance(detail,list) and all(
            isinstance(item,list) and len(item)==2 and isinstance(item[0],str)
            for item in detail):
        if len({item[0] for item in detail})==len(detail):
            detail=dict(detail)
    et=str(fields.get('eventTypeName') or fields.get('event_type') or fields.get('eventType') or '')
    oc=str(fields.get('outcome') or fields.get('result') or '')
    if isinstance(detail,dict): oc=oc or str(detail.get('outcome') or '')
    raw={'recordId':event_id,'event_type':et,'outcome':oc,
         'observedAt':str(fields.get('observedAt') or ''),
         'user_id':str(fields.get('user') or fields.get('userId') or ''),
         'source_ip':str(fields.get('ip') or fields.get('sourceIp') or '')}
    if isinstance(detail,dict):raw['fieldsJson']=detail
    original=fields.get('rawLog') or fields.get('raw_log')
    if isinstance(original,str):
        raw['rawLog_excerpt']=original[:2800]
        if len(original)<=64000:
            try:notification=json.loads(original)
            except (ValueError,TypeError):notification=None
            if isinstance(notification,dict):
                # The detached worker redacts this structure before any API
                # request. It still excludes the unstructured plaintext excerpt.
                raw['notification']=notification
    return et,oc,raw


def _quick_text(event_id, et, oc, alerts, env):
    lines = ['**로그 빠른 요약**',f'- 이벤트 ID: `{event_id}`',
             f'- 유형: `{et or "미확인"}`',f'- 결과: `{oc or "미확인"}`',
             f'- 관련 경보: {len(alerts)}건']
    rules=sorted(set(str(a.get('rule') or '') for a in alerts if a.get('rule')))
    if rules:lines.append('- 적용된 탐지 규칙: ' + ', '.join('`'+i+'`' for i in rules))
    if et:
        try:
            rag=env['run_graph_rag_event'](et,oc or None)
            if rag.get('no_match'):
                lines.append('- Graph RAG: 관련 지식을 찾지 못했습니다.')
            else:
                groups=env['_rag_entities'](rag)
                for kind,label in [('techniques','관련 후보 공격 기법'),('mitigations','관련 완화 지식')]:
                    entities=groups.get(kind) or []
                    if entities:
                        lines.append('- '+label+' (확정 아님): '+', '.join(
                            '`'+str(x.get('id') or '')+'` '+str(x.get('name') or '') for x in entities[:6]))
        except Exception:
            lines.append('- Graph RAG: 조회에 실패해 관련 지식을 표시하지 못했습니다.')
    lines.append('\n**주의:** 경보나 연관 지식이 검색되었다고 실제 공격 성공을 뜻하지는 않습니다.')
    return '\n'.join(lines)


def _close(st):
    st.session_state['cto_float_chat_active_id']=''
    try:
        if 'cto_float_chat' in st.query_params:del st.query_params['cto_float_chat']
    except (AttributeError,KeyError):pass
    st.rerun()


# CTO_CHAT_TIMER_UI_V9

def _cto_chat_visual_started_at(st, job):
    '''Use per-job UI clock, rather than reusing a worker's historical start timestamp.

    Keep it through 5-second Streamlit fragment reruns but reset for each new job_id.
    It measures time since the active job first appeared in this Streamlit session.
    Worker elapsed_sec in stored answers remains authoritative backend run time.
    '''
    from datetime import datetime, timezone

    job_id = str(job.get('job_id') or '').strip()
    now = datetime.now(timezone.utc).isoformat()
    if not job_id:
        return now
    cache_key = 'cto_fchat_visual_start_by_job_v9'
    starts = st.session_state.get(cache_key)
    if not isinstance(starts, dict):
        starts = {}
    if job_id not in starts:
        starts[job_id] = now
        # Bound memory used by repeated investigations in long-lived dashboards.
        if len(starts) > 40:
            starts = dict(list(starts.items())[-40:])
        st.session_state[cache_key] = starts
    return starts[job_id]


def _cto_live_progress_html(current_phase, visual_started_at):
    '''Stable spinner and 1-second browser clock; never rerun Streamlit for ticks.'''
    from datetime import datetime, timezone
    from html import escape as _esc

    try:
        dt = datetime.fromisoformat(str(visual_started_at).strip().replace('Z', '+00:00'))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        start_ms = int(dt.timestamp() * 1000)
        if not 0 <= start_ms < 9999999999999:
            start_ms = None
    except (TypeError, ValueError, OverflowError, OSError):
        start_ms = None

    phase = _esc(str(current_phase or '진행 상태 확인 중')[:120], quote=True)
    start_js = 'null' if start_ms is None else str(start_ms)
    return f'''<!doctype html><html lang="ko"><head><meta charset="utf-8"><style>
      :root{{color-scheme:dark}}
      *{{box-sizing:border-box}}
      html, body{{margin:0;padding:0;width:100%;height:100%;background:#111a2a;
        color:#e8efff;font-family:system-ui,'Malgun Gothic',sans-serif;overflow:hidden}}
      .card{{width:100%;height:100%;display:flex;flex-direction:column;justify-content:center;
        border:1px solid #405877;border-radius:9px;background:#16243a;padding:9px 12px;overflow:hidden}}
      .top{{display:flex;gap:9px;align-items:center;font-size:12px;font-weight:700;min-width:0}}
      .title{{display:flex;align-items:center;gap:9px;flex:1;min-width:0}}
      .spinner{{flex:none;display:inline-block;width:16px;height:16px;
        border:2px solid rgba(128,155,213,.28);border-top-color:#91b4ff;border-right-color:#91b4ff;
        border-radius:50%;animation:spin .8s linear infinite}}
      @keyframes spin{{to{{transform:rotate(360deg)}}}}
      .headline{{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
      .clock{{flex:none;white-space:nowrap;font-variant-numeric:tabular-nums;letter-spacing:.015em;
        font-size:12px;color:#d9e7ff}}
      .meta{{color:#b1c0d8;font-size:11px;line-height:1.35;margin-top:9px;
        overflow:hidden;display:-webkit-box;-webkit-box-orient:vertical;-webkit-line-clamp:2}}
      @media(prefers-reduced-motion:reduce){{.spinner{{animation-duration:2s}}}}
    </style></head><body>
      <div class="card" role="status" aria-live="off">
        <div class="top"><div class="title"><span class="spinner" aria-label="분석 중"></span>
          <span class="headline">AI가 답변을 준비하고 있습니다...</span></div>
          <span id="cto-running-clock" class="clock">0초</span>
        </div>
        <div class="meta">현재 단계: {phase}</div>
      </div>
      <script>
      (() => {{
        const firstShown = {start_js};
        const clock = document.getElementById('cto-running-clock');
        const tick = () => {{
          if (!clock) return;
          if (firstShown === null) {{clock.textContent = '0초'; return;}}
          const n = Math.max(0, Math.floor((Date.now() - firstShown)/1000));
          const min = Math.floor(n/60), sec = n%60;
          clock.textContent = min ? `${{min}}분 ${{sec}}초` : `${{sec}}초`;
        }};
        tick();
        window.setInterval(tick,1000);
      }})();
      </script>
    </body></html>'''

def render_panel(st, env):
    """A CSS-fixed native Streamlit panel, nonmodal (background remains clickable)."""
    try:qp=str(st.query_params.get('cto_float_chat','') or '')
    except AttributeError:qp=(st.experimental_get_query_params().get('cto_float_chat') or [''])[0]
    if qp and not st.session_state.get('cto_float_chat_from_bridge'):
        if EVENT_ID.fullmatch(qp):
            st.session_state['cto_float_chat_active_id']=qp
        else:
            st.warning('챗봇으로 전달된 로그 ID 형식이 올바르지 않습니다.')
    eid=str(st.session_state.get('cto_float_chat_active_id') or '')
    if not eid:
        return
    if not EVENT_ID.fullmatch(eid):return

    # CTO_FLOAT_CHAT_READABILITY_V2: UI only; AI, event IDs and storage unchanged.
    expanded = bool(st.session_state.get('cto_fchat_expanded', False))
    panel_width = 700 if expanded else 450
    st.markdown(f"""<style>
    .st-key-cto_floating_chat_panel {{
      position: fixed!important;
      top: 5vh!important;
      right: 14px!important;
      z-index: 100050!important;
      width: min({panel_width}px, calc(100vw - 28px))!important;
      max-height: 88vh!important;
      overflow-y: auto!important;
      overscroll-behavior: contain;
      box-sizing: border-box!important;
      background: #111a2a!important;
      border: 1px solid #53668a!important;
      border-radius: 14px!important;
      padding: 14px!important;
      box-shadow: 0 16px 50px rgba(0,0,0,.52)!important;
    }}
    .st-key-cto_floating_chat_panel p,
    .st-key-cto_floating_chat_panel li {{
      overflow-wrap: anywhere;
    }}
    .st-key-cto_fchat_history {{
      overflow-y: auto!important;
      overscroll-behavior: contain;
      scroll-behavior: auto;
      border: 1px solid rgba(108,130,164,.30);
      border-radius: 10px;
      padding: 6px;
    }}
    .st-key-cto_floating_chat_panel [data-testid="stChatMessage"] {{
      padding: 10px 12px!important;
      margin-bottom: 7px!important;
      border-radius: 10px!important;
      overflow-wrap: anywhere;
    }}
    .st-key-cto_floating_chat_panel [data-testid="stChatMessage"] :is(h1,h2,h3,h4,h5,h6) {{
      font-size: 17px!important;
      line-height: 1.4!important;
      margin-top: .55em!important;
      margin-bottom: .4em!important;
      font-weight: 700!important;
    }}
    .st-key-cto_floating_chat_panel [data-testid="stChatMessage"] :is(p,li,blockquote,td,th) {{
      font-size: 14px!important;
      line-height: 1.65!important;
    }}
    .st-key-cto_floating_chat_panel [data-testid="stChatMessage"] :is(code,pre) {{
      font-size: 12px!important;
      line-height: 1.5!important;
    }}
    .st-key-cto_floating_chat_panel [data-testid="stChatMessage"] pre {{
      max-width: 100%!important;
      overflow-x: auto!important;
    }}
    .st-key-cto_floating_chat_panel [data-testid="stChatMessage"] table {{
      display: block;
      max-width: 100%;
      overflow-x: auto;
    }}
    .st-key-cto_fchat_footer {{
      position: sticky!important;
      bottom: 0!important;
      z-index: 100052!important;
      background: #111a2a!important;
      padding: 8px 1px 3px!important;
      box-shadow: 0 -10px 14px rgba(17,26,42,.94);
    }}
    @media (max-width: 600px) {{
      .st-key-cto_floating_chat_panel {{
        top: 4vh!important;
        right: 7px!important;
        width: calc(100vw - 14px)!important;
        max-height: 92vh!important;
      }}
    }}
    </style>""", unsafe_allow_html=True)
    with st.container(key='cto_floating_chat_panel'):
        head, resize, close = st.columns([5, 1.4, 1], vertical_alignment='center')
        head.markdown('**🤖 로그별 AI 챗봇**')
        if resize.button('축소' if expanded else '확대', key='cto_fchat_resize',
                         help='챗봇 가로 너비를 변경합니다', use_container_width=True):
            st.session_state['cto_fchat_expanded'] = not expanded
            st.rerun()
        if close.button('✕',key='cto_fchat_close',help='챗봇 창 닫기'):
            _close(st)
        try:record=_event_fetch(env,eid)
        except Exception as exc:
            st.error('선택 로그 조회 실패: '+str(exc));return
        if not record:
            st.warning('실제 Alert와 연결된 로그가 확인되지 않아 분석을 열 수 없습니다.')
            return
        props=record.get('event') or {}
        alerts=record.get('alerts') or []
        et,oc,raw=_event_fields(eid,props)
        st.caption('분석 대상 고정 · 다른 로그를 클릭해도 이 대화는 바뀌지 않습니다.')
        st.info(f'이벤트: {et or "유형 미확인"} · 결과: {oc or "미확인"} · 경보 {len(alerts)}건')
        st.caption(f'로그 ID: {eid}')
        current_job = _cto_job_status(eid)
        busy = current_job.get('status') in ('queued', 'running')
        c1,c2,c3=st.columns(3)
        quick=c1.button('⚡ 빠른 요약', key='cto_fchat_quick',
                        disabled=busy, use_container_width=True)
        deep=c2.button('🔎 심층 분석', key='cto_fchat_deep',
                       disabled=busy, use_container_width=True)
        _cto_report_clicked = c3.button('📄 보고서', key='cto_fchat_report_generate',
                                        disabled=busy, use_container_width=True)
        if quick:
            from time import monotonic as _cto_monotonic
            _started_quick = _cto_monotonic()
            with st.spinner('탐지 및 Graph RAG 정보 검색 중...'):
                summary=_quick_text(eid,et,oc,alerts,env)
                _chat_append(eid,'assistant',summary,
                             elapsed_sec=_cto_monotonic() - _started_quick)
            st.rerun()
        if deep:
            if not et:
                st.warning('이벤트 유형이 없어 심층 분석할 수 없습니다.')
            else:
                try:
                    launched, _ = _cto_submit_job(eid, 'deep')
                    if not launched:
                        st.info('이 로그에 대한 분석이 이미 진행 중입니다.')
                    st.rerun()
                except Exception as exc:
                    st.error('분석 시작 실패: ' + str(exc))
        _cto_report_render(st, env, eid, generate_clicked=_cto_report_clicked, busy=busy)
        job = _cto_job_status(eid)
        status = job.get('status')
        active = status in ('queued', 'running')
        # CTO_CHAT_RESPONSE_V5: show analysis state as an assistant message in history.
        # No banner above chat or misleading completion notification.
        messages=_chat_load(eid)

        # CTO_SOC_CHAT_BADGE_EMITTER_V1: signal only the selected event's
        # user-question state to the already-rendered threat-log table iframe.
        # This is a browser-only visual update, not a new database/AI call.
        from inspect import signature as _cto_soc_signature
        if 'unsafe_allow_javascript' in _cto_soc_signature(st.html).parameters:
            _cto_soc_has_question = any(
                m.get('role') == 'user' and str(m.get('content') or '').strip()
                for m in messages
            )
            _cto_soc_payload = json.dumps({
                'kind': 'cto_soc_chat_history',
                'eventId': eid,
                'hasQuestion': bool(_cto_soc_has_question),
            }, ensure_ascii=True)
            _cto_soc_js = (
                '<script> (() => { const data = ' + _cto_soc_payload + ';'
                ' for (const frame of document.querySelectorAll(\'iframe\')) {'
                ' try { frame.contentWindow.postMessage(data, \'*\'); } catch (_) {}'
                ' } })(); </script>'
            )
            st.html(_cto_soc_js, unsafe_allow_javascript=True)

        st.markdown('**이 로그에 대한 대화**')
        st.caption('질문과 AI의 준비 상태·완료 답변이 이 영역에 표시됩니다.')
        if st.button('↺ 이 로그 대화 초기화',key='cto_fchat_reset',
                     disabled=active, help='현재 로그 대화만 삭제 (분석 중에는 비활성화)'):
            _chat_path(eid).unlink(missing_ok=True)
            st.rerun()
        with st.container(height=430 if expanded else 320, key='cto_fchat_history'):
            if not messages:st.caption('빠른 요약·심층 분석을 누르거나 아래에서 질문해 주세요.')
            for msg in messages[-18:]:
                with st.chat_message(msg['role']):
                    st.caption('사용자' if msg['role']=='user' else 'AI 분석')
                    st.markdown(_cto_display_md(msg['content']) if msg['role'] == 'assistant' else msg['content'])
                    if msg['role'] == 'assistant' and msg.get('elapsed_sec') is not None:
                        st.caption(f"답변 소요 시간: {msg['elapsed_sec']:.1f}초")
                    if msg['role'] == 'assistant' and msg.get('progress_steps'):
                        with st.expander('조회·검증 기록', expanded=False):
                            st.table(msg['progress_steps'])
            # A running task is shown immediately after the submitted question.
            # It disappears once the worker persists the actual assistant reply.
            if active:
                with st.chat_message('assistant'):
                    st.caption('AI 분석 · 진행 중')
                    _phase = ('대기 중' if status == 'queued' else
                              str(job.get('phase') or 'Qwen 분석 중'))
                    # Pure browser timer: only the clock ticks every second;
                    # the Streamlit page continues its pre-existing 5s status refresh.
                    import streamlit.components.v1 as _cto_components_v7
                    # v9: the visual clock is scoped to this job ID, never a previous answer.
                    _cto_components_v7.html(
                        _cto_live_progress_html(_phase, _cto_chat_visual_started_at(st, job)),
                        height=80,
                        scrolling=False,
                    )
                    from hermes_dashboard import public_progress_steps
                    _steps = public_progress_steps(job.get('progress_steps'))
                    _completed = [row['작업'] for row in _steps if row['상태'] == '완료']
                    if _completed:
                        st.caption('완료: ' + ' → '.join(_completed[-4:]))
                    if _steps:
                        with st.expander('조회·검증 기록', expanded=False):
                            st.table(_steps)
            elif status in ('failed', 'interrupted'):
                with st.chat_message('assistant'):
                    if status == 'failed':
                        st.error('분석 실패: ' + str(job.get('error') or '오류 내용을 확인해 주세요.'))
                    else:
                        st.warning('분석이 중단되었습니다. 질문을 다시 보낼 수 있습니다.')
        with st.container(key='cto_fchat_footer'):
            # CTO_FLOAT_CHAT_ENTER_SEND_V1: st.chat_input supports Enter-send and Shift+Enter-newline.
            st.markdown("**추가 질문**")
            user_text = st.chat_input(
                "이 이벤트는 실제 공격인가요?",
                key="cto_fchat_prompt",
                max_chars=2000,
                submit_mode="disable",
            )
            send = bool(user_text and user_text.strip())
            user_text = user_text or ""
        if send and user_text.strip():
            if active:
                st.info('현재 분석이 완료된 후 새 질문을 전송할 수 있습니다.')
            else:
                question = user_text.strip()[:2000]
                try:
                    launched, _ = _cto_submit_job(eid, 'question', question, previous=messages[-12:])
                    if launched:
                        st.rerun()
                    else:
                        st.info('이 로그의 이전 질문이 아직 처리 중입니다.')
                except Exception as exc:
                    st.error('질문 전송 실패: ' + str(exc))


def native_fallback_open(st, threats):
    """Fallback launcher: works even when browser iframe-to-parent bridge is unavailable."""
    choices=[]
    for t in threats:
        try:label=str(t.get('event_type') or t.get('eventTypeName') or '이벤트')
        except (AttributeError,TypeError):continue
        eid=str(t.get('event_id') or t.get('recordId') or '')
        if EVENT_ID.fullmatch(eid):choices.append((eid,label))
    if not choices:return
    with st.expander('🤖 AI 챗봇 직접 열기 (호환 모드)',expanded=False):
        index=st.selectbox('로그 선택',range(len(choices)),
                           format_func=lambda i: choices[i][1]+' · '+choices[i][0],
                           key='cto_fchat_select')
        if st.button('선택 로그 챗봇 열기',key='cto_fchat_manual',use_container_width=True):
            st.session_state['cto_float_chat_active_id']=choices[index][0]
            st.rerun()

# CTO_CHAT_PROGRESS_V4

# CTO_CHAT_RESPONSE_V5

# CTO_CHAT_COMPACT_STAGE_V6


# CTO_FLOATING_CHAT_NO_FLASH_V12
def _cto_fchat_open_receiver(st):
    """Hidden native Streamlit input; on_change supplies a trusted session-selected ID.

    It lives inside a fragment, so a browser click refreshes ONLY the Floating chat.
    The actual event/Alert association is still verified by _event_fetch.
    """
    st.html("""<style>
      .st-key-cto_float_chat_open_bridge {
        position: fixed !important;
        left: -10000px !important;
        top: 0 !important;
        width: 1px !important;
        height: 1px !important;
        overflow: hidden !important;
        opacity: 0 !important;
        pointer-events: none !important;
      }
    </style>""")

    def _accept():
        value = str(st.session_state.get('cto_fchat_open_payload') or '')
        eid, separator, nonce = value.partition('|')
        if separator and nonce and EVENT_ID.fullmatch(eid):
            st.session_state['cto_float_chat_active_id'] = eid
            st.session_state['cto_float_chat_from_bridge'] = True

    with st.container(key='cto_float_chat_open_bridge'):
        st.text_input('Floating chat event bridge',
                      key='cto_fchat_open_payload', max_chars=250,
                      label_visibility='collapsed', on_change=_accept)


_cto_fchat_original_render_panel_v12 = render_panel


def render_panel(st, env):
    """Render the floating chat in its own rerunnable fragment, not the full page."""
    @st.fragment
    def _cto_fchat_only_fragment():
        _cto_fchat_open_receiver(st)
        if str(st.session_state.get('cto_float_chat_active_id') or '').startswith(('lx-ev-', 'win-ev-')):
            from cto_observation_chat_unified import render_panel as _cto_obs_panel
            _cto_obs_panel(st, env)
        else:
            _cto_fchat_original_render_panel_v12(st, env)

    _cto_fchat_only_fragment()
