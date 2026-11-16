"""Windows 4625 / Linux SSH floating chat. Observations are never Alerts.

Uses the same fixed Streamlit panel and native Enter-to-send chat input as
OpenStack, while preserving source-specific evidence and analysis prompts.
"""
from __future__ import annotations
import hashlib
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from cto_linux_ssh_page import prompt_for as linux_prompt
from cto_windows_security_page import prompt_for as windows_prompt

QUERY = '''MATCH (e:ObservedEvent)
WHERE e.recordId = $id
  AND ((e.sourceType='linux_ssh' AND e.eventTypeName='linux.ssh.authentication_failure')
    OR (e.sourceType='windows_security' AND e.eventTypeName='windows.security.logon_failure'))
RETURN e.recordId AS event_id, e.sourceType AS source_type,
       e.eventTypeName AS event_type, toString(e.observedAt) AS observed_at,
       e.user AS username, e.ip AS source_ip, e.fieldsJson AS evidence_json
LIMIT 1'''
CHAT_DIR = Path.home() / '.cto_event_ai_chats'


def _read_record(query, eid):
    rows = query(QUERY, id=eid)
    if not rows:
        return None
    row = rows[0]
    if str(row.get('event_id') or '') != eid or row.get('source_type') not in ('linux_ssh','windows_security'):
        return None
    try:
        evidence = json.loads(row.get('evidence_json') or '{}')
        if not isinstance(evidence, dict): evidence = {}
    except (ValueError, TypeError):
        evidence = {}
    return row, evidence


def _path(eid):
    return CHAT_DIR / (hashlib.sha256(eid.encode('utf-8')).hexdigest() + '.jsonl')


def _load(eid):
    path = _path(eid)
    if not path.exists(): return []
    records = []
    for line in path.read_text(encoding='utf-8', errors='replace').splitlines()[-150:]:
        try: msg=json.loads(line)
        except (ValueError, TypeError): continue
        if msg.get('event_id') == eid and msg.get('role') in ('user', 'assistant'):
            records.append(msg)
    return records


def _append(eid, role, content, elapsed_sec=None):
    CHAT_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(CHAT_DIR, 0o700)
    record = {'event_id':eid, 'role':role, 'content':str(content)[:20000],
              'time':datetime.now(timezone.utc).isoformat()}
    if elapsed_sec is not None: record['elapsed_sec'] = round(float(elapsed_sec), 1)
    target = _path(eid)
    fd = os.open(target, os.O_APPEND | os.O_WRONLY | os.O_CREAT, 0o600)
    with os.fdopen(fd, 'a', encoding='utf-8') as file:
        os.fchmod(file.fileno(), 0o600)
        file.write(json.dumps(record, ensure_ascii=False) + '\n')


def _quick(row, evidence):
    is_linux = row['source_type'] == 'linux_ssh'
    label = 'Linux SSH 인증 실패' if is_linux else 'Windows 로그인 실패 4625'
    pairs = [('이벤트', label), ('시간(UTC)', row.get('observed_at')), ('계정', row.get('username')),
             ('출발지 IP', row.get('source_ip')), ('호스트', evidence.get('hostname'))]
    if is_linux:
        pairs.extend([('인증 방식', evidence.get('auth_method')),
                      ('로그 일부', str(evidence.get('message_excerpt') or '')[:700])])
    else:
        pairs.extend([('로그온 유형', evidence.get('logon_type')),
                      ('상태', evidence.get('status')), ('하위 상태', evidence.get('sub_status'))])
    return ('**수집된 로그 빠른 요약**\n\n'
            + '\n'.join(f'- {k}: {str(v)[:750] if v not in (None, "") else "미확인"}' for k,v in pairs)
            + '\n\n**판정:** 인증 실패 관측 기록이며 3K1H Alert 또는 공격 성공이 확인된 것은 아닙니다.')


def _analyze(env, row, evidence, question, history):
    is_linux = row['source_type'] == 'linux_ssh'
    prompt = (linux_prompt if is_linux else windows_prompt)(row, evidence, question, history)
    safe = {'source_type':row['source_type'], 'event_type':row['event_type'],
            'outcome':'failure', 'source_evidence':evidence,
            'attack_confirmed':False,'alert_confirmed':False}
    analyze = env['run_ontology_agent_analysis']
    result = analyze(prompt, event_type='', outcome='', raw_event=safe,
                     timeout=660, user_question=question, question_only=True)
    if not isinstance(result, dict) or result.get('error') or not str(result.get('answer') or '').strip():
        raise RuntimeError('AI 최종 답변을 확인할 수 없습니다.')
    return str(result['answer']).strip()


def render_panel(st, env):
    eid = str(st.session_state.get('cto_float_chat_active_id') or '')
    from cto_floating_chat import EVENT_ID
    if not EVENT_ID.fullmatch(eid) or not eid.startswith(('lx-ev-', 'win-ev-')):
        return
    expanded = bool(st.session_state.get('cto_obs_fchat_expanded', False))
    width = 700 if expanded else 450
    st.markdown(f'''<style>
      .st-key-cto_obs_fchat_panel {{position:fixed!important;top:5vh!important;right:14px!important;
        z-index:100050!important;width:min({width}px,calc(100vw - 28px))!important;
        max-height:88vh!important;overflow-y:auto!important;overscroll-behavior:contain;
        background:#111a2a!important;border:1px solid #53668a!important;
        border-radius:14px!important;padding:14px!important;box-shadow:0 16px 50px rgba(0,0,0,.52)!important;}}
      .st-key-cto_obs_fchat_panel [data-testid="stChatMessage"] {{padding:10px 12px!important;
         margin-bottom:7px!important;border-radius:10px!important;overflow-wrap:anywhere;}}
      .st-key-cto_obs_fchat_panel pre {{max-width:100%!important;overflow-x:auto!important;}}
      .st-key-cto_obs_fchat_history {{overflow-y:auto!important;border:1px solid #53668a50;
         border-radius:10px!important;padding:6px!important;}}
      @media(max-width:600px){{.st-key-cto_obs_fchat_panel{{right:7px!important;top:4vh!important;
         width:calc(100vw - 14px)!important;max-height:92vh!important;}}}}
    </style>''', unsafe_allow_html=True)
    with st.container(key='cto_obs_fchat_panel'):
        head, resize, close = st.columns([5, 1.4, 1], vertical_alignment='center')
        head.markdown('**🤖 로그별 AI 챗봇**')
        if resize.button('축소' if expanded else '확대',key='cto_obs_fchat_resize',use_container_width=True):
            st.session_state['cto_obs_fchat_expanded'] = not expanded
            st.rerun()
        if close.button('✕',key='cto_obs_fchat_close'):
            st.session_state['cto_float_chat_active_id']=''
            st.rerun()
        try:
            loaded = _read_record(env['neo4j_query'],eid)
        except Exception as exc:
            st.error('로그 조회 실패: '+type(exc).__name__)
            return
        if loaded is None:
            st.warning('이 ID에 일치하는 Linux SSH 또는 Windows 4625 관측 로그가 없습니다.')
            return
        row,evidence = loaded
        label = 'Linux SSH' if row['source_type']=='linux_ssh' else 'Windows 4625'
        st.info(f'{label} · 인증 실패 관측 · 공격 미확정 · Alert 아님')
        st.caption('이벤트 ID: '+eid+' · 로그별 대화는 독립적으로 저장됩니다.')
        c1,c2 = st.columns(2)
        quick = c1.button('⚡ 빠른 요약',key='cto_obs_fchat_quick',use_container_width=True)
        deep = c2.button('🔎 심층 분석',key='cto_obs_fchat_deep',use_container_width=True)
        history = _load(eid)
        if st.button('↺ 이 로그 대화 초기화',key='cto_obs_fchat_reset'):
            _path(eid).unlink(missing_ok=True)
            st.rerun()
        with st.container(height=430 if expanded else 320,key='cto_obs_fchat_history'):
            if not history: st.caption('빠른 요약·심층 분석을 누르거나 아래에서 질문해 주세요.')
            for msg in history[-18:]:
                with st.chat_message(msg['role']):
                    st.caption('사용자' if msg['role']=='user' else 'AI 분석')
                    st.markdown(str(msg.get('content') or ''))
                    if msg['role']=='assistant' and isinstance(msg.get('elapsed_sec'), (float,int)):
                        st.caption(f"답변 소요 시간: {msg['elapsed_sec']:.1f}초")
        st.markdown('**추가 질문**')
        user_text = st.chat_input('Enter 전송 · Shift+Enter 줄바꿈',
                                  key='cto_obs_fchat_prompt',max_chars=1600,submit_mode='disable')
        question = (user_text or '').strip()[:1600]
        if quick:
            started=time.monotonic()
            _append(eid,'assistant',_quick(row,evidence),time.monotonic()-started)
            st.rerun()
        if deep or question:
            q = question or ('이 인증 실패 로그에서 확인 가능한 사실, 확인 불가능한 사실, '
                             '추가 조사 명령어, 관리자 승인 후 대응, 재확인 절차를 구분하여 심층 분석해 줘.')
            _append(eid,'user',q)
            with st.spinner('AI가 선택한 로그를 분석하고 있습니다...'):
                started=time.monotonic()
                try: answer = _analyze(env,row,evidence,q,history)
                except Exception as exc:
                    # Persist the failure so the user can see it after reruns.
                    answer='분석 실패: '+type(exc).__name__+' · '+str(exc)[:180]
                elapsed=time.monotonic()-started
                _append(eid,'assistant',answer,elapsed)
            st.rerun()
