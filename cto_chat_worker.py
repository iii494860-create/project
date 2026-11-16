# CTO_FLOATING_CHAT_QUALITY_V11
"""Independent Qwen worker for a selected Alert-linked event.

The worker loads only the AI helper functions from dashboard_app.py's AST:
no Streamlit dashboard UI is imported or executed in this process.
"""
from __future__ import annotations
import ast
import json
import os
import re
import subprocess
import sys
import time
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path

from cto_chat_jobs import _read, set_status
from cto_floating_chat import EVENT_ID, _chat_append, _event_fetch, _event_fields
from cto_chat_answer_quality import compact_previous, format_answer
from hermes_dashboard import TOOL_LABELS, public_progress_steps

ROOT = Path(os.environ.get('CTO_PROJECT_ROOT', Path(__file__).resolve().parent))
SOURCE = ROOT / 'dashboard_app.py'
GRAPH_RAG = ROOT / 'graph_rag.py'
AGENT_TEST_DIR = ROOT / 'agent_test'

# CTO_BG_PROGRESS_V3
class BackgroundProgress:
    """Headless, factual progress updates for the dashboard.

    This intentionally does NOT expose model reasoning traces, token streams,
    prompts, model arguments, or raw logs. Only verified stages and an approved
    list of tool names are saved to persistent status metadata.
    """
    _event_id = None
    _job_id = None
    _allowed_tools = TOOL_LABELS
    _phase_map = {
        **{label+' 중':label+' 중' for label in TOOL_LABELS.values()},
        '분석 연결·초기화 중':'분석 연결 준비 중',
        '모델 연결·응답 대기 중':'모델 연결·응답 대기 중',
        '조회 결과를 받은 뒤 모델 응답 대기 중':'조회 결과 수신·다음 단계 준비 중',
        '조회 오류 확인 후 모델 응답 대기 중':'조회 오류 확인 중',
        '답변 작성 중':'Qwen 응답 생성 중',
        '답변 수신 완료':'AI 최종 답변 정리 중',
    }

    @classmethod
    def bind(cls, event_id, job_id):
        cls._event_id, cls._job_id = event_id, job_id

    def __init__(self):
        self.started = time.monotonic()
        self.panel = self
        self.progress_steps = []
        self._phase = ''
        self._last_persist = 0.0
        self._timeline = []
        self._tool_steps = []

    def _publish(self, phase, *, force=False):
        if phase not in self._allowed_tools.values() and phase not in self._phase_map.values() and phase not in {
            '온톨로지·인용 근거 확인 중', 'Qwen 응답 생성 중',
            'AI 최종 답변 정리 중', 'AI 분석 진행 중',
        }:
            phase = 'AI 분석 진행 중'
        now = time.monotonic()
        # Emit a milestone only when the stage changes. Avoid a growing
        # activity list of token events and costly disk writes per token.
        changed = phase != self._phase
        if changed:
            self._phase = phase
            self.progress_steps.append(phase)
            self._timeline.append({
                'time': datetime.now(timezone.utc).isoformat(),
                'label': phase,
            })
            self._timeline = self._timeline[-10:]
        if not changed and not force and now - self._last_persist < 5.0:
            return
        self._last_persist = now
        if self._event_id and self._job_id:
            try:
                set_status(self._event_id, self._job_id, 'running',
                           phase=phase, timeline=list(self._timeline),
                           progress_steps=list(self._tool_steps),
                           last_progress_at=datetime.now(timezone.utc).isoformat())
            except (OSError, ValueError, TypeError):
                pass

    @staticmethod
    def _tool_name(values):
        # Never forward arbitrary event labels, arguments or model thoughts.
        for val in values:
            if not isinstance(val, dict):
                continue
            for key in ('tool', 'tool_name', 'name'):
                name = val.get(key)
                if isinstance(name, dict):
                    name = name.get('name')
                if isinstance(name, str):
                    name = name.rsplit('.', 1)[-1].rsplit('/', 1)[-1].rsplit('__', 1)[-1]
                    if name in BackgroundProgress._allowed_tools:
                        return name
        return None

    def __call__(self, *args, **kwargs):
        for value in list(args) + [kwargs]:
            if isinstance(value, dict) and isinstance(value.get('steps'), list):
                rows = public_progress_steps(value['steps'])
                changed = rows != self._tool_steps
                self._tool_steps = rows
                raw_phase = value.get('phase')
                phase = self._phase_map.get(raw_phase, 'AI 분석 진행 중') if isinstance(raw_phase, str) else 'AI 분석 진행 중'
                self._publish(phase, force=changed)
                return None
        tool = self._tool_name(list(args) + [kwargs])
        self._publish(self._allowed_tools[tool]+' 중' if tool else 'AI 분석 진행 중')
        return None

    def stage(self, label, *args, **kwargs):
        label = str(label or '')
        if '답변' in label or '최종' in label:
            phase = 'AI 최종 답변 정리 중'
        elif any(k in label for k in ('근거', 'RAG', 'Citation', '인용', '검증')):
            phase = '온톨로지·인용 근거 확인 중'
        else:
            phase = 'AI 분석 진행 중'
        self._publish(phase)

    def finish(self, *args, **kwargs):
        # Only the worker can set completed after storing the final answer.
        return None

    def warning(self, *args, **kwargs):
        # Never print or persist untrusted model text.
        return None

    def __getattr__(self, name):
        return lambda *args, **kwargs: None


def _load_runner():
    """Reuse the exact configured AI/GraphRAG/citation implementation, no UI side effects."""
    from hermes_dashboard import run_hermes_stream, run_qwen_harness

    def _tracked_hermes(*args, **kwargs):
        return run_hermes_stream(*args, **kwargs)

    def _tracked_harness(*args, **kwargs):
        return run_qwen_harness(*args, **kwargs)

    names = {
        '_neo4j_password', '_json_default', 'run_graph_rag_event', 'run_graph_rag_query',
        '_extract_event_type_outcome', '_audit_citation_calls_strict',
        '_answer_attack_ids', '_chat_history_prompt',
        'run_ontology_agent_analysis', 'run_ontology_agent_chat'
    }
    source = SOURCE.read_text(encoding='utf-8')
    tree = ast.parse(source, filename=str(SOURCE))
    defs = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in names]
    available = {node.name for node in defs}
    missing = names - available
    if missing:
        raise RuntimeError('현재 dashboard_app.py에 필요한 분석 함수가 없습니다: ' + ', '.join(sorted(missing)))
    # Remove UI decorators, if a future version adds them to a helper.
    for node in defs:
        node.decorator_list = []
    module = ast.fix_missing_locations(ast.Module(body=defs, type_ignores=[]))
    ns = {
        '__name__': 'cto_ai_background_runtime',
        'os': os, 're': re, 'json': json, 'sys': sys,
        'Path': Path, 'datetime': datetime, 'timezone': timezone,
        'uuid': uuid, 'time': time, 'subprocess': subprocess,
        'Any': object,
        'PROJECT_ROOT': ROOT, 'GRAPH_RAG': GRAPH_RAG, 'AGENT_TEST_DIR': AGENT_TEST_DIR,
        'StreamlitProgress': BackgroundProgress,
        'run_hermes_stream': _tracked_hermes, 'run_qwen_harness': _tracked_harness,
    }
    exec(compile(module, str(SOURCE), 'exec'), ns)
    return ns


def _neo4j_query(sql, **params):
    from neo4j import GraphDatabase
    p = os.environ.get('NEO4J_PASSWORD')
    if not p:
        secret_file = Path.home() / '.cto_neo4j_password'
        if secret_file.is_file():
            p = secret_file.read_text(encoding='utf-8').strip()
    if not p:
        raise RuntimeError('Neo4j 비밀번호 설정을 확인할 수 없습니다.')
    uri = os.environ.get('NEO4J_URI', 'bolt://127.0.0.1:7687')
    user = os.environ.get('NEO4J_USER', 'neo4j')
    db = os.environ.get('NEO4J_DATABASE', 'neo4j')
    with GraphDatabase.driver(uri, auth=(user, p)) as driver:
        records, _, _ = driver.execute_query(sql, database_=db, **params)
        return [r.data() for r in records]


def _redact(value):
    needles = ('password','passwd','passphrase','secret','token','api_key',
               'authorization','credential','private_key','access_key','cookie','client_secret')
    if isinstance(value, dict):
        return {k: ('[MASKED]' if any(x in str(k).lower().replace('-','_') for x in needles)
                    else _redact(v)) for k,v in value.items()}
    if isinstance(value, list):
        return [_redact(x) for x in value]
    return value


def execute(job):
    eid = str(job.get('event_id') or '')
    if not EVENT_ID.fullmatch(eid):
        raise ValueError('로그 ID 형식 오류')
    record = _event_fetch({'neo4j_query': _neo4j_query}, eid)
    if not record:
        raise ValueError('Alert와 연결된 로그를 찾지 못하여 분석을 중단합니다.')
    props = record.get('event') or {}
    alerts = record.get('alerts') or []
    et, oc, raw = _event_fields(eid, props)
    if not et:
        raise ValueError('event_type을 찾지 못했습니다.')
    # No rawLog plaintext excerpt in the detached worker; use structured fields.
    raw.pop('rawLog_excerpt', None)
    # These links came from the actual TRIGGERED_BY query, not log text.
    raw['linked_alerts'] = alerts
    raw = _redact(raw)
    runner = _load_runner()
    kind = job.get('kind')
    if kind == 'deep':
        result = runner['run_ontology_agent_analysis'](
            '선택된 OpenStack 이벤트를 실제 로그와 경보를 기반으로 심층 분석해줘.',
            event_type=et, outcome=oc, raw_event=raw, timeout=660,
            related_alert_ids=[a['id'] for a in alerts if a.get('id')])
    elif kind == 'question':
        q = str(job.get('question') or '').strip()[:2000]
        if not q:
            raise ValueError('질문 내용이 없습니다.')
        previous = compact_previous(job.get('previous') or [])
        hist = runner['_chat_history_prompt'](previous, max_messages=8, max_chars=6000)
        result = runner['run_ontology_agent_analysis'](
            q, event_type=et, outcome=oc, raw_event=raw,
            timeout=420, question_only=True, user_question=q, previous_questions=hist,
            related_alert_ids=[a['id'] for a in alerts if a.get('id')])
    else:
        raise ValueError('알 수 없는 분석 작업')
    if result.get('error'):
        raise RuntimeError(str(result['error'])[:400])
    answer = str(result.get('answer') or '').strip()
    if not answer:
        raise RuntimeError('Qwen이 빈 응답을 반환했습니다.')
    # Tool-call output / exception is not a usable final security analysis.
    low = answer.casefold()
    if 'traceback (most recent call last)' in low or 'calls array is not valid json' in low:
        raise RuntimeError('모델 응답 형식 오류')
    return format_answer(answer, kind, job.get('question') or '', et,
                         command_block_owned=(result.get('harness_metrics') or {}).get('command_output_owner') == 'server')


def main(args):
    if len(args) != 3:
        return 2
    path, claimed_id = Path(args[1]), args[2]
    job = _read(path)
    if not job or job.get('job_id') != claimed_id:
        return 2
    eid = job['event_id']
    if not set_status(eid, claimed_id, 'running', pid=os.getpid(), started_at=datetime.now(timezone.utc).isoformat(),
                      phase='Qwen 분석 준비 중', last_progress_at=datetime.now(timezone.utc).isoformat()):
        return 2
    BackgroundProgress.bind(eid, claimed_id)
    _execution_started = time.monotonic()
    try:
        answer = execute(job)
        _execution_seconds = round(time.monotonic() - _execution_started, 1)
        # Store duration together with this exact reply, not in a mutable last-job status.
        current = _read(path)
        steps = public_progress_steps(current.get('progress_steps')) if current.get('job_id') == claimed_id else []
        _chat_append(eid, 'assistant', answer, elapsed_sec=_execution_seconds, progress_steps=steps)
        set_status(eid, claimed_id, 'completed', phase='답변 생성 완료',
                   finished_at=datetime.now(timezone.utc).isoformat())
        return 0
    except BaseException as exc:
        print(traceback.format_exc()[-6000:], flush=True)
        set_status(eid, claimed_id, 'failed', error=f'{type(exc).__name__}: {str(exc)[:350]}',
                   finished_at=datetime.now(timezone.utc).isoformat())
        return 1
    finally:
        BackgroundProgress.bind(None, None)

if __name__ == '__main__':
    raise SystemExit(main(sys.argv))

# CTO_CHAT_PROGRESS_V4

# CTO_CHAT_RESPONSE_V5

# CTO_CHAT_COMPACT_STAGE_V6
