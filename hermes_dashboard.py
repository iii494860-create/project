"""Live Hermes execution progress for the dashboard (no private reasoning text)."""
from __future__ import annotations

import codecs
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import subprocess
import sys
import time


TOOL_LABELS = {
    'tool_search': '사용할 도구 찾기', 'tool_describe': '도구 사용법 확인',
    'tool_call': '조회 도구 실행',
    'retrieve_log_context': '로그 관련 온톨로지 근거 조회',
    'explain_log_event': '로그 이벤트·탐지 조건 확인',
    'search_knowledge': '관련 보안 지식 검색',
    'lookup_technique': '공격 기법 상세 조회',
    'get_defenses': '대응 방법·완화책 조회',
    'validate_citations': '인용 근거 검증',
    'summarize_incident': '사건과 연결 경보 조회',
    'get_incident': '사건 상세 조회', 'get_alert': '경보 상세 조회',
    'list_recent_alerts': '최근 경보 조회',
    'next_attack_steps': '후속 공격 가능성 조회',
    'related_activity': '관련 활동 조회', 'find_vulnerabilities': '취약점 조회',
    'save_report': '요청한 보고서 저장',
    'get_openstack_user': 'OpenStack 사용자 상태 조회',
    'get_openstack_user_roles': 'OpenStack 사용자 권한 조회',
    'get_openstack_server': 'OpenStack 서버 상태 조회',
    'get_openstack_security_group': 'OpenStack 보안그룹 조회',
    'get_openstack_project_resources': 'OpenStack 프로젝트 자원 조회',
}


def tool_label(name):
    return TOOL_LABELS.get(str(name).rsplit('__', 1)[-1], '도구 실행')


def public_progress_steps(value):
    """Persist only the fixed, public columns emitted by ProgressState.rows."""
    if not isinstance(value, list):
        return []
    labels = set(TOOL_LABELS.values()) | {'도구 실행'}
    summaries = {'요청 전송', '도구 응답 수신', '요청한 근거를 찾지 못함',
        '인용 존재·근거 범위 확인', '인용 검증 실패 또는 범위 미확인',
        '도구 호출 형식 오류', '임베딩 조회 실패', '조회 서버 연결 실패',
        '조회 시간 초과', '도구 실행 실패'}
    rows = []
    for row in value[:40]:
        if not isinstance(row, dict) or not isinstance(row.get('작업'), str) or row['작업'] not in labels:
            continue
        if not isinstance(row.get('상태'), str) or row['상태'] not in ('진행 중', '완료', '확인 필요', '오류'):
            continue
        duration = str(row.get('소요 시간') or '')
        if not re.fullmatch(r'(?:\d{1,5}(?:\.\d{1,2})?초|진행 중)', duration):
            duration = '미확인'
        summary = row.get('확인 내용')
        rows.append({'순서': len(rows)+1, '작업': row['작업'], '상태': row['상태'],
                     '소요 시간': duration, '확인 내용': summary if isinstance(summary, str) and summary in summaries else '상태 확인'})
    return rows


def result_summary(event):
    """Only return fixed UI summaries; never render raw tool arguments/secrets."""
    value = event.get('output', '')
    failure = bool(event.get('is_error'))
    error_text = str(value) if failure else ''
    for _ in range(6):
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except (ValueError, TypeError):
                break
        elif isinstance(value, dict):
            if value.get('error'):
                failure, error_text = True, str(value['error'])
                break
            if 'result' in value:
                value = value['result']
            else:
                break
        else:
            break
    if failure:
        lower = error_text.lower()
        if 'exactly one entry' in lower or 'valid json' in lower:
            return '오류', '도구 호출 형식 오류'
        if '임베딩' in error_text:
            return '오류', '임베딩 조회 실패'
        if 'connection' in lower or '연결' in error_text:
            return '오류', '조회 서버 연결 실패'
        if 'timeout' in lower or '시간 초과' in error_text:
            return '오류', '조회 시간 초과'
        return '오류', '도구 실행 실패'
    if isinstance(value, dict):
        if value.get('no_match') is True or value.get('found') is False:
            return '확인 필요', '요청한 근거를 찾지 못함'
        if 'all_exist' in value or 'all_in_context' in value:
            if value.get('all_exist') is True and value.get('all_in_context') is True:
                return '완료', '인용 존재·근거 범위 확인'
            return '확인 필요', '인용 검증 실패 또는 범위 미확인'
    return '완료', '도구 응답 수신'


class ProgressState:
    def __init__(self):
        self.phase = '분석 연결·초기화 중'
        self.steps = []
        self.terminal = None
        self.cto_calls = []
        self.harness_metrics = {}

    def accept(self, event):
        kind = event.get('type')
        if kind == 'system':
            self.phase = '모델 연결·응답 대기 중'
            if event.get('subtype') == 'harness_metrics':
                self.harness_metrics = {k: v for k, v in event.items() if k not in ('type', 'subtype')}
        elif kind == 'tool_use':
            name = str(event.get('name') or '')
            self.steps.append({'name': name, 'id': event.get('tool_call_id'),
                               'input': event.get('input') or {}, 'status': '진행 중',
                               'summary': '요청 전송', 'seconds': None})
            self.phase = tool_label(name) + ' 중'
        elif kind == 'tool_result':
            name, call_id = str(event.get('name') or ''), event.get('tool_call_id')
            step = next((s for s in self.steps if s['status'] == '진행 중'
                         and s['name'] == name and (not call_id or s['id'] == call_id)), None)
            if step is None:
                step = {'name': name, 'id': call_id, 'input': {}}
                self.steps.append(step)
            step['status'], step['summary'] = result_summary(event)
            step['seconds'] = round(float(event.get('duration_ms') or 0) / 1000, 2)
            # This session's stream, not a slice of a global concurrent tool log.
            names = [name]
            if name == 'tool_call' and not event.get('is_error'):
                calls = step['input'].get('calls', [])
                names = [str(c.get('name') or '') for c in calls if isinstance(c, dict)]
            for actual in names:
                if actual.startswith(('mcp__cto__', 'cto__')):
                    self.cto_calls.append({'tool': actual.removeprefix('mcp__cto__').removeprefix('cto__'),
                                           'ok': step['status'] != '오류',
                                           'ms': event.get('duration_ms', 0)})
            self.phase = ('조회 오류 확인 후 모델 응답 대기 중' if step['status'] == '오류'
                          else '조회 결과를 받은 뒤 모델 응답 대기 중')
        elif kind == 'text':
            self.phase = '답변 작성 중'
        elif kind == 'result':
            self.terminal = event
            self.phase = '답변 수신 완료'
        # Unknown events, including reasoning/thinking, are never displayed.

    def rows(self):
        return [{'순서': i + 1, '작업': tool_label(s['name']), '상태': s['status'],
                 '소요 시간': f"{s['seconds']:.2f}초" if s.get('seconds') is not None else '진행 중',
                 '확인 내용': s['summary']} for i, s in enumerate(self.steps)]

    def snapshot(self, elapsed):
        return {'phase': self.phase, 'elapsed_sec': elapsed, 'steps': self.rows()}


def _private_file(path, mode='w'):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    return os.fdopen(fd, mode, encoding='utf-8')


def _stop_process(proc):
    # Includes children even if the main process has already exited.
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    proc.wait()


def run_hermes_stream(prompt, project_root, output_dir, tag, timeout=600,
                      on_progress=None, command=None, env=None):
    """Run once, emit progress during quiet waits, and require a terminal answer.

    command is injectable for offline transport tests. It is never a shell string.
    The subprocess group is terminated on timeout, rerun/cancellation or failure.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    prefix = output_dir / f'{tag}_1'
    prompt_path = prefix.with_suffix('.prompt.txt')
    with _private_file(prompt_path) as f:
        f.write(prompt)
    if command is None:
        hermes = shutil.which('hermes') or str(Path.home() / '.local/bin/hermes')
        command = [hermes, 'chat', '--query-file', str(prompt_path),
                   '--oneshot', '--format', 'stream-json']
    state = ProgressState()
    started = time.monotonic()
    proc = None
    complete = False
    try:
        with _private_file(prefix.with_suffix('.stderr.txt')) as stderr, \
                _private_file(prefix.with_suffix('.events.jsonl')) as log, \
                selectors.DefaultSelector() as selector:
            proc = subprocess.Popen(command, cwd=project_root, env=env,
                                    stdout=subprocess.PIPE, stderr=stderr,
                                    start_new_session=True)
            selector.register(proc.stdout, selectors.EVENT_READ)
            decoder = codecs.getincrementaldecoder('utf-8')(errors='replace')
            buffer, last_update = '', -1.0

            def consume(line):
                try:
                    event = json.loads(line)
                except (ValueError, TypeError):
                    return False
                if not isinstance(event, dict) or event.get('type') not in (
                        'system', 'tool_use', 'tool_result', 'text', 'result'):
                    return False
                log.write(json.dumps(event, ensure_ascii=False) + '\n')
                log.flush()
                state.accept(event)
                return event.get('type') != 'text'

            while selector.get_map() or proc.poll() is None:
                elapsed = time.monotonic() - started
                if elapsed >= timeout:
                    raise subprocess.TimeoutExpired(command, timeout)
                changed = False
                for key, _ in selector.select(timeout=min(0.2, max(0, timeout - elapsed))):
                    chunk = os.read(key.fd, 65536)
                    if chunk:
                        buffer += decoder.decode(chunk)
                    else:
                        buffer += decoder.decode(b'', final=True)
                        selector.unregister(key.fileobj)
                    while '\n' in buffer:
                        line, buffer = buffer.split('\n', 1)
                        changed = consume(line) or changed
                    if not chunk and buffer:
                        changed = consume(buffer) or changed
                        buffer = ''
                if on_progress and (changed or elapsed - last_update >= 1):
                    on_progress(state.snapshot(elapsed))
                    last_update = elapsed
            proc.wait()
            terminal = state.terminal or {}
            if proc.returncode or terminal.get('exit_code') or terminal.get('error'):
                raise RuntimeError('분석 실행이 실패했습니다. 진행 기록과 실행 로그를 확인하세요.')
            answer = str(terminal.get('text') or '').strip()
            if not answer:
                raise RuntimeError('모델이 최종 답변을 반환하지 않았습니다.')
            with _private_file(prefix.with_suffix('.txt')) as f:
                f.write(answer)
            complete = True
            return {'answer': answer, 'elapsed_sec': round(time.monotonic() - started, 1),
                    'tools': [s['name'] for s in state.steps], 'progress_steps': state.rows(),
                    'session_id': terminal.get('session_id', ''),
                    'harness_metrics': state.harness_metrics,
                    'calls_path': prefix.with_suffix('.calls.jsonl')}
    finally:
        if proc is not None:
            if not complete:
                _stop_process(proc)
            if proc.stdout:
                proc.stdout.close()
        with _private_file(prefix.with_suffix('.calls.jsonl')) as f:
            for call in state.cto_calls:
                f.write(json.dumps(call, ensure_ascii=False) + '\n')


def run_qwen_harness(prompt, project_root, output_dir, tag, timeout=660,
                     on_progress=None, env=None, analysis_mode='deep', request_context=None):
    """Run the standalone Qwen API worker through the shared progress transport."""
    if analysis_mode not in ('fast', 'deep'):
        raise ValueError('지원하지 않는 분석 모드')
    python = Path(os.environ.get('QWEN_API_PYTHON', sys.executable))
    worker = Path(project_root) / 'qwen_direct_worker.py'
    prompt_file = Path(output_dir) / f'{tag}_1.prompt.txt'
    command = [str(python), '-u', str(worker), '--prompt-file', str(prompt_file),
               '--run-id', tag, '--mode', analysis_mode, '--timeout', str(timeout)]
    if request_context is not None:
        context_file = Path(output_dir) / f'{tag}_1.context.json'
        context_file.parent.mkdir(parents=True, exist_ok=True)
        with _private_file(context_file) as handle:
            json.dump(request_context, handle, ensure_ascii=False, default=str)
        command += ['--context-file', str(context_file)]
    return run_hermes_stream(prompt, project_root, output_dir, tag, timeout=timeout,
                             on_progress=on_progress, command=command, env=env)


class StreamlitProgress:
    """Main-thread-only UI adapter. Raw reasoning and raw tool data stay hidden."""
    def __init__(self):
        import streamlit as st
        self.panel = st.status('분석 준비 중', expanded=True)
        self.started = time.monotonic()
        self.last_rows = None
        with self.panel:
            st.caption('실제 조회 단계와 결과를 표시합니다. 경과 시간에는 모델 응답 대기도 포함됩니다.')
            self.detail = st.empty()
            self.table = st.empty()

    def stage(self, label):
        self.panel.update(label=label, state='running')
        self.detail.caption(f'{int(time.monotonic() - self.started)}초 경과')

    def __call__(self, progress):
        self.stage(progress['phase'])
        self.detail.caption(f"{int(time.monotonic() - self.started)}초 경과 · 도구 요청 {len(progress['steps'])}회")
        if progress['steps'] != self.last_rows:
            self.last_rows = progress['steps']
            if self.last_rows:
                self.table.table(self.last_rows)

    def finish(self, failed=False):
        errors = sum(row['상태'] == '오류' for row in (self.last_rows or []))
        label = '분석 중단' if failed else '답변 생성 완료'
        if errors:
            label += f' · 도구 오류 {errors}회 기록'
        self.panel.update(label=label, state='error' if failed else 'complete', expanded=True)
        self.detail.caption(f'{time.monotonic() - self.started:.1f}초 경과')
