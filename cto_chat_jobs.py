# CTO_BG_PROGRESS_V3: allow worker-generated safe phase/timestamp metadata.
"""Durable, per-event background chat job launcher (no Streamlit dependencies)."""
from __future__ import annotations
import fcntl
import hashlib
import json
import os
import re
import subprocess
import sys
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

EVENT_ID = re.compile(r"[A-Za-z0-9._:\-]{1,180}\Z")
JOB_DIR = Path.home() / '.cto_event_ai_jobs'
ACTIVE = {'queued', 'running'}


def _utc():
    return datetime.now(timezone.utc).isoformat()


def _paths(event_id):
    if not EVENT_ID.fullmatch(str(event_id or '')):
        raise ValueError('잘못된 이벤트 ID입니다.')
    digest = hashlib.sha256(event_id.encode('utf-8')).hexdigest()
    return (JOB_DIR / (digest + '.json'),
            JOB_DIR / (digest + '.lock'),
            JOB_DIR / (digest + '.worker.log'))


def _private_folder():
    JOB_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(JOB_DIR, 0o700)


@contextmanager
def _lock(event_id):
    _private_folder()
    _, lockpath, _ = _paths(event_id)
    fd = os.open(str(lockpath), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _read(path):
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError, TypeError):
        return {}


def _write(path, data):
    _private_folder()
    temp = path.with_name(path.name + '.' + uuid.uuid4().hex[:8] + '.tmp')
    fd = os.open(str(temp), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as fh:
            json.dump(data, fh, ensure_ascii=False)
            fh.write('\n')
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def _alive(pid):
    if not isinstance(pid, int) or pid <= 1:
        return None
    try:
        # A detached child can briefly remain as a zombie until reaped.
        # Treat it as finished rather than leaving the UI 'running' forever.
        stat = Path(f'/proc/{pid}/stat')
        if stat.is_file():
            try:
                state = stat.read_text(encoding='utf-8').rsplit(')', 1)[-1].strip().split()[0]
                if state in ('Z', 'X'):
                    return False
            except (OSError, IndexError):
                pass
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _stale_status(job):
    if job.get('status') not in ACTIVE:
        return job
    from datetime import datetime
    timestamp = job.get('started_at') or job.get('submitted_at')
    try:
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(timestamp)).total_seconds()
    except (TypeError, ValueError):
        age = 0
    # Allow worker startup before its PID is published.
    if age < 20:
        return job
    pid_alive = _alive(job.get('pid'))
    if pid_alive is False or (pid_alive is None and age > 45):
        job = dict(job)
        job['status'] = 'interrupted'
        job['error'] = '실행 프로세스가 종료되어 결과를 확인할 수 없습니다. 재시도할 수 있습니다.'
        job['updated_at'] = _utc()
    return job


def get_status(event_id):
    path, _, _ = _paths(event_id)
    with _lock(event_id):
        job = _read(path)
        newer = _stale_status(job)
        if newer is not job and job:
            _write(path, newer)
        return {k: v for k, v in newer.items() if k not in ('previous', 'question')}


def submit(event_id, kind, question='', previous=None):
    """Atomically admit one active job per event, then detach its worker."""
    if kind not in {'deep', 'question'}:
        raise ValueError('지원하지 않는 분석 방식입니다.')
    if kind == 'question' and not str(question).strip():
        raise ValueError('질문을 입력해 주세요.')
    path, _, logpath = _paths(event_id)
    with _lock(event_id):
        old = _stale_status(_read(path))
        if old.get('status') in ACTIVE:
            return False, {k: v for k,v in old.items() if k not in ('previous','question')}
        job = {
            'job_id': uuid.uuid4().hex, 'event_id': event_id,
            'kind': kind, 'question': str(question)[:2000],
            'previous': [{'role': str(x.get('role') or ''),
                          'content': str(x.get('content') or '')[:7000]}
                         for x in (previous or [])[-12:]
                         if isinstance(x, dict) and x.get('role') in ('user','assistant')],
            'status': 'queued', 'submitted_at': _utc(), 'updated_at': _utc(),
            'pid': None, 'error': '', 'phase': '분석 요청 접수',
            'timeline': [{'time': _utc(), 'label': '분석 요청 접수'}],
        }
        _write(path, job)
        if kind == 'question':
            # Append the user prompt BEFORE worker spawn, preserving chat order.
            from cto_floating_chat import _chat_append
            _chat_append(event_id, 'user', str(question)[:2000])
        worker_script = Path(__file__).with_name('cto_chat_worker.py')
        fd = os.open(str(logpath), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            with os.fdopen(fd,'ab',buffering=0) as log:
                subprocess.Popen(
                    [sys.executable, str(worker_script), str(path), job['job_id']],
                    cwd=str(worker_script.parent),
                    stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                    start_new_session=True, close_fds=True,
                )
        except Exception as exc:
            job['status'] = 'failed'
            job['error'] = '백그라운드 작업을 시작하지 못했습니다: ' + str(exc)[:250]
            job['updated_at'] = _utc()
            _write(path, job)
            raise
        return True, {k:v for k,v in job.items() if k not in ('previous','question')}


def set_status(event_id, job_id, status, **fields):
    path, _, _ = _paths(event_id)
    with _lock(event_id):
        job = _read(path)
        if job.get('job_id') != job_id:
            return False
        job.update({k:v for k,v in fields.items() if k in ('pid','started_at','finished_at','error','phase','last_progress_at','timeline','progress_steps')})
        job.update(status=status, updated_at=_utc())
        _write(path, job)
        return True

# CTO_CHAT_PROGRESS_V4
