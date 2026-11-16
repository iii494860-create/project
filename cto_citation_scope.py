"""3K1H: trusted, per-run Graph RAG technique scopes for Citation verification.

The evidence comes from graph_rag.py's *actual* result, not an LLM assertion.
No database queries occur in this helper. A missing/invalid scope fails closed.
"""
from __future__ import annotations

import datetime as dt
import json
import os
from pathlib import Path
import re

RUN_RE = re.compile(r"dashboard_[0-9]{8}_[0-9]{6}_[0-9a-f]{6}\Z")
TECH_RE = re.compile(r"T\d{4}(?:\.\d{3})?\Z")
TECH_IN_TEXT_RE = re.compile(r"(?<![A-Za-z0-9_])T\d{4}(?:\.\d{3})?(?![A-Za-z0-9_.])")
SCOPE_HOME = Path.home() / '.cto_citation_scopes'
MAX_AGE_SECONDS = 7200


def _normalized_ids(items):
    if not isinstance(items, (list, tuple, set)):
        return []
    return sorted({x.strip() for x in items if isinstance(x, str) and TECH_RE.fullmatch(x.strip())})[:40]


def extract_techniques_from_rag(data: dict) -> list[str]:
    """Select techniques grounded in returned 1-2 hop Graph RAG evidence.

    Do not harvest arbitrary Txxxx strings in user input, explanations, or unrelated
    knowledge: only facts typed Technique or explicit SUGGESTS_TECHNIQUE paths.
    """
    if not isinstance(data, dict) or data.get('no_match') is True:
        return []
    techniques = set()
    for key in ('context', 'facts'):
        seq = data.get(key)
        if isinstance(seq, dict):
            seq = seq.get('facts') or seq.get('items') or seq.get('context')
        if not isinstance(seq, list):
            continue
        for fact in seq:
            if not isinstance(fact, dict):
                continue
            ident = str(fact.get('id') or fact.get('uri') or '').strip()
            kind = str(fact.get('kind') or fact.get('type') or fact.get('label') or '').lower()
            path = str(fact.get('path') or fact.get('relation') or '').upper()
            if TECH_RE.fullmatch(ident) and ('technique' in kind or 'SUGGESTS_TECHNIQUE' in path):
                techniques.add(ident)
            # Some serializers put a technique in the target rather than the id field.
            if 'SUGGESTS_TECHNIQUE' in path:
                candidates = [fact.get('target_id'), fact.get('target'), fact.get('to')]
                for item in candidates:
                    if isinstance(item, str) and TECH_RE.fullmatch(item.strip()):
                        techniques.add(item.strip())
    text = data.get('context_text') or data.get('contextText')
    if not isinstance(text, str):
        text = data.get('context') if isinstance(data.get('context'), str) else ''
    for line in text.splitlines():
        # Graph RAG's event type and technique path lines, not arbitrary mentions.
        if ('SUGGESTS_TECHNIQUE' in line or '시사 기법' in line or '(Technique)' in line):
            techniques.update(TECH_IN_TEXT_RE.findall(line))
    return _normalized_ids(techniques)


def save_scope(run_id: str, ids, *, source: str) -> Path:
    if not isinstance(run_id, str) or RUN_RE.fullmatch(run_id) is None:
        raise ValueError('잘못된 대시보드 실행 ID')
    scope = _normalized_ids(ids)
    if not scope:
        raise ValueError('조회 근거가 없는 Technique 범위는 저장하지 않습니다')
    if source not in ('event_graph_rag', 'query_graph_rag', 'live_cto_tools'):
        raise ValueError('지원하지 않는 범위 출처')
    SCOPE_HOME.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Scope directory should be private to the owner, even after unusual umask.
    os.chmod(SCOPE_HOME, 0o700)
    path = SCOPE_HOME / (run_id + '.json')
    body = {
        'run_id': run_id,
        'source': source,
        'technique_ids': scope,
        'created_at_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
    }
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            json.dump(body, handle, ensure_ascii=False, separators=(',', ':'))
            handle.write('\n')
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise
    return path


def load_scope(run_id: str | None) -> list[str]:
    if not isinstance(run_id, str) or RUN_RE.fullmatch(run_id) is None:
        return []
    path = SCOPE_HOME / (run_id + '.json')
    try:
        # No symlinks and reject stale/run-mismatched entries.
        if path.is_symlink() or path.stat().st_size > 8192:
            return []
        with path.open('r', encoding='utf-8') as handle:
            data = json.load(handle)
        if not isinstance(data, dict) or data.get('run_id') != run_id:
            return []
        if data.get('source') not in ('event_graph_rag', 'query_graph_rag', 'live_cto_tools'):
            return []
        recorded_at = dt.datetime.fromisoformat(str(data['created_at_utc']))
        if recorded_at.tzinfo is None:
            return []
        age = (dt.datetime.now(dt.timezone.utc) - recorded_at).total_seconds()
        if not (0 <= age <= MAX_AGE_SECONDS):
            return []
        ids = data.get('technique_ids')
        if not isinstance(ids, list) or len(ids) < 1 or len(ids) > 40:
            return []
        normalized = _normalized_ids(ids)
        if normalized != sorted(set(ids)):
            return []
        return normalized
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        return []


def merge_scope(run_id: str, ids) -> list[str]:
    """Atomically extend a run's scope from host-observed CTO results only.

    This is a host API, never an MCP/model tool. Callers must extract typed
    evidence from successful tool results, not from tool arguments or prose.
    """
    import fcntl
    import tempfile
    if not isinstance(run_id, str) or RUN_RE.fullmatch(run_id) is None:
        raise ValueError('잘못된 대시보드 실행 ID')
    incoming = _normalized_ids(ids)
    if not incoming:
        return load_scope(run_id)
    SCOPE_HOME.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(SCOPE_HOME, 0o700)
    path = SCOPE_HOME / (run_id + '.json')
    lock_fd = os.open(SCOPE_HOME / (run_id + '.lock'), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    temp = None
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        if path.is_symlink():
            raise ValueError('Scope symlinks are not permitted')
        merged = sorted(set(load_scope(run_id)) | set(incoming))
        if len(merged) > 40:
            raise ValueError('Technique scope exceeds 40 IDs')
        body = {'run_id': run_id, 'source': 'live_cto_tools', 'technique_ids': merged,
                'created_at_utc': dt.datetime.now(dt.timezone.utc).isoformat()}
        fd, temp = tempfile.mkstemp(dir=SCOPE_HOME, prefix=run_id + '.', suffix='.tmp')
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            json.dump(body, handle, ensure_ascii=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
        return merged
    finally:
        if temp:
            Path(temp).unlink(missing_ok=True)
        os.close(lock_fd)
