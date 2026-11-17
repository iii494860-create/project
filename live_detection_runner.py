#!/usr/bin/env python3
"""
live_detection_runner.py
- live_notifications.jsonl이 변경되었을 때만 record_writer.py를 실행
- 기존 record_writer.py의 MERGE/idempotent 저장 방식을 그대로 사용
- baseline_real.json / allowlist_real.json이 있으면 자동 적용
- 성공한 입력 파일 signature를 저장해 변경 없을 때 재실행하지 않음
"""

from __future__ import annotations

import json
import fcntl
import os
import subprocess
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(os.environ.get("CTO_PROJECT_ROOT", Path(__file__).resolve().parent))
LIVE_LOG = Path(
    os.environ.get(
        "CTO_LIVE_LOG",
        str(PROJECT_ROOT / "real_logs" / "live_notifications.jsonl"),
    )
)
RECORD_WRITER = PROJECT_ROOT / "record_writer.py"
STATE_FILE = Path(
    os.environ.get(
        "CTO_DETECTION_STATE",
        str(PROJECT_ROOT / "real_logs" / ".live_detection_state.json"),
    )
)

BASELINE = Path(
    os.environ.get(
        "CTO_BASELINE_FILE",
        str(PROJECT_ROOT / "real_logs" / "baseline_real.json"),
    )
)
ALLOWLIST = Path(
    os.environ.get(
        "CTO_ALLOWLIST_FILE",
        str(PROJECT_ROOT / "real_logs" / "allowlist_real.json"),
    )
)


def signature(path: Path) -> dict[str, int]:
    st = path.stat()
    return {
        "size": st.st_size,
        "mtime_ns": st.st_mtime_ns,
    }


def load_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_state(sig: dict[str, int]) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(
        json.dumps({"signature": sig}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    tmp.replace(STATE_FILE)


def main() -> int:
    if not LIVE_LOG.exists():
        print(f"SKIP: live log not found: {LIVE_LOG}", flush=True)
        return 0

    if not RECORD_WRITER.exists():
        print(f"ERROR: record_writer.py not found: {RECORD_WRITER}", flush=True)
        return 1

    if LIVE_LOG.stat().st_size == 0:
        print("SKIP: live log is empty", flush=True)
        return 0

    before = signature(LIVE_LOG)
    state = load_state()

    if state.get("signature") == before:
        print("SKIP: no new OpenStack notification", flush=True)
        return 0

    cmd = [
        sys.executable,
        str(RECORD_WRITER),
        "--log",
        str(LIVE_LOG),
    ]

    if BASELINE.exists():
        cmd += ["--baseline", str(BASELINE)]
        print(f"baseline: {BASELINE}", flush=True)
    else:
        print("baseline: not found (running without baseline)", flush=True)

    if ALLOWLIST.exists():
        cmd += ["--allowlist", str(ALLOWLIST)]
        print(f"allowlist: {ALLOWLIST}", flush=True)
    else:
        print("allowlist: not found (running without allowlist)", flush=True)

    print(f"RUN: {' '.join(cmd)}", flush=True)

    env = os.environ.copy()
    env.setdefault(
        "CTO_NEO4J_PASSWORD_FILE",
        str(Path.home() / ".cto_neo4j_password"),
    )

    # Snapshot complete, fsynced lines under the same lock as the consumer.
    # Do not read a partially appended last JSON record.
    snapshot = tempfile.NamedTemporaryFile(mode="wb", dir=LIVE_LOG.parent, prefix=".detect-", delete=False)
    try:
        with LIVE_LOG.open("rb") as source:
            fcntl.flock(source, fcntl.LOCK_SH)
            before = signature(LIVE_LOG)
            import shutil
            shutil.copyfileobj(source, snapshot)
        snapshot.close()
        cmd[cmd.index("--log") + 1] = snapshot.name
        result = subprocess.run(
            cmd,
            cwd=str(PROJECT_ROOT),
            env=env,
            text=True,
            capture_output=True,
            timeout=180,
            check=False,
        )
    except subprocess.TimeoutExpired:
        print("ERROR: record_writer timeout (180s)", flush=True)
        return 1
    finally:
        snapshot.close()
        Path(snapshot.name).unlink(missing_ok=True)

    if result.stdout:
        print(result.stdout.rstrip(), flush=True)
    if result.stderr:
        print(result.stderr.rstrip(), file=sys.stderr, flush=True)

    if result.returncode != 0:
        print(f"ERROR: record_writer exit={result.returncode}", flush=True)
        return result.returncode

    # 실행 중 새 로그가 추가됐으면 before signature만 저장해서
    # 다음 timer 실행에서 다시 처리되도록 한다.
    save_state(before)

    after = signature(LIVE_LOG)
    if after != before:
        print("INFO: new events arrived during analysis; next timer run will process again", flush=True)

    print("OK: live events analyzed and Neo4j recording completed", flush=True)
    return 0


if __name__ == "__main__":
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with (STATE_FILE.parent / '.detection.lock').open('w') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print('SKIP: detector already running', flush=True)
            raise SystemExit(0)
        raise SystemExit(main())
