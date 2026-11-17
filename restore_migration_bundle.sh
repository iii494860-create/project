#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
BUNDLE="$ROOT/migration_bundle.tar.gz"
STAGE="$ROOT/.migration_restore"

if [ ! -f "$BUNDLE" ]; then
  echo "migration_bundle.tar.gz가 없습니다." >&2
  exit 1
fi
if [ ! -x "$ROOT/.venv/bin/python" ] || [ ! -f "$ROOT/.env" ]; then
  echo "먼저 ./install.sh 를 실행하세요." >&2
  exit 1
fi

set -a
. "$ROOT/.env"
set +a

if docker info >/dev/null 2>&1; then
  DOCKER=(docker)
elif command -v sudo >/dev/null 2>&1 && sudo docker info >/dev/null 2>&1; then
  DOCKER=(sudo docker)
else
  echo "Docker 데몬에 접근할 수 없습니다." >&2
  exit 1
fi

mkdir -p "$STAGE"
"$ROOT/.venv/bin/python" - "$BUNDLE" "$ROOT" "$STAGE" <<'PY'
import re
import shutil
import sys
import tarfile
from pathlib import Path, PurePosixPath

archive_path, root_arg, stage_arg = map(Path, sys.argv[1:])
root = root_arg.resolve()
stage = stage_arg.resolve()
payload = stage / "payload"
payload.mkdir(parents=True, exist_ok=True)

def normalized(name):
    parts = [part for part in PurePosixPath(name).parts if part not in ("", ".", "/")]
    if not parts:
        return PurePosixPath(".")
    if any(part == ".." for part in parts):
        raise ValueError("백업에 안전하지 않은 경로가 있습니다.")
    return PurePosixPath(*parts)

with tarfile.open(archive_path, "r:gz") as tf:
    members = tf.getmembers()
    by_name = {normalized(m.name).as_posix(): m for m in members}
    required = ("migration_manifest.txt", "neo4j/neo4j.dump",
                "out/ontology_all.ttl", "embeddings_cache.jsonl")
    missing = [name for name in required if name not in by_name or not by_name[name].isfile()]
    if missing:
        raise SystemExit("백업 필수 파일 누락: " + ", ".join(missing))
    manifest = tf.extractfile(by_name["migration_manifest.txt"]).read().decode("utf-8", "replace")
    version = re.search(r"(?m)^source_neo4j_version=(\S+)", manifest)
    compose = (root / "docker-compose.yml").read_text(encoding="utf-8")
    image = re.search(r"(?m)^\s*image:\s*neo4j:([^\s]+)", compose)
    if not version or not image:
        raise SystemExit("백업 또는 Neo4j 이미지 버전을 확인하지 못했습니다.")
    image_release = image.group(1).split("-", 1)[0]
    if not version.group(1).startswith(image_release):
        raise SystemExit(f"백업 Neo4j {version.group(1)}와 설치 이미지 {image_release}가 맞지 않습니다.")

    for member in members:
        rel = normalized(member.name)
        if rel.as_posix() == ".":
            continue
        first = rel.parts[0]
        if not (first in ("docs", "out") or rel.as_posix() == "embeddings_cache.jsonl"
                or rel.as_posix() == "neo4j/neo4j.dump"):
            continue
        if first == "neo4j" and rel.as_posix() != "neo4j/neo4j.dump":
            continue
        dest = payload.joinpath(*rel.parts)
        if not dest.resolve().is_relative_to(payload):
            raise SystemExit("백업 경로가 복원 폴더 밖을 가리킵니다.")
        if member.isdir():
            dest.mkdir(parents=True, exist_ok=True)
        elif member.isfile():
            dest.parent.mkdir(parents=True, exist_ok=True)
            source = tf.extractfile(member)
            with dest.open("wb") as out:
                shutil.copyfileobj(source, out)
            dest.chmod(0o600 if rel.as_posix() == "neo4j/neo4j.dump" else 0o644)
        elif member.issym():
            link = (dest.parent / member.linkname).resolve()
            docs_root = (payload / "docs").resolve()
            if not link.is_relative_to(docs_root):
                raise SystemExit("문서 백업의 심볼릭 링크가 docs 밖을 가리킵니다.")
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.symlink_to(member.linkname)

for name in ("docs", "out", "embeddings_cache.jsonl"):
    if (root / name).exists():
        raise SystemExit(f"기존 {name}이 있어 덮어쓰지 않았습니다. 별도 백업 후 비우고 다시 설치하세요.")
PY
chmod 755 "$STAGE" "$STAGE/payload" "$STAGE/payload/neo4j"

echo "기존 Neo4j 데이터가 있는지 확인합니다. 기존 데이터는 덮어쓰지 않습니다."
"$ROOT/.venv/bin/python" - <<'PY'
import os
from neo4j import GraphDatabase

driver = GraphDatabase.driver(os.environ.get("NEO4J_URI", "bolt://127.0.0.1:7687"),
    auth=(os.environ.get("NEO4J_USER", "neo4j"), os.environ["NEO4J_PASSWORD"]))
try:
    with driver.session(database=os.environ.get("NEO4J_DATABASE", "neo4j")) as session:
        count = session.run("MATCH (n) RETURN count(n) AS n").single()["n"]
    if count:
        raise SystemExit(f"현재 Neo4j에 {count}개 노드가 있어 복원을 중단했습니다. 기존 데이터를 보호했습니다.")
finally:
    driver.close()
PY

echo "Neo4j를 잠시 멈추고 백업 덤프를 복원합니다."
IMAGE="$(sed -n 's/^[[:space:]]*image:[[:space:]]*neo4j:\([^[:space:]]*\).*/neo4j:\1/p' "$ROOT/docker-compose.yml" | head -1)"
NEO4J_UID="$("${DOCKER[@]}" run --rm --entrypoint id "$IMAGE" -u neo4j)"
NEO4J_GID="$("${DOCKER[@]}" run --rm --entrypoint id "$IMAGE" -g neo4j)"
"${DOCKER[@]}" run --rm --user 0:0 -v "$STAGE/payload/neo4j:/migration" \
  --entrypoint chown "$IMAGE" "$NEO4J_UID:$NEO4J_GID" /migration/neo4j.dump
"${DOCKER[@]}" compose stop neo4j
if ! "${DOCKER[@]}" compose run --rm --no-deps \
  -v "$STAGE/payload/neo4j:/migration:ro" neo4j \
  neo4j-admin database load neo4j --from-path=/migration --overwrite-destination; then
  "${DOCKER[@]}" compose up -d neo4j || true
  echo "Neo4j 복원에 실패했습니다. 백업과 기존 빈 DB를 보존했습니다." >&2
  exit 1
fi
"${DOCKER[@]}" compose up -d neo4j

"$ROOT/.venv/bin/python" - <<'PY'
import os, time
from neo4j import GraphDatabase

driver = GraphDatabase.driver(os.environ.get("NEO4J_URI", "bolt://127.0.0.1:7687"),
    auth=(os.environ.get("NEO4J_USER", "neo4j"), os.environ["NEO4J_PASSWORD"]))
try:
    for attempt in range(180):
        try:
            with driver.session(database=os.environ.get("NEO4J_DATABASE", "neo4j")) as session:
                session.run("RETURN 1").consume()
            break
        except Exception:
            if attempt == 179:
                raise SystemExit("복원 뒤 Neo4j 연결을 확인하지 못했습니다.")
            time.sleep(1)
    with driver.session(database=os.environ.get("NEO4J_DATABASE", "neo4j")) as session:
        counts = session.run("""
            MATCH (n) UNWIND labels(n) AS label
            RETURN label, count(*) AS n ORDER BY label
        """).data()
        events = session.run("MATCH (n:ObservedEvent) RETURN count(n) AS n").single()["n"]
        alerts = session.run("MATCH (n:Alert) RETURN count(n) AS n").single()["n"]
        knowledge = session.run("MATCH (n:Knowledge) RETURN count(n) AS n").single()["n"]
    if not events or not alerts:
        raise SystemExit("복원 뒤 로그/경보 노드를 확인하지 못했습니다.")
    print(f"복원 확인: ObservedEvent {events}, Alert {alerts}, Knowledge {knowledge}")
finally:
    driver.close()
PY

echo "저장된 임베딩 캐시로 벡터를 복구·검증합니다. 외부 임베딩 API는 호출하지 않습니다."
"$ROOT/.venv/bin/python" - "$STAGE/payload/embeddings_cache.jsonl" "$ROOT/embeddings_cache.jsonl" <<'PY'
import sys
from pathlib import Path
Path(sys.argv[1]).rename(Path(sys.argv[2]))
PY
"$ROOT/.venv/bin/python" "$ROOT/embed_knowledge.py" --restore

"$ROOT/.venv/bin/python" - "$STAGE" "$ROOT" <<'PY'
import shutil
import sys
from pathlib import Path

stage, root = map(Path, sys.argv[1:])
payload = stage / "payload"
for name in ("docs", "out", "embeddings_cache.jsonl"):
    source, destination = payload / name, root / name
    if source.exists():
        if destination.exists():
            raise SystemExit(f"복원 도중 기존 {name}이 확인되어 파일 복사를 중단했습니다.")
        source.rename(destination)
shutil.rmtree(stage, ignore_errors=True)
PY

echo "이전 Neo4j 그래프·로그·임베딩 복원이 완료되었습니다."
