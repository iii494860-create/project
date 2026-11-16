# OpenStack 위협 분석 대시보드

대시보드 소스와 온톨로지 생성·적재 도구입니다. Ubuntu 22.04 이상 기준입니다. OpenStack 서버, Qwen API 서버, 인증정보는 별도 준비물입니다.

먼저 OS 기본 도구를 설치합니다.

    sudo apt update
    sudo apt install git curl python3 python3-venv

## 새 PC 한 번에 설치

Ubuntu 22.04 이상, 저장소를 clone할 Git, GitHub 접근 권한, `sudo` 권한이 필요합니다. `setup.sh`가 Python/venv와 Docker Engine/Compose가 없으면 Ubuntu 패키지로 설치하고 Docker 서비스를 시작합니다. 설치 PC에서 Qwen API와 Ollama 호환 임베딩 API에 접속할 수 있어야 하며, 임베딩 서버에는 `CTO_EMBED_MODEL` 모델이 준비되어 있어야 합니다. Docker의 공식 Ubuntu 설치 안내도 [참고](https://docs.docker.com/engine/install/ubuntu/)하세요.

저장소를 clone한 뒤 저장소 폴더에서 다음 한 명령을 실행합니다.

    ./setup.sh

설치 중 직접 입력하는 값은 다음과 같습니다.

- 대시보드 접속 IPv4. 다른 PC에서 접속하려면 설치 PC의 LAN IPv4를 입력합니다.
- Qwen API 기본 주소(`/v1`까지), 모델명, API key(필요한 경우).
- 임베딩 API 기본 주소(`/api/embed`는 입력하지 않음), 임베딩 모델명. 기본값은 `http://127.0.0.1:11434`, `qwen3-embedding:8b`입니다. 해당 모델은 4096차원 벡터를 반환해야 합니다.
- 사용할 OpenStack Keystone v3 URL, 사용자명, 암호/application credential, 프로젝트명, 선택적 프로젝트 ID, 리전. 최대 세 프로필을 입력하고 기본 프로필을 고릅니다. 사용하지 않을 프로필은 Keystone URL을 비워 건너뜁니다. 주소만으로는 인증할 수 없으므로 계정 인증정보도 입력해야 합니다.
- RabbitMQ에서 알림 로그를 읽는 환경이면 브로커 호스트, 계정, vhost와 queue를 입력합니다. 사용하지 않으면 호스트를 비워 건너뜁니다. 브로커가 외부에 있어도 queue 생성·OpenStack 알림 발행 설정은 OpenStack/RabbitMQ 관리자 쪽에서 미리 되어 있어야 합니다.

## 현재 PC 데이터를 그대로 이식

복사·복원 전 주의 사항은 [MIGRATION_NOTES.md](MIGRATION_NOTES.md)를 먼저 확인하세요.

새 PC에서 재생성하지 않고 현재 Neo4j와 같은 데이터를 쓰려면, 먼저 기존 PC에서 이식 묶음을 만듭니다.

    ./export_migration_bundle.sh /path/to/current-project

이 명령은 Neo4j의 일관된 백업을 위해 실행 중인 Neo4j 서비스를 잠시 중지했다가 다시 시작합니다. 만들어진 `migration_bundle.tar.gz`에는 Neo4j 데이터베이스, 생성 온톨로지, 문서와 임베딩 캐시가 들어갑니다. 이 파일은 민감한 데이터가 포함될 수 있어 Git에 올리지 않습니다. 새 PC에서 저장소를 clone한 다음 이 파일을 저장소 폴더로 안전하게 복사하고 `./setup.sh`를 실행하세요. 설치기가 이 파일을 발견하면 데이터를 복원하고, 입력한 새 주소와 인증정보로 대시보드를 시작합니다.

이식 묶음 없이 `./setup.sh`를 실행하면 문서와 온톨로지를 다시 내려받아 새로 구성합니다. 즉, 두 설치 방식은 이식 묶음이 있느냐로 결정됩니다.

스크립트는 Python 패키지와 로컬 설정을 준비하고 Neo4j를 시작한 뒤, 이식 묶음이 있으면 기존 데이터를 복원합니다. 묶음이 없으면 문서를 내려받아 온톨로지를 만들고 적재한 다음 임베딩을 생성합니다. 마지막으로 대시보드를 시작하며 종료하려면 `Ctrl+C`를 누릅니다. 나중에 다시 실행할 때는:

    ./run_dashboard.sh

브라우저에서 http://127.0.0.1:8501을 엽니다.

대시보드 외부 접속에는 방화벽 TCP 8501 허용이 필요합니다. OpenStack의 서비스 알림 발행이나 원격 방화벽은 이 설치 스크립트가 변경하지 않습니다.

선택한 OpenStack 주소는 `.env`의 `OPENSTACK_AUTH_URL`에 기록됩니다. 대시보드 실행 때 이 값을 `clouds.yaml`의 선택 프로필에 반영하므로, Keystone 주소를 바꿀 때는 `.env`에서 이 항목을 수정한 뒤 대시보드를 다시 시작하면 됩니다. 인증정보는 계속 권한 제한된 `clouds.yaml`에 저장됩니다.

Neo4j는 전용 Docker volume에 저장됩니다. 생성 온톨로지, Neo4j 데이터, 벡터 임베딩은 Git에 올리지 않으며 새 PC에서 재생성합니다. 임베딩 캐시(`embeddings_cache.jsonl`)는 재실행할 때 같은 모델·문장을 재사용하도록 로컬에 저장됩니다. 온톨로지만 다시 적재하고 벡터를 복원할 때는 `./setup_knowledge.sh`를 실행하세요.

## Git에 올리지 않는 로컬 파일

.env, qwen_api_config.json, clouds.yaml, 로그, SQLite DB, 캐시, 내려받은 문서, 생성 온톨로지와 백업은 .gitignore에 포함되어 있습니다. 예시 설정 파일만 Git에 올립니다.

## 구성과 범위

- 대시보드: dashboard_app.py 및 cto_*.py, qwen_*.py
- 온톨로지 입력: schema.ttl, openstack_mapping.ttl, d3fend_mitigation_map.csv
- Qwen 기본 지침: prompts/qwen_policy.md
- OpenStack CLI는 읽기 전용 allowlist 방식으로 호출합니다.
