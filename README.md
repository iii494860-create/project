# OpenStack 위협 분석 대시보드

대시보드 소스와 온톨로지 생성·적재 도구입니다. Ubuntu 22.04 이상 기준입니다. OpenStack 서버, Qwen API 서버, 인증정보는 별도 준비물입니다.

먼저 OS 기본 도구를 설치합니다.

    sudo apt update
    sudo apt install git curl python3 python3-venv

## 새 PC 설치 순서

### 1. Python 앱 의존성 설치

    ./install.sh

Python 패키지는 저장소 안의 .venv/에 설치됩니다. .env가 만들어지고 Neo4j 비밀번호가 로컬에서 생성됩니다. 설치 질문에서 대시보드를 실행할 PC의 IPv4 주소, Qwen API 주소, OpenStack 세 프로필의 Keystone 주소와 인증정보를 입력합니다. 인증정보는 Git에서 제외된 로컬 파일에만 저장됩니다.

다른 PC에서 대시보드에 접속하려면 실행 PC의 LAN IPv4를 입력하고 방화벽에서 TCP 8501을 허용해야 합니다. 이 절차는 대시보드 PC에만 적용됩니다. OpenStack 서비스의 알림 발행이나 방화벽 설정을 원격으로 변경하지 않습니다.

설치 후 대시보드 PC 주소는 .env의 DASHBOARD_BIND_ADDRESS를 수정합니다. OpenStack 주소나 인증정보를 바꾸려면 clouds.yaml을 직접 수정합니다. 두 파일은 Git에서 제외됩니다.

### 2. Neo4j 시작

먼저 OS의 Docker Engine과 Docker Compose plugin을 설치한 뒤 실행합니다.

    ./start_services.sh

Neo4j는 Docker 컨테이너와 전용 Docker volume에 저장되며 localhost에서만 접속됩니다. 데이터 volume을 지우지 않는 한 컨테이너를 다시 만들어도 데이터는 유지됩니다.

### 3. 온톨로지 만들고 적재

    ./build_load_ontology.sh

문서 원본을 download_docs.sh가 내려받고 온톨로지를 생성한 뒤, .env의 Neo4j에 적재합니다. 외부 문서 다운로드가 필요하므로 네트워크 연결이 필요합니다.

### 4. 외부 API와 OpenStack 설정

- 설치 단계의 질문에 QWEN_API_BASE_URL, QWEN_API_MODEL, API key를 입력합니다. API key는 .qwen_api_key에 저장되고 권한이 제한됩니다. Qwen API 주소는 새 PC에서 네트워크로 접근 가능해야 합니다.
- 설치 단계에서 입력한 세 Keystone 주소와 인증정보는 저장소 안의 ignored clouds.yaml에 저장되며 파일 권한은 600입니다. .env의 OPENSTACK_CLOUD는 사용할 프로필 이름을 선택합니다. 암호와 application credential은 Git에 올리지 않습니다.
- 현재 코드는 프로세스마다 OpenStack cloud 프로필 하나를 사용합니다. 세 클러스터를 동시에 고르는 UI는 별도 구현이 필요하므로, 우선 한 프로필씩 설정해 사용합니다.
- .env에 CTO_OPENSTACK_PROJECT_ID와 CTO_OPENSTACK_PROJECT_NAME을 실제 환경 값으로 설정합니다. 사용자 역할 조회에 필요한 OPENSTACK_USERNAME도 설정하세요.

### 5. 대시보드 실행

    ./run_dashboard.sh

브라우저에서 http://127.0.0.1:8501을 엽니다.

## Git에 올리지 않는 로컬 파일

.env, qwen_api_config.json, clouds.yaml, 로그, SQLite DB, 캐시, 내려받은 문서, 생성 온톨로지와 백업은 .gitignore에 포함되어 있습니다. 예시 설정 파일만 Git에 올립니다.

## 구성과 범위

- 대시보드: dashboard_app.py 및 cto_*.py, qwen_*.py
- 온톨로지 입력: schema.ttl, openstack_mapping.ttl, d3fend_mitigation_map.csv
- Qwen 기본 지침: prompts/qwen_policy.md
- OpenStack CLI는 읽기 전용 allowlist 방식으로 호출합니다.
