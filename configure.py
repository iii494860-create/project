#!/usr/bin/env python3
"""Collect local Qwen/OpenStack settings without committing credentials."""
import getpass
import ipaddress
import json
import os
from pathlib import Path
from urllib.parse import urlparse

import yaml

ROOT = Path(__file__).resolve().parent
ENV_FILE = ROOT / ".env"
CLOUD_FILE = ROOT / "clouds.yaml"
KEY_FILE = ROOT / ".qwen_api_key"


def quote_env(value):
    if "\n" in value or "\r" in value:
        raise ValueError("설정값에는 줄바꿈을 넣을 수 없습니다.")
    return json.dumps(value)


def update_env(values):
    lines = ENV_FILE.read_text(encoding="utf-8").splitlines()
    done = set()
    output = []
    for line in lines:
        key, sep, rest = line.partition("=")
        if sep and key in values:
            output.append(key + "=" + quote_env(values[key]))
            done.add(key)
        else:
            output.append(line)
    for key, value in values.items():
        if key not in done:
            output.append(key + "=" + quote_env(value))
    ENV_FILE.write_text("\n".join(output) + "\n", encoding="utf-8")
    ENV_FILE.chmod(0o600)


def main():
    if not ENV_FILE.exists():
        raise SystemExit("먼저 install.sh를 실행하세요.")
    bind_address = input(
        "대시보드 PC의 접속 IP [127.0.0.1; 다른 PC에서 접속하려면 이 PC의 LAN IP]: "
    ).strip() or "127.0.0.1"
    try:
        ipaddress.IPv4Address(bind_address)
    except ipaddress.AddressValueError:
        raise SystemExit("대시보드 접속 주소는 IPv4 주소로 입력하세요.")

    example = json.loads((ROOT / "qwen_api_config.example.json").read_text(encoding="utf-8"))
    base_url = input("Qwen API 주소 [" + example["base_url"] + "]: ").strip() or example["base_url"]
    if not base_url.startswith(("http://", "https://")) or not base_url.rstrip("/").endswith("/v1"):
        raise SystemExit("Qwen API 주소는 http(s)://호스트/v1 형식이어야 합니다.")
    model = input("Qwen 모델 [" + example["model"] + "]: ").strip() or example["model"]
    key = getpass.getpass("Qwen API key (없으면 Enter): ").strip()
    if key:
        KEY_FILE.write_text(key + "\n", encoding="utf-8")
        KEY_FILE.chmod(0o600)

    print("\n온톨로지 벡터 임베딩 설정 (Ollama 호환 /api/embed, 4096차원 모델 필요)")
    embed_url = input("임베딩 서버 기본 주소 [http://127.0.0.1:11434]: ").strip() or "http://127.0.0.1:11434"
    parsed_embed = urlparse(embed_url)
    if parsed_embed.scheme not in ("http", "https") or not parsed_embed.netloc or parsed_embed.path.rstrip("/").endswith("/api/embed"):
        raise SystemExit("임베딩 주소는 http(s)://호스트[:포트] 형식으로 입력하세요 (/api/embed 제외).")
    embed_model = input("임베딩 모델 [qwen3-embedding:8b]: ").strip() or "qwen3-embedding:8b"

    print("\nRabbitMQ 설정 (OpenStack 알림 큐에서 로그를 읽을 때만 입력, 미사용이면 Enter)")
    rabbit_host = input("RabbitMQ 호스트/IP: ").strip()
    rabbit_user = ""
    rabbit_password = ""
    rabbit_vhost = "/"
    rabbit_queue = "cto.openstack.notifications"
    if rabbit_host:
        rabbit_user = input("RabbitMQ 사용자명: ").strip()
        rabbit_password = getpass.getpass("RabbitMQ 비밀번호: ")
        rabbit_vhost = input("RabbitMQ vhost [/]: ").strip() or "/"
        rabbit_queue = input("알림 queue [cto.openstack.notifications]: ").strip() or "cto.openstack.notifications"

    clouds = {}
    profiles = {}
    names = ("openstack-one", "openstack-two", "openstack-three")
    for name in names:
        print("\n" + name + " 설정. endpoint를 비우면 건너뜁니다.")
        auth_url = input("Keystone v3 URL: ").strip()
        if not auth_url:
            continue
        if urlparse(auth_url).scheme not in ("http", "https") or not urlparse(auth_url).netloc:
            raise SystemExit("올바른 Keystone http(s) URL을 입력하세요.")
        username = input("사용자 이름: ").strip()
        password = getpass.getpass("비밀번호/application credential: ")
        project = input("프로젝트 이름: ").strip()
        project_id = input("프로젝트 ID (선택): ").strip()
        region = input("Region [RegionOne]: ").strip() or "RegionOne"
        if not username or not password or not project:
            raise SystemExit("사용자 이름, 비밀번호, 프로젝트 이름은 필수입니다.")
        clouds[name] = {
            "auth": {
                "auth_url": auth_url,
                "username": username,
                "password": password,
                "project_name": project,
                "user_domain_name": "Default",
                "project_domain_name": "Default",
            },
            "region_name": region,
            "interface": "public",
            "identity_api_version": 3,
        }
        profiles[name] = {
            "username": username,
            "project": project,
            "project_id": project_id,
        }

    values = {
        "DASHBOARD_BIND_ADDRESS": bind_address,
        "QWEN_API_BASE_URL": base_url.rstrip("/"),
        "QWEN_API_MODEL": model,
        "CTO_EMBED_URL": embed_url.rstrip("/"),
        "CTO_EMBED_MODEL": embed_model,
        "RABBIT_HOST": rabbit_host,
        "RABBIT_PORT": "5672",
        "RABBIT_USER": rabbit_user,
        "RABBIT_PASSWORD": rabbit_password,
        "RABBIT_VHOST": rabbit_vhost,
        "RABBIT_QUEUE": rabbit_queue,
    }
    if clouds:
        chosen = input("기본 OpenStack 프로필 " + str(list(clouds)) + ": ").strip()
        if chosen not in clouds:
            raise SystemExit("목록에 있는 프로필 이름을 입력하세요.")
        CLOUD_FILE.write_text(
            yaml.safe_dump({"clouds": clouds}, allow_unicode=True, sort_keys=False),
            encoding="utf-8",
        )
        CLOUD_FILE.chmod(0o600)
        selected = profiles[chosen]
        values.update({
            "OPENSTACK_CLOUD": chosen,
            "OPENSTACK_AUTH_URL": clouds[chosen]["auth"]["auth_url"],
            "OPENSTACK_USERNAME": selected["username"],
            "CTO_OPENSTACK_PROJECT_NAME": selected["project"],
            "CTO_OPENSTACK_PROJECT_ID": selected["project_id"],
        })
    update_env(values)
    print("\n설정을 저장했습니다. 암호와 API key는 권한 제한된 로컬 파일에만 저장했습니다.")
    print(f"대시보드 접속 주소: http://{bind_address}:8501")
    if bind_address != "127.0.0.1":
        print("다른 PC에서 접속하려면 방화벽에서 TCP 8501도 허용되어야 합니다.")


if __name__ == "__main__":
    main()
