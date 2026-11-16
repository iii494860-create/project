#!/usr/bin/env python3
"""Apply the active Keystone URL from .env to its local clouds.yaml profile."""
import os
from pathlib import Path
from urllib.parse import urlparse

import yaml

root = Path(__file__).resolve().parent
cloud_file = root / "clouds.yaml"
cloud_name = os.environ.get("OPENSTACK_CLOUD", "").strip()
auth_url = os.environ.get("OPENSTACK_AUTH_URL", "").strip()

if not cloud_name or not auth_url or not cloud_file.exists():
    raise SystemExit(0)
parsed = urlparse(auth_url)
if parsed.scheme not in ("http", "https") or not parsed.netloc:
    raise SystemExit(".env의 OPENSTACK_AUTH_URL은 http(s) Keystone URL이어야 합니다.")

config = yaml.safe_load(cloud_file.read_text(encoding="utf-8")) or {}
cloud = config.get("clouds", {}).get(cloud_name)
if cloud is None:
    raise SystemExit(f"clouds.yaml에 {cloud_name} 프로필이 없습니다.")
cloud.setdefault("auth", {})["auth_url"] = auth_url
cloud_file.write_text(
    yaml.safe_dump(config, allow_unicode=True, sort_keys=False), encoding="utf-8"
)
cloud_file.chmod(0o600)
