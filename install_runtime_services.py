#!/usr/bin/env python3
"""Install services for this checkout; refuse to replace another checkout's services."""
import getpass
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent
PREFIX = '# Managed by CTO installer: ' + str(ROOT) + '\n'


def unit_texts():
    # systemd uses its own quoting and percent-specifier rules, not shell quoting.
    path = str(ROOT).replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%')
    user = os.environ.get('SUDO_USER') or getpass.getuser()
    directory = str(ROOT).replace('%', '%%')
    common = f'User={user}\nWorkingDirectory={directory}\nUMask=0077\n'
    return {
        'cto-openstack-consumer.service': '[Unit]\nDescription=OpenStack notification receiver\nAfter=network-online.target docker.service\nWants=network-online.target\n[Service]\n' + common + f'ExecStart="{path}/run_component.sh" consumer\nRestart=always\nRestartSec=5\n[Install]\nWantedBy=multi-user.target\n',
        'cto-live-detection.service': '[Unit]\nDescription=Ontology detection and Neo4j writer\nAfter=docker.service\n[Service]\nType=oneshot\n' + common + f'ExecStart="{path}/run_component.sh" detect\nTimeoutStartSec=240\n',
        'cto-live-detection.timer': '[Unit]\nDescription=Analyze newly received notifications\n[Timer]\nOnBootSec=30\nOnUnitInactiveSec=15\n[Install]\nWantedBy=timers.target\n',
        'cto-binding-check.service': '[Unit]\nDescription=Verify notification bindings\nAfter=network-online.target\n[Service]\nType=oneshot\n' + common + f'ExecStart="{path}/run_component.sh" bindings\n',
        'cto-binding-check.timer': '[Unit]\nDescription=Maintain notification bindings\n[Timer]\nOnBootSec=45\nOnUnitInactiveSec=120\n[Install]\nWantedBy=timers.target\n',
    }


def main():
    from runtime_env import load
    load()
    if not os.environ.get('RABBIT_HOST'):
        print('RabbitMQ 미설정: 실시간 로그 수집은 활성화되지 않았습니다.')
        return
    units = unit_texts()
    for name in units:
        dest = Path('/etc/systemd/system') / name
        if dest.exists() and not dest.read_text().startswith(PREFIX):
            raise SystemExit(f'{name}: 다른 설치가 사용 중입니다. 기존 서비스를 덮어쓰지 않습니다.')
    subprocess.run([str(ROOT / '.venv/bin/python'), str(ROOT / 'live_notification_consumer.py'), '--check'], check=True)
    sudo = [] if os.geteuid() == 0 else ['sudo']
    with tempfile.TemporaryDirectory(prefix='cto-units-') as work:
        for name, content in units.items():
            path = Path(work) / name
            path.write_text(PREFIX + content)
            subprocess.run(sudo + ['install', '-m', '644', str(path), '/etc/systemd/system/' + name], check=True)
    subprocess.run(sudo + ['systemctl', 'daemon-reload'], check=True)
    subprocess.run(sudo + ['systemctl', 'enable', '--now', 'cto-openstack-consumer.service', 'cto-live-detection.timer', 'cto-binding-check.timer'], check=True)
    subprocess.run(sudo + ['systemctl', 'is-active', '--quiet', 'cto-openstack-consumer.service', 'cto-live-detection.timer', 'cto-binding-check.timer'], check=True)
    print('로그 수신 → 온톨로지 탐지 → Neo4j 저장 서비스 활성화 완료')


if __name__ == '__main__':
    main()
