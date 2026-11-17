#!/usr/bin/env python3
"""Fail visibly when configured external services cannot be used."""
import json
import os
import subprocess
from urllib.request import Request, urlopen


def main():
    base = os.environ['QWEN_API_BASE_URL'].rstrip('/')
    headers = {'Content-Type': 'application/json'}
    key = os.environ.get('QWEN_API_KEY', '')
    from pathlib import Path
    if not key and Path('.qwen_api_key').exists():
        key = Path('.qwen_api_key').read_text().strip()
    if key:
        headers['Authorization'] = 'Bearer ' + key
    body = {'model': os.environ['QWEN_API_MODEL'], 'messages': [{'role': 'user', 'content': '한국어로 연결 확인이라고 답하세요.'}], 'max_tokens': 128, 'stream': False,
            'reasoning_effort': 'none', 'reasoning': None}
    request = Request(base + '/chat/completions', data=json.dumps(body).encode(), headers=headers)
    try:
        probe = Request(base[:-3] + '/api/show', data=json.dumps({'model': body['model']}).encode(), headers=headers)
        with urlopen(probe, timeout=20) as response:
            capabilities = json.load(response).get('thinking') or {}
        switches = capabilities.get('values', [])
        if not any(type(v) is bool and v is True for v in switches) or not any(type(v) is bool and v is False for v in switches):
            raise ValueError('Qwen server must support the harness /api/show thinking switches')
        with urlopen(request, timeout=180) as response:
            data = json.load(response)
        message = data['choices'][0]['message']
        if not message.get('content'):
            raise ValueError('Empty Qwen response')
    except Exception as exc:
        raise SystemExit('Qwen 호출/추론 전환 검사 실패: ' + type(exc).__name__ + '. 주소·모델·API key와 /api/show thinking 지원을 확인하세요.')
    print('Qwen API 실제 호출 성공')
    if os.environ.get('OPENSTACK_CLOUD'):
        result = subprocess.run(['.venv/bin/openstack', '--os-cloud', os.environ['OPENSTACK_CLOUD'], 'token', 'issue', '-f', 'json'], capture_output=True, timeout=60)
        if result.returncode:
            raise SystemExit('OpenStack 인증 실패: 주소·계정·프로젝트·인증서 설정을 확인하세요.')
        print('OpenStack 인증 성공 (토큰은 출력하지 않음)')


if __name__ == '__main__':
    main()
