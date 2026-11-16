"""Conservative metadata extraction for 3K1H model comparisons.

No model answer or ontology lookup is used to assign ground-truth ATT&CK IDs.
"""
from __future__ import annotations

import re

EVENT_PREFIXES = frozenset({
    'identity', 'image', 'instance', 'compute', 'port', 'network', 'volume',
    'keypair', 'role_assignment', 'security_group', 'security_group_rule',
    'floatingip', 'router', 'subnet', 'server', 'project', 'user', 'role',
    'snapshot', 'backup', 'interface', 'flavor', 'aggregate', 'quota',
    'hypervisor', 'loadbalancer', 'firewall', 'orchestration', 'stack',
})
_EVENT_TOKEN = re.compile(r'(?<![A-Za-z0-9_.])([a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){1,6})(?![A-Za-z0-9_.])', re.I)
_FAIL = re.compile(r'(?i)(?<![A-Za-z0-9_])(?:failure|failed)(?![A-Za-z0-9_])|실패|거부|인증\s*오류')
_SUCCESS = re.compile(r'(?i)(?<![A-Za-z0-9_])(?:success|succeeded)(?![A-Za-z0-9_])|성공')

DEFAULT_QUESTION = (
    'Keystone에서 같은 출발지 IP의 identity.authenticate failure가 '
    '300초 안에 반복됐다. 어떤 공격이고 어떻게 대응해야 하는가?'
)


def _normalize(question: str) -> str:
    return ' '.join(str(question or '').split())


def extract_fields(question: str) -> tuple[str, str]:
    """Return a uniquely specified OpenStack event type and outcome.

    An empty event type or '없음' outcome means insufficient/ambiguous evidence.
    """
    question = str(question or '')
    events = sorted({m.group(1).lower() for m in _EVENT_TOKEN.finditer(question)
                     if m.group(1).split('.', 1)[0].lower() in EVENT_PREFIXES})
    event_type = events[0] if len(events) == 1 else ''
    has_fail = bool(_FAIL.search(question))
    has_success = bool(_SUCCESS.search(question))
    outcome = ('failure' if has_fail and not has_success else
               'success' if has_success and not has_fail else '없음')
    return event_type, outcome


def known_gold(question: str) -> str:
    """Only the built-in, explicitly labeled evaluation example has known gold.

    Never infer a gold label from a retrieved ATT&CK mapping or model output.
    """
    return 'T1110' if _normalize(question) == _normalize(DEFAULT_QUESTION) else ''
