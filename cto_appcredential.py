"""Scoped application credential processing shared by both deployed engines."""
import hashlib
import ipaddress
import json
import re

EVENTS = {'identity.application_credential.created', 'identity.application_credential.deleted'}
ID = re.compile(r'(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})\Z')
SAFE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}\Z')


def _object(value):
    return value if isinstance(value, dict) else {}


def duplicate(engine, raw):
    if raw.get('event_type') not in EVENTS:
        return False
    # Delivery timestamp is transport metadata; content conflicts are not deduplicated.
    canonical = {k: v for k, v in raw.items() if k != 'received_at'}
    digest = hashlib.sha256(json.dumps(canonical, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    seen = engine.__dict__.setdefault('_appcredential_notifications', set())
    if digest in seen:
        return True
    seen.add(digest)
    return False


def normalize(event):
    if event['event_type'] not in EVENTS:
        return
    raw = event['raw']
    payload = _object(raw.get('payload'))
    initiator = _object(payload.get('initiator'))
    user = initiator.get('user_id') or initiator.get('id')
    project = initiator.get('project_id') or raw.get('_context_project_id')
    event['user'] = user if isinstance(user, str) and SAFE.fullmatch(user) else None
    event['project'] = project if isinstance(project, str) and SAFE.fullmatch(project) else None


def evaluate(engine, rule, event):
    """Require a prior confirmed rule match, not simply an unfamiliar IP."""
    if event['event_type'] != 'identity.application_credential.created':
        return None
    payload = _object(event['raw'].get('payload'))
    target = _object(payload.get('target'))
    cid = payload.get('resource_info') or target.get('id')
    if (payload.get('outcome') != 'success' or not event['user'] or not event['project']
            or not isinstance(cid, str) or not ID.fullmatch(cid) or event['ts'] < 1e9):
        return None
    if payload.get('resource_info') and target.get('id') and payload['resource_info'] != target['id']:
        return None
    try:
        ipaddress.ip_address(event['ip'])
    except (ValueError, TypeError):
        return None
    if cid in engine.allow['approved_application_credential']:
        return None
    win = int(engine.s.val(rule, 'cto:windowSeconds', 3600))
    candidates = []
    for alert in engine.alerts:
        if alert['rule'] != 'kb:rule_fail_then_success':
            continue
        for item in alert['events']:
            previous = engine.events[item['n']]
            if (previous['bc'] != 'kb:bc_auth_success' or previous['user'] != event['user']
                    or previous['ip'] != event['ip'] or not 0 <= event['ts'] - previous['ts'] <= win):
                continue
            old_payload = _object(previous['raw'].get('payload'))
            old_project = _object(old_payload.get('initiator')).get('project_id') or previous['project']
            if old_project and old_project != event['project']:
                continue
            candidates.append((previous, alert))
    if not candidates:
        return None
    seen = engine.__dict__.setdefault('_appcredential_alerts', set())
    identity = (str(rule), event['user'], event['project'], cid)
    if identity in seen:
        return None
    previous, precursor = max(candidates, key=lambda pair: pair[0]['ts'])
    # Include the actual precursor's evidence (not just its label) for incident review.
    evidence = {x['n']: engine.events[x['n']] for x in precursor['events']}
    evidence[previous['n']] = previous
    evidence[event['n']] = event
    result = engine.alert(rule, 'appcredential:' + cid,
                          sorted(evidence.values(), key=lambda x: x['ts']), related_alerts=[precursor])
    result['attack_confirmed'] = False
    result['credential_use_confirmed'] = False
    seen.add(identity)
    return result
