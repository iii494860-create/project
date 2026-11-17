import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from configure import quote_env
from runtime_env import values
from live_notification_consumer import decode, handle, durable_append
from record_writer import run_engine, build_rows, event_id

ROOT = Path(__file__).resolve().parents[1]


def event(n=0, kind='identity.authenticate', outcome='failure'):
    return {'message_id': f'synthetic-install-{n}', 'publisher_id': 'test.keystone',
            'event_type': kind, 'timestamp': f'2026-01-01T00:00:{n:02d}Z',
            '_context_project_id': 'synthetic-project', '_context_user_id': 'synthetic-user',
            'payload': {'outcome': outcome, 'initiator': {'id': 'synthetic-user', 'host': {'address': '198.51.100.42'}},
                        'resource_info': 'synthetic-resource'}}


class FreshInstallTests(unittest.TestCase):
    def test_secret_roundtrip_without_expansion(self):
        secret = 'a $HOME $(touch /tmp/not-a-command) `id` \\ " \' # 한글'
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / '.env'
            path.write_text('TEST_VALUE=' + quote_env(secret) + '\n')
            self.assertEqual(values(path)['TEST_VALUE'], secret)

    def test_oslo_context_preserved(self):
        raw = event()
        raw['_context_roles'] = ['reader']
        parsed = decode(json.dumps({'oslo.message': json.dumps(raw)}).encode())
        self.assertEqual(parsed['_context_roles'], ['reader'])
        self.assertEqual(parsed['payload'], raw['payload'])

    def test_no_ack_on_storage_failure(self):
        channel = Mock()
        with patch('live_notification_consumer.durable_append', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                handle(channel, Mock(delivery_tag=1), None, json.dumps(event()).encode())
        channel.basic_ack.assert_not_called()

    def test_malformed_preserved_before_ack(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {'CTO_LIVE_LOG': str(Path(folder)/'live.jsonl')}):
            channel = Mock()
            handle(channel, Mock(delivery_tag=2), None, b'{malformed')
            self.assertTrue((Path(folder)/'rejected_notifications.jsonl').exists())
            channel.basic_ack.assert_called_once_with(delivery_tag=2)

    def test_partial_journal_never_silently_overwritten(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'live.jsonl'
            path.write_bytes(b'{partial')
            with self.assertRaises(OSError):
                durable_append(path, event())
            self.assertEqual(path.read_bytes(), b'{partial')

    def test_unknown_event_preserved_and_redelivery_deduplicated(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'live.jsonl'
            messages = [event(1, 'custom.event'), {**event(1, 'custom.event'), 'received_at': 'later'}]
            path.write_text(''.join(json.dumps(x)+'\n' for x in messages))
            engine = run_engine(path, str(ROOT/'knowledge/ontology_all.ttl'))
            nodes, _ = build_rows(engine)
            self.assertEqual(len(nodes['ObservedEvent']), 1)
            self.assertEqual(len(engine.alerts), 0)

    def test_repeated_delivery_does_not_manufacture_bruteforce(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'live.jsonl'
            path.write_text(''.join(json.dumps({**event(1), 'received_at': str(n)})+'\n' for n in range(20)))
            engine = run_engine(path, str(ROOT/'knowledge/ontology_all.ttl'))
            self.assertEqual(len(engine.events), 1)
            self.assertEqual(len(engine.alerts), 0)

    def test_attack_sequence_without_old_site_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'live.jsonl'
            messages = [event(n) for n in range(10)] + [event(10, outcome='success')]
            path.write_text(''.join(json.dumps(x)+'\n' for x in messages))
            engine = run_engine(path, str(ROOT/'knowledge/ontology_all.ttl'))
            self.assertTrue(any(a['rule'] == 'kb:rule_fail_then_success' for a in engine.alerts))
            self.assertEqual(len(build_rows(engine)[0]['ObservedEvent']), 11)


if __name__ == '__main__':
    unittest.main()
