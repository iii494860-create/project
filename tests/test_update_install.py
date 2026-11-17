import os
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from update_install import configuration_changes


class UpdateSettingsTests(unittest.TestCase):
    def test_current_settings_are_preserved_without_prompting(self):
        current = {'NEO4J_PASSWORD': 'private', 'QWEN_API_BASE_URL': 'https://model.invalid/v1',
                   'CTO_EMBED_LOCAL': 'false', 'RABBIT_HOST': 'broker.invalid',
                   'RABBIT_USER': 'reader', 'RABBIT_PASSWORD': 'private',
                   'RABBIT_QUEUE': 'cto.dashboard.example', 'RABBIT_DECLARE_QUEUE': 'true',
                   'RABBIT_EXCHANGES': 'cloud', 'RABBIT_ROUTING_KEYS': 'custom.info',
                   'RABBIT_TLS': 'true', 'RABBIT_PORT': '5671', 'RABBIT_VHOST': '/cloud'}
        before = dict(current)
        ask = Mock(side_effect=AssertionError('unexpected prompt'))
        self.assertEqual(configuration_changes(current, ask), {})
        self.assertEqual(current, before)

    def test_legacy_monitor_gets_dedicated_queue_without_changing_credentials(self):
        current = {'CTO_EMBED_URL': 'http://old-embed.invalid', 'NEO4J_PASSWORD': 'private',
                   'RABBIT_HOST': 'broker.invalid', 'RABBIT_USER': 'reader', 'RABBIT_PASSWORD': 'secret',
                   'RABBIT_QUEUE': 'production.notifications'}
        changes = configuration_changes(current, Mock(side_effect=['k', 'cloud']))
        self.assertEqual(changes['CTO_EMBED_LOCAL'], 'false')
        self.assertEqual(changes['RABBIT_EXCHANGES'], 'cloud')
        self.assertTrue(changes['RABBIT_QUEUE'].startswith('cto.dashboard.'))
        self.assertNotIn('NEO4J_PASSWORD', changes)
        self.assertNotIn('RABBIT_PASSWORD', changes)
        self.assertNotIn('CTO_EMBED_URL', changes)

    def test_incomplete_broker_configuration_is_not_accepted(self):
        current = {'CTO_EMBED_LOCAL': 'true', 'RABBIT_HOST': 'broker.invalid',
                   'RABBIT_USER': 'reader', 'RABBIT_PASSWORD': 'secret'}
        with self.assertRaises(ValueError):
            configuration_changes(current, Mock(return_value=''))

    def test_existing_manual_subscription_is_preserved(self):
        current = {'CTO_EMBED_LOCAL': 'false', 'RABBIT_HOST': 'broker.invalid',
                   'RABBIT_USER': 'reader', 'RABBIT_PASSWORD': 'secret',
                   'RABBIT_QUEUE': 'manually-approved', 'RABBIT_DECLARE_QUEUE': 'false'}
        changes = configuration_changes(current, Mock(side_effect=AssertionError('unexpected prompt')))
        self.assertNotIn('RABBIT_QUEUE', changes)
        self.assertNotIn('RABBIT_DECLARE_QUEUE', changes)

    def test_service_application_restarts_running_processes(self):
        import install_runtime_services as services
        with patch.dict(os.environ, {'RABBIT_HOST': 'broker.invalid'}), \
                patch('runtime_env.load'), patch.object(services, 'check_ownership'), \
                patch.object(services.subprocess, 'run') as call:
            services.main()
        commands = [entry.args[0] for entry in call.call_args_list]
        self.assertTrue(any('systemctl' in cmd and 'restart' in cmd and 'cto-openstack-consumer.service' in cmd for cmd in commands))

    def test_failed_update_resumes_owned_services(self):
        import update_install as update
        import subprocess
        config = {'NEO4J_URI':'bolt://127.0.0.1:28687', 'NEO4J_USER':'neo4j', 'NEO4J_PASSWORD':'test',
                  'CTO_EMBED_LOCAL':'false', 'RABBIT_HOST':'broker.invalid', 'RABBIT_USER':'reader',
                  'RABBIT_PASSWORD':'test', 'RABBIT_EXCHANGES':'cloud', 'RABBIT_DECLARE_QUEUE':'true',
                  'RABBIT_QUEUE':'cto.dashboard.example', 'RABBIT_PORT':'5672', 'RABBIT_VHOST':'/',
                  'RABBIT_TLS':'false', 'RABBIT_ROUTING_KEYS':'notifications.info'}
        original_exists = Path.exists
        def exists(path):
            return True if str(path).startswith('/etc/systemd/system/cto-') else original_exists(path)
        with patch.dict(os.environ, config), patch.object(update,'manifest'), \
                patch.object(update,'values',return_value=config), patch.object(update,'load'), \
                patch('install_runtime_services.check_ownership'), patch('neo4j.GraphDatabase.driver'), \
                patch.object(Path,'exists',exists), patch.object(update,'update_knowledge',side_effect=ValueError('test failure')), \
                patch.object(update.subprocess,'run',return_value=subprocess.CompletedProcess([],0)) as call:
            with self.assertRaisesRegex(ValueError,'test failure'):
                update.main()
        commands = [entry.args[0] for entry in call.call_args_list]
        resumed = next(cmd for cmd in commands if 'systemctl' in cmd and 'start' in cmd)
        self.assertIn('cto-live-detection.timer', resumed)
        self.assertIn('cto-openstack-consumer.service', resumed)


if __name__ == '__main__':
    unittest.main()
