#!/usr/bin/env python3
"""Opt-in integration check against disposable local Neo4j and RabbitMQ only."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from neo4j import GraphDatabase
import pika
from test_fresh_install import event
from live_notification_consumer import parameters, subscription
from knowledge_assets import verify_graph

ROOT = Path(__file__).resolve().parents[1]


def main():
    uri = os.environ['NEO4J_URI']
    parsed = urlsplit(uri)
    if parsed.hostname != '127.0.0.1' or parsed.port == 7687 or os.environ.get('RABBIT_HOST') != '127.0.0.1' or os.environ.get('RABBIT_PORT') == '5672':
        raise SystemExit('Use disposable localhost services on non-default ports')
    with GraphDatabase.driver(uri, auth=(os.environ['NEO4J_USER'], os.environ['NEO4J_PASSWORD'])) as driver:
        rows,_,_=driver.execute_query('MATCH(n:Record) RETURN count(n) AS c')
        if rows[0]['c']:
            raise SystemExit('Test database must have no records')
        verify_graph(driver, vectors=False)
        connection = pika.BlockingConnection(parameters())
        channel = connection.channel()
        channel.exchange_declare(exchange='cto.synthetic.notifications', exchange_type='topic', durable=True)
        os.environ.update(RABBIT_EXCHANGES='cto.synthetic.notifications', RABBIT_ROUTING_KEYS='notifications.info', RABBIT_DECLARE_QUEUE='true', RABBIT_QUEUE='cto.synthetic.install-a')
        subscription(channel)
        os.environ['RABBIT_QUEUE'] = 'cto.synthetic.install-b'
        subscription(channel)
        os.environ['RABBIT_QUEUE'] = 'cto.synthetic.install-a'
        with tempfile.TemporaryDirectory(prefix='cto-pipeline-check-') as folder:
            log = Path(folder)/'live.jsonl'
            env = {**os.environ, 'CTO_LIVE_LOG': str(log), 'CTO_DETECTION_STATE': str(Path(folder)/'state.json')}
            output = (Path(folder)/'consumer.log').open('w')
            consumer = subprocess.Popen([sys.executable, str(ROOT/'live_notification_consumer.py')], env=env, stdout=output, stderr=output)
            try:
                messages = [event(n) for n in range(10)] + [event(10, outcome='success'), event(11, 'custom.event'), event(12, 'volume.create.end', 'success')]
                for n, message in enumerate(messages):
                    message['timestamp'] = (datetime.now(timezone.utc) - timedelta(seconds=30-n)).isoformat()
                messages.append({**messages[0], 'received_at': 'redelivery'})
                for message in messages:
                    channel.basic_publish(exchange='cto.synthetic.notifications', routing_key='notifications.info', body=json.dumps({'oslo.message':json.dumps(message)}), properties=pika.BasicProperties(delivery_mode=2))
                channel.basic_publish(exchange='cto.synthetic.notifications', routing_key='notifications.info', body=b'{malformed')
                for _ in range(100):
                    if log.exists() and len(log.read_text().splitlines()) == len(messages) and (Path(folder)/'rejected_notifications.jsonl').exists():
                        break
                    if consumer.poll() is not None:
                        raise AssertionError('Consumer exited unexpectedly')
                    time.sleep(.2)
                else:
                    raise AssertionError('Consumer did not durably receive all events')
                # Independent installation must receive its own full copy.
                other = 0
                while True:
                    method,_,_=channel.basic_get('cto.synthetic.install-b', auto_ack=True)
                    if method is None:break
                    other += 1
                assert other == 15, other
                for _ in range(2):
                    subprocess.run([sys.executable, str(ROOT/'live_detection_runner.py')], cwd=ROOT, env=env, check=True)
                # Force replay, independently of the unchanged-file optimization.
                subprocess.run([sys.executable, str(ROOT/'record_writer.py'), '--log', str(log)], cwd=ROOT, env=env, check=True)
                rows,_,_=driver.execute_query('MATCH(e:ObservedEvent) RETURN count(e) AS c')
                assert rows[0]['c'] == 13, rows
                rows,_,_=driver.execute_query('MATCH(a:Alert)-[:TRIGGERED_BY]->(e:ObservedEvent) RETURN count(a) AS c')
                assert rows[0]['c'] > 0
                rows,_,_=driver.execute_query("MATCH(e:ObservedEvent {eventTypeName:'custom.event'}) RETURN count(e) AS c")
                assert rows[0]['c'] == 1
                verify_graph(driver, vectors=False)
                import logging
                logging.getLogger('neo4j').setLevel(logging.ERROR)
                from streamlit.testing.v1 import AppTest
                os.environ.update(env)
                app = AppTest.from_file(str(ROOT/'dashboard_app.py'), default_timeout=60).run()
                assert len(app.exception) == 0, [x.message for x in app.exception]
                tables = [frame.value.to_json() for frame in app.dataframe]
                # The live dashboard renders its event table in an HTML iframe.
                tables += [str(frame.proto) for frame in app.get('iframe')]
                assert any('synthetic' in value for value in tables), 'Synthetic events not visible in dashboard tables'
                print('PASS: dashboard renders received synthetic events without exceptions')
                print('PASS: 15 deliveries to both subscriptions, 13 distinct events, malformed quarantine, alerts, replay without duplicates, knowledge unchanged')
            finally:
                consumer.terminate()
                try:consumer.wait(timeout=10)
                except subprocess.TimeoutExpired:consumer.kill();consumer.wait()
                output.close()
        connection.close()


if __name__ == '__main__':
    main()
