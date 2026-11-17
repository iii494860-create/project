#!/usr/bin/env python3
"""Dedicated RabbitMQ subscription -> durable local notifications journal."""
import argparse
import base64
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import ssl
import time

import pika

ROOT = Path(__file__).resolve().parent


def parameters():
    tls = None
    host = os.environ['RABBIT_HOST']
    if os.environ.get('RABBIT_TLS', 'false').lower() == 'true':
        ctx = ssl.create_default_context(cafile=os.environ.get('RABBIT_CA_FILE') or None)
        tls = pika.SSLOptions(ctx, host)
    return pika.ConnectionParameters(
        host=host, port=int(os.environ.get('RABBIT_PORT', '5672')),
        virtual_host=os.environ.get('RABBIT_VHOST', '/'),
        credentials=pika.PlainCredentials(os.environ['RABBIT_USER'], os.environ['RABBIT_PASSWORD']),
        ssl_options=tls, heartbeat=60, blocked_connection_timeout=60,
        socket_timeout=10, connection_attempts=1)


def subscription(channel):
    queue = os.environ['RABBIT_QUEUE']
    if os.environ.get('RABBIT_DECLARE_QUEUE', 'true').lower() == 'false':
        channel.queue_declare(queue=queue, passive=True)
        return queue
    exchanges = [v.strip() for v in os.environ.get('RABBIT_EXCHANGES', '').split(',') if v.strip()]
    keys = [v.strip() for v in os.environ.get('RABBIT_ROUTING_KEYS', 'notifications.info').split(',') if v.strip()]
    if not exchanges or not keys:
        raise ValueError('RABBIT_EXCHANGES and RABBIT_ROUTING_KEYS required')
    # Never create guessed OpenStack exchanges; a typo must fail visibly.
    for exchange in exchanges:
        channel.exchange_declare(exchange=exchange, passive=True)
    channel.queue_declare(queue=queue, durable=True, exclusive=False, auto_delete=False)
    for exchange in exchanges:
        for key in keys:
            channel.queue_bind(queue=queue, exchange=exchange, routing_key=key)
    return queue


def decode(body):
    if len(body) > 8 * 1024 * 1024:
        raise ValueError('Notification exceeds 8 MiB')
    message = json.loads(body)
    if isinstance(message, dict) and 'oslo.message' in message:
        message = message['oslo.message']
        if isinstance(message, str):
            message = json.loads(message)
    if not isinstance(message, dict) or not isinstance(message.get('event_type'), str) or not message['event_type']:
        raise ValueError('Missing event_type')
    if not isinstance(message.get('payload'), dict):
        raise ValueError('payload must be an object')
    # Preserve all context and payload fields needed by the ontology.
    return {**message, 'received_at': datetime.now(timezone.utc).isoformat()}


def durable_append(path, data):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_APPEND | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        end = os.lseek(fd, 0, os.SEEK_END)
        if end:
            os.lseek(fd, -1, os.SEEK_END)
            if os.read(fd, 1) != b'\n':
                # Never silently overwrite a partial record after a disk failure.
                raise OSError('Journal ends in a partial record; repair before consuming')
        payload = memoryview((json.dumps(data, ensure_ascii=False) + '\n').encode())
        while payload:
            written = os.write(fd, payload)
            if written <= 0:
                raise OSError('Journal write failed')
            payload = payload[written:]
        os.fsync(fd)
        # Directory fsync ensures the first created journal survives power loss.
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        os.close(fd)


def handle(channel, method, properties, body):
    path = Path(os.environ.get('CTO_LIVE_LOG', ROOT / 'real_logs/live_notifications.jsonl'))
    try:
        message = decode(body)
    except (ValueError, UnicodeError, TypeError) as exc:
        durable_append(path.parent / 'rejected_notifications.jsonl', {
            'received_at': datetime.now(timezone.utc).isoformat(),
            'reason': type(exc).__name__, 'body_base64': base64.b64encode(body).decode()})
        print('Malformed notification preserved in rejected_notifications.jsonl', flush=True)
    else:
        durable_append(path, message)
    # An I/O failure escapes: reconnect leaves the unacknowledged delivery on MQ.
    channel.basic_ack(delivery_tag=method.delivery_tag)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--check', action='store_true', help='Verify connection and bindings; do not consume')
    args = ap.parse_args()
    while True:
        connection = None
        try:
            connection = pika.BlockingConnection(parameters())
            channel = connection.channel()
            queue = subscription(channel)
            if args.check:
                print('RabbitMQ 연결 및 전용 큐 바인딩 확인 완료')
                return
            channel.basic_qos(prefetch_count=20)
            channel.basic_consume(queue=queue, on_message_callback=handle, auto_ack=False)
            print('OpenStack notification consumer started', flush=True)
            channel.start_consuming()
        except KeyboardInterrupt:
            return
        except Exception as exc:
            # Avoid passwords and connection strings in system journals.
            print('Consumer error: ' + type(exc).__name__, flush=True)
            if args.check:
                raise SystemExit(1)
        finally:
            if connection and connection.is_open:
                connection.close()
        time.sleep(5)


if __name__ == '__main__':
    main()
