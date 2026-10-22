"""Bounded private same-namespace probe. Never emits request or certificate data."""
import json
import os
from pathlib import Path
import socket
import ssl
import sys


def connect(context):
    raw = socket.create_connection(('127.0.0.1', 8444), timeout=2)
    try:
        return context.wrap_socket(raw, server_hostname=os.environ.get('APPGUARD_BACKEND_HOSTNAME', 'backend.example.test'))
    except Exception:
        raw.close()
        raise


def ready():
    context = ssl.create_default_context(cafile=os.environ['APPGUARD_BACKEND_CA'])
    context.load_cert_chain(os.environ['APPGUARD_BACKEND_CLIENT_CERT'], os.environ['APPGUARD_BACKEND_CLIENT_KEY'])
    with connect(context) as connection:
        connection.settimeout(2)
        # Completing TLS alone does not dispatch an HTTP request.


def bypass():
    path = Path('/run/probe/request.bin')
    if path.stat().st_size > 32768:
        raise ValueError('probe input limit')
    data = path.read_bytes()
    results = {}
    for mode in ('plaintext', 'no_client', 'wrong_client'):
        failed = False
        try:
            if mode == 'plaintext':
                connection = socket.create_connection(('127.0.0.1', 8444), timeout=2)
            else:
                context = ssl.create_default_context(cafile='/run/secrets/server-ca.pem')
                if mode == 'wrong_client':
                    context.load_cert_chain('/run/secrets/wrong-client.pem', '/run/secrets/wrong-client.key')
                connection = connect(context)
            with connection:
                connection.settimeout(2)
                connection.sendall(data)
                response = connection.recv(4096)
                # Plaintext may receive Tomcat's fixed HTTPS-port diagnostic.
                failed = (not response or (mode == 'plaintext' and response.startswith(b'HTTP/1.1 400 ')))
        except (OSError, ssl.SSLError):
            failed = True
        if not failed:
            raise AssertionError('backend transport boundary failed')
        results[mode] = True
    print(json.dumps(results, sort_keys=True))


if __name__ == '__main__':
    try:
        if sys.argv[1:] == ['ready']:
            ready()
        elif sys.argv[1:] == ['bypass']:
            bypass()
        else:
            raise ValueError('invalid probe')
    except Exception:
        raise SystemExit(1) from None
