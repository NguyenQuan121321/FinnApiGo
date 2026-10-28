"""Ephemeral F02 HTTP consumer, not Jake or a production application.

No issuance API, positive state cache, proxy, redirect or TLS bypass. The
shared HS256 verification material can mint staging tokens (accepted test risk).
"""
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import ssl
import sys
import time
import urllib.error
import urllib.request

from rehearsal import NoRedirect, origin
from verifier import decode, unique_object, verify


class Consumer:
    def __init__(self, config):
        if not __debug__:
            raise ValueError('normal Python required')
        self.config = config
        self.upstream = origin(config['issuer_origin'])
        self.keys = config['keys']
        if not 1 <= len(self.keys) <= 2:
            raise ValueError('explicit current/previous keys required')
        decoded = set()
        for kid, value in self.keys.items():
            key = base64.b64decode(value, validate=True)
            if (not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', kid) or len(key) < 32 or len(set(key)) < 16
                    or base64.b64encode(key).decode() != value or key in decoded):
                raise ValueError('strong configured key required')
            decoded.add(key)
        self.retired = config.get('retired', {})
        if len(self.keys) == 2:
            previous = config['previous_kid']
            last = config['last_old_issuance_unix']
            if type(last) is not int or last > time.time() or self.retired != {previous: last + 930} or previous not in self.keys:
                raise ValueError('immutable real previous-key deadline required')
        elif self.retired:
            raise ValueError('unexpected retirement configuration')
        service_key = base64.b64decode(config['service_secret'], validate=True)
        if (service_key in decoded or len(service_key) < 32 or len(set(service_key)) < 16
                or base64.b64encode(service_key).decode() != config['service_secret']):
            raise ValueError('separate service purpose required')
        context = ssl.create_default_context(cafile=config['ca_file'])
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.http = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                               urllib.request.HTTPSHandler(context=context), NoRedirect())

    def check(self, token):
        if not isinstance(token, str) or len(token) > 12000:
            return 401
        try:
            raw = json.loads(decode(token.split('.')[1]), object_pairs_hook=unique_object)
            tid = raw['tid']
            if tid not in self.config['tenants']:
                return 401
            c = verify(token, self.keys, tid, 'jakeai-service', int(time.time()), self.retired)
        except (AssertionError, ValueError, KeyError, TypeError, IndexError, UnicodeError):
            return 401
        request = urllib.request.Request(self.upstream + '/api/v1/identity/introspect',
            data=json.dumps({'token': token, 'tenant_id': c['tid']}).encode(),
            headers={'Content-Type': 'application/json', 'Authorization': 'Bearer ' + self.config['service_secret'],
                     'X-Service-Key-ID': self.config['service_kid']})
        try:
            try:
                response = self.http.open(request, timeout=5)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                body = response.read(65537)
                if len(body) > 65536:
                    return 503
                state = json.loads(body, object_pairs_hook=unique_object)
                if response.code == 401 and state == {'active': False}:
                    return 401
                if response.code != 200:
                    return 503
            if set(state) != {'contract_ver', 'active', 'tid', 'sub', 'sid', 'jti', 'pwdver', 'auth_epoch', 'checked_at', 'max_cache_seconds'}:
                return 503
            if state['active'] is not True or type(state['contract_ver']) is not int or state['contract_ver'] != 1:
                return 503
            if not all(type(state[k]) is type(c[k]) and state[k] == c[k] for k in ('tid', 'sub', 'sid', 'jti', 'pwdver', 'auth_epoch')):
                return 503
            if type(state['checked_at']) is not int or not -1 <= time.time() - state['checked_at'] <= 15:
                return 503
            if type(state['max_cache_seconds']) is not int or not 0 <= state['max_cache_seconds'] <= 15:
                return 503
        except Exception:  # No upstream error/body/credential escapes to HTTP or logs.
            return 503
        return 200 if {'chat:read', 'chat:write'}.intersection(c['perms']) else 403


def handler(consumer):
    class Handler(BaseHTTPRequestHandler):
        server_version = 'F02Diagnostic'
        sys_version = ''

        def setup(self):
            super().setup()
            self.connection.settimeout(10)

        def log_message(self, *_args):
            pass

        def browser_origin(self):
            allowed = consumer.config.get('browser_origin')
            if allowed and self.headers.get('Origin') == allowed:
                self.send_header('Access-Control-Allow-Origin', allowed)
                self.send_header('Vary', 'Origin')

        def do_OPTIONS(self):
            allowed = consumer.config.get('browser_origin')
            if (not allowed or self.headers.get('Origin') != allowed or self.path != '/diagnostic/v1/access'
                    or self.headers.get('Access-Control-Request-Method') != 'GET'):
                self.send_response(403)
            else:
                self.send_response(204)
                self.browser_origin()
                self.send_header('Access-Control-Allow-Methods', 'GET')
                self.send_header('Access-Control-Allow-Headers', 'Authorization, X-Tenant-ID')
            self.send_header('Content-Length', '0')
            self.end_headers()

        def do_GET(self):
            if len(self.headers.as_bytes()) > 16384 or (self.path == '/diagnostic/v1/access' and len(self.headers.get_all('Authorization', [])) != 1):
                status = 401
            elif self.path == '/diagnostic/v1/access':
                auth = self.headers.get('Authorization', '')
                status = consumer.check(auth[7:]) if auth.startswith('Bearer ') else 401
            elif self.path == '/browser':
                body = b'<!doctype html><meta charset="utf-8"><title>F02 diagnostic browser boundary</title><p>Synthetic diagnostic client. Credentials remain in JavaScript memory.</p>'
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Content-Length', str(len(body)))
                self.send_header('Cache-Control', 'no-store')
                self.end_headers()
                self.wfile.write(body)
                return
            else:
                status = 404
            body = json.dumps({'boundary': 'f02-diagnostic-only', 'active': status == 200, 'contract_ver': 1}).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.browser_origin()
            self.end_headers()
            self.wfile.write(body)

    return Handler


def serve(config, address=('0.0.0.0', 8443)):
    server = ThreadingHTTPServer(address, handler(Consumer(config)))
    server.daemon_threads = True
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(config['cert_file'], config['key_file'])
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    return server


if __name__ == '__main__':
    try:
        serve(json.loads(Path(sys.argv[1]).read_text())).serve_forever()
    except Exception:
        sys.exit('diagnostic startup failed (details withheld)')
