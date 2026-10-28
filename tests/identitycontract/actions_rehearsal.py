"""Authorized same-repository hosted-job operations; never use on a workstation.

Only compact allowlisted receipts are printed. Private material stays in this
job's RUNNER_TEMP, is masked, is never uploaded, and is deleted at cleanup.
"""
import base64
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import ssl
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.request

from rehearsal import Blocked, NoRedirect, Probe, decode, signed, token_pair

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
ROLLBACK = '9947b8e857de9b5d4512310e346c042a3b1f35dc'
JAKE = '64f087ca708200a2c81ba646acfa6112876f601c'


def identity():
    run, attempt = os.environ['GITHUB_RUN_ID'], os.environ['GITHUB_RUN_ATTEMPT']
    if (os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'
            or os.environ.get('GITHUB_REPOSITORY') != 'NguyenQuan121321/FinnApiGo'
            or os.environ.get('GITHUB_EVENT_NAME') != 'pull_request'
            or not re.fullmatch(r'[0-9]+', run) or not re.fullmatch(r'[0-9]+', attempt)):
        raise RuntimeError('hosted job guard')
    event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
    if (event['repository']['private'] or event['pull_request']['head']['repo']['full_name'] != 'NguyenQuan121321/FinnApiGo'
            or event['pull_request']['head']['ref'] != 'codex/f02-actions-rehearsal'):
        raise RuntimeError('trusted public PR guard')
    project = 'f02-' + run + '-' + attempt
    parent = Path(os.environ['RUNNER_TEMP']).resolve()
    root = parent / project
    if root.resolve().parent != parent or root.is_symlink():
        raise RuntimeError('runtime path guard')
    return project, root


def emit(kind, **fields):
    receipt = {'kind': kind, 'observed_utc': datetime.now(timezone.utc).isoformat(), **fields}
    print('F02_RECEIPT ' + json.dumps(receipt, separators=(',', ':')), flush=True)
    summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        with open(summary, 'a', encoding='utf-8') as stream:
            stream.write('```json\n' + json.dumps(receipt, separators=(',', ':')) + '\n```\n')


def command(args, *, data=None, env=None, timeout=120, check=True):
    result = subprocess.run(args, input=data, capture_output=True, timeout=timeout, env=env, cwd=REPO)
    if check and result.returncode:
        # Never leak subprocess diagnostics, resolved env, SQL/mail or tokens.
        raw = result.stderr.decode(errors='replace')
        emit('command_failure', executable=Path(args[0]).name, operation=args[1:4], exit_code=result.returncode,
             categories=[word for word in ['permission denied','connection refused','certificate','syntax','access denied','no such','migrate','unknown option'] if word in raw.lower()])
        raise RuntimeError('command failed: ' + str(args[0]))
    return result


def private(path, value, mode=0o600):
    path.write_text(value, encoding='utf-8')
    path.chmod(mode)


def mask(value):
    if os.environ.get('GITHUB_ACTIONS') == 'true':
        print('::add-mask::' + value, flush=True)
    return value


def rng():
    return mask(base64.b64encode(secrets.token_bytes(32)).decode())


def compose(*args, data=None, check=True, timeout=180, image=None):
    project, root = identity()
    env = dict(os.environ, F02_ROOT=str(root), F02_ISSUER_IMAGE=image or 'finnapigo:' + project,
               F02_DIAGNOSTIC_IMAGE='f02-diagnostic:' + project)
    return command(['docker', 'compose', '-p', project, '-f', str(HERE / 'actions.compose.yml'), *args],
                   data=data, env=env, timeout=timeout, check=check)


def config(root, keys, last=None, remove=False):
    current = 'old' if last is None else 'new'
    env = {'GIN_MODE': 'release', 'SERVER_PORT': '8443', 'SERVER_TLS_CERT_FILE': '/run/tls/cert.pem',
           'SERVER_TLS_KEY_FILE': '/run/tls/key.pem', 'SSL_CERT_FILE': '/run/tls/ca.crt',
           'DB_HOST': 'mysql', 'DB_PORT': '3306', 'DB_NAME': 'f02', 'DB_USER': 'f02', 'DB_PASSWORD': keys['mysql-app'],
           'DB_MAX_OPEN_CONNS': '20', 'DB_MAX_IDLE_CONNS': '5', 'MIGRATE_AUTO': 'false',
           'JWT_ALGORITHM': 'HS256', 'JWT_ISSUER': 'finnapigo', 'JWT_KEY_ID': 'sign-' + current,
           'JWT_SECRET': keys['sign-' + current], 'IDENTITY_STATE_KEY_ID': 'state-' + current,
           'IDENTITY_STATE_SECRET': keys['state-' + current], 'ACCESS_TOKEN_TTL': '15m',
           'RECOVERY_CODE_KEY': keys['recovery'], 'METRICS_TOKEN': keys['metrics'],
           'AUDIT_KEY_ID': 'audit', 'AUDIT_SIGNING_KEYS': json.dumps({'audit': keys['audit']}),
           'AUDIT_CHECKPOINT_KEY_ID': 'checkpoint', 'AUDIT_CHECKPOINT_KEY': keys['checkpoint'],
           'AUDIT_RETENTION_DAYS': '0', 'REDIS_URL': 'redis://:' + keys['redis'] + '@redis:6379/0',
           'SMTP_HOST': 'mail', 'SMTP_PORT': '1025', 'SMTP_FROM': 'f02@example.invalid',
           'REQUIRE_EMAIL_VERIFIED': 'true', 'CORS_ALLOWED_ORIGINS': 'https://localhost:19443',
           # Runtime network has no Internet. No external breach/provider call;
           # randomly generated synthetic passwords retain strength validation.
           'BREACHED_PASSWORD_CHECK': 'false'}
    if last is not None and not remove:
        utc = lambda stamp: datetime.fromtimestamp(stamp, timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        env.update(JWT_PREVIOUS_KEY_ID='sign-old', JWT_SECRET_PREVIOUS=keys['sign-old'],
                   JWT_PREVIOUS_LAST_ISSUED_AT=utc(last), IDENTITY_STATE_PREVIOUS_KEY_ID='state-old',
                   IDENTITY_STATE_PREVIOUS_SECRET=keys['state-old'], IDENTITY_STATE_PREVIOUS_UNTIL=utc(last + 930))
    private(root / 'finn.env', '\n'.join(name + '=' + value for name, value in env.items()) + '\n')
    diagnostic = {'issuer_origin': 'https://finn-a:8443', 'keys': {'sign-' + current: keys['sign-' + current]},
                  'service_kid': 'state-' + current, 'service_secret': keys['state-' + current],
                  'tenants': ['f02-a', 'f02-b', 'default'], 'ca_file': '/run/tls/ca.crt',
                  'cert_file': '/run/tls/cert.pem', 'key_file': '/run/tls/key.pem'}
    if last is not None and not remove:
        diagnostic.update(previous_kid='sign-old', last_old_issuance_unix=last,
                          retired={'sign-old': last + 930})
        diagnostic['keys']['sign-old'] = keys['sign-old']
    private(root / 'diagnostic.json', json.dumps(diagnostic), 0o644)
    emit('configuration', phase='baseline' if last is None else 'removed' if remove else 'overlap-or-expired',
         finn_sha256=hashlib.sha256((root / 'finn.env').read_bytes()).hexdigest(),
         diagnostic_sha256=hashlib.sha256((root / 'diagnostic.json').read_bytes()).hexdigest(),
         last_old_issuance_unix=last, signing_deadline_unix=last + 930 if last else None,
         service_deadline_unix=last + 930 if last else None, previous_runtime_references=last is not None and not remove)


def prepare():
    project, root = identity()
    root.mkdir(mode=0o700, exist_ok=False)
    with open(os.environ['GITHUB_ENV'], 'a', encoding='utf-8') as stream:
        stream.write('F02_ROOT=' + str(root) + '\n')
    keys = {name: rng() for name in ['sign-old', 'sign-new', 'state-old', 'state-new', 'audit', 'checkpoint', 'metrics']}
    keys.update(recovery=mask(secrets.token_hex(32)), redis=mask(secrets.token_hex(32)),
                **{'mysql-root': mask(secrets.token_hex(32)), 'mysql-app': mask(secrets.token_hex(32)),
                   'password': mask('F02!aZ9-' + secrets.token_urlsafe(30))})
    assert len(set(keys.values())) == len(keys)
    private(root / 'private-keys.json', json.dumps(keys))
    for name in ['mysql-root', 'mysql-app']:
        private(root / name, keys[name], 0o444)
    private(root / 'mysql-client.cnf', '[client]\nuser=root\npassword=' + keys['mysql-root'] + '\n', 0o444)
    private(root / 'redis.conf', 'bind 0.0.0.0\nprotected-mode yes\nappendonly yes\nmaxmemory 64mb\nmaxmemory-policy noeviction\nrequirepass ' + keys['redis'] + '\n', 0o444)
    tls = root / 'tls'
    tls.mkdir(mode=0o755)
    command(['openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-sha256', '-days', '2',
             '-subj', '/CN=' + project, '-keyout', str(tls / 'ca.key'), '-out', str(tls / 'ca.crt')])
    (tls / 'ca.key').chmod(0o600)
    for name in ['finn-a', 'finn-b', 'diagnostic', 'mail']:
        private(tls / (name + '.ext'), 'subjectAltName=DNS:localhost,DNS:' + name + ',IP:127.0.0.1\nextendedKeyUsage=serverAuth\n')
        command(['openssl', 'req', '-new', '-newkey', 'rsa:3072', '-nodes', '-subj', '/CN=' + name,
                 '-keyout', str(tls / (name + '.key')), '-out', str(tls / (name + '.csr'))])
        command(['openssl', 'x509', '-req', '-in', str(tls / (name + '.csr')), '-CA', str(tls / 'ca.crt'),
                 '-CAkey', str(tls / 'ca.key'), '-CAcreateserial', '-days', '2', '-sha256',
                 '-extfile', str(tls / (name + '.ext')), '-out', str(tls / (name + '.crt'))])
        (tls / (name + '.key')).chmod(0o644)  # Individual RO bind; host parent remains0700.
    config(root, keys)
    # Previous strict source already includes every F02/F03 repair. No state or
    # retired configuration rollback. Assert relevant runtime trees identical.
    command(['git', 'diff', '--exit-code', ROLLBACK, 'HEAD', '--', 'cmd', 'internal', 'migrations', 'Dockerfile', 'go.mod', 'go.sum'])
    archive = command(['git', 'archive', ROLLBACK]).stdout
    import io
    rollback = root / 'rollback-source'
    rollback.mkdir()
    with tarfile.open(fileobj=io.BytesIO(archive)) as stream:
        stream.extractall(rollback, filter='data')
    emit('source', project=project, head_sha=os.environ['F02_HEAD_SHA'],
         tested_merge=command(['git', 'rev-parse', 'HEAD']).stdout.decode().strip(),
         tree=command(['git', 'rev-parse', 'HEAD^{tree}']).stdout.decode().strip(),
         rollback_source=ROLLBACK, jake_reference=JAKE, runtime_unchanged=True,
         cost='public-standard-ubuntu-24.04; no new cache/artifact/package upload')


class Rehearsal:
    def __init__(self):
        self.project, self.root = identity()
        self.keys = json.loads((self.root / 'private-keys.json').read_text())
        for value in self.keys.values():
            mask(value)
        self.last = None
        self.last_phase = 0
        self.pairs = []
        context = ssl.create_default_context(cafile=str(self.root / 'tls/ca.crt'))
        self.http = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context), NoRedirect())
        self.manifest = json.loads((HERE / 'staging.example.json').read_text())
        self.manifest.update(environment='isolated-synthetic-staging', identity_owner='NguyenQuan121321', security_owner='NguyenQuan121321',
            platform_owner='NguyenQuan121321', risk_disposition_ref='F02-LOCAL-STAGING-RISK-001 extended by invoking user to Actions',
            mysql_resource_ref=self.project + '-mysql', redis_resource_ref=self.project + '-redis', tls_trust_ref=self.project + '-ca',
            rollback_ref=ROLLBACK, authorization_ref='invoking user F02-actions-rehearsal automatic same-repository PR run',
            consumer_decision_ref='F02-SCOPE-DIAGNOSTIC-20261028', finn_sha=os.environ['F02_HEAD_SHA'], jake_sha=JAKE,
            replicas=[{'id': 'finn-a', 'origin': 'https://localhost:18443', 'deployment_ref': self.project},
                      {'id': 'finn-b', 'origin': 'https://localhost:20443', 'deployment_ref': self.project}],
            consumer_kind='dedicated-contract-probe', consumer_origin='https://localhost:19443', consumer_path='/diagnostic/v1/access',
            tenant='f02-a', foreign_tenant='f02-b', current_kid='sign-new', previous_kid='sign-old', service_kid='state-new', previous_service_kid='state-old')

    def request(self, base, path, body=None, token=None, tenant='f02-a'):
        headers = {'Content-Type': 'application/json', 'X-Tenant-ID': tenant}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        req = urllib.request.Request(base + path, data=json.dumps(body).encode() if body is not None else None, headers=headers)
        try:
            response = self.http.open(req, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read(65537)
            if len(raw) > 65536:
                raise RuntimeError('response bound')
            try:
                data = json.loads(raw)
            except ValueError:
                data = None
            return response.code, data, response.headers.get('Date')

    def check(self, name, actual, expected):
        emit('case', case=name, actual=actual, expected=expected, status='PASS' if actual == expected else 'FAIL')
        if actual != expected:
            raise RuntimeError('case failed: ' + name)

    def ready(self, service, port):
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            try:
                status, _, _ = self.request('https://localhost:' + str(port), '/healthz' if service != 'diagnostic' else '/diagnostic/v1/access')
                if status == (401 if service == 'diagnostic' else 200):
                    self.inventory(service)
                    return
            except (OSError, urllib.error.URLError):
                pass
            time.sleep(2)
        # Allowlisted startup messages only; never publish raw container logs.
        raw = compose('logs', '--no-color', '--tail', '60', service, check=False).stdout.decode(errors='replace')
        allowed = ['key ID required', 'invalid authentication key', 'insufficient diversity', 'database', 'permission denied',
                   'audit', 'metrics', 'certificate', 'dial tcp', 'no such', 'connection refused', 'TLS', 'fatal']
        emit('startup_failed', service=service, matched_categories=[word for word in allowed if word.lower() in raw.lower()])
        raise RuntimeError('service readiness failed: ' + service)

    def inventory(self, service):
        cid = compose('ps', '-q', service).stdout.decode().strip()
        info = json.loads(command(['docker', 'inspect', cid]).stdout)[0]
        assert info['Config']['Labels']['com.docker.compose.project'] == self.project
        bindings = info['HostConfig']['PortBindings'] or {}
        assert all(binding['HostIp'] == '127.0.0.1' for values in bindings.values() for binding in (values or []))
        assert len(info['NetworkSettings']['Networks']) == 1
        for replica in self.manifest['replicas']:
            if replica['id'] == service:
                replica['deployment_ref'] = cid + '@' + info['Image']
        emit('container', service=service, container_id=cid, image_id=info['Image'], started_at=info['State']['StartedAt'],
             finished_at=info['State']['FinishedAt'], running=info['State']['Running'], published_ports=bindings)

    def sql(self, sql):
        return compose('exec', '-T', 'mysql', 'mysql', '--defaults-extra-file=/run/secrets/mysql-client.cnf', '-N', 'f02', data=sql.encode()).stdout.decode()

    def login(self, port=18443, tenant='f02-a'):
        status, payload, date = self.request('https://localhost:' + str(port), '/api/v1/auth/login',
            {'email': tenant + '@example.invalid', 'password': self.keys['password']}, tenant=tenant)
        self.check('seed-login-' + tenant + '-' + str(port), status, 200)
        pair = token_pair(payload, 'login')
        for value in pair.values():
            mask(value)
        self.pairs.append((tenant, pair))
        claims = json.loads(decode(pair['accessToken'].split('.')[1]))
        header = json.loads(decode(pair['accessToken'].split('.')[0]))
        self.check('real-current-issuance-' + str(port), header['kid'], 'sign-old' if self.last is None else 'sign-new')
        emit('actual_issuance', replica_port=port, tenant=tenant, kid=header['kid'], iat=claims['iat'],
             http_date=date, token_sha256=hashlib.sha256(pair['accessToken'].encode()).hexdigest())
        return pair, claims

    def fixtures(self):
        self.sql("INSERT INTO tenants(id,slug,name,is_active) VALUES ('f02-a','f02-a','F02 A',1),('f02-b','f02-b','F02 B',1);")
        for tenant in ['f02-a', 'f02-b', 'default']:
            status, _, _ = self.request('https://localhost:18443', '/api/v1/auth/register',
                {'username': 'fixture-' + tenant, 'email': tenant + '@example.invalid', 'password': self.keys['password'], 'fullName': 'Synthetic F02'}, tenant=tenant)
            self.check('real-register-' + tenant, status, 201)
            deadline = time.monotonic() + 30
            verification = None
            while time.monotonic() < deadline and verification is None:
                _, messages, _ = self.request('http://127.0.0.1:18025', '/api/v1/messages')
                for message in messages.get('messages', []):
                    if any(to['Address'] == tenant + '@example.invalid' for to in message.get('To', [])) and message['Subject'] == 'Verify your email':
                        _, content, _ = self.request('http://127.0.0.1:18025', '/api/v1/message/' + message['ID'])
                        found = re.search(r'Use this token to verify your email: (\S+)', content['Text'])
                        if found:
                            verification = mask(found[1])
                if verification is None:
                    time.sleep(1)
            if verification is None:
                raise RuntimeError('synthetic mail verification missing')
            status, _, _ = self.request('https://localhost:18443', '/api/v1/auth/verify-email', {'token': verification}, tenant=tenant)
            self.check('real-email-verification-' + tenant, status, 200)
            # Task-owned explicit grants with the same epoch seam as the real
            # repository; no platform/admin role or authority is seeded.
            self.sql("INSERT IGNORE INTO permissions(name) VALUES ('chat:read');"
                     "INSERT INTO roles(tenant_id,name) VALUES ('" + tenant + "','f02-reader');"
                     "INSERT INTO role_permissions SELECT r.id,p.id FROM roles r JOIN permissions p ON p.name='chat:read' WHERE r.tenant_id='" + tenant + "' AND r.name='f02-reader';"
                     "INSERT INTO user_roles SELECT u.id,r.id FROM users u JOIN roles r ON u.tenant_id=r.tenant_id WHERE u.tenant_id='" + tenant + "' AND r.name='f02-reader';"
                     "UPDATE users SET auth_epoch=auth_epoch+1 WHERE tenant_id='" + tenant + "';")
        emit('fixtures', tenants=['f02-a', 'f02-b', 'default'], provenance='actual registration + STARTTLS mail verification + isolated SQL grants/epoch',
             schema=self.sql('SELECT version,dirty FROM schema_migrations;').strip(), table_count=int(self.sql('SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE();')))

    def phase(self, phase, *, fresh=True, label=None):
        # Preserve default per-account login limiter, with explicit test pacing.
        wait = self.last_phase + 65 - time.monotonic()
        if wait > 0:
            emit('pacing', seconds=round(wait, 1), reason='preserve default per-account login limits')
            time.sleep(wait)
        if fresh:
            pair, _ = self.login()
            self.access = pair['accessToken']
        self.last_phase = time.monotonic()
        self.manifest['last_old_issuance_unix'] = self.last if self.last is not None else json.loads(decode(self.access.split('.')[1]))['iat']
        self.manifest['service_overlap_until_unix'] = self.manifest['last_old_issuance_unix'] + 930
        path = self.root / 'private-manifest.json'
        private(path, json.dumps(self.manifest))
        legacy_claims = json.loads(decode(self.access.split('.')[1]))
        legacy_claims.pop('contract_ver')
        legacy = mask(signed(legacy_claims, 'sign-old' if self.last is None else 'sign-new', self.keys['sign-old' if self.last is None else 'sign-new']))
        env = dict(os.environ, F02_CA_FILE=str(self.root / 'tls/ca.crt'), F02_ACCESS_TOKEN=self.access,
            F02_PREVIOUS_ACCESS_TOKEN=getattr(self, 'old_access', self.access), F02_CURRENT_SIGNING_KEY=self.keys['sign-new'],
            F02_PREVIOUS_SIGNING_KEY=self.keys['sign-old'], F02_CURRENT_SERVICE_KEY=self.keys['state-new'],
            F02_PREVIOUS_SERVICE_KEY=self.keys['state-old'], F02_SYNTHETIC_EMAIL='f02-a@example.invalid',
            F02_SYNTHETIC_PASSWORD=self.keys['password'], F02_LEGACY_ACCESS_TOKEN=legacy)
        result = command([sys.executable, '-B', str(HERE / 'rehearsal.py'), str(path), '--phase', phase,
            '--execute-reviewed-manifest-sha256', hashlib.sha256(path.read_bytes()).hexdigest()], env=env, check=False)
        report = json.loads(result.stdout)
        emit('guarded_phase', label=label or phase, report=report, exit_code=result.returncode)
        if result.returncode:
            raise RuntimeError('guarded phase failed: ' + phase)
        return env

    def extended(self):
        claims = json.loads(decode(self.access.split('.')[1]))
        probe = Probe(self.manifest)
        service = ('state-old', self.keys['state-old']) if self.last is None else ('state-new', self.keys['state-new'])
        kid = 'sign-old' if self.last is None else 'sign-new'
        candidates = []
        for field in ['contract_ver','iss','aud','sub','uid','type','tid','exp','iat','nbf','jti','sid','pwdver','auth_epoch','perms']:
            for variation in ['missing', 'null']:
                value = dict(claims)
                if variation == 'missing':
                    value.pop(field)
                else:
                    value[field] = None
                candidates.append((variation + '-' + field, signed(value, kid, self.keys[kid]), 401))
        for field, value in [('uid', True), ('pwdver', True), ('auth_epoch', -1), ('perms', ['ungranted']), ('sid','unknown'),
                             ('jti',''), ('exp',int(time.time())-31), ('nbf',int(time.time())+60), ('iss','other'), ('type','sudo')]:
            modified = dict(claims)
            modified[field] = value
            candidates.append(('wrong-' + field, signed(modified, kid, self.keys[kid]), 401))
        for field in ['tenant_id', 'permissions', 'roles', 'scopes', 'id', 'UID', 'Auth_Epoch']:
            candidates.append(('alias-' + field, signed(dict(claims, **{field: 'forbidden'}), kid, self.keys[kid]), 401))
        for name, candidate, expected in candidates:
            probe.introspect(self.manifest['replicas'][0], candidate, service, expected, label='extended-' + name)
            probe.consumer(candidate, expected, 'extended-' + name)
        for purpose in ['reset', 'verify-email', 'mfa_pending', 'sudo', 'service', 'obo']:
            token = signed(dict(claims, type=purpose), kid, self.keys[kid])
            status, _, _ = self.request('https://localhost:18443', '/api/v1/auth/me', token=token)
            self.check('protected-purpose-' + purpose, status, 401)
        probe.introspect(self.manifest['replicas'][0], self.access, (service[0], self.keys[kid]), 401, label='signing-is-not-service-key')
        emit('extended_matrix', cases=probe.results)

    def incorrect_consumer_control(self):
        # Deliberately wrong real HTTPS endpoint: the guard must catch it while
        # actual Finn rejects the fresh retired-key challenge over live state.
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        import threading
        class Wrong(BaseHTTPRequestHandler):
            def log_message(self,*_args):pass
            def do_GET(self):
                self.send_response(200);self.send_header('Content-Length','2');self.end_headers();self.wfile.write(b'{}')
        server=ThreadingHTTPServer(('127.0.0.1',19444),Wrong)
        tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(self.root/'tls/diagnostic.crt',self.root/'tls/diagnostic.key')
        server.socket=tls.wrap_socket(server.socket,server_side=True)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        manifest=dict(self.manifest,consumer_origin='https://localhost:19444')
        os.environ['F02_CA_FILE']=str(self.root/'tls/ca.crt')
        probe=Probe(manifest)
        claims=json.loads(decode(self.access.split('.')[1]));now=int(time.time());claims.update(iat=now,nbf=now,exp=now+900)
        current=signed(claims,'sign-new',self.keys['sign-new']);old=signed(claims,'sign-old',self.keys['sign-old'])
        try:
            service=('state-new',self.keys['state-new'])
            probe.introspect(manifest['replicas'][0],current,service,label='wrong-consumer-current-control')
            probe.introspect(manifest['replicas'][0],old,service,401,label='actual-Finn-retired-control')
            try:probe.consumer(old,401,'deliberately-incorrect-consumer')
            except Blocked:pass
            else:raise RuntimeError('incorrect consumer undetected')
            assert probe.results[-1]['status']=='FAIL' and probe.results[-1]['http_status']==200
            emit('incorrect_consumer_control',status='PASS_DETECTED_EXPECTED_FAILURE',intentional_negative_control=True,cases=probe.results)
        finally:server.shutdown();server.server_close();thread.join(timeout=5)

    def run(self):
        compose('pull', 'mysql', 'redis', 'mail', timeout=300)
        compose('up', '-d', 'mysql', 'redis', 'mail')
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            try:
                if self.sql('SELECT 1;').strip() == '1':
                    break
            except RuntimeError:
                pass
            time.sleep(2)
        else:
            raise RuntimeError('isolated mysql readiness')
        for operation in [('up',), ('version',), ('check','up')]:
            result = compose('run', '--rm', '--no-deps', '--entrypoint', '/app/migrate', 'finn-a', *operation)
            emit('migration', operation=list(operation), exit_code=result.returncode)
        compose('up', '-d', 'finn-a', 'finn-b')
        self.ready('finn-a',18443)
        self.ready('finn-b',20443)
        emit('issuer_ready_before_consumer', replicas=['finn-a','finn-b'])
        compose('up', '-d', 'diagnostic')
        self.ready('diagnostic',19443)
        self.fixtures()
        for tenant in ['f02-a', 'f02-b', 'default']:
            pair, _ = self.login(tenant=tenant)
            status, _, _ = self.request('https://localhost:19443','/diagnostic/v1/access',token=pair['accessToken'],tenant='forged-header')
            self.check('signed-tenant-positive-' + tenant,status,200)
        self.phase('baseline')
        self.extended()
        final = [self.login(port) for port in [18443,20443]]
        self.old_access = final[-1][0]['accessToken']
        self.last = max(claims['iat'] for _, claims in final)
        compose('stop','-t','30','finn-a','finn-b')
        for service in ['finn-a','finn-b']:
            # ps --all is required for stopped containers.
            cid = compose('ps','--all','-q',service).stdout.decode().strip()
            state=json.loads(command(['docker','inspect',cid]).stdout)[0]['State']
            assert not state['Running']
            emit('old_issuer_stopped',service=service,container_id=cid,finished_at=state['FinishedAt'],last_old_issuance_unix=self.last)
        emit('cessation',last_old_issuance_unix=self.last,deadline_unix=self.last+930,
             provenance='final actual token+HTTP Date on each issuer, single job client, isolated network, both issuers stopped; no subsequent old issuance')
        config(self.root,self.keys,self.last)
        compose('up','-d','--force-recreate','finn-a','finn-b')
        self.ready('finn-a',18443)
        self.ready('finn-b',20443)
        emit('new_issuers_ready_before_consumer',last_old_issuance_unix=self.last)
        compose('up','-d','--force-recreate','diagnostic')
        self.ready('diagnostic',19443)
        self.phase('overlap')
        compose('restart','-t','20','finn-b','diagnostic')
        self.ready('finn-b',20443)
        self.ready('diagnostic',19443)
        self.phase('overlap',label='overlap-after-restart-same-deadline')
        while time.time() < self.last+930:
            remaining=self.last+930-time.time()
            emit('real_clock_wait',remaining_seconds=round(remaining,1),deadline_unix=self.last+930)
            time.sleep(min(30,remaining))
        self.phase('retired')
        self.incorrect_consumer_control()
        compose('restart','-t','20','finn-a','diagnostic')
        self.ready('finn-a',18443)
        self.ready('diagnostic',19443)
        self.phase('retired',label='retired-after-restart')
        config(self.root,self.keys,self.last,remove=True)
        compose('up','-d','--force-recreate','finn-a','finn-b')
        self.ready('finn-a',18443)
        self.ready('finn-b',20443)
        compose('up','-d','--force-recreate','diagnostic')
        self.ready('diagnostic',19443)
        self.phase('retired',label='retired-after-runtime-reference-removal')
        for dependency in ['mysql','redis']:
            pair,_=self.login()
            self.access=pair['accessToken']
            compose('stop','-t','20',dependency)
            emit('dependency_stopped',service=dependency)
            try:
                self.phase(dependency+'-outage',fresh=False)
            finally:
                compose('start',dependency)
                emit('dependency_restart',service=dependency)
            # Actual positive recovery, not health-only. Bounded readiness below
            # is followed by the full guarded positive matrix.
            time.sleep(10)
            self.phase('retired',label=dependency+'-restored')
        self.phase('reauth')
        from browser_rehearsal import browser
        browser(self)
        compose('stop','-t','30','finn-a','finn-b')
        compose('up','-d','--force-recreate','finn-a','finn-b',image='f02-rollback:'+self.project)
        self.ready('finn-a',18443)
        self.ready('finn-b',20443)
        emit('strict_artifact_rollback',source=ROLLBACK,retired_keys_restored=False,latest_store_state_retained=True)
        self.phase('rollback')
        browser(self)
        for tenant in ['f02-a','f02-b','default']:
            pair,_=self.login(tenant=tenant)
            status,_,_=self.request('https://localhost:18443','/api/v1/auth/logout-all',body={},token=pair['accessToken'],tenant=tenant)
            self.check('owned-session-logout-all-'+tenant,status,200)
            status,_,_=self.request('https://localhost:18443','/api/v1/auth/me',token=pair['accessToken'],tenant=tenant)
            self.check('owned-session-inactive-'+tenant,status,401)
        emit('limitations',historical_legacy_browser='NOT_RUN_SYNTHETIC_NEGATIVES_ONLY',actual_jake='NOT_CERTIFIED_J02',
             mfa_passkey_reset_device='NOT_RUN',render_pilot='NOT_RUN',independent_acceptance='PENDING')
        emit('rehearsal_result',status='EXECUTED_MATRIX_PASS_ACCEPTANCE_PENDING',cleanup='project cleanup follows in always step')


def cleanup():
    project, root = identity()
    if not root.exists():
        emit('cleanup',status='NOT_REQUIRED_NO_RUNTIME_ROOT')
        return
    result=compose('down','--volumes','--remove-orphans',check=False)
    remaining=command(['docker','ps','-aq','--filter','label=com.docker.compose.project='+project]).stdout.decode().split()
    volumes=command(['docker','volume','ls','-q','--filter','label=com.docker.compose.project='+project]).stdout.decode().split()
    networks=command(['docker','network','ls','-q','--filter','label=com.docker.compose.project='+project]).stdout.decode().split()
    emit('cleanup',status='PASS' if result.returncode==0 and not (remaining or volumes or networks) else 'FAIL',
         project=project,containers_remaining=len(remaining),volumes_remaining=len(volumes),networks_remaining=len(networks),
         session_revocation_claim='only observed API acknowledgments; task store removal destroys remaining synthetic state')
    if result.returncode or remaining or volumes or networks:
        raise RuntimeError('cleanup incomplete')
    # identity() verified this exact absolute child of RUNNER_TEMP; never a repo.
    shutil.rmtree(root)
    emit('private_file_cleanup',status='PASS',runtime_root_removed=not root.exists(),secure_erasure_claim=False)


if __name__ == '__main__':
    operation=sys.argv[1]
    try:
        if operation=='prepare': prepare()
        elif operation=='run': Rehearsal().run()
        elif operation=='cleanup': cleanup()
        else: raise ValueError('operation')
    except Exception as error:
        emit('operation_failed',operation=operation,error_type=type(error).__name__,
             reason=str(error) if type(error) is RuntimeError else 'details withheld',remaining_cases='NOT_RUN',acceptance='BLOCKED')
        sys.exit(1)
