"""Actual HTTPS service tests with a fixture upstream, not staging acceptance."""
import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import ssl
import threading
import time
import unittest
import urllib.error
import urllib.request

from diagnostic_consumer import Consumer, serve
from rehearsal import signed


class DiagnosticHTTPS(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(os.environ['F02_ROOT'])
        cls.keys = json.loads((cls.root / 'private-keys.json').read_text())
        cls.mode = 'valid'
        cls.claims = {'contract_ver':1,'iss':'finnapigo','aud':['finnapigo-api','jakeai-service'],'sub':'1','uid':1,
            'type':'access','tid':'f02-a','iat':int(time.time()),'nbf':int(time.time()),'exp':int(time.time())+900,
            'jti':'fixture-jti','sid':'fixture-sid','pwdver':0,'auth_epoch':0,'perms':['chat:read']}

        class Upstream(BaseHTTPRequestHandler):
            def log_message(self,*_args):pass
            def do_POST(self):
                self.rfile.read(int(self.headers['Content-Length']))
                data={name:cls.claims[name] for name in ['contract_ver','tid','sub','sid','jti','pwdver','auth_epoch']}
                data.update(active=True,checked_at=int(time.time()),max_cache_seconds=15)
                status=200
                if self.headers.get('Authorization')!='Bearer '+cls.keys['state-old']:
                    status=401;data={'error':'invalid_service_credential'}
                elif cls.mode=='stale':data['checked_at']-=20
                elif cls.mode=='mismatch':data['sid']='other'
                elif cls.mode=='inactive':status=401;data={'active':False}
                elif cls.mode=='error':status=503;data={'error':'unavailable'}
                elif cls.mode=='redirect':status=302;data={}
                elif cls.mode=='malformed':data={'active':True}
                body=json.dumps(data).encode()
                self.send_response(status)
                if status==302:self.send_header('Location','https://localhost:1/forbidden')
                self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        cls.up=ThreadingHTTPServer(('127.0.0.1',0),Upstream)
        tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);tls.load_cert_chain(cls.root/'tls/finn-a.crt',cls.root/'tls/finn-a.key')
        cls.up.socket=tls.wrap_socket(cls.up.socket,server_side=True)
        cls.thread=threading.Thread(target=cls.up.serve_forever,daemon=True);cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.up.shutdown();cls.up.server_close();cls.thread.join(timeout=5)

    def setUp(self):
        type(self).mode='valid'
        self.config={'issuer_origin':'https://localhost:'+str(self.up.server_port),'keys':{'sign-old':self.keys['sign-old']},
            'service_kid':'state-old','service_secret':self.keys['state-old'],'tenants':['f02-a'],
            'ca_file':str(self.root/'tls/ca.crt'),'cert_file':str(self.root/'tls/diagnostic.crt'),'key_file':str(self.root/'tls/diagnostic.key')}

    def token(self,kid='sign-old',claims=None):return signed(claims or self.claims,kid,self.keys[kid])

    def test_real_tls_consumer_and_upstream(self):
        server=serve(self.config,('127.0.0.1',0));thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        context=ssl.create_default_context(cafile=self.config['ca_file']);context.verify_flags|=ssl.VERIFY_X509_STRICT
        http=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=context))
        try:
            request=urllib.request.Request('https://localhost:'+str(server.server_port)+'/diagnostic/v1/access',headers={'Authorization':'Bearer '+self.token()})
            with http.open(request,timeout=5) as response:self.assertEqual(response.code,200)
            with self.assertRaises(urllib.error.URLError):
                urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request,timeout=5)
        finally:server.shutdown();server.server_close();thread.join(timeout=5)

    def test_state_error_is_never_active(self):
        consumer=Consumer(self.config)
        for mode in ['stale','mismatch','error','redirect','malformed']:
            with self.subTest(mode=mode):
                type(self).mode=mode;self.assertEqual(consumer.check(self.token()),503)
        type(self).mode='inactive';self.assertEqual(consumer.check(self.token()),401)
        type(self).mode='valid';self.assertEqual(consumer.check(self.token()),200)

    def test_service_auth_failure_and_upstream_tls_failure(self):
        config=copy.deepcopy(self.config);config['service_secret']=self.keys['state-new']
        self.assertEqual(Consumer(config).check(self.token()),503)
        config=copy.deepcopy(self.config);config['ca_file']=ssl.get_default_verify_paths().cafile
        self.assertEqual(Consumer(config).check(self.token()),503)

    def test_retired_previous_key_even_when_upstream_accepts(self):
        config=copy.deepcopy(self.config);last=int(time.time())-931
        config.update(keys={'sign-old':self.keys['sign-old'],'sign-new':self.keys['sign-new']},previous_kid='sign-old',last_old_issuance_unix=last,retired={'sign-old':last+930})
        consumer=Consumer(config)
        self.assertEqual(consumer.check(self.token()),401)
        self.assertEqual(consumer.check(self.token('sign-new')),200)

    def test_missing_claims_and_wrong_purpose(self):
        consumer=Consumer(self.config)
        for field in self.claims:
            claims=dict(self.claims);claims.pop(field)
            with self.subTest(field=field):self.assertEqual(consumer.check(self.token(claims=claims)),401)
        for purpose in ['reset','sudo','service','obo']:
            self.assertEqual(consumer.check(self.token(claims=dict(self.claims,type=purpose))),401)

    def test_browser_preflight_is_exact_origin_and_method_only(self):
        config=dict(self.config,browser_origin='https://localhost:18443')
        server=serve(config,('127.0.0.1',0));thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        http=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=config['ca_file'])))
        try:
            for origin,method,expected in [('https://localhost:18443','GET',204),('https://other.invalid','GET',403),('https://localhost:18443','POST',403)]:
                request=urllib.request.Request('https://localhost:'+str(server.server_port)+'/diagnostic/v1/access',method='OPTIONS',headers={'Origin':origin,'Access-Control-Request-Method':method})
                try:response=http.open(request,timeout=5)
                except urllib.error.HTTPError as error:response=error
                with response:
                    self.assertEqual(response.code,expected)
                    self.assertIsNone(response.headers.get('Access-Control-Allow-Credentials'))
                    self.assertEqual(response.headers.get('Access-Control-Allow-Origin'),origin if expected==204 else None)
        finally:server.shutdown();server.server_close();thread.join(timeout=5)


if __name__=='__main__':unittest.main()
