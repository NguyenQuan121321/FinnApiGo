"""Real Chrome/WebDriver ceremony against actual Finn and diagnostic HTTPS.

No HAR/screenshots, credential persistence, TLS ignore flags or production UI.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import urllib.error
import urllib.request

from rehearsal import decode, signed


SCRIPT = r"""
const [accounts, password, legacy] = arguments; const done=arguments[arguments.length-1];
(async()=>{
 const results=[];
 function check(name,actual,expected){results.push({case:name,actual,expected});if(actual!==expected)throw new Error(name);}
 const call=(url,options={})=>fetch(url,{cache:'no-store',credentials:'omit',...options});
 let pair=null, tenant='f02-a', refreshUnknown=false;
 const headers=()=>({'Content-Type':'application/json','X-Tenant-ID':tenant});
 try {
  const old=await call('/diagnostic/v1/access',{headers:{Authorization:'Bearer '+legacy}});
  check('synthetic-legacy-reauth',old.status,401);
  for(tenant of accounts){
   const login=await call('https://localhost:18443/api/v1/auth/login',{method:'POST',headers:headers(),body:JSON.stringify({email:tenant+'@example.invalid',password})});
   check('browser-login-'+tenant,login.status,200);
   pair=(await login.json()).data;
   if(!pair || typeof pair.accessToken!=='string' || typeof pair.refreshToken!=='string')throw new Error('shape');
   const access=await call('/diagnostic/v1/access',{headers:{Authorization:'Bearer '+pair.accessToken,'X-Tenant-ID':'forged-header'}});
   check('browser-consumer-'+tenant,access.status,200);
   refreshUnknown=true;
   const refreshed=await call('https://localhost:18443/api/v1/auth/refresh-token',{method:'POST',headers:headers(),body:JSON.stringify({refreshToken:pair.refreshToken})});
   check('browser-refresh-'+tenant,refreshed.status,200);
   const next=(await refreshed.json()).data;
   if(!next || typeof next.accessToken!=='string' || typeof next.refreshToken!=='string')throw new Error('refresh-shape');
   const verify=await call('/diagnostic/v1/access',{headers:{Authorization:'Bearer '+next.accessToken}});
   check('browser-refreshed-consumer-'+tenant,verify.status,200);
   pair=next; refreshUnknown=false;
   const logout=await call('https://localhost:18443/api/v1/auth/logout',{method:'POST',headers:{...headers(),Authorization:'Bearer '+pair.accessToken},body:JSON.stringify({refreshToken:pair.refreshToken})});
   check('browser-logout-'+tenant,logout.status,200);
   const revoked=await call('/diagnostic/v1/access',{headers:{Authorization:'Bearer '+pair.accessToken}});
   check('browser-after-logout-'+tenant,revoked.status,401);
   pair=null;
   check('localStorage-empty-'+tenant,localStorage.length,0);
   check('sessionStorage-empty-'+tenant,sessionStorage.length,0);
   check('cookies-empty-'+tenant,document.cookie,'');
  }
  window.f02Memory=null;
  done({status:'PASS_DIAGNOSTIC_BROWSER_ONLY',results,cleanup_unresolved:false});
 } catch(e){
  let acknowledged=false;
  if(pair){try{const r=await call('https://localhost:18443/api/v1/auth/logout',{method:'POST',headers:{...headers(),Authorization:'Bearer '+pair.accessToken},body:JSON.stringify({refreshToken:pair.refreshToken})});acknowledged=r.status===200;}catch{}}
  pair=null;
  done({status:'FAIL',results,cleanup_unresolved:refreshUnknown||!acknowledged});
 }
})().catch(()=>done({status:'FAIL',cleanup_unresolved:true}));
"""


def browser(rehearsal):
    from actions_rehearsal import command, emit, mask
    root = rehearsal.root
    home = root / 'browser-home'
    nss = home / '.pki/nssdb'
    nss.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, HOME=str(home))
    if not (nss / 'cert9.db').exists():
        command(['certutil','-N','--empty-password','-d','sql:'+str(nss)],env=env)
        command(['certutil','-A','-n',rehearsal.project,'-t','C,,','-d','sql:'+str(nss),'-i',str(root/'tls/ca.crt')],env=env)
    driver = shutil.which('chromedriver')
    chrome = shutil.which('google-chrome')
    if not driver or not chrome:
        emit('browser',status='BLOCKED_NOT_RUN',reason='installed Chrome/driver unavailable')
        raise RuntimeError('browser prerequisite')
    process = subprocess.Popen([driver,'--port=19515','--allowed-ips=127.0.0.1'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    session = None
    http = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def wd(method, path, value=None):
        request=urllib.request.Request('http://127.0.0.1:19515'+path,
            data=json.dumps(value).encode() if value is not None else None, method=method,
            headers={'Content-Type':'application/json'})
        with http.open(request,timeout=75) as response:
            body=response.read(65537)
            if len(body)>65536:raise RuntimeError('webdriver response bound')
            result=json.loads(body)['value']
            if isinstance(result,dict) and 'error' in result:raise RuntimeError('webdriver failure')
            return result
    try:
        for _ in range(30):
            try:
                wd('GET','/status')
                break
            except (OSError,urllib.error.URLError):time.sleep(1)
        capabilities=wd('POST','/session',{'capabilities':{'alwaysMatch':{'browserName':'chrome','acceptInsecureCerts':False,
            'goog:chromeOptions':{'binary':chrome,'args':['--headless=new','--disable-dev-shm-usage','--no-proxy-server','--user-data-dir='+str(root/'browser-profile')]}}}})
        session=capabilities['sessionId']
        emit('browser_identity',browser_version=capabilities['capabilities']['browserVersion'],accept_insecure_certs=capabilities['capabilities'].get('acceptInsecureCerts'))
        wd('POST','/session/'+session+'/timeouts',{'script':65000})
        wd('POST','/session/'+session+'/url',{'url':'https://localhost:19443/browser'})
        claims=json.loads(decode(rehearsal.access.split('.')[1]));claims.pop('contract_ver')
        legacy=mask(signed(claims,'sign-new',rehearsal.keys['sign-new']))
        result=wd('POST','/session/'+session+'/execute/async',{'script':SCRIPT,'args':[['f02-a','f02-b','default'],rehearsal.keys['password'],legacy]})
        emit('browser_matrix',report=result,boundary='actual Finn + diagnostic UI; synthetic legacy shape; no Jake/MFA certification')
        if result.get('status')!='PASS_DIAGNOSTIC_BROWSER_ONLY' or result.get('cleanup_unresolved') is not False:raise RuntimeError('browser matrix failed')
        wd('POST','/session/'+session+'/refresh',{})
        storage=wd('POST','/session/'+session+'/execute/sync',{'script':'return {local:localStorage.length,session:sessionStorage.length,cookies:document.cookie,memory:typeof window.f02Memory};','args':[]})
        if storage!={'local':0,'session':0,'cookies':'','memory':'undefined'}:raise RuntimeError('browser persistence')
        emit('browser_reload',status='PASS',storage_empty=True,memory_lost=True)
    finally:
        if session:
            try:wd('DELETE','/session/'+session)
            except Exception:emit('browser_session_cleanup',status='UNRESOLVED_DRIVER_CLEANUP')
        process.terminate()
        try:process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill();process.wait(timeout=5)
