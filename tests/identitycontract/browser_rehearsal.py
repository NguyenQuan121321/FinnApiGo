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
const [accounts, password, legacy, finn, consumer] = arguments; const done=arguments[arguments.length-1];
(async()=>{
 const results=[];
 function check(name,actual,expected){results.push({case:name,actual,expected});if(actual!==expected)throw new Error(name);}
 const call=(url,options={})=>fetch(url,{cache:'no-store',credentials:'omit',...options});
 const consumerCall=(token,forged=false)=>new Promise((resolve,reject)=>{
  const target=window.f02Diagnostic, id=crypto.randomUUID();
  const receive=event=>{if(event.origin===consumer && event.source===target && event.data?.type==='f02-result' && event.data.id===id){clearTimeout(timer);removeEventListener('message',receive);resolve({status:event.data.status});}};
  const timer=setTimeout(()=>{removeEventListener('message',receive);reject(new Error('consumer message timeout'));},10000);
  addEventListener('message',receive);
  target.postMessage({type:'f02-request',id,token,forged},consumer);
 });
 let pair=null, tenant='f02-a', refreshUnknown=false;
 const headers=()=>({'Content-Type':'application/json','X-Tenant-ID':tenant});
 try {
  const old=await consumerCall(legacy);
  check('synthetic-legacy-reauth',old.status,401);
  for(tenant of accounts){
   const login=await call(finn+'/api/v1/auth/login',{method:'POST',headers:headers(),body:JSON.stringify({email:tenant+'@example.invalid',password})});
   check('browser-login-'+tenant,login.status,200);
   pair=(await login.json()).data;
   if(!pair || typeof pair.accessToken!=='string' || typeof pair.refreshToken!=='string')throw new Error('shape');
   check('authenticated-localStorage-empty-'+tenant,localStorage.length,0);
   check('authenticated-sessionStorage-empty-'+tenant,sessionStorage.length,0);
   check('authenticated-cookies-empty-'+tenant,document.cookie==='',true);
   const access=await consumerCall(pair.accessToken,true);
   check('browser-consumer-'+tenant,access.status,200);
   refreshUnknown=true;
   const refreshed=await call(finn+'/api/v1/auth/refresh-token',{method:'POST',headers:headers(),body:JSON.stringify({refreshToken:pair.refreshToken})});
   check('browser-refresh-'+tenant,refreshed.status,200);
   const next=(await refreshed.json()).data;
   if(!next || typeof next.accessToken!=='string' || typeof next.refreshToken!=='string')throw new Error('refresh-shape');
   const verify=await consumerCall(next.accessToken);
   check('browser-refreshed-consumer-'+tenant,verify.status,200);
   pair=next; refreshUnknown=false;
   check('refreshed-localStorage-empty-'+tenant,localStorage.length,0);
   check('refreshed-sessionStorage-empty-'+tenant,sessionStorage.length,0);
   const logout=await call(finn+'/api/v1/auth/logout',{method:'POST',headers:{...headers(),Authorization:'Bearer '+pair.accessToken},body:JSON.stringify({refreshToken:pair.refreshToken})});
   check('browser-logout-'+tenant,logout.status,200);
   const revoked=await consumerCall(pair.accessToken);
   check('browser-after-logout-'+tenant,revoked.status,401);
   pair=null;
   check('localStorage-empty-'+tenant,localStorage.length,0);
   check('sessionStorage-empty-'+tenant,sessionStorage.length,0);
   check('cookies-empty-'+tenant,document.cookie==='',true);
  }
  window.f02Memory=null;
  done({status:'PASS_DIAGNOSTIC_BROWSER_ONLY',results,cleanup_unresolved:false});
 } catch(e){
  let acknowledged=false;
  if(pair){try{const r=await call(finn+'/api/v1/auth/logout',{method:'POST',headers:{...headers(),Authorization:'Bearer '+pair.accessToken},body:JSON.stringify({refreshToken:pair.refreshToken})});acknowledged=r.status===200;}catch{}}
  pair=null;
  done({status:'FAIL',results,error_type:e.name,cleanup_unresolved:refreshUnknown||!acknowledged});
 }
})().catch(()=>done({status:'FAIL',cleanup_unresolved:true}));
"""

CONSUMER_BRIDGE = r"""
const finn=arguments[0], parent=window.opener;
window.addEventListener('message',async event=>{
 if(event.origin!==finn || event.source!==parent || event.data?.type!=='f02-request')return;
 const {id,token,forged}=event.data;
 if(typeof id!=='string' || typeof token!=='string')return;
 let status=0;
 try{const headers={Authorization:'Bearer '+token};if(forged)headers['X-Tenant-ID']='forged-header';
 const response=await fetch('/diagnostic/v1/access',{cache:'no-store',credentials:'omit',headers});status=response.status;}catch{}
 parent.postMessage({type:'f02-result',id,status},finn);
});
return {opener:!!parent,storage_empty:localStorage.length===0&&sessionStorage.length===0&&document.cookie===''};
"""


def browser(rehearsal,label):
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
        # Each window uses same-origin fetch. Exact origin+source postMessage
        # handoff preserves Finn's existing CSP/CORS without an HTTP proxy.
        wd('POST','/session/'+session+'/url',{'url':rehearsal.url('finn-a')+'/healthz'})
        if not wd('POST','/session/'+session+'/execute/sync',{'script':'return location.origin===arguments[0];','args':[rehearsal.url('finn-a')]}):raise RuntimeError('browser auth origin mismatch')
        auth_window=wd('GET','/session/'+session+'/window')
        opened=wd('POST','/session/'+session+'/execute/sync',{'script':"window.f02Diagnostic=window.open(arguments[0]+'/browser',arguments[1]);return !!window.f02Diagnostic;",'args':[rehearsal.url('diagnostic'),rehearsal.project]})
        if not opened:raise RuntimeError('browser diagnostic window blocked')
        handles=wd('GET','/session/'+session+'/window/handles')
        children=[handle for handle in handles if handle!=auth_window]
        if len(children)!=1:raise RuntimeError('browser window identity')
        wd('POST','/session/'+session+'/window',{'handle':children[0]})
        wd('POST','/session/'+session+'/url',{'url':rehearsal.url('diagnostic')+'/browser'})
        bridge=wd('POST','/session/'+session+'/execute/sync',{'script':CONSUMER_BRIDGE,'args':[rehearsal.url('finn-a')]})
        if bridge!={'opener':True,'storage_empty':True}:raise RuntimeError('browser message origin setup')
        wd('POST','/session/'+session+'/window',{'handle':auth_window})
        initial=wd('POST','/session/'+session+'/execute/sync',{'script':'return {local:localStorage.length,session:sessionStorage.length,cookies:document.cookie==="",memory:typeof window.f02Memory};','args':[]})
        if initial!={'local':0,'session':0,'cookies':True,'memory':'undefined'}:raise RuntimeError('browser initial persistence')
        emit('browser_open_or_reopen',status='PASS',storage_empty=True,memory_absent=True)
        claims=json.loads(decode(rehearsal.access.split('.')[1]));claims.pop('contract_ver')
        kid='sign-old' if rehearsal.last is None else 'sign-new'
        legacy=mask(signed(claims,kid,rehearsal.keys[kid]))
        result=wd('POST','/session/'+session+'/execute/async',{'script':SCRIPT,'args':[['f02-a','f02-b','default'],rehearsal.keys['password'],legacy,rehearsal.url('finn-a'),rehearsal.url('diagnostic')]})
        emit('browser_matrix',label=label,report=result,boundary='actual Finn + diagnostic windows; exact origin/source handoff, synthetic legacy shape; no Jake/MFA certification')
        if result.get('status')!='PASS_DIAGNOSTIC_BROWSER_ONLY' or result.get('cleanup_unresolved') is not False:raise RuntimeError('browser matrix failed')
        wd('POST','/session/'+session+'/refresh',{})
        storage=wd('POST','/session/'+session+'/execute/sync',{'script':'return {local:localStorage.length,session:sessionStorage.length,cookies:document.cookie==="",memory:typeof window.f02Memory};','args':[]})
        if storage!={'local':0,'session':0,'cookies':True,'memory':'undefined'}:raise RuntimeError('browser persistence')
        emit('browser_reload',status='PASS',storage_empty=True,memory_lost=True)
    finally:
        if session:
            try:wd('DELETE','/session/'+session)
            except Exception:emit('browser_session_cleanup',status='UNRESOLVED_DRIVER_CLEANUP')
        process.terminate()
        try:process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill();process.wait(timeout=5)
