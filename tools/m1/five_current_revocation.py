"""PREPARED ONLY: canonical BUSY prevented execution; no cache-proof/admission claim."""
from pathlib import Path
import ctypes,contextlib,base64,hashlib,json,os,time,struct,datetime
import crl_der as D
import support as S
TARGET_LEAF='2d7ffce2c256016291b67285456aa8da779d711bbf8e6b85c212a157ddfbe77e'
TARGET_ISSUER='e8e95f0733a55e8bad7be0a1413ee23c51fcea64b3c8fa6a786935fddcc71961'
ROOT='df545bf919a2439c36983b54cdfc903dfa4f37d3996d8d84b4c31eec6f3c163e'
class Blob(ctypes.Structure):_fields_=[('size',ctypes.c_uint),('data',ctypes.c_void_p)]
class CC(ctypes.Structure):_fields_=[('encoding',ctypes.c_uint),('data',ctypes.c_void_p),('size',ctypes.c_uint),('info',ctypes.c_void_p),('store',ctypes.c_void_p)]
class Array(ctypes.Structure):_fields_=[('count',ctypes.c_uint),('blobs',ctypes.c_void_p)]
class Aux(ctypes.Structure):_fields_=[('size',ctypes.c_uint),('last',ctypes.c_void_p),('maxBytes',ctypes.c_uint),('preFetch',ctypes.c_void_p),('flush',ctypes.c_void_p),('response',ctypes.c_void_p),('prefix',ctypes.c_void_p),('resync',ctypes.c_void_p),('proxy',ctypes.c_int),('httpStatus',ctypes.c_uint),('errorHeaders',ctypes.c_void_p),('errorContent',ctypes.c_void_p)]
class IO(ctypes.Structure):_fields_=[(n,ctypes.c_ulonglong) for n in ('reads','writes','other','readBytes','writeBytes','otherBytes')]
class Native:
 def __init__(self):
  self.c=ctypes.WinDLL('crypt32',use_last_error=True);self.n=ctypes.WinDLL('cryptnet',use_last_error=True);self.k=ctypes.WinDLL('kernel32',use_last_error=True)
  self.c.CryptQueryObject.argtypes=[ctypes.c_uint,ctypes.c_void_p,ctypes.c_uint,ctypes.c_uint,ctypes.c_uint]+[ctypes.c_void_p]*6;self.c.CryptQueryObject.restype=ctypes.c_int
  self.c.CertEnumCertificatesInStore.argtypes=[ctypes.c_void_p,ctypes.c_void_p];self.c.CertEnumCertificatesInStore.restype=ctypes.c_void_p
  for n in ('CertFreeCertificateContext','CertFreeCRLContext','CryptMsgClose'):
   getattr(self.c,n).argtypes=[ctypes.c_void_p];getattr(self.c,n).restype=ctypes.c_int
  self.c.CertCloseStore.argtypes=[ctypes.c_void_p,ctypes.c_uint]
  for n in ('CertCreateCertificateContext','CertCreateCRLContext'):
   getattr(self.c,n).argtypes=[ctypes.c_uint,ctypes.c_void_p,ctypes.c_uint];getattr(self.c,n).restype=ctypes.c_void_p
  self.c.CryptVerifyCertificateSignatureEx.argtypes=[ctypes.c_void_p,ctypes.c_uint,ctypes.c_uint,ctypes.c_void_p,ctypes.c_uint,ctypes.c_void_p,ctypes.c_uint,ctypes.c_void_p];self.c.CryptVerifyCertificateSignatureEx.restype=ctypes.c_int
  self.c.CertFindCertificateInCRL.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_uint,ctypes.c_void_p,ctypes.c_void_p];self.c.CertFindCertificateInCRL.restype=ctypes.c_int
  self.n.CryptRetrieveObjectByUrlW.argtypes=[ctypes.c_wchar_p,ctypes.c_void_p,ctypes.c_uint,ctypes.c_uint,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,ctypes.POINTER(Aux)];self.n.CryptRetrieveObjectByUrlW.restype=ctypes.c_int
  self.c.CryptMemFree.argtypes=[ctypes.c_void_p]
  self.k.GetCurrentProcess.restype=ctypes.c_void_p;self.k.GetProcessIoCounters.argtypes=[ctypes.c_void_p,ctypes.POINTER(IO)]
 def reads(self):
  x=IO();D.need(self.k.GetProcessIoCounters(self.k.GetCurrentProcess(),ctypes.byref(x)),'IO_COUNTER');return x.readBytes
 def context(self,b,crl=False):
  buf=ctypes.create_string_buffer(b);h=(self.c.CertCreateCRLContext if crl else self.c.CertCreateCertificateContext)(1,buf,len(b));D.need(h,'DECODE_CONTEXT');return h
 def signed(self,b,issuer):
  buf=ctypes.create_string_buffer(b);blob=Blob(len(b),ctypes.cast(buf,ctypes.c_void_p));return bool(self.c.CryptVerifyCertificateSignatureEx(None,1,1,ctypes.byref(blob),2,issuer,0,None))
 def listed(self,cert,crl):
  e=ctypes.c_void_p();D.need(self.c.CertFindCertificateInCRL(cert,crl,0,None,ctypes.byref(e)),'NATIVE_SERIAL_SEARCH');return bool(e.value)
 def catalog_certs(self,path):
  # Exact previously observed catalog, public certificate metadata only. No WVT
  # signature replay or import, no native/library execution from this catalog.
  from six_held_readers import _INPUT_FILE_INFO
  k=self.k;k.CreateFileW.argtypes=[ctypes.c_wchar_p,ctypes.c_uint,ctypes.c_uint,ctypes.c_void_p,ctypes.c_uint,ctypes.c_uint,ctypes.c_void_p];k.CreateFileW.restype=ctypes.c_void_p
  k.GetFileInformationByHandle.argtypes=[ctypes.c_void_p,ctypes.POINTER(_INPUT_FILE_INFO)];k.CloseHandle.argtypes=[ctypes.c_void_p]
  h=k.CreateFileW(path,0x80000000,1,None,3,0x200000,None);D.need(h not in (None,ctypes.c_void_p(-1).value),'EXACT_CATALOG_OPEN')
  store=ctypes.c_void_p();msg=ctypes.c_void_p();current=None;found={}
  try:
   before=_INPUT_FILE_INFO();D.need(k.GetFileInformationByHandle(h,ctypes.byref(before)) and not before.attrs&0x410 and ((before.sizeHigh<<32)|before.sizeLow)<=16777216,'CATALOG_METADATA_CAP')
   name=ctypes.create_unicode_buffer(path);enc=ctypes.c_uint();content=ctypes.c_uint();fmt=ctypes.c_uint()
   D.need(self.c.CryptQueryObject(1,ctypes.cast(name,ctypes.c_void_p),256,2,0,ctypes.byref(enc),ctypes.byref(content),ctypes.byref(fmt),ctypes.byref(store),ctypes.byref(msg),None),'CATALOG_CERTIFICATE_METADATA')
   for i in range(12):
    current=self.c.CertEnumCertificatesInStore(store,current)
    if not current:break
    c=CC.from_address(current);D.need(0<c.size<=32768,'PUBLIC_CERT_CAP');b=ctypes.string_at(c.data,c.size);digest=D.sha(b)
    if digest in (TARGET_LEAF,TARGET_ISSUER):found[digest]=b
    if len(found)==2:break
   after=_INPUT_FILE_INFO();D.need(k.GetFileInformationByHandle(h,ctypes.byref(after)),'CATALOG_HELD_METADATA_AFTER')
   def identity(x):return (x.attrs,x.created.dwHighDateTime,x.created.dwLowDateTime,x.written.dwHighDateTime,x.written.dwLowDateTime,x.volume,x.sizeHigh,x.sizeLow,x.links,x.indexHigh,x.indexLow)
   D.need(identity(before)==identity(after),'CATALOG_HELD_METADATA_CHANGED')
   D.need(len(found)==2,'EXACT_CATALOG_CERTIFICATE_NOT_EXPOSED');return found
  finally:
   if current:self.c.CertFreeCertificateContext(current)
   if msg:self.c.CryptMsgClose(msg)
   if store:self.c.CertCloseStore(store,0)
   k.CloseHandle(h)
 def cached(self,url):
  D.need(url.startswith(('http://','https://')) and len(url)<=2048,'SIGNED_CDP_URL_SCOPE')
  out=ctypes.c_void_p();a=Aux();a.size=ctypes.sizeof(a);a.maxBytes=1048576
  ok=self.n.CryptRetrieveObjectByUrlW(url,None,6,2000,ctypes.byref(out),None,None,None,ctypes.byref(a));err=ctypes.get_last_error()
  if not ok:return None,err
  try:
   D.need(out.value,'CACHE_RAW_POINTER');arr=Array.from_address(out.value);D.need(arr.count==1,'ONE_ARTIFACT_PER_RETRIEVAL');blob=Blob.from_address(arr.blobs);D.need(0<blob.size<=1048576,'ARTIFACT_1M_CAP');return ctypes.string_at(blob.data,blob.size),0
  finally:
   if out:self.c.CryptMemFree(out)
def extensions(b):
 for n in D.children(b,D.children(b,D.tlv(b))[0]):
  if n[0]==163:return D.extensions(b,D.children(b,n)[0])
 return {}
def issuer_can_sign(c):
 ex=extensions(c['der']);D.need('2.5.29.15' in ex and '2.5.29.19' in ex,'ISSUER_KEY_USAGE')
 n=D.tlv(ex['2.5.29.15']);v=D.value(ex['2.5.29.15'],n);D.need(n[0]==3 and len(v)>=2 and v[1]&6==6,'ISSUER_CRL_SIGN');v=D.children(ex['2.5.29.19'],D.tlv(ex['2.5.29.19']));D.need(v and D.value(ex['2.5.29.19'],v[0])==b'\xff','ISSUER_CA')
def crl_entries(data):
 outer=D.children(data,D.tlv(data));fields=D.children(data,outer[0]);off=1 if fields[0][0]==2 else 0;count=0
 for node in fields[off+4:]:
  if node[0]!=48:continue
  for entry in D.children(data,node):
   vals=D.children(data,entry);D.need(2<=len(vals)<=3 and vals[0][0]==2 and vals[1][0] in (23,24),'CRL_ENTRY_FRAME');serial=D.value(data,vals[0]);D.need(0<len(serial)<=21 and not serial[0]&128,'CRL_ENTRY_SERIAL')
   D.der_time(data,vals[1])
   if len(vals)==3:
    critical=set();ext=D.extensions(data,vals[2],critical);D.need(not critical,'CRL_ENTRY_CRITICAL_UNKNOWN');D.need('2.5.29.29' not in ext,'INDIRECT_CRL_ENTRY_UNSUPPORTED')
    if '2.5.29.21' in ext:
     r=ext['2.5.29.21'];n=D.tlv(r);D.need(n[0]==10 and n[3]==len(r) and len(D.value(r,n))==1 and D.value(r,n)[0] in (0,1,2,3,4,5,6,9,10),'CRL_REASON_UNSUPPORTED_OR_DELTA_REMOVE')
   count+=1
 return count

def entry(f):
 start=time.monotonic();end=min(f['window']['deadlineUnix']-30,f['phaseDeadlineUnix'],time.time()+20)
 def clock():D.need(time.time()<end and time.monotonic()-start<20,'REVOCATION_ROLE_ABSOLUTE_CLOCK')
 action=S.read(f['revocationActionPath']);D.need(S.sha(f['revocationActionPath'])==f['revocationActionSHA256'],'REVOCATION_ACTION')
 result={'schema':'tail11-five-current-crl-artifacts/v1','status':'HOLD','artifacts':[],'records':[],'cacheRequests':[],'networkRequests':0,'clockTrustStoreCacheOrProtectionChanged':False,'healthyTestsReplayed':0,'timestampValidationsReplayed':0,'nonce':f['nonce'],'actionSHA256':f['revocationActionSHA256']}
 out=Path(f['receiptPath']).parent;native=Native();io=native.reads();contexts=[]
 try:
  for key in ('gap','timestamps','catalogEvidence','rootDER'):D.need(S.sha(action[key]['path'])==action[key]['sha256'],'PRIOR_EXACT_METADATA_HASH')
  old=S.read(action['timestamps']['path']);gap=S.read(action['gap']['path']);prior=S.read(action['catalogEvidence']['path'])
  D.need(action['exactCertificateOnlyCatalogPath']==next(r['catalogPath'] for r in prior['records'] if r['exactPath'].lower().endswith('dsparse.dll')),'EXACT_PRIOR_CATALOG_PATH')
  raw=native.catalog_certs(action['exactCertificateOnlyCatalogPath']);root=S.raw(action['rootDER']['path'],32768);D.need(D.sha(root)==ROOT,'EXACT_EXISTING_ROOT');raw[ROOT]=root
  for row in old['records']:
   D.need(row['signerAtTimestamp']['valid'] and row['timestampAtTimestamp']['valid'] and row['originalCurrentChainValid'] is False,'REUSE_AUTHENTICATED_TIMESTAMP_PROOF')
   for b64 in row['timestamps'][0]['chainDER']:
    der=base64.b64decode(b64,validate=True);D.need(len(der)<=32768,'PRIOR_TIMESTAMP_CERT_CAP');raw[D.sha(der)]=der
  certs={h:D.certificate(b) for h,b in raw.items()};targets=[r['certificate'] for r in gap['distinctNonrootCertificates']];D.need(len(targets)==5 and all(r['sha256'] in certs for r in targets),'EXACT_FIVE_PUBLIC_CERTIFICATES')
  requests={};artifactBytes=0;signatureCache={};cryptContexts={}
  for h,c in certs.items():cryptContexts[h]=native.context(c['der']);contexts.append(cryptContexts[h])
  for target in targets:
   clock();h=target['sha256'];c=certs[h];record={'certificateSHA256':h,'serial':target['serial'],'status':'HOLD','attempts':[]};result['records'].append(record)
   try:
    serial=D.value(c['serialDER'],D.tlv(c['serialDER'])).hex().lstrip('0').upper();D.need(serial==target['serial'].lstrip('0').upper(),'EXACT_CERT_SERIAL')
    issuers=[ic for ic in certs.values() if ic['subjectDER']==c['issuerDER'] and ic['SKI']==c['AKI'] and ic['SKI']];D.need(len(issuers)==1,'EXACT_ISSUER_NAME_KEY');issuer=issuers[0];issuer_can_sign(issuer)
    uris=D.cert_dp_uris(extensions(c['der']));D.need(uris,'CERTIFICATE_HAS_NO_CDP')
    record['issuerSHA256']=issuer['sha256'];record['certificateCDPURLs']=[u.decode('ascii') for u in uris]
    for urlb in uris:
     clock();url=urlb.decode('ascii')
     if url not in requests:
      D.need(len(requests)<5,'CACHE_REQUEST_COUNT_CAP');body,err=native.cached(url);requests[url]=(body,err);result['cacheRequests'].append({'url':url,'flags':6,'maximumBytes':1048576,'cacheOnly':True,'success':body is not None,'error':err})
      if body is not None:
       D.need(len(result['artifacts'])<5 and artifactBytes+len(body)<=5242880,'FIVE_ARTIFACT_5M_CAP');artifactBytes+=len(body)
       fp=out/('current-revocation-artifact-'+str(len(result['artifacts']))+'.der')
       with fp.open('xb') as w:w.write(body);w.flush();os.fsync(w.fileno())
       result['artifacts'].append({'path':str(fp),'bytes':len(body),'sha256':D.sha(body),'sourceSignedCDPURL':url})
     body,err=requests[url]
     if body is None:record['attempts'].append({'url':url,'code':'EXACT_CACHE_OBJECT_UNAVAILABLE','nativeError':err});continue
     try:
      now=int(time.time());rc=D.crl_data(body,now);D.need(rc['thisUpdate']<=now<rc['nextUpdate'],'CURRENT_CRL_INTERVAL');D.need(rc['issuerDER']==issuer['subjectDER'] and rc['AKI']==issuer['SKI'],'CRL_ISSUER_KEY_BINDING')
      D.need(not rc['scopeURIs'] or bool(set(uris)&set(rc['scopeURIs'])),'SIGNED_CDP_IDP_SCOPE')
      outer=D.children(body,D.tlv(body));tbs=D.children(body,outer[0]);off=1 if tbs[0][0]==2 else 0;D.need(D.raw(body,tbs[off])==D.raw(body,outer[1]),'CRL_ALGORITHM_BINDING');alg=D.oid(body,D.children(body,outer[1])[0]);D.need(alg in ('1.2.840.113549.1.1.11','1.2.840.113549.1.1.12'),'CRL_STRONG_ALGORITHM')
      key=(rc['sha256'],issuer['sha256'])
      if key not in signatureCache:
       crl_entries(body);D.need(native.signed(body,cryptContexts[issuer['sha256']]),'CRL_NATIVE_SIGNATURE');signatureCache[key]=True
      ch=native.context(body,True)
      try:revoked=native.listed(cryptContexts[h],ch)
      finally:native.c.CertFreeCRLContext(ch)
      D.need(not revoked,'CERTIFICATE_REVOKED_IN_CURRENT_CRL');record.update(status='PASS_EXACT_CURRENT_SIGNED_CRL_NONREVOCATION',crlSHA256=rc['sha256'],thisUpdateUnix=rc['thisUpdate'],nextUpdateUnix=rc['nextUpdate'],verifiedAtUnix=now,serialRevoked=False,directAllReasons=True,sourceSignedCDPURL=url);break
     except (D.Hold,S.Hold) as e:record['attempts'].append({'url':url,'code':str(e)})
    if record['status']=='HOLD':record['code']='CURRENT_SIGNED_REVOCATION_ARTIFACT_NOT_ACCEPTED'
   except (D.Hold,S.Hold) as e:record['code']=str(e)
   D.need(native.reads()-io<=67108864,'REVOCATION_IO64M');clock()
  result['artifactBytes']=artifactBytes;result['allFiveAccepted']=len(result['records'])==5 and all(x['status'].startswith('PASS_') for x in result['records'])
  result['status']='PASS_FIVE_CURRENT_SIGNED_REVOCATION_PROOFS' if result['allFiveAccepted'] else 'HOLD_FIVE_CURRENT_REVOCATION_PROOFS_NO_SSH'
 except Exception as e:
  result.update(code=str(e) if isinstance(e,(D.Hold,S.Hold)) else 'REVOCATION_CAPTURE_HOLD',exceptionType=type(e).__name__)
 finally:
  for h in contexts:native.c.CertFreeCertificateContext(h)
  result['nativeReadBytes']=native.reads()-io;result['phaseSeconds']=time.monotonic()-start;result['artifactBytes']=sum(x['bytes'] for x in result['artifacts'])
  if result['nativeReadBytes']>67108864:result.update(status='HOLD',code='REVOCATION_IO64M',allFiveAccepted=False)
  S.fresh(out/'five-current-revocation-proof.json',result,cap=262144)
 return result
