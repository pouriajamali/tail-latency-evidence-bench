"""Exactly three approved plain-HTTP CDP GETs, no redirect/normalization/retry."""
from pathlib import Path
import argparse,ctypes,hashlib,json,os,subprocess,time
import _winapi
import support as S
ACTION_SHA='6e9c1da2b641c11068ddb21322a1a2f4c8f24e10e744777cc050c17281ffdff4'
TARGETS=(('www.microsoft.com','/pkiops/crl/MicWinProPCA2011_2011-10-19.crl%20'),('crl.microsoft.com','/pki/crl/products/MicRooCerAut_2010-06-23.crl'),('www.microsoft.com','/pkiops/crl/Microsoft%20Time-Stamp%20PCA%202010(1).crl'))
def need(v,c):
 if not v:raise S.Hold(c)
def exact_action(f):
 need(S.sha(f['downloadActionPath'])==f['downloadActionSHA256']==ACTION_SHA,'EXACT_NETWORK_ACTION')
 p=S.read(f['downloadActionPath'],16384)
 need(len(p['exactRequests'])==3 and p['maxRequests']==3 and p['combinedArtifactBytes']==3145728,'EXACT_THREE_GET_CAPS')
 for i,(host,target) in enumerate(TARGETS):need(p['exactRequests'][i]['url']=='http://'+host+target and p['exactRequests'][i]['method']=='GET','LITERAL_URL_AND_METHOD')
 return p
def child_entry():
 import http.client
 p=argparse.ArgumentParser();p.add_argument('--frame',required=True);p.add_argument('--frame-sha',required=True);a=p.parse_args()
 raw=Path(a.frame).read_bytes();need(len(raw)<=32768 and hashlib.sha256(raw).hexdigest()==a.frame_sha,'DOWNLOAD_FRAME_HASH');f=json.loads(raw);exact_action(f)
 need(S.sha(__file__)==f['downloadSourceSHA256'],'DOWNLOAD_SOURCE')
 profile=S.read(f['profilePath'],8192);need(profile['childPid']==os.getpid() and profile['nonce']==f['nonce'],'DOWNLOAD_CHILD_IDENTITY');kernel=S.input_kernel(profile)
 idx=f['downloadIndex'];need(type(idx) is int and 0<=idx<3,'EXACT_INDEX');host,target=TARGETS[idx];url='http://'+host+target
 start=time.monotonic();end=min(f['requestDeadlineUnix'],f['networkDeadlineUnix'],f['window']['deadlineUnix']-30)
 def left():return min(end-time.time(),5-(time.monotonic()-start))
 def clock():need(left()>0,'SINGLE_GET_ABSOLUTE_TIMEOUT')
 result={'schema':'tail11-one-exact-public-cdp-download/v1','status':'HOLD','index':idx,'url':url,'method':'GET','attempts':0,'requestInvoked':False,'redirectsFollowed':0,'urlChanged':False,'bytes':0,'nonce':f['nonce'],'pid':os.getpid(),'actualKernel':kernel,'sourceSHA256':f['downloadSourceSHA256']}
 connection=None;total=0;tmp=Path(f['artifactPath']+'.part');dest=Path(f['artifactPath'])
 try:
  clock();need(dest.parent==Path(f['receiptPath']).parent and not dest.exists() and not tmp.exists(),'PRIVATE_FRESH_OUTPUT')
  # HTTPConnection ignores proxy environment configuration. No proxy setting is
  # changed. The literal ASCII path, including percent escapes, is sent intact.
  connection=http.client.HTTPConnection(host,80,timeout=max(.001,min(5,left())))
  result['attempts']=1;result['requestInvoked']=True
  connection.request('GET',target,headers={'Accept':'application/pkix-crl, application/octet-stream','Accept-Encoding':'identity','Connection':'close'})
  clock()
  if connection.sock:connection.sock.settimeout(max(.001,min(5,left())))
  response=connection.getresponse();result['httpStatus']=response.status;result['locationRecordedNotFollowed']=(response.getheader('Location') or '')[:2048]
  need(response.status==200,'HTTP_STATUS_'+str(response.status))
  need((response.getheader('Content-Encoding') or 'identity').lower()=='identity','ENCODED_HTTP_BODY_NOT_ALLOWED')
  length=response.getheader('Content-Length');expected=None
  if length is not None:
   need(length.isascii() and length.isdecimal(),'CONTENT_LENGTH_INVALID');expected=int(length);need(0<expected<=1048576,'CONTENT_LENGTH_CAP')
  total=0;digest=hashlib.sha256()
  with tmp.open('xb') as w:
   while True:
    clock()
    if connection.sock:connection.sock.settimeout(max(.001,min(5,left())))
    if total==1048576:
     need(expected==total,'SIZE_AT_CAP_REQUIRES_DECLARED_LENGTH');break
    block=response.read(min(65536,1048576-total))
    if not block:break
    total+=len(block);need(total<=1048576,'ONE_ARTIFACT_1M_CAP');digest.update(block);w.write(block)
   need(total>0 and (expected is None or total==expected),'COMPLETE_HTTP_BODY_REQUIRED');clock();w.flush();os.fsync(w.fileno())
  need(not dest.exists(),'NO_ARTIFACT_OVERWRITE');tmp.rename(dest)
  result.update(status='HTTP200_BOUNDED_BYTES_NOT_YET_CRL_ACCEPTED',bytes=total,sha256=digest.hexdigest(),path=str(dest))
 except Exception as e:
  result.update(code=str(e) if isinstance(e,S.Hold) else 'EXACT_GET_TRANSPORT_HOLD',exceptionType=type(e).__name__)
 finally:
  if connection:connection.close()
  result['receivedBodyBytes']=total;result['partialBytesWritten']=tmp.stat().st_size if tmp.exists() else 0;result['phaseSeconds']=time.monotonic()-start;S.fresh(f['receiptPath'],result,cap=16384)
 if result['status']!='HTTP200_BOUNDED_BYTES_NOT_YET_CRL_ACCEPTED':raise SystemExit(1)
def _kernel():
 k=ctypes.WinDLL('kernel32',use_last_error=True)
 k.OpenJobObjectW.argtypes=[ctypes.c_uint,ctypes.c_int,ctypes.c_wchar_p];k.OpenJobObjectW.restype=ctypes.c_void_p
 k.IsProcessInJob.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.POINTER(ctypes.c_int)]
 k.GetProcessTimes.argtypes=[ctypes.c_void_p]*5;k.ResumeThread.argtypes=[ctypes.c_void_p];k.ResumeThread.restype=ctypes.c_uint;k.CloseHandle.argtypes=[ctypes.c_void_p]
 return k
def download_all(f):
 exact_action(f);need(S.sha(__file__)==f['downloadSourceSHA256'],'DOWNLOAD_SOURCE')
 out=Path(f['receiptPath']).parent;begin=time.monotonic();end=min(time.time()+20,f['phaseDeadlineUnix'],f['window']['deadlineUnix']-30);rows=[];k=_kernel()
 for i,(host,target) in enumerate(TARGETS):
  hp=ht=job=None;forced=False;resumed=False;started=time.monotonic();receipt=out/('download-'+str(i)+'-result.json');url='http://'+host+target
  row={'index':i,'url':url,'status':'HOLD','attemptUpperBound':0,'requestInvoked':False}
  try:
   need(time.time()<end and time.monotonic()-begin<20,'NETWORK_ROLE20')
   g=dict(f);g.update(downloadIndex=i,networkDeadlineUnix=end,requestDeadlineUnix=min(end,time.time()+5),profilePath=str(out/('download-'+str(i)+'-profile.json')),receiptPath=str(receipt),artifactPath=str(out/('download-'+str(i)+'.der')))
   frame=out/('download-'+str(i)+'-frame.json');S.fresh(frame,g,cap=32768)
   entry='import sys;sys.path[:0]=[sys.argv.pop(1),sys.argv.pop(1)];import exact_cdp_download;exact_cdp_download.child_entry()'
   argv=[f['pythonPath'],'-I','-S','-B','-c',entry,str(Path(__file__).parent),f['supportDirectory'],'--frame',str(frame),'--frame-sha',S.sha(frame)]
   env=dict(os.environ);env['TAIL11_ROOT_PROFILE']=g['profilePath']
   hp,ht,pid,tid=_winapi.CreateProcess(f['pythonPath'],subprocess.list2cmdline(argv),None,None,False,0x08000004,env,str(out),subprocess.STARTUPINFO())
   row['attemptUpperBound']=1;row['pid']=pid
   job=k.OpenJobObjectW(4,False,'tail11-input-only-'+f['nonce']);member=ctypes.c_int();need(job and k.IsProcessInJob(hp,job,ctypes.byref(member)) and member.value==1,'GET_INHERITED_JOB_BEFORE_RESUME')
   c,e,kt,ut=(ctypes.c_ulonglong() for _ in range(4));need(k.GetProcessTimes(hp,ctypes.byref(c),ctypes.byref(e),ctypes.byref(kt),ctypes.byref(ut)),'GET_PROCESS_BIRTH')
   S.fresh(g['profilePath'],{'nonce':f['nonce'],'childPid':pid,'processCreationFileTime':c.value,'sameJobBeforeResume':True})
   need(time.time()<g['requestDeadlineUnix'] and k.ResumeThread(ht)!=0xffffffff,'GET_RESUME_WITHIN_DEADLINE');resumed=True
   wait=_winapi.WaitForSingleObject(hp,max(1,int(min(g['requestDeadlineUnix']-time.time(),5-(time.monotonic()-started))*1000)))
   if wait!=0:
    forced=True;_winapi.TerminateProcess(hp,124);need(_winapi.WaitForSingleObject(hp,2000)==0,'OWN_GET_TERMINAL_UNKNOWN')
   code=_winapi.GetExitCodeProcess(hp);row['terminal']={'pid':pid,'birth':c.value,'exitCode':code,'forced':forced,'originalWait':wait,'originalHandleTerminal':_winapi.WaitForSingleObject(hp,0)==0,'sameJobBeforeResume':True}
   if receipt.exists():
    r=S.read(receipt,16384);need(r['index']==i and r['url']==url and r['nonce']==f['nonce'] and r['pid']==pid and r['sourceSHA256']==f['downloadSourceSHA256'],'EXACT_DOWNLOAD_RESULT');row.update(r);row['receiptSHA256']=S.sha(receipt)
   else:row.update(code='GET_TIMEOUT_OR_NO_RECEIPT_NO_RETRY',requestInvocation='UNKNOWN_AT_MOST_ONE')
   if row['status']=='HTTP200_BOUNDED_BYTES_NOT_YET_CRL_ACCEPTED':
    need(not forced and code==0 and row['bytes']<=1048576 and S.sha(row['path'])==row['sha256'],'COMPLETE_DOWNLOAD_BINDING')
  except Exception as e:row.update(status='HOLD',code=str(e) if isinstance(e,S.Hold) else 'GET_PARENT_HOLD',exceptionType=type(e).__name__)
  finally:
   if hp and _winapi.WaitForSingleObject(hp,0)!=0:
    _winapi.TerminateProcess(hp,126);need(_winapi.WaitForSingleObject(hp,2000)==0,'OWN_GET_CLEANUP_TERMINAL_UNKNOWN');row['forcedCleanup']=True
   if hp:row['originalHandleTerminalConfirmed']=_winapi.WaitForSingleObject(hp,0)==0
   if ht:_winapi.CloseHandle(ht)
   if hp:_winapi.CloseHandle(hp)
   if job:k.CloseHandle(job)
   rows.append(row)
  need(sum(x.get('bytes',0) for x in rows)<=3145728,'ALL_THREE_ARTIFACT_3M_CAP')
 result={'schema':'tail11-three-exact-public-cdp-downloads/v1','rows':rows,'networkRequestsKnown':sum(x.get('requestInvoked') is True for x in rows),'networkRequestsUpperBound':sum(x.get('attemptUpperBound',0) for x in rows),'artifactBytes':sum(x.get('bytes',0) for x in rows),'receivedBodyBytesKnown':sum(x.get('receivedBodyBytes',0) for x in rows),'roleSeconds':time.monotonic()-begin,'withinRoleCap':time.monotonic()-begin<=20 and time.time()<=end,'actionSHA256':ACTION_SHA,'nonce':f['nonce'],'noAutomaticRetries':True,'redirectsFollowed':0,'urlNormalization':False}
 need(result['networkRequestsUpperBound']<=3 and result['artifactBytes']<=3145728,'TOTAL_NETWORK_CAPS');S.fresh(out/'three-cdp-downloads.json',result,cap=65536);return result
