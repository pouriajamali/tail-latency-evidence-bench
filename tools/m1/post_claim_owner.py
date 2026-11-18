"""One authorized exact public-provider data read; no M1 replay or Actions API."""
from pathlib import Path
import ctypes,hashlib,json,os,re,subprocess,time
O=Path(r'E:\Codex WorkSpace\Git Projects\tail-latency-evidence-bench\outputs\wave4-m1-record-cap-20261116')
A=O/'five-cert-flags-fixed-source-20261118';M=O/'five-cert-flags-fixed-once-20261118'
R=Path(r'E:\Codex WorkSpace\Git Projects\tail-latency-evidence-bench\worktree-wave4-m1-20261117')
PROTOCOL=Path(r'E:\Codex WorkSpace\Git Projects\portfolio-management\development-management-20261110\wave2-state\LEASE-PROTOCOL.json');LEASE=PROTOCOL.with_name('LOCAL-FIXTURE-LEASE.json')
SCOPE=O/'OWNED-SSH-ALL-GAPS-TECHNICAL-SCOPE.json'
ACTION=O/'OWNED-SSH-ALL-GAPS-ACTION.json'
PS=Path(r'C:\Program Files\WindowsApps\OpenAI.CodexPrimaryRuntime.v26-1112-611-0_26.1112.611.0_x64__3k8sg7r9htsxt\dependencies\native\powershell\pwsh.exe')
OLD_TIMESTAMP_SOURCE=O/'two-expired-signers-timestamp-source-20261118/exact_two_timestamp_reader.cs'
OLD_TIMESTAMP_INSPECTOR=O/'two-expired-signers-timestamp-source-20261118/two_timestamp_proofs.ps1'
HANDOFF=O/'EXECUTION02-TO-TAIL-HANDOFF-20261118.json'
AUTHORITY=O/'DIRECT-RETRY-FLAGS-FIX-20261118.json'
claimed=False;all_terminal=False;ticket=None;mono=None;child=None
def need(v,c):
 if not v:raise RuntimeError(c)

def sha(p):
 h=hashlib.sha256()
 with Path(p).open('rb') as f:
  for b in iter(lambda:f.read(65536),b''):h.update(b)
 return h.hexdigest()

def read(p,cap=1048576):
 with Path(p).open('rb') as f:b=f.read(cap+1)
 need(len(b)<=cap,'PROOF_READ_CAP');return json.loads(b)

def fresh(p,v):
 p.parent.mkdir(parents=True,exist_ok=True)
 b=(json.dumps(v,sort_keys=True,indent=2)+'\n').encode();need(len(b)<=2097152,'PROOF_CAP')
 with p.open('xb') as f:f.write(b);f.flush();os.fsync(f.fileno())

def state(status,**kw):
 t=M/('state-'+os.urandom(4).hex()+'.tmp');fresh(t,{'status':status,'atUnix':time.time(),**kw});os.replace(t,M/'current.json')

def remaining(reserve=30):
 return max(.001,min(ticket['window']['deadlineUnix']-time.time()-reserve,300-(time.monotonic()-mono)-reserve))

def owner_start():
 k=ctypes.WinDLL('kernel32',use_last_error=True);k.GetCurrentProcess.restype=ctypes.c_void_p
 k.GetProcessTimes.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p]
 c,e,kt,ut=(ctypes.c_ulonglong() for _ in range(4))
 need(k.GetProcessTimes(k.GetCurrentProcess(),ctypes.byref(c),ctypes.byref(e),ctypes.byref(kt),ctypes.byref(ut)),'OWNER_BIRTH')
 return 'FILETIME:'+str(c.value)

def exact_owner():
 x=read(LEASE,8192)
 return x['projectId']=='11' and x['randomToken']==ticket['nonce'] and x['ownerPID']==os.getpid() and x['ownerProcessStartIdentity']==ticket['ownerStartIdentity']

def main():
 global claimed,all_terminal,ticket,mono,child
 need(not M.exists(),'NO_READ_REPLAY_OR_RESET');M.mkdir()
 handoff=read(HANDOFF,16384);authority=read(AUTHORITY,16384)
 need(handoff['schema']=='execution02-to-tail-canonical-handoff/v1' and handoff['sourceThreadId']=='01a1c661-0902-70d3-8cef-74af44ffc600' and handoff['allOwnedTerminal'] is True and handoff['exactOwnLeaseReleased'] is True and handoff['projectId']=='02' and handoff['canonicalLeasePath']==str(LEASE),'EXPLICIT_IDENTITY_BOUND_HANDOFF_REQUIRED')
 need(authority['actionSHA256']==sha(A/'ACTION.json')=='d8a83d86c8db9dada60c697560e1c1983c12b4fa571ce78be6169d4fd2cb9f3f' and authority['clockStartsOnlyAfterAtomicClaim'] is True,'POST_CLAIM_CLOCK_AUTHORITY')
 need(sha(O/'TWO-EXPIRED-SIGNERS-TIMESTAMP-NEXT-ACTION.json')=='1d38f2af453d2664b15974b24381293f0b35f203a6d5e3a8040fdc6126232a32','EXACT_TIMESTAMP_AUTHORITY');scope=read(SCOPE,16384);need(scope['actionSHA256']==sha(ACTION)=='b1bb79cb22ec3f437280c0eaba45afb992a53c037f01e532dc0ebcfcda1666f0' and len(scope['exactAdditionalPaths'])==6,'EXACT_ALL_GAPS_SCOPE')
 need(sha(PROTOCOL)=='9120ca49a0d46673053aa0ec0cdbbc6f00731d71ea0b57ddab09e8fc3ac3ac8b','CANONICAL_PROTOCOL')
 policy=read(PROTOCOL,32768);need('11' in policy['participants'] and policy['canonicalLeaseWindows']==str(LEASE) and policy['authoritativePolicy']==str(PROTOCOL),'CANONICAL_POLICY')
 nonce=os.urandom(16).hex();birth=owner_start()
 # One atomic attempt, only after the explicit release event. No queue polling,
 # change notification, target or qualification process before this acquisition.
 try:
  lease_file=LEASE.open('xb')
 except FileExistsError:
  observed=read(LEASE,16384)
  fresh(M/'claim-busy-no-window.json',{'status':'CANONICAL_BUSY_WINDOW_NOT_STARTED','observedHolder':observed,'handoffSHA256':sha(HANDOFF),'claimAttempts':1,'windowStarted':False,'targetChildrenStarted':0,'noRetry':True})
  raise RuntimeError('CANONICAL_BUSY_WINDOW_NOT_STARTED')
 claimed=True
 acquired_unix=time.time();mono=time.monotonic()
 ticket={'nonce':nonce,'ownerPID':os.getpid(),'ownerStartIdentity':birth,'window':{'startUnix':acquired_unix,'deadlineUnix':acquired_unix+300.0}}
 holder={'projectId':'11','randomToken':nonce,'ownerOS':'Windows','ownerPID':os.getpid(),'ownerProcessStartIdentity':birth,'phase':'FIVE_CURRENT_REVOCATION_THEN_CONDITIONAL_OWNED_SSH','startedAtUtc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(acquired_unix)),'receiptDirectory':str(M),'executionWindow':ticket['window'],'postAtomicClaimStartUnix':acquired_unix}
 with lease_file:
  payload=(json.dumps(holder,sort_keys=True,indent=2)+'\n').encode()
  lease_file.write(payload);lease_file.flush();os.fsync(lease_file.fileno())
 fresh(M/'lease-claimed.json',{'holder':holder,'protocolSha256':sha(PROTOCOL),'handoffSHA256':sha(HANDOFF),'authoritySHA256':sha(AUTHORITY),'atomicCreateNew':True,'claimAttempts':1,'clockStartedOnlyAfterSuccessfulAtomicCreateNew':True,'actualClaimStartUnix':acquired_unix,'clockAnchorMonotonic':mono,'window':ticket['window'],'queueTimeIncluded':False})
 need(sha(PS)=='2a6769a3330dc1084d0154bfde7d164ab750ca7f700f313f9d417c1be78b2233','CRITICAL_POWERSHELL')
 frame={'schema':'tail11-exact-provider-read-frame/v1',**ticket,'exactPath':'EXACT_SIX_AND_TARGETED_RDATA_ONLY','pythonPath':r'C:\Users\Office\AppData\Local\Programs\Python\Python312\python.exe','supportDirectory':str(R/'tools/m1'),'leafDERPath':str(O/'provider-proof-access-prep-once-20261117/leaf-cert.der'),'scopePath':str(SCOPE),'scopeSha256':sha(SCOPE),
  'preparedActionPath':str(ACTION),'preparedActionSha256':sha(ACTION),'protocolPath':str(PROTOCOL),'leasePath':str(LEASE),
  'providerReaderPath':str(A/'provider_file_reader.cs'),'providerReaderSha256':sha(A/'provider_file_reader.cs'),'crlProofPath':str(O/'eset-current-crl-once-20261117/provider-file-observation.json'),'crlProofSha256':sha(O/'eset-current-crl-once-20261117/provider-file-observation.json'),'sourcePath':str(A/'owned_ssh_all_gaps.py'),'sourceSha256':sha(A/'owned_ssh_all_gaps.py'),
  'inspectorPath':str(A/'owned_ssh_all_gaps.py'),'inspectorSha256':sha(A/'owned_ssh_all_gaps.py'),
  'helperPath':str(A/'crypto_held_reader.py'),'helperSha256':sha(A/'crypto_held_reader.py'),'allHelpers':{str(A/n):sha(A/n) for n in ('six_held_readers.py','eset_held_reader.py','five_current_revocation.py','crl_der.py')},'exactAdditionalPaths':scope['exactAdditionalPaths'],'actionSHA256':sha(ACTION),'sixNativeSourcePath':str(OLD_TIMESTAMP_SOURCE),'sixNativeSourceSHA256':sha(OLD_TIMESTAMP_SOURCE),'sixNativeInspectorPath':str(OLD_TIMESTAMP_INSPECTOR),'sixNativeInspectorSHA256':sha(OLD_TIMESTAMP_INSPECTOR),'pwshPath':str(PS),'bridgePath':str(R/'tools/m1/job_bridge11.cs'),'fileProof':{'path':str(O/'libcrypto-exact-read-once-20261117/provider-file-observation.json'),'sha256':sha(O/'libcrypto-exact-read-once-20261117/provider-file-observation.json')},'catalogProof':{'path':str(O/'libcrypto-catalog-once-20261117/provider-file-observation.json'),'sha256':sha(O/'libcrypto-catalog-once-20261117/provider-file-observation.json')},'receiptPath':str(M/'provider-file-observation.json')}
 frame.update(timestampActionPath=str(O/'TWO-EXPIRED-SIGNERS-TIMESTAMP-NEXT-ACTION.json'),timestampActionSHA256='1d38f2af453d2664b15974b24381293f0b35f203a6d5e3a8040fdc6126232a32',existingFileProofs=read(O/'TWO-EXPIRED-SIGNERS-TIMESTAMP-NEXT-ACTION.json')['existingFileProofs'],exactTimestampPaths=[r['path'] for r in read(O/'TWO-EXPIRED-SIGNERS-TIMESTAMP-NEXT-ACTION.json')['exactFailedInputs']])
 frame.update(revocationActionPath=str(A/'ACTION.json'),revocationActionSHA256=sha(A/'ACTION.json'),existingTimestampProofSHA256='994401e2a42138ccb823d525a8dbdb74785cafc2bf17cfdd51a9f34c5919febe')
 fresh(M/'permit.json',frame);fresh(M/'once-intent.json',{'attempts':1,'dataOnly':True,'revocationCertificateCount':5,'conditionalMappingFileCount':6,'timestampReplays':0,'sourceHashes':{p.name:sha(p) for p in A.iterdir() if p.is_file()},'managerSha256':sha(__file__),'window':ticket['window'],'GitHubActions':0})
 state('EXACT_PROVIDER_DATA_READ_RUNNING')
 child=subprocess.Popen([str(PS),'-NoProfile','-NonInteractive','-File',str(A/'provider_read_controller.ps1')],cwd=R,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=0x08000000)
 code=child.wait(timeout=remaining(2));terminal=read(M/'controller-terminal.json')
 need(terminal['allOwnedTerminal'] is True,'READ_CHILD_TERMINAL_UNKNOWN');all_terminal=True
 observation=read(M/'provider-file-observation.json') if (M/'provider-file-observation.json').exists() else None
 fresh(M/'FINAL.json',{'schema':'tail11-exact-provider-read-final/v1','status':terminal['status'],'parentOriginalPopenWaitReturned':True,'parentPid':child.pid,'parentExitCode':code,
  'allOwnedTerminal':True,'observationStatus':observation['status'] if observation else None,'observationSha256':sha(M/'provider-file-observation.json') if observation else None,
  'scopeSha256':sha(SCOPE),'sameCurrentFileOnly':True,'oldExitedChildByteIdentity':'UNKNOWN_NOT_ATTRIBUTED','providerAdmission':False,'M1':'HOLD','GitHubActions':0,'healthyTestsRepeated':0})
try:main()
except Exception as e:
 code=str(e) if isinstance(e,RuntimeError) and re.fullmatch('[A-Z][A-Z0-9_]{0,99}',str(e)) else 'EXACT_PROVIDER_OWNER_HOLD'
 if M.exists():
  if child is None:all_terminal=True
  if not (M/'FINAL.json').exists():fresh(M/'FINAL.json',{'status':'HOLD','code':code,'allOwnedTerminal':all_terminal,'providerAdmission':False,'GitHubActions':0,'exceptionType':type(e).__name__,'windowStarted':claimed,'window':ticket['window'] if ticket else None,'noAutomaticRetry':True})
finally:
 if claimed:
  if all_terminal and exact_owner():
   fresh(M/'all-owned-terminal.json',{'status':'ALL_OWNED_TERMINAL','nonce':ticket['nonce'],'ownerPID':os.getpid()})
   need(exact_owner(),'OWNER_CHANGED_RETAIN_LEASE');LEASE.unlink()
   fresh(M/'lease-released.json',{'status':'EXACT_OWN_LEASE_RELEASED','allOwnedTerminalSha256':sha(M/'all-owned-terminal.json')})
  else:fresh(M/'RECOVERY-REQUIRED.json',{'status':'CANONICAL_LEASE_RETAINED_TERMINAL_UNKNOWN','ownerPID':os.getpid(),'noAutomaticReset':True})
 if M.exists():state('STOPPED',leaseReleased=(M/'lease-released.json').exists())
print(json.dumps({'status':'STOPPED','receipt':str(M/'FINAL.json'),'leaseReleased':(M/'lease-released.json').exists(),'GitHubActions':0}))
