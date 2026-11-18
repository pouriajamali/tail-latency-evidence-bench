"""One fixed Tail Linux qualification phase; event handoff, post-claim clock."""
from pathlib import Path
import ctypes,hashlib,json,os,re,subprocess,time
R=Path(r'E:\Codex WorkSpace\Git Projects\tail-latency-evidence-bench\worktree-wave4-m1-20261117')
O=R.parent/'outputs/wave4-m1-record-cap-20261116'
D=R/'tools/m1'
PROTOCOL=Path(r'E:\Codex WorkSpace\Git Projects\portfolio-management\development-management-20261110\wave2-state\LEASE-PROTOCOL.json')
LEASE=PROTOCOL.with_name('LOCAL-FIXTURE-LEASE.json')
RUN=O/'linux-loader-static-file-once-20261118'
MODE='loader-static'
CLAIMED=False;TERMINAL=False;ticket=None;mono=None;child=None
def need(v,c):
    if not v:raise RuntimeError(c)
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def read(p,cap=1048576):
    with Path(p).open('rb') as f:b=f.read(cap+1)
    need(len(b)<=cap,'JSON_CAP');return json.loads(b)
def fresh(p,v):
    b=(json.dumps(v,sort_keys=True,indent=2)+'\n').encode();need(len(b)<=1048576,'PROOF_CAP')
    with Path(p).open('xb') as f:f.write(b);f.flush();os.fsync(f.fileno())
def linux(p):
    p=Path(p);need(p.drive.upper()=='E:','CANONICAL_E_INPUT');return '/mnt/e/'+str(p)[3:].replace('\\','/')
def birth():
    k=ctypes.WinDLL('kernel32',use_last_error=True);k.GetCurrentProcess.restype=ctypes.c_void_p;k.GetProcessTimes.argtypes=[ctypes.c_void_p]*5
    c,e,kt,ut=(ctypes.c_ulonglong() for _ in range(4));need(k.GetProcessTimes(k.GetCurrentProcess(),ctypes.byref(c),ctypes.byref(e),ctypes.byref(kt),ctypes.byref(ut)),'OWNER_BIRTH');return 'FILETIME:'+str(c.value)
def ours():
    h=read(LEASE,16384);return h['projectId']=='11' and h['randomToken']==ticket['nonce'] and h['ownerPID']==os.getpid() and h['ownerProcessStartIdentity']==ticket['ownerBirth']
def remaining(reserve=30):return min(ticket['window']['deadlineUnix']-time.time()-reserve,300-(time.monotonic()-mono)-reserve)
def main():
    global CLAIMED,TERMINAL,ticket,mono,child
    need(not RUN.exists(),'NO_PHASE_REPLAY');RUN.mkdir()
    h=read(O/'OWN02-TO-TAIL-LINUX-ROLE-HANDOFF-20261118.json',16384)
    need(h['sourceThreadId']=='01a1c661-0902-70d3-8cef-74af44ffc600' and h['actualTerminalReleaseEvent'] is True and sha(h['releaseReceipt']['path'])==h['releaseReceipt']['sha256'],'02_HANDOFF')
    need(sha(PROTOCOL)=='9120ca49a0d46673053aa0ec0cdbbc6f00731d71ea0b57ddab09e8fc3ac3ac8b','CANONICAL_PROTOCOL')
    m=read(D/'source-manifest.json');need(len(m['files'])<=32,'SOURCE_SET')
    for n,hv in m['files'].items():need(sha(D/n)==hv,'SOURCE_BINDING')
    nonce=os.urandom(16).hex();owner_birth=birth()
    try:lf=LEASE.open('xb')
    except FileExistsError:
        fresh(RUN/'FINAL.json',{'status':'BUSY_WINDOW_NOT_STARTED','holder':read(LEASE,16384),'claimAttempts':1,'windowStarted':False,'targetCalls':0,'allOwnedTerminal':True});return
    CLAIMED=True;started=time.time();mono=time.monotonic();ticket={'nonce':nonce,'ownerPID':os.getpid(),'ownerBirth':owner_birth,'window':{'startUnix':started,'deadlineUnix':started+300}}
    holder={'projectId':'11','randomToken':nonce,'ownerOS':'Windows','ownerPID':os.getpid(),'ownerProcessStartIdentity':owner_birth,'phase':'LINUX_SIGNATURE_ROLE_'+MODE.upper(),'startedAtUtc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(started)),'receiptDirectory':str(RUN),'executionWindow':ticket['window']}
    with lf:lf.write((json.dumps(holder,sort_keys=True,indent=2)+'\n').encode());lf.flush();os.fsync(lf.fileno())
    fresh(RUN/'lease-claimed.json',{'holder':holder,'postAtomicClaimClock':True,'window':ticket['window'],'cause':'Need exact retained loader bytes for actual RVA222112 static analysis; ad-hoc WSL command timed out, independent05 host receipt now shows UbuntuStopped; use existing direct-file capped launcher for one236616B data-only read, ordinary existing Ubuntu start only, no SSH/metadata/test/recovery/reset','handoffSHA256':sha(O/'OWN02-TO-TAIL-LINUX-ROLE-HANDOFF-20261118.json'),'wholeSeconds':300,'authoritySHA256':sha(O/'LINUX-SIGNATURE-BROAD-CONTINUATION-AUTHORITY-20261118.json')})
    frame={'schema':'tail11-linux-role-frame/v1','mode':MODE,**ticket,'sourceDirectory':linux(D),'sourceHashes':m['files'],'sourceManifestSHA256':sha(D/'source-manifest.json'),'hostOutputLinuxPath':linux(RUN),'protocolLinuxPath':linux(PROTOCOL),'leaseLinuxPath':linux(LEASE),'limits':{'memory':536870912,'swap':0,'pids':64,'cpuQuota':200000,'cpuPeriod':100000,'whole':300,'work':270,'terminal':30,'role':20,'qualification':60,'read':67108864,'roleProof':262144,'allRoleProof':1048576,'scratch':1073741824}}
    frame['metadataInput']={'path':linux(O/'linux-role-metadata-exact-package-fix-20261118/metadata.json'),'sha256':'8b1d6345f7ae58a9357aa194ced570458c76e799d056fe8e034daa3c0f2b9bef'}
    fp=RUN/'frame.json';fresh(fp,frame);need(remaining()>60,'NO_TIME_FOR_ROLE')
    argv=[r'C:\Windows\System32\wsl.exe','--distribution','Ubuntu-24.04','--user','root','--exec','/usr/bin/python3','-I','-S','-B',linux(D/'linux_cgroup_launcher.py'),'--frame',linux(fp),'--frame-sha',sha(fp)]
    child=subprocess.Popen(argv,cwd=R,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,creationflags=0x08000400)
    out,err=child.communicate(timeout=max(.001,remaining(2)));need(len(out)+len(err)<=262144,'SUPERVISOR_STDIO_CAP')
    terminal=read(RUN/'linux-role-terminal.json',262144);need(terminal['nonce']==ticket['nonce'] and terminal['frameSHA256']==sha(fp) and terminal['allOwnedTerminal'] is True and (terminal['originalWaitpidReturned'] is True or terminal.get('noOwnedChildCreated') is True) and terminal['cgroupEmpty'] and (terminal['cgroupRemoved'] or terminal.get('cgroupNeverCreated') is True),'ALL_OWNED_TERMINAL');TERMINAL=True
    observation_name={'metadata':'metadata.json','signature':'signature-proof.json','loader-static':'loader-static.json'}[MODE]
    observation=read(RUN/observation_name,262144) if (RUN/observation_name).exists() else None
    fresh(RUN/'FINAL.json',{'schema':'tail11-linux-role-owner-final/v1','status':observation['status'] if child.returncode==0 and observation and observation['status'] in ('METADATA_COMPLETE_NOT_ADMISSION','QUALIFIED_LINUX_MANIFEST_SIGNATURE','EXACT_LOADER_DATA_ONLY') else 'ROLE_HOLD','mode':MODE,'childPID':child.pid,'originalPopenWaitReturned':True,'returncode':child.returncode,'allOwnedTerminal':True,'window':ticket['window'],'terminalSHA256':sha(RUN/'linux-role-terminal.json'),'observationSHA256':sha(RUN/observation_name) if observation else None,'stdoutSHA256':hashlib.sha256(out).hexdigest(),'stderrSHA256':hashlib.sha256(err).hexdigest(),'stderrDiagnostic':err.decode('utf-8','replace')[:4096],'signatureInvocations':observation.get('signatureExecAttempts',0) if observation else 0,'nativeM1Calls':0,'Actions':0,'admissionClaimed':bool(observation and observation.get('admitted') is True and child.returncode==0)})
try:main()
except Exception as e:
    if child is None:TERMINAL=True
    if RUN.exists() and not (RUN/'FINAL.json').exists():fresh(RUN/'FINAL.json',{'status':'ROLE_OWNER_HOLD','code':str(e) if isinstance(e,RuntimeError) else 'OWNER_EXCEPTION','exceptionType':type(e).__name__,'allOwnedTerminal':TERMINAL,'windowStarted':CLAIMED,'noAutomaticRetry':True})
finally:
    if CLAIMED:
        if TERMINAL and ours():
            fresh(RUN/'all-owned-terminal.json',{'status':'ALL_OWNED_TERMINAL','nonce':ticket['nonce'],'ownerPID':os.getpid()});need(ours(),'EXACT_OWNER_RECHECK');LEASE.unlink();fresh(RUN/'lease-released.json',{'status':'EXACT_OWN_LEASE_RELEASED','terminalSHA256':sha(RUN/'all-owned-terminal.json')})
        else:fresh(RUN/'RECOVERY-REQUIRED.json',{'status':'OWN_LEASE_RETAINED_TERMINAL_UNKNOWN','automaticReset':False})
print(json.dumps({'receipt':str(RUN/'FINAL.json'),'leaseClaimed':CLAIMED,'leaseReleased':(RUN/'lease-released.json').exists()}))
