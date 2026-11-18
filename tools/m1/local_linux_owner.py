"""One fixed Tail Linux qualification phase; event handoff, post-claim clock."""
from pathlib import Path
import ctypes,hashlib,json,os,re,subprocess,time
R=Path(r'E:\Codex WorkSpace\Git Projects\tail-latency-evidence-bench\worktree-wave4-m1-20261117')
O=R.parent/'outputs/wave4-m1-record-cap-20261116'
D=R/'tools/m1'
PROTOCOL=Path(r'E:\Codex WorkSpace\Git Projects\portfolio-management\development-management-20261110\wave2-state\LEASE-PROTOCOL.json')
LEASE=PROTOCOL.with_name('LOCAL-FIXTURE-LEASE.json')
RUN=O/'windows-official-debug-deadline15-once-20261118'
MODE='windows-data'
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
    h=read(O/'OWN04-PRODUCT05-TO-TAIL-DATA-HANDOFF-20261118.json',16384)
    need(h['sourceThreadId']=='01a1c661-2773-7f81-9ae7-c5756abd8095' and h['actualTerminalReleaseEvent'] is True and sha(h['releaseReceipt']['path'])==h['releaseReceipt']['sha256'],'04_STATIC_HANDOFF')
    need(sha(PROTOCOL)=='9120ca49a0d46673053aa0ec0cdbbc6f00731d71ea0b57ddab09e8fc3ac3ac8b','CANONICAL_PROTOCOL')
    m=read(D/'source-manifest.json');need(len(m['files'])<=32,'SOURCE_SET')
    for n,hv in m['files'].items():need(sha(D/n)==hv,'SOURCE_BINDING')
    nonce=os.urandom(16).hex();owner_birth=birth()
    try:lf=LEASE.open('xb')
    except FileExistsError:
        fresh(RUN/'FINAL.json',{'status':'BUSY_WINDOW_NOT_STARTED','holder':read(LEASE,16384),'claimAttempts':1,'windowStarted':False,'targetCalls':0,'allOwnedTerminal':True});return
    CLAIMED=True;started=time.time();mono=time.monotonic();ticket={'nonce':nonce,'ownerPID':os.getpid(),'ownerBirth':owner_birth,'window':{'startUnix':started,'deadlineUnix':started+300}}
    holder={'projectId':'11','randomToken':nonce,'ownerOS':'Windows','ownerPID':os.getpid(),'ownerProcessStartIdentity':owner_birth,'phase':('WINDOWS_RETAINED_DATA_ONLY' if MODE=='windows-data' else 'LINUX_SIGNATURE_ROLE_'+MODE.upper()),'startedAtUtc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(started)),'receiptDirectory':str(RUN),'executionWindow':ticket['window']}
    with lf:lf.write((json.dumps(holder,sort_keys=True,indent=2)+'\n').encode());lf.flush();os.fsync(lf.fileno())
    fresh(RUN/'lease-claimed.json',{'holder':holder,'postAtomicClaimClock':True,'window':ticket['window'],'cause':'Explicit fresh manager-relayed owner authority: exactly one causal overall deadline5to15 GET delta after prior5s TimeoutError/noHTTPresponse; role20/whole300 and CPU/memory/process/bytes/storage/trust/protection unchanged; no automatic further retry or UNC replay','handoffSHA256':sha(O/'OWN04-PRODUCT05-TO-TAIL-DATA-HANDOFF-20261118.json'),'wholeSeconds':300,'authoritySHA256':sha(O/'LINUX-SIGNATURE-BROAD-CONTINUATION-AUTHORITY-20261118.json')})
    frame={'schema':'tail11-linux-role-frame/v1','mode':MODE,**ticket,'sourceDirectory':linux(D),'sourceHashes':m['files'],'sourceManifestSHA256':sha(D/'source-manifest.json'),'hostOutputLinuxPath':linux(RUN),'protocolLinuxPath':linux(PROTOCOL),'leaseLinuxPath':linux(LEASE),'limits':{'memory':536870912,'swap':0,'pids':64,'cpuQuota':200000,'cpuPeriod':100000,'whole':300,'work':270,'terminal':30,'role':20,'qualification':60,'read':67108864,'roleProof':262144,'allRoleProof':1048576,'scratch':1073741824}}
    frame['metadataInput']={'path':linux(O/'linux-role-metadata-exact-package-fix-20261118/metadata.json'),'sha256':'8b1d6345f7ae58a9357aa194ced570458c76e799d056fe8e034daa3c0f2b9bef'}
    frame['transport']='EXISTING_WINDOWS_JOB_DATA_ONLY' if MODE=='windows-data' else 'EXISTING_UBUNTU_USER_SUDO_N'
    frame.update(sourceDirectoryWindows=str(D),hostOutputWindowsPath=str(RUN),protocolWindowsPath=str(PROTOCOL),leaseWindowsPath=str(LEASE),supportDirectory=str(D),pythonPath=r'C:\Users\Office\AppData\Local\Programs\Python\Python312\python.exe',inspectorPath=str(D/'windows_retained_input.py'))
    frame['retainedUnavailableReceipt']={'path':str(O/'windows-retained-debug-frame-binding-fix-20261118/terminal-retained-and-one-official-debug-data.json'),'sha256':'57d2ae654b4efc0a69d0b7bcf9283683788dfdffdaf25b0d616b5f7760053b17','oldSourceSHA256':'a33e0917f5aa16abf3a011bf71722779189a11b7a998a616299d44b7ceea5749'}
    frame['officialDebugRequest']={'url': 'https://debuginfod.ubuntu.com/buildid/0d77dbd4379bf0b5af3e05be7fb6af1e4cea7c96/debuginfo', 'artifacts': 1, 'bodyCap': 1048576, 'requestSeconds': 15, 'roleSeconds': 20, 'wholeSeconds': 300, 'redirects': False, 'buildID': '0d77dbd4379bf0b5af3e05be7fb6af1e4cea7c96', 'debuglinkCRC32': '7273804a', 'loaderSHA256': 'c20a2dc8917c755f02b94049356320fe1f62ac7d9f8994731f807d9df39302da'}
    frame['deadlineDeltaAuthority']={'path':str(O/'OFFICIAL-DEBUG-15S-AUTHORITY-20261118.json'),'sha256':'0c95e187abc1f14e5c82cc48438f75b00305c3df21e425b5e1a53b3719ffb774'}
    frame['priorFiveSecondFailure']={'path':str(O/'OFFICIAL-DEBUG-RETRY-FINAL-20261118.json'),'sha256':'be84f75d71474bb2282a839b66cea4b5f6f68a7c6d7fa7ae3df55d24b859fcb3'}
    fp=RUN/'frame.json';fresh(fp,frame);need(remaining()>60,'NO_TIME_FOR_ROLE')
    argv=[r'C:\Windows\System32\wsl.exe','--distribution','Ubuntu-24.04','--user','ubuntu','--exec','/usr/bin/sudo','-n','/usr/bin/python3','-I','-S','-B',linux(D/'linux_cgroup_launcher.py'),'--frame',linux(fp),'--frame-sha',sha(fp)]
    if MODE=='windows-data':
        ps=Path(r'C:\Program Files\WindowsApps\OpenAI.CodexPrimaryRuntime.v26-1112-611-0_26.1112.611.0_x64__3k8sg7r9htsxt\dependencies\native\powershell\pwsh.exe');need(sha(ps)=='2a6769a3330dc1084d0154bfde7d164ab750ca7f700f313f9d417c1be78b2233','CRITICAL_POWERSHELL');argv=[str(ps),'-NoProfile','-NonInteractive','-File',str(D/'windows_data_controller.ps1'),'-FramePath',str(fp),'-FrameSha',sha(fp),'-ExpectedNonce',ticket['nonce']]
    child=subprocess.Popen(argv,cwd=R,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,creationflags=0x08000400)
    out,err=child.communicate(timeout=max(.001,remaining(2)));need(len(out)+len(err)<=262144,'SUPERVISOR_STDIO_CAP')
    fresh(RUN/'launcher-result.json',{'pid':child.pid,'originalPopenWaitReturned':True,'returncode':child.returncode,'stdoutBytes':len(out),'stderrBytes':len(err),'stdoutDiagnostic':out.decode('utf-8','replace')[:4096],'stderrDiagnostic':err.decode('utf-8','replace')[:4096]})
    terminal=read(RUN/('windows-data-terminal.json' if MODE=='windows-data' else 'linux-role-terminal.json'),262144)
    need(terminal['nonce']==ticket['nonce'] and terminal['allOwnedTerminal'] is True,'ALL_OWNED_TERMINAL')
    if MODE!='windows-data':need(terminal['frameSHA256']==sha(fp) and (terminal['originalWaitpidReturned'] is True or terminal.get('noOwnedChildCreated') is True) and terminal['cgroupEmpty'] and (terminal['cgroupRemoved'] or terminal.get('cgroupNeverCreated') is True),'LINUX_ALL_OWNED_TERMINAL')
    TERMINAL=True
    observation_name={'metadata':'metadata.json','signature':'signature-proof.json','loader-static':'loader-static.json','loader-symbols':'loader-symbols.json','loader-debug':'loader-symbols.json','windows-data':'windows-retained-input.json'}[MODE]
    observation=read(RUN/observation_name,262144) if (RUN/observation_name).exists() else None
    fresh(RUN/'FINAL.json',{'schema':'tail11-linux-role-owner-final/v1','status':observation['status'] if child.returncode==0 and observation and observation['status'] in ('METADATA_COMPLETE_NOT_ADMISSION','QUALIFIED_LINUX_MANIFEST_SIGNATURE','EXACT_LOADER_DATA_ONLY','EXACT_UBUNTU_SYMBOL_SECTIONS_DATA_ONLY','EXACT_DEBUG_SYMBOL_DATA_ONLY') else 'ROLE_HOLD','mode':MODE,'childPID':child.pid,'originalPopenWaitReturned':True,'returncode':child.returncode,'allOwnedTerminal':True,'window':ticket['window'],'terminalSHA256':sha(RUN/('windows-data-terminal.json' if MODE=='windows-data' else 'linux-role-terminal.json')),'observationSHA256':sha(RUN/observation_name) if observation else None,'stdoutSHA256':hashlib.sha256(out).hexdigest(),'stderrSHA256':hashlib.sha256(err).hexdigest(),'stderrDiagnostic':err.decode('utf-8','replace')[:4096],'signatureInvocations':observation.get('signatureExecAttempts',0) if observation else 0,'nativeM1Calls':0,'Actions':0,'admissionClaimed':bool(observation and observation.get('admitted') is True and child.returncode==0)})
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
