"""One servicing phase, one canonical claim, exact own terminal and release."""
import argparse,ctypes,hashlib,json,os,subprocess,time
from pathlib import Path
R=Path(r'E:\Codex WorkSpace\Git Projects\tail-latency-evidence-bench\worktree-wave4-m1-20261117')
O=R.parent/'outputs/technology-refresh-20261120'
PROTOCOL=Path(r'E:\Codex WorkSpace\Git Projects\portfolio-management\development-management-20261110\wave2-state\LEASE-PROTOCOL.json')
LEASE=PROTOCOL.with_name('LOCAL-FIXTURE-LEASE.json')
PS=Path(r'C:\Program Files\WindowsApps\OpenAI.CodexPrimaryRuntime.v26-1112-611-0_26.1112.611.0_x64__3k8sg7r9htsxt\dependencies\native\powershell\pwsh.exe')
PY=Path(r'C:\Users\Office\AppData\Local\Programs\Python\Python312\python.exe')

def need(v,c):
    if not v:raise RuntimeError(c)
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def read(p):
    with Path(p).open('rb') as stream:b=stream.read(1048577)
    need(len(b)<=1048576,'JSON_CAP');return json.loads(b)
def fresh(p,v):
    b=(json.dumps(v,indent=2,sort_keys=True)+'\n').encode();need(len(b)<=262144,'PROOF_CAP')
    with Path(p).open('xb') as f:f.write(b);f.flush();os.fsync(f.fileno())
def linux(p):
    s=str(p).replace('\\','/');need(s.startswith('E:/'),'SAME_E_WORKSPACE');return '/mnt/e/'+s[3:]
def birth():
    k=ctypes.WinDLL('kernel32',use_last_error=True);k.GetCurrentProcess.restype=ctypes.c_void_p;k.GetProcessTimes.argtypes=[ctypes.c_void_p]*5
    c,e,kt,ut=(ctypes.c_ulonglong() for _ in range(4));need(k.GetProcessTimes(k.GetCurrentProcess(),ctypes.byref(c),ctypes.byref(e),ctypes.byref(kt),ctypes.byref(ut)),'ACTUAL_OWNER_BIRTH');return 'FILETIME:'+str(c.value)

def event_claim(run):
    # Register before the initial atomic claim, then wake only for this filename's
    # deletion. No holder-content read, timer polling, reset, or parallel lease.
    k=ctypes.WinDLL('kernel32',use_last_error=True)
    class OVERLAPPED(ctypes.Structure):
        _fields_=[('internal',ctypes.c_size_t),('internalHigh',ctypes.c_size_t),('offset',ctypes.c_uint),('offsetHigh',ctypes.c_uint),('event',ctypes.c_void_p)]
    k.CreateFileW.argtypes=[ctypes.c_wchar_p,ctypes.c_uint,ctypes.c_uint,ctypes.c_void_p,ctypes.c_uint,ctypes.c_uint,ctypes.c_void_p];k.CreateFileW.restype=ctypes.c_void_p
    k.CreateEventW.argtypes=[ctypes.c_void_p,ctypes.c_int,ctypes.c_int,ctypes.c_wchar_p];k.CreateEventW.restype=ctypes.c_void_p
    k.ReadDirectoryChangesW.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_uint,ctypes.c_int,ctypes.c_uint,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p]
    k.WaitForSingleObject.argtypes=[ctypes.c_void_p,ctypes.c_uint];k.GetOverlappedResult.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_int];k.CancelIoEx.argtypes=[ctypes.c_void_p,ctypes.c_void_p];k.ResetEvent.argtypes=[ctypes.c_void_p];k.CloseHandle.argtypes=[ctypes.c_void_p]
    directory=k.CreateFileW(str(LEASE.parent),1,7,None,3,0x42000000,None);need(directory not in (None,ctypes.c_void_p(-1).value),'CANONICAL_DIRECTORY_WATCH')
    event=k.CreateEventW(None,True,False,None);need(event,'CANONICAL_EVENT_HANDLE');ov=OVERLAPPED();ov.event=event;buffer=ctypes.create_string_buffer(8192);pending=False;claims=0;deletions=0;end=time.monotonic()+300
    def watch():
        nonlocal pending
        k.ResetEvent(event);need(k.ReadDirectoryChangesW(directory,buffer,len(buffer),False,1,None,ctypes.byref(ov),None),'CANONICAL_DIRECTORY_CHANGE_REQUEST');pending=True
    def claim():
        nonlocal claims
        claims+=1
        try:
            file=LEASE.open('xb');return file,time.time(),time.monotonic(),{'claimAttempts':claims,'canonicalDeletionEvents':deletions,'eventDriven':True,'holderContentsRead':False}
        except FileExistsError:return None
    try:
        watch();found=claim()
        if found:return found
        fresh(run/'lane-wait-start.json',{'status':'BUSY_WAITING_ONE_BOUNDED_KERNEL_EVENT_SEQUENCE','maxWaitSeconds':300,'windowStarted':False,'holderContentsRead':False,'eventDriven':True})
        while time.monotonic()<end and deletions<64:
            left=max(1,int(1000*(end-time.monotonic())));wait=k.WaitForSingleObject(event,left)
            if wait==258:return None
            need(wait==0,'CANONICAL_EVENT_WAIT');count=ctypes.c_uint();need(k.GetOverlappedResult(directory,ctypes.byref(ov),ctypes.byref(count),False),'CANONICAL_EVENT_RESULT');pending=False;offset=0;deleted=False
            while offset<count.value:
                raw=buffer.raw;next_offset=int.from_bytes(raw[offset:offset+4],'little');action=int.from_bytes(raw[offset+4:offset+8],'little');length=int.from_bytes(raw[offset+8:offset+12],'little');name=raw[offset+12:offset+12+length].decode('utf-16-le')
                if action==2 and name.casefold()==LEASE.name.casefold():deleted=True;deletions+=1
                if not next_offset:break
                offset+=next_offset
            watch()
            if deleted:
                found=claim()
                if found:return found
        return None
    finally:
        if pending:k.CancelIoEx(directory,ctypes.byref(ov));k.WaitForSingleObject(event,5000)
        k.CloseHandle(event);k.CloseHandle(directory)

def main():
    p=argparse.ArgumentParser();p.add_argument('--rid',choices=['win-x64','linux-x64'],required=True);p.add_argument('--phase',choices=['qualify','restore','build','test','package','package-check','runtime-verify','runtime-verify-linux-data','negative'],required=True);p.add_argument('--packet',required=True);p.add_argument('--packet-sha',required=True);p.add_argument('--attempt',default='once');p.add_argument('--cause');a=p.parse_args()
    need(a.attempt=='once' or a.cause,'CAUSAL_RETRY_REQUIRED')
    run=O/'runs'/(a.rid+'-'+a.phase+'-'+a.attempt);need(not run.exists(),'NO_PHASE_REPLAY');run.mkdir(parents=True)
    need(sha(PROTOCOL)=='fca40422e6abb4aa552759d7aadfd63fda6eccde4a8be3b272ff480fa72a6035','CANONICAL_PROTOCOL')
    packet=Path(a.packet);need(packet.stat().st_size<=1048576 and sha(packet)==a.packet_sha,'INPUT_PACKET_BYTES');contract=O/'RECEIVER-CONTRACT.json';need(sha(contract)=='46e6a21b28c9f0b930dadcb19726c05b085faed2e721602dac82eb87535c5341','RECEIVER_CONTRACT')
    manifest=read(R/'tools/technology/source-manifest.json');need(len(manifest['files'])<=32,'SOURCE_SET')
    for n,h in manifest['files'].items():need(sha(R/n)==h,'SOURCE_DRIFT')
    head=subprocess.check_output(['git','-C',str(R),'rev-parse','HEAD'],timeout=10).decode().strip()
    nonce=os.urandom(16).hex();owner_birth=birth();claimed=False;terminal=False;child=None;started=None;mono=None;frame=None
    try:
        acquired=event_claim(run)
        if acquired is None:
            fresh(run/'FINAL.json',{'status':'BUSY_NO_RELEASE_EVENT_WITHIN_BOUND','targetCalls':0,'allOwnedTerminal':True,'foreignLeaseReadOrChanged':False,'windowStarted':False});return
        lf,started,mono,lane_event=acquired;claimed=True;deadline=started+300
        fresh(run/'lane-claim-event.json',lane_event)
        holder={'projectId':'11','randomToken':nonce,'ownerOS':'Windows','ownerPID':os.getpid(),'ownerProcessStartIdentity':owner_birth,'phase':'TECHNOLOGY_'+a.rid+'_'+a.phase,'startedAtUtc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(started)),'receiptDirectory':str(run),'executionWindow':{'startUnix':started,'deadlineUnix':deadline}}
        with lf:lf.write((json.dumps(holder,indent=2)+'\n').encode());lf.flush();os.fsync(lf.fileno())
        fresh(run/'lease-claimed.json',{'holder':holder,'postAtomicClaimClock':True,'sourceManifestSHA256':sha(R/'tools/technology/source-manifest.json'),'causalRetry':a.cause})
        transform=(lambda p:str(p)) if a.rid=='win-x64' else linux
        sdkout=O/'artifacts';sdkout.mkdir(exist_ok=True);cache=O/'cache'/a.rid
        frame={'schema':'tail11-technology-frame/v1','rid':a.rid,'phase':a.phase,'nonce':nonce,'ownerPID':os.getpid(),'ownerBirth':owner_birth,'started':started,'deadline':deadline,'phaseDeadline':min(deadline-30,time.time()+60),'workspace':transform(R),'output':transform(run),'protocol':transform(PROTOCOL),'lease':transform(LEASE),'sourceCommit':head,'sourceHashes':manifest['files'],'sourceManifestSHA256':sha(R/'tools/technology/source-manifest.json'),'packet':transform(packet),'packetSha256':a.packet_sha,'contractSha256':sha(contract),'packages':transform(cache/'packages'),'cliHome':transform(cache/'home'),'nugetConfig':transform(O/('NuGet-'+a.rid+'.Config')),'packageWork':transform(O/'packages'/a.rid),'packageOut':transform(sdkout),'packageDirectory':transform(O/'packages'/a.rid/('tail-latency-evidence-bench-v0.1.0-preview.2-'+a.rid))}
        frame['packages']=transform(O/'cache/shared-packages')
        if a.phase=='package-check':frame['packageDirectory']=transform(O/'packages'/a.rid/('tail-latency-evidence-bench-v0.1.0-preview.2-'+a.rid))
        if a.phase=='package':
            candidates=list((O/'runs').glob(a.rid+'-restore-*/FINAL.json'));accepted=[x for x in candidates if read(x).get('status')=='ACCEPTED_CHANGED_SERVICING_PHASE' and read(x).get('sourceCommit')==head and read(x).get('packetSHA256')==a.packet_sha]
            need(len(accepted)==1,'ONE_ACCEPTED_CURRENT_RESTORE');frame['restoreFinal']=transform(accepted[0]);frame['restoreFinalSha256']=sha(accepted[0])
        frame_path=run/'frame.json';fresh(frame_path,frame)
        if a.rid=='win-x64':
            need(sha(PS)=='2a6769a3330dc1084d0154bfde7d164ab750ca7f700f313f9d417c1be78b2233' and sha(PY)=='4d6f5f81a4bca11191c4c7c6b43632694d0a4ce74e068619d8fdc161d469859a','EXACT_WINDOWS_TOOLS')
            argv=[str(PS),'-NoProfile','-NonInteractive','-File',str(R/'tools/technology/windows.ps1'),'-FramePath',str(frame_path),'-FrameSha',sha(frame_path)]
        else:argv=[r'C:\Windows\System32\wsl.exe','--distribution','Ubuntu-24.04','--user','root','--exec','/usr/bin/python3','-I','-S','-B',linux(R/'tools/technology/linux.py'),'--frame',linux(frame_path),'--frame-sha',sha(frame_path)]
        child=subprocess.Popen(argv,cwd=R,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,creationflags=0x08000400)
        stdout,stderr=child.communicate(timeout=max(1,min(deadline-time.time()-2,300-(time.monotonic()-mono)-2)))
        need(len(stdout)+len(stderr)<=262144,'SUPERVISOR_OUTPUT_CAP');fresh(run/'launcher.json',{'pid':child.pid,'originalPopenWaitReturned':True,'exitCode':child.returncode,'stdoutBytes':len(stdout),'stderrBytes':len(stderr),'stderrDiagnostic':stderr.decode('utf-8','replace')[:4096]})
        t=read(run/'terminal.json');need(t['nonce']==nonce and t['allOwnedTerminal'] is True,'EXACT_OWN_TERMINAL')
        if a.rid=='win-x64':need(t['active']==0,'OWN_JOB_POPULATION_ZERO')
        else:need(t['cgroupEmpty'] and t['cgroupRemoved'] and t['originalSystemdPopenWaitReturned'],'OWN_SYSTEMD_TERMINAL')
        terminal=True
        result=read(run/'result.json') if (run/'result.json').exists() else None
        accepted=child.returncode==0 and result is not None and result['status']=='PASS_CHANGED_SERVICING_PHASE' and t['forced'] is False
        fresh(run/'FINAL.json',{'status':'ACCEPTED_CHANGED_SERVICING_PHASE' if accepted else 'PHASE_HOLD','rid':a.rid,'phase':a.phase,'sourceCommit':head,'sourceManifestSHA256':frame['sourceManifestSHA256'],'packetSHA256':a.packet_sha,'terminalSHA256':sha(run/'terminal.json'),'resultSHA256':sha(run/'result.json') if result else None,'wholeSeconds':time.monotonic()-mono,'allOwnedTerminal':True,'formalVendorSupport':'NOT_CONFIRMED' if a.rid=='win-x64' else 'SUPPORTED_OS_ROW_ONLY_NOT_GLOBAL_ADMISSION','M1Calls':0,'Actions':0})
    except Exception as e:
        if child is None:terminal=True
        if not (run/'FINAL.json').exists():fresh(run/'FINAL.json',{'status':'OWNER_HOLD','code':str(e) if isinstance(e,RuntimeError) else type(e).__name__,'exceptionType':type(e).__name__,'claimed':claimed,'allOwnedTerminal':terminal,'noAutomaticRetry':True})
    finally:
        if claimed:
            h=read(LEASE);ours=h['projectId']=='11' and h['randomToken']==nonce and h['ownerPID']==os.getpid() and h['ownerProcessStartIdentity']==owner_birth
            if terminal and ours:
                fresh(run/'all-owned-terminal.json',{'nonce':nonce,'ownerPID':os.getpid(),'allOwnedTerminal':True})
                h=read(LEASE);need(h['randomToken']==nonce and h['ownerPID']==os.getpid() and h['ownerProcessStartIdentity']==owner_birth,'EXACT_OWNER_BEFORE_RELEASE');LEASE.unlink();fresh(run/'lease-released.json',{'nonce':nonce,'status':'EXACT_OWN_LEASE_RELEASED','terminalSHA256':sha(run/'all-owned-terminal.json')})
            else:fresh(run/'RECOVERY-REQUIRED.json',{'nonce':nonce,'status':'OWN_LEASE_RETAINED_TERMINAL_UNKNOWN','automaticReset':False})
    print(json.dumps({'receipt':str(run/'FINAL.json'),'result':read(run/'FINAL.json'),'leaseReleased':(run/'lease-released.json').exists()}))

if __name__=='__main__':main()
