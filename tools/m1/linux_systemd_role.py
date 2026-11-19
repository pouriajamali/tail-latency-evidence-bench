"""Existing root systemd-run method, Tail's own unchanged finite resource caps."""
from pathlib import Path
import argparse,hashlib,json,os,stat,subprocess,sys,time

def need(v,c):
    if not v:raise RuntimeError(c)
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def fresh(p,v):
    b=(json.dumps(v,sort_keys=True,indent=2)+'\n').encode();need(len(b)<=262144,'PROOF256K')
    with Path(p).open('xb') as f:f.write(b);f.flush();os.fsync(f.fileno())
def main():
    p=argparse.ArgumentParser();p.add_argument('--frame',required=True);p.add_argument('--frame-sha',required=True);a=p.parse_args();raw=Path(a.frame).read_bytes();need(len(raw)<=32768 and hashlib.sha256(raw).hexdigest()==a.frame_sha,'FIXED_FRAME');f=json.loads(raw)
    need(os.getuid()==0 and f['mode'] in ('signature','loader-native-diagnostics') and f['transport']=='EXISTING_ROOT_SYSTEMD_SAME_CAPS','ROOT_ROLE_TRANSPORT')
    source=Path(f['sourceDirectory']);out=Path(f['hostOutputLinuxPath']);started=time.monotonic();end=min(time.time()+60,f['window']['deadlineUnix']-30)
    need(f['window']['deadlineUnix']-f['window']['startUnix']==300 and end-time.time()>10,'UNCHANGED_CLOCK')
    for n,h in f['sourceHashes'].items():need(sha(source/n)==h,'SOURCE_BINDING')
    need(sha(f['protocolLinuxPath'])=='9120ca49a0d46673053aa0ec0cdbbc6f00731d71ea0b57ddab09e8fc3ac3ac8b','CANONICAL_PROTOCOL')
    lease=json.loads(Path(f['leaseLinuxPath']).read_bytes());need(lease['projectId']=='11' and lease['randomToken']==f['nonce'] and lease['ownerPID']==f['ownerPID'] and lease['ownerProcessStartIdentity']==f['ownerBirth'],'EXACT_CANONICAL_OWNER')
    tools={}
    for s in ('/usr/bin/systemd-run','/usr/bin/python3'):
        q=Path(s).resolve();st=q.stat();need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and not st.st_mode&0o022,'EXISTING_ROOT_OS_TRANSPORT');tools[str(q)]={'bytes':st.st_size,'sha256':sha(q)}
    unit='tail11sig-'+f['nonce']+'.service';cg=Path('/sys/fs/cgroup/system.slice')/unit
    need(not cg.exists() and Path('/run/systemd/private').exists(),'EXISTING_SYSTEMD_NEW_OWN_SCOPE')
    inner=dict(f);inner['transport']='EXISTING_ROOT_CAPPED_SYSTEMD_SERVICE';inner['preallocatedUnit']=unit;fp=out/'frame-systemd-unit.json';fresh(fp,inner)
    runtime=min(50,max(1,int(end-time.time()-6)))
    argv=['/usr/bin/systemd-run','--wait','--collect','--pipe','--unit='+unit,'--uid=0','--gid=0','--property=Type=exec','--property=MemoryMax=536870912','--property=MemorySwapMax=0','--property=TasksMax=64','--property=CPUQuota=200%','--property=CPUQuotaPeriodSec=100ms','--property=RuntimeMaxSec='+str(runtime),'--property=TimeoutStopSec=1','--property=KillMode=control-group','--setenv=PYTHONDONTWRITEBYTECODE=1','/usr/bin/python3','-I','-S','-B',str(source/'linux_cgroup_launcher.py'),'--frame',str(fp),'--frame-sha',sha(fp)]
    fresh(out/'systemd-role-start.json',{'schema':'tail11-own-systemd-role-start/v1','argv':argv,'unit':unit,'sourceManifestSHA256':f['sourceManifestSHA256'],'frameSHA256':sha(fp),'transportFiles':tools,'noGlobalControllerSettingsChanged':True,'noAdmissionTransferred':True,'qualificationSeconds':60,'rootOnlyCoordinator':True,'targetUIDGID':[1000,1000]})
    proc=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','HOME':'/root','PYTHONDONTWRITEBYTECODE':'1'})
    stdout,stderr=proc.communicate(timeout=max(.001,min(end-time.time(),60-(time.monotonic()-started))))
    need(len(stdout)+len(stderr)<=262144,'ROOT_STARTER_OUTPUT_CAP')
    fresh(out/'systemd-role-original-wait.json',{'pid':proc.pid,'originalPopenWaitReturned':True,'exitCode':proc.returncode,'stdoutBytes':len(stdout),'stderrBytes':len(stderr),'stderrDiagnostic':stderr.decode('utf-8','replace')[:4096],'unit':unit})
    need(not cg.exists(),'OWN_COLLECTED_CGROUP_REQUIRED')
    terminal_path=out/'service-worker-terminal.json';t=json.loads(terminal_path.read_bytes()) if terminal_path.exists() else None
    if t is not None:need(t['nonce']==f['nonce'] and t['frameSHA256']==sha(fp) and t['preallocatedUnit']==unit,'EXACT_SERVICE_WORKER_TERMINAL')
    proof={k:t[k] for k in ('worker','proofs','guestEvidenceRoot','cgroupInode','forced')} if t else {'worker':None,'proofs':{},'guestEvidenceRoot':None,'cgroupInode':None,'forced':None}
    admitted=(proc.returncode==0 and t is not None and t['returncode']==0 and t['allOwnedChildrenTerminal'] is True)
    final={'schema':'tail11-linux-role-terminal/v1','status':'ROLE_COMPLETED' if admitted else 'ROLE_HOLD','returncode':proc.returncode,'originalWaitpidReturned':True,'originalWaitTarget':'OWN_SYSTEMD_RUN_STARTER','originalWorkerWaitpidReturned':t['originalWaitpidReturned'] if t else None,'noOwnedChildCreated':t['noOwnedChildCreated'] if t else None,'workerProofPresent':t is not None,'allOwnedTerminal':True,'cgroupEmpty':True,'cgroupRemoved':True,'wholeOwnServiceCollected':True,'frameSHA256':a.frame_sha,'nonce':f['nonce'],**proof}
    fresh(out/'linux-role-terminal.json',final)
    if final['status']!='ROLE_COMPLETED':raise SystemExit(1)
if __name__=='__main__':main()
