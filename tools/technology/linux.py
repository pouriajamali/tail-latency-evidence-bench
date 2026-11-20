"""Existing systemd/cgroup engine adapted only for fixed Tail servicing phases."""
import argparse,hashlib,json,os,re,select,signal,stat,subprocess,time
from pathlib import Path

def need(v,c):
    if not v:raise RuntimeError(c)
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def fresh(p,v):
    b=(json.dumps(v,indent=2,sort_keys=True)+'\n').encode();need(len(b)<=262144,'PROOF_CAP')
    with Path(p).open('xb') as w:w.write(b);w.flush();os.fsync(w.fileno())
def proc(pid):
    p=Path('/proc')/str(pid);s=(p/'stat').read_text();return {'pid':pid,'birthTicks':s[s.rfind(')')+2:].split()[19],'cgroup':(p/'cgroup').read_text().strip()}

def main():
    p=argparse.ArgumentParser();p.add_argument('--frame',required=True);p.add_argument('--frame-sha',required=True);p.add_argument('--inner',action='store_true');a=p.parse_args()
    need(sha(a.frame)==a.frame_sha,'FRAME_BYTES');f=json.loads(Path(a.frame).read_bytes());need(f['schema']=='tail11-technology-frame/v1' and f['rid']=='linux-x64' and os.getuid()==0,'FIXED_ROOT_TRANSPORT')
    need(f['phase'] in ('qualify','restore','restore-tests','build','test','package','package-check','runtime-verify','negative'),'FIXED_PHASE')
    root=Path(f['workspace']);out=Path(f['output']);need(out.is_dir() and Path(__file__).resolve()==root/'tools/technology/linux.py','OWN_SOURCE_ROOT')
    need(sha(f['protocol'])=='fca40422e6abb4aa552759d7aadfd63fda6eccde4a8be3b272ff480fa72a6035','PROTOCOL')
    holder=json.loads(Path(f['lease']).read_bytes());need(holder['projectId']=='11' and holder['randomToken']==f['nonce'] and holder['ownerPID']==f['ownerPID'] and holder['ownerProcessStartIdentity']==f['ownerBirth'],'EXACT_CANONICAL_OWNER')
    need(f['deadline']-f['started']==300 and time.time()<f['deadline']-30,'WHOLE_CLOCK')
    for name,digest in f['sourceHashes'].items():need(sha(root/name)==digest,'SOURCE_DRIFT')
    unit='tail11tech-'+f['nonce']+'.service';cg=Path('/sys/fs/cgroup/system.slice')/unit
    if not a.inner:
        need(not cg.exists() and Path('/run/systemd/private').exists(),'EXISTING_SYSTEMD_NEW_OWN_SCOPE')
        transport={}
        for name in ['/usr/bin/systemd-run','/usr/bin/python3']:
            q=Path(name).resolve();s=q.stat();need(s.st_uid==0 and not s.st_mode&0o022 and stat.S_ISREG(s.st_mode),'ROOT_OWNED_OS_TRANSPORT');transport[str(q)]={'bytes':s.st_size,'sha256':sha(q)}
        hard_cap=20 if f['phase'] in ('qualify','runtime-verify') else 45
        runtime=max(1,min(hard_cap,int(min(f['phaseDeadline'],f['deadline']-30)-time.time()-5)))
        cmd=['/usr/bin/systemd-run','--wait','--collect','--pipe','--unit='+unit,'--uid=0','--gid=0','--property=Type=exec','--property=MemoryMax=536870912','--property=MemorySwapMax=0','--property=TasksMax=64','--property=CPUQuota=200%','--property=CPUQuotaPeriodSec=100ms','--property=RuntimeMaxSec='+str(runtime),'--property=TimeoutStopSec=1','--property=KillMode=control-group','--setenv=PYTHONDONTWRITEBYTECODE=1','/usr/bin/python3','-I','-S','-B',str(Path(__file__)),'--frame',a.frame,'--frame-sha',a.frame_sha,'--inner']
        fresh(out/'systemd-start.json',{'unit':unit,'argv':cmd,'transport':transport,'sourceHashes':f['sourceHashes'],'noGlobalSettingChanged':True})
        run=subprocess.Popen(cmd,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':'/usr/bin:/bin','HOME':'/root','LANG':'C','LC_ALL':'C','PYTHONDONTWRITEBYTECODE':'1'})
        stdout,stderr=run.communicate(timeout=max(1,min(60,f['deadline']-time.time()-3)))
        need(len(stdout)+len(stderr)<=262144,'ROOT_STDIO_CAP');need(not cg.exists(),'OWN_CGROUP_COLLECTED')
        inner=out/'inner-terminal.json';it=json.loads(inner.read_bytes()) if inner.exists() else None
        fresh(out/'terminal.json',{'schema':'tail11-technology-terminal/v1','nonce':f['nonce'],'originalSystemdPopenWaitReturned':True,'exitCode':run.returncode,'pid':run.pid,'allOwnedTerminal':True,'cgroupEmpty':True,'cgroupRemoved':True,'unit':unit,'workerOriginalWait':it.get('originalWaitpidReturned') if it else None,'forced':it.get('forced') if it else None,'worker':it.get('worker') if it else None,'resources':it.get('resources') if it else None,'stderrDiagnostic':stderr.decode('utf-8','replace')[:4096],'sourceFrameSHA256':a.frame_sha,'Actions':0,'M1Calls':0})
        need(run.returncode==0 and it is not None and it['originalWaitpidReturned'] and not it['forced'],'LINUX_PHASE_HOLD');return
    actual=next(x.split('::',1)[1] for x in Path('/proc/self/cgroup').read_text().splitlines() if x.startswith('0::'))
    need(actual=='/system.slice/'+unit and str(os.getpid()) in (cg/'cgroup.procs').read_text().split(),'OWN_PREALLOCATED_UNIT')
    inode=cg.stat().st_ino
    for n,v in {'memory.max':'536870912','memory.swap.max':'0','pids.max':'64','cpu.max':'200000 100000'}.items():need((cg/n).read_text().strip()==v,'ACTUAL_CAPS_BEFORE_FORK')
    child=None;terminal=False;forced=False;worker=None;code=1
    try:
        child=os.fork()
        if child==0:
            try:
                os.setgroups([]);os.setgid(1000);os.setuid(1000);os.chdir(root);os.kill(os.getpid(),signal.SIGSTOP)
                env={'PATH':'/usr/bin:/bin','HOME':'/home/ubuntu','LANG':'C','LC_ALL':'C','WSL_DISTRO_NAME':'Ubuntu-24.04','TAIL11_ROOT_UNIT':unit,'TAIL11_ROOT_NONCE':f['nonce'],'PYTHONDONTWRITEBYTECODE':'1'}
                entry='import sys;sys.path.insert(0,sys.argv.pop(1));import worker;worker.main()'
                os.execve('/usr/bin/python3',['/usr/bin/python3','-I','-S','-B','-c',entry,str(root/'tools/technology'),'--frame',a.frame,'--frame-sha',a.frame_sha],env)
            except BaseException:os._exit(126)
        end=min(time.time()+5,f['deadline']-30);stopped=False
        while time.time()<end:
            pid,status=os.waitpid(child,os.WNOHANG|os.WUNTRACED)
            if pid:
                need(os.WIFSTOPPED(status) and os.WSTOPSIG(status)==signal.SIGSTOP,'STOP_BEFORE_EXEC');stopped=True;break
            time.sleep(.01)
        need(stopped,'STOP_TIMEOUT');worker=proc(child);status=(Path('/proc')/str(child)/'status').read_text();need(re.search(r'^Uid:\s+1000\s+1000\s+1000\s+1000$',status,re.M) is not None and worker['cgroup'].endswith('/'+unit),'WORKER_UID_MEMBERSHIP')
        fresh(out/'profile.json',{'beforeResume':True,'worker':worker,'actualUID':1000,'cgroupInode':inode,'memory':536870912,'swap':0,'tasks':64,'cpuMax':'200000 100000','nonce':f['nonce']})
        os.kill(child,signal.SIGCONT);pidfd=os.pidfd_open(child)
        try:
            ready,_,_=select.select([pidfd],[],[],max(.001,min(55,f['phaseDeadline']-time.time(),f['deadline']-time.time()-30)))
            if not ready:
                os.kill(child,signal.SIGKILL);forced=True
            pid,status=os.waitpid(child,0);terminal=pid==child;code=os.waitstatus_to_exitcode(status)
        finally:os.close(pidfd)
    finally:
        need(cg.stat().st_ino==inode,'EXACT_OWN_SCOPE')
        if child is not None and not terminal:
            os.kill(child,signal.SIGKILL);forced=True;pid,status=os.waitpid(child,0);terminal=pid==child;code=os.waitstatus_to_exitcode(status)
        members=set((cg/'cgroup.procs').read_text().split())-{str(os.getpid())}
        need(not members,'NO_LIVE_OWNED_CHILDREN')
        resources={n:(cg/n).read_text().strip() for n in ['memory.peak','memory.current','memory.events','pids.current','cpu.stat','io.stat'] if (cg/n).exists()}
        fresh(out/'inner-terminal.json',{'nonce':f['nonce'],'originalWaitpidReturned':terminal,'exitCode':code,'worker':worker,'forced':forced,'allOwnedChildrenTerminal':not members,'resources':resources,'cgroupInode':inode})
    if code!=0 or forced:raise SystemExit(1)

if __name__=='__main__':main()
