"""Fixed Tail Linux role launcher: own cgroup, UID1000, exact terminal proof."""
from pathlib import Path
import argparse,hashlib,json,os,re,signal,subprocess,sys,time

def need(v,c):
    if not v:raise RuntimeError(c)
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def fresh(p,v):
    b=(json.dumps(v,sort_keys=True,indent=2)+'\n').encode();need(len(b)<=262144,'PROOF_CAP')
    with Path(p).open('xb') as w:w.write(b);w.flush();os.fsync(w.fileno())
def proc(pid):
    p=Path('/proc')/str(pid);s=(p/'stat').read_text();return {'pid':pid,'birth':s[s.rfind(')')+2:].split()[19],'cgroup':(p/'cgroup').read_text().strip()}
def main():
    p=argparse.ArgumentParser();p.add_argument('--frame',required=True);p.add_argument('--frame-sha',required=True);a=p.parse_args();f=json.loads(Path(a.frame).read_bytes())
    need(sha(a.frame)==a.frame_sha and f['schema']=='tail11-linux-role-frame/v1' and os.getuid()==0,'FIXED_ROOT_LAUNCH')
    need(f['mode'] in ('metadata','signature','loader-static','loader-symbols','loader-debug','loader-native-diagnostics') and re.fullmatch('[0-9a-f]{32}',f['nonce']) is not None,'FIXED_ROLE')
    need(time.time()<f['window']['deadlineUnix']-30 and f['window']['deadlineUnix']-f['window']['startUnix']==300,'WHOLE_CLOCK')
    source=Path(f['sourceDirectory']);out=Path(f['hostOutputLinuxPath']);need(out.is_dir(),'OWN_OUTPUT')
    for n,h in f['sourceHashes'].items():need(sha(source/n)==h,'SOURCE_BINDING')
    protocol=Path(f['protocolLinuxPath']);lease=Path(f['leaseLinuxPath']);need(sha(protocol)=='9120ca49a0d46673053aa0ec0cdbbc6f00731d71ea0b57ddab09e8fc3ac3ac8b','CANONICAL_PROTOCOL')
    holder=json.loads(lease.read_bytes());need(holder['projectId']=='11' and holder['randomToken']==f['nonce'] and holder['ownerPID']==f['ownerPID'] and holder['ownerProcessStartIdentity']==f['ownerBirth'],'CANONICAL_OWNER')
    preallocated=f.get('transport')=='EXISTING_ROOT_CAPPED_SYSTEMD_SERVICE'
    cgroot=Path('/sys/fs/cgroup');unit='tail11sig-'+f['nonce']+'.service';cg=(cgroot/'system.slice'/unit) if preallocated else (cgroot/unit);guest=Path('/home/ubuntu')/('tail11-linux-role-'+f['nonce'])
    need(not guest.exists(),'NO_EXISTING_GUEST_SCOPE_REUSE')
    if preallocated:
        actual=next(x.split('::',1)[1] for x in Path('/proc/self/cgroup').read_text().splitlines() if x.startswith('0::'))
        need(f['preallocatedUnit']==unit and actual=='/system.slice/'+unit and str(os.getpid()) in (cg/'cgroup.procs').read_text().split(),'EXACT_PREALLOCATED_OWN_SERVICE')
    else:need(str(cg.parent)==str(cgroot) and not cg.exists(),'NO_EXISTING_SCOPE_REUSE')
    created=False
    child=None;terminal=False;code=1;reason='LAUNCH_HOLD';killed=False;worker=None
    try:
        if f.get('transport')=='EXISTING_UBUNTU_USER_SUDO_N':
            sudo=Path('/usr/bin/sudo');st=sudo.stat();need(st.st_uid==0 and not st.st_mode&0o022 and sha(sudo)=='6ae6665cc51295ea8aaba94a3377dafa563f950aafc6296c0704fb33401a31ff','EXISTING_SUDO_TRANSPORT_IDENTITY')
        if not preallocated:
            need({'cpu','memory','pids'}<=set((cgroot/'cgroup.subtree_control').read_text().split()),'EXISTING_CGROUP_CONTROLLERS_REQUIRED');cg.mkdir()
        created=True;cginode=cg.stat().st_ino
        guest.mkdir(mode=0o700);os.chown(guest,1000,1000)
        if not preallocated:
            for n,v in {'cpu.max':'200000 100000','memory.max':'536870912','memory.swap.max':'0','pids.max':'64'}.items():(cg/n).write_text(v)
        need((cg/'cpu.max').read_text().strip()=='200000 100000' and (cg/'memory.max').read_text().strip()=='536870912' and (cg/'memory.swap.max').read_text().strip()=='0' and (cg/'pids.max').read_text().strip()=='64','ACTUAL_CAPS_BEFORE_FORK')
        gf=dict(f);gf['guestOutputPath']=str(guest);gp=guest/'frame.json';fresh(gp,gf);os.chown(gp,1000,1000)
        module={'metadata':'linux_role_probe','signature':'linux_ssh_role','loader-static':'linux_static_input','loader-symbols':'linux_loader_symbols','loader-debug':'linux_loader_symbols','loader-native-diagnostics':'linux_loader_diagnostics'}[f['mode']]
        need(module+'.py' in f['sourceHashes'],'FIXED_ENTRY_SOURCE')
        child=os.fork()
        if child==0:
            try:
                (cg/'cgroup.procs').write_text(str(os.getpid()));os.setgroups([]);os.setgid(1000);os.setuid(1000)
                os.chdir(guest);os.kill(os.getpid(),signal.SIGSTOP)
                env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','HOME':str(guest),'TMPDIR':str(guest),'TEMP':str(guest),'TMP':str(guest),'TAIL11_ROOT_UNIT':cg.name,'TAIL11_ROOT_NONCE':f['nonce'],'WSL_DISTRO_NAME':'Ubuntu-24.04','PYTHONDONTWRITEBYTECODE':'1'}
                entry='import sys;sys.path.insert(0,sys.argv.pop(1));import '+module+';'+module+'.main()'
                os.execve('/usr/bin/python3',['/usr/bin/python3','-I','-S','-B','-c',entry,str(source),'--frame',str(gp),'--frame-sha',sha(gp)],env)
            except BaseException:os._exit(126)
        stop_deadline=min(time.time()+5,f['window']['deadlineUnix']-30);stopped=False
        while time.time()<stop_deadline:
            pid,status=os.waitpid(child,os.WNOHANG|os.WUNTRACED)
            if pid:
                need(os.WIFSTOPPED(status) and os.WSTOPSIG(status)==signal.SIGSTOP,'WORKER_STOP_BEFORE_EXEC');stopped=True;break
            time.sleep(.01)
        need(stopped,'WORKER_STOP_TIMEOUT');worker=proc(child)
        status=(Path('/proc')/str(child)/'status').read_text();need(re.search(r'^Uid:\s+1000\s+1000\s+1000\s+1000$',status,re.M) is not None and worker['cgroup'].endswith('/'+cg.name) and str(child) in (cg/'cgroup.procs').read_text().split(),'ACTUAL_CHILD_UID_AND_MEMBERSHIP_BEFORE_EXEC')
        fresh(out/'worker-before-exec.json',{'worker':worker,'actualUIDs':[1000]*4,'cgroupPath':str(cg),'cgroupInode':cginode,'memoryMax':536870912,'swapMax':0,'pidsMax':64,'cpuMax':'200000 100000','beforeResume':True,'nonce':f['nonce']})
        os.kill(child,signal.SIGCONT)
        pidfd=os.pidfd_open(child,0)
        try:
            import select
            left=min(60,f['window']['deadlineUnix']-30-time.time());need(left>0,'WHOLE_WORK_CLOCK');ready,_,_=select.select([pidfd],[],[],left)
            if not ready:
                need(cg.stat().st_ino==cginode,'EXACT_OWN_CGROUP');(cg/'cgroup.kill').write_text('1');killed=True
            pid,status=os.waitpid(child,0);terminal=pid==child;code=os.waitstatus_to_exitcode(status)
        finally:os.close(pidfd)
        reason='ROLE_COMPLETED' if code==0 and not killed else 'ROLE_HOLD'
    except Exception as e:reason=str(e) if isinstance(e,RuntimeError) else 'LINUX_LAUNCHER_HOLD'
    finally:
        if not created:
            fresh(out/'linux-role-terminal.json',{'schema':'tail11-linux-role-terminal/v1','status':reason,'returncode':1,'originalWaitpidReturned':False,'noOwnedChildCreated':True,'allOwnedTerminal':True,'cgroupEmpty':True,'cgroupRemoved':False,'cgroupNeverCreated':True,'forced':False,'frameSHA256':a.frame_sha,'nonce':f['nonce'],'proofs':{}})
            raise SystemExit(1)
        need(cg.stat().st_ino==cginode,'EXACT_OWN_CGROUP_BEFORE_TEARDOWN')
        if not preallocated and (cg/'cgroup.procs').read_text().split():(cg/'cgroup.kill').write_text('1');killed=True
        if child is not None and not terminal:
            try:pid,status=os.waitpid(child,0);terminal=pid==child;code=os.waitstatus_to_exitcode(status)
            except ChildProcessError:terminal=True
        if child is None:terminal=True
        end=min(time.time()+10,f['window']['deadlineUnix'])
        while (set((cg/'cgroup.procs').read_text().split())-({str(os.getpid())} if preallocated else set())) and time.time()<end:time.sleep(.01)
        members=(cg/'cgroup.procs').read_text().split();empty=(set(members)<={str(os.getpid())}) if preallocated else not members;events=(cg/'cgroup.events').read_text().strip();need(empty and (preallocated or re.search(r'^populated 0$',events,re.M) is not None),'OWN_CGROUP_TERMINAL_UNKNOWN')
        names=('metadata.json','profile.json','signature-proof.json','signature-controls.json','elf-closure.json','loader-static.json','loader.elf','loader-symbols.json','loader.symtab','loader.strtab','loader-symbols-request0.json','loader-symbols-request1.json','loader-cpu-diagnostics.json','loader-native-cpu.txt','loader-native-tunables.txt')
        files={};total=0
        for name in names:
            src=guest/name
            if src.exists():
                need(src.is_file() and not src.is_symlink() and src.stat().st_size<=262144,'PRIVATE_PROOF_BOUNDS');b=src.read_bytes();total+=len(b);need(total<=1048576,'ALL_ROLE_PROOF_CAP')
                with (out/name).open('xb') as w:w.write(b);w.flush();os.fsync(w.fileno())
                files[name]={'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
        if not preallocated:(cg).rmdir()
        terminal_name='service-worker-terminal.json' if preallocated else 'linux-role-terminal.json'
        fresh(out/terminal_name,{'schema':'tail11-linux-role-terminal/v1','status':reason,'returncode':code,'originalWaitpidReturned':terminal if child is not None else False,'noOwnedChildCreated':child is None,'worker':worker,'allOwnedTerminal':False if preallocated else terminal and empty,'cgroupEmpty':False if preallocated else empty,'cgroupRemoved':not preallocated,'allOwnedChildrenTerminal':terminal and empty,'preallocatedUnit':unit if preallocated else None,'serviceCoordinatorStillLive':preallocated,'cgroupInode':cginode,'forced':killed,'frameSHA256':a.frame_sha,'nonce':f['nonce'],'proofs':files,'guestEvidenceRoot':str(guest)})
    if reason!='ROLE_COMPLETED':raise SystemExit(1)

if __name__=='__main__':main()
