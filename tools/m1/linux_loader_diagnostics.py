"""Two never-before-run public native loader diagnostics, metadata only."""
from pathlib import Path
import argparse,hashlib,json,os,re,resource,select,signal,stat,time
import support as S

LOADER='/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2'
PIN='c20a2dc8917c755f02b94049356320fe1f62ac7d9f8994731f807d9df39302da'
def main():
    p=argparse.ArgumentParser();p.add_argument('--frame',required=True);p.add_argument('--frame-sha',required=True);a=p.parse_args();raw=S.raw(a.frame,32768);S.need(hashlib.sha256(raw).hexdigest()==a.frame_sha,'FRAME_HASH');f=json.loads(raw);out=Path(f['guestOutputPath']);end=min(time.time()+20,f['window']['deadlineUnix']-30)
    result={'schema':'tail11-public-loader-native-metadata/v1','status':'HOLD','admitted':False,'nativeM1Calls':0,'signatureInvocations':0,'networkCalls':0,'nonce':f['nonce'],'commands':[]};fd=None
    try:
        S.need(f['mode']=='loader-native-diagnostics' and f['schema']=='tail11-linux-role-frame/v1','EXACT_NEW_METADATA_SCOPE');result['actualKernel']=S.actual_profile({'runNonce':f['nonce']},'linux-x64')
        for n,h in f['sourceHashes'].items():S.need(S.sha(Path(f['sourceDirectory'])/n)==h,'SOURCE_BINDING')
        fd=os.open(LOADER,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC);st=os.fstat(fd);S.need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and not st.st_mode&0o022 and st.st_size==236616,'EXACT_ROOT_LOADER_DATA_TOOL');b=os.pread(fd,st.st_size,0);S.need(hashlib.sha256(b).hexdigest()==PIN,'EXACT_NATIVE_LOADER_SHA')
        env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','HOME':str(out),'TMPDIR':str(out)}
        for option,name in (('--list-diagnostics','loader-native-cpu.txt'),('--list-tunables','loader-native-tunables.txt')):
            S.need(end-time.time()>1,'NATIVE_METADATA_ROLE20');stdout=out/name;stderr=out/(name+'.stderr')
            with stdout.open('xb') as so,stderr.open('xb') as se:
                pid=os.fork()
                if pid==0:
                    try:
                        os.dup2(so.fileno(),1);os.dup2(se.fileno(),2);resource.setrlimit(resource.RLIMIT_FSIZE,(131072,131072));os.kill(os.getpid(),signal.SIGSTOP);os.execve(LOADER,[LOADER,option],env)
                    except BaseException:os._exit(126)
                handle=os.pidfd_open(pid);wp,status=os.waitpid(pid,os.WUNTRACED);S.need(wp==pid and os.WIFSTOPPED(status),'DIAGNOSTIC_STOP_BEFORE_EXEC')
                birth=(Path('/proc')/str(pid)/'stat').read_text().split(') ',1)[1].split()[19]
                S.need((Path('/proc')/str(pid)/'cgroup').read_text()==Path('/proc/self/cgroup').read_text(),'DIAGNOSTIC_OWN_CGROUP')
                timed=False;waited=False
                try:
                    os.kill(pid,signal.SIGCONT);ready,_,_=select.select([handle],[],[],min(5,max(.001,end-time.time())))
                    if not ready:timed=True;signal.pidfd_send_signal(handle,signal.SIGKILL)
                    wp,status=os.waitpid(pid,0);waited=wp==pid;rc=os.waitstatus_to_exitcode(status)
                finally:
                    if not waited:
                        try:signal.pidfd_send_signal(handle,signal.SIGKILL)
                        except ProcessLookupError:pass
                        try:os.waitpid(pid,0)
                        except ChildProcessError:pass
                    os.close(handle)
            S.need(stdout.stat().st_size<=131072 and stderr.stat().st_size<=32768,'DIAGNOSTIC_OUTPUT_CAP')
            result['commands'].append({'argv':[LOADER,option],'pid':pid,'birth':birth,'originalWaitpidReturned':waited,'originalPIDFDTerminal':True,'beforeExecStopAndCgroupMatched':True,'hardFileBytes':131072,'exitCode':rc,'forced':timed,'stdout':{'name':name,'bytes':stdout.stat().st_size,'sha256':S.sha(stdout)},'stderrBytes':stderr.stat().st_size})
            S.need(rc==0 and not timed,'NATIVE_METADATA_COMMAND_REQUIRED')
        text=(out/'loader-native-cpu.txt').read_text('ascii');numeric={}
        for line in text.splitlines():
            if not line.startswith('x86.cpu_features.'):continue
            k,sep,v=line.partition('=');S.need(sep and re.fullmatch('0x[0-9a-fA-F]+',v),'NATIVE_CPU_DIAGNOSTIC_FORMAT');S.need(k not in numeric,'UNIQUE_NATIVE_CPU_DIAGNOSTIC');numeric[k]=int(v,16)
        S.need(100<=len(numeric)<=1024,'COMPLETE_PUBLIC_CPU_DIAGNOSTICS')
        S.need(hashlib.sha256(os.pread(fd,st.st_size,0)).hexdigest()==PIN and os.fstat(fd).st_ino==st.st_ino,'LOADER_HELD_THROUGH_DATA_TERMINAL')
        result.update(status='NATIVE_LOADER_DIAGNOSTICS_METADATA_ONLY',loaderSHA256=PIN,bootID=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),numericCPU=numeric,elapsedSeconds=20-(end-time.time()),successfulMetadataReplayed=False,metadataIsNotRoleAdmission=True)
    except Exception as e:result.update(code=getattr(e,'code','NATIVE_LOADER_METADATA_HOLD'),exceptionType=type(e).__name__,errno=getattr(e,'errno',None))
    finally:
        if fd is not None:os.close(fd)
    S.fresh(out/'loader-cpu-diagnostics.json',result,262144)
    if result['status']!='NATIVE_LOADER_DIAGNOSTICS_METADATA_ONLY':raise SystemExit(1)
if __name__=='__main__':main()
