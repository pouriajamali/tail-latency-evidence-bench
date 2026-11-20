"""Fixed bounded servicing consumer; never execute an M1 case or benchmark."""
import argparse,copy,ctypes,hashlib,importlib.util,json,os,stat,subprocess,sys,time
from pathlib import Path,PurePosixPath
import receiver

def need(v,c):
    if not v:raise RuntimeError(c)

def sha(p):return receiver.sha(p)

def read(p,cap=1048576):
    p=Path(p);need(p.is_file() and not p.is_symlink() and p.stat().st_size<=cap,'BOUNDED_REGULAR_JSON')
    with p.open('rb') as stream:b=stream.read(cap+1)
    need(len(b)<=cap,'JSON_CAP');return json.loads(b)

def fresh(p,v):
    raw=(json.dumps(v,indent=2,sort_keys=True)+'\n').encode('utf-8');need(len(raw)<=262144,'PROOF_CAP')
    with Path(p).open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())

def storage(f,root):
    total=proof=count=0
    roots=[Path(x) for x in f['scratchRoots']]
    roots += [root/name for name in ['src/Evidence/bin','src/Evidence/obj','src/Bench.Cli/bin','src/Bench.Cli/obj','tests/Evidence.Tests/bin','tests/Evidence.Tests/obj']]
    for base in roots:
        if not base.exists():continue
        pending=[base]
        while pending:
            directory=pending.pop()
            with os.scandir(directory) as entries:
                for entry in entries:
                    info=entry.stat(follow_symlinks=False)
                    need(not stat.S_ISLNK(info.st_mode),'NO_LINKED_SCRATCH')
                    if stat.S_ISDIR(info.st_mode):pending.append(Path(entry.path))
                    elif stat.S_ISREG(info.st_mode):
                        size=info.st_size;total+=size;count+=1
                        p=Path(entry.path)
                        if '/runs/' in p.as_posix() and p.suffix in ('.json','.log','.xml'):proof+=size
                        need(total<=1073741824 and proof<=8388608 and count<=4096,'ACTUAL_SCRATCH_PROOF_BOUND')
    need(total<=1073741824 and proof<=8388608 and count<=4096,'ACTUAL_SCRATCH_PROOF_BOUND')
    return {'actualScratchBytes':total,'actualProofBytes':proof,'files':count,'scratchLimit':1073741824,'proofLimit':8388608,'scope':'Current task scratch roots and affected build outputs only; immutable SDK/M1 inputs excluded'}

def bound_packet(data,contract_sha):
    result=receiver.packet(data,contract_sha)
    for rid,entry in data['roots'].items():
        expected='E:/Codex WorkSpace/Git Projects/data-admission-gate/state/toolchain/'+rid
        need(entry['pathWindows'].replace('\\','/').rstrip('/')==expected,'EXACT_RETAINED_SDK_ROOT')
        need(entry['pathLinux']=='/mnt/e/'+expected[3:],'EXACT_SAME_PHYSICAL_SDK_ROOT')
    return result

def path(ref):
    if os.name=='nt':return Path(ref['pathWindows'])
    return Path(ref.get('pathLinux') or ('/mnt/e/'+ref['pathWindows'].replace('\\','/')[3:]))

def held_file(p,expected,size,budget,holds):
    p=Path(p);need(p.is_file() and not p.is_symlink(),'INPUT_REGULAR_FILE')
    need(type(size) is int and size>=0 and p.stat().st_size==size,'INPUT_SIZE')
    budget[0]+=size;budget[1]+=1;need(budget[0]<=67108864 and budget[1]<=256,'CONSUMING_READ_FILE_CAP')
    if os.name=='nt':
        import msvcrt
        k=ctypes.WinDLL('kernel32',use_last_error=True);k.CreateFileW.restype=ctypes.c_void_p;k.CreateFileW.argtypes=[ctypes.c_wchar_p,ctypes.c_uint,ctypes.c_uint,ctypes.c_void_p,ctypes.c_uint,ctypes.c_uint,ctypes.c_void_p]
        h=k.CreateFileW(str(p),0x80000000,1,None,3,0x00200000,None)
        need(h not in (None,ctypes.c_void_p(-1).value),'DENY_WRITE_DELETE_INPUT_HANDLE')
        f=os.fdopen(msvcrt.open_osfhandle(h,os.O_RDONLY|os.O_BINARY),'rb')
    else:f=p.open('rb')
    before=os.fstat(f.fileno());digest=hashlib.sha256()
    consumed=0
    for b in iter(lambda:f.read(65536),b''):
        consumed+=len(b);need(consumed<=size,'CONSUMING_FILE_GREW');digest.update(b)
    need(consumed==size and digest.hexdigest()==expected,'CONSUMING_BYTES_CHANGED')
    after=os.fstat(f.fileno());need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns),'CONSUMING_FILE_RACE')
    f.seek(0);holds.append((f,p,(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns)))

def source(f):
    root=Path(f['workspace']);need(root.resolve()==Path(__file__).resolve().parents[2],'ACTUAL_CHECKOUT')
    need(len(f['sourceHashes'])<=32,'SOURCE_FILE_SET')
    for name,digest in f['sourceHashes'].items():
        p=root/name;need(root.resolve() in p.resolve().parents and sha(p)==digest,'SOURCE_DRIFT')
    profile=read(root/'tools/technology/consumer-profile.json');need(profile['protocolSha256']==sha(f['protocol']),'PROTOCOL_CHANGED')
    h=read(f['lease'],16384);need(h['projectId']=='11' and h['randomToken']==f['nonce'] and h['ownerPID']==f['ownerPID'] and h['ownerProcessStartIdentity']==f['ownerBirth'],'EXACT_CANONICAL_OWNER')
    need(f['deadline']-f['started']==300 and f['started']<=time.time()<f['deadline']-30,'POST_CLAIM_WINDOW')
    return root,profile

def kernel(f,root):
    p=root/'tools/m1/support.py';need(sha(p)==f['sourceHashes']['tools/m1/support.py'],'EXISTING_KERNEL_WITNESS')
    spec=importlib.util.spec_from_file_location('tail11_existing_kernel',p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    if os.name=='nt':
        result=m.actual_profile({'runNonce':f['nonce']},'win-x64')
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r'SOFTWARE\Microsoft\Windows NT\CurrentVersion') as key:
            result['observedWindows']={n:winreg.QueryValueEx(key,n)[0] for n in ['DisplayVersion','CurrentBuild','UBR','EditionID']}
        result['formalVendorSupport']='NOT_CONFIRMED';result['hostClass']='OBSERVED_EXPERIMENTAL'
    else:
        result=m.actual_profile({'runNonce':f['nonce']},'linux-x64');result['osRelease']={}
        for line in Path('/etc/os-release').read_text().splitlines():
            if '=' in line:
                k,v=line.split('=',1)
                if k in ('ID','VERSION_ID'):result['osRelease'][k]=v.strip('"')
        need(result['osRelease']=={'ID':'ubuntu','VERSION_ID':'24.04'},'ACTUAL_UBUNTU_24_04')
        result['formalVendorSupport']='SUPPORTED_OS_ROW_ONLY_NOT_GLOBAL_ADMISSION'
    return result

def sdk_files(packet,rid,phase,budget,holds):
    entry=packet['roots'][rid];root=path(entry);inv=entry['memberInventory'];inv_path=path(inv)
    need(inv_path.stat().st_size==inv['bytes'] and inv['bytes']<=67108864,'SEALED_INVENTORY_SIZE')
    with inv_path.open('rb') as stream:inventory=stream.read(inv['bytes']+1)
    need(len(inventory)==inv['bytes'] and hashlib.sha256(inventory).hexdigest()==inv['sha256'],'SEALED_INVENTORY_BYTES')
    budget[0]+=len(inventory);budget[1]+=1;need(budget[0]<=67108864,'INVENTORY_READ_CAP')
    archive_name=Path(entry['archive']['pathWindows'].replace('\\','/')).name
    records={}
    for line in inventory.splitlines():
        r=json.loads(line)
        if r.get('archive')==archive_name and r.get('type')=='file':records[r['path'].removeprefix('./')]=r
    need(len(records)>=1000,'SEALED_SDK_MEMBER_GRAPH')
    if os.name=='nt':
        names=['dotnet.exe','host/fxr/10.0.15/hostfxr.dll','shared/Microsoft.NETCore.App/10.0.15/coreclr.dll','shared/Microsoft.NETCore.App/10.0.15/clrjit.dll','shared/Microsoft.NETCore.App/10.0.15/hostpolicy.dll','shared/Microsoft.NETCore.App/10.0.15/System.Private.CoreLib.dll']
    else:
        names=['dotnet','host/fxr/10.0.15/libhostfxr.so','shared/Microsoft.NETCore.App/10.0.15/libcoreclr.so','shared/Microsoft.NETCore.App/10.0.15/libclrjit.so','shared/Microsoft.NETCore.App/10.0.15/libhostpolicy.so','shared/Microsoft.NETCore.App/10.0.15/System.Private.CoreLib.dll']
    names+=['sdk/10.0.404/dotnet.dll','sdk/10.0.404/dotnet.deps.json','sdk/10.0.404/dotnet.runtimeconfig.json']
    if phase in ('restore','restore-tests','build','test','package','evaluate'):names+=['sdk/10.0.404/MSBuild.dll','sdk/10.0.404/MSBuild.deps.json']
    if phase in ('build','package'):names+=['sdk/10.0.404/Roslyn/bincore/csc.dll','sdk/10.0.404/Roslyn/bincore/Microsoft.CodeAnalysis.dll','sdk/10.0.404/Roslyn/bincore/Microsoft.CodeAnalysis.CSharp.dll']
    seen=[]
    for name in names:
        need(name in records,'REQUIRED_SDK_MEMBER_UNKNOWN')
        row=records[name];p=root/name
        need(root.resolve() in p.resolve().parents,'SDK_ROOT_ESCAPE')
        held_file(p,row['sha256'],row['bytes'],budget,holds);seen.append({'path':name,'bytes':row['bytes'],'sha256':row['sha256']})
    return root/('dotnet.exe' if os.name=='nt' else 'dotnet'),seen

def main():
    a=argparse.ArgumentParser();a.add_argument('--frame',required=True);a.add_argument('--frame-sha',required=True);args=a.parse_args()
    need(sha(args.frame)==args.frame_sha,'FRAME_BYTES');f=read(args.frame);root,profile=source(f);out=Path(f['output']);need(out.is_dir(),'OWN_OUTPUT')
    phase=f['phase'];need(phase in ('qualify','restore','restore-tests','build','test','package','package-check','runtime-verify','runtime-verify-linux-data','negative','evaluate'),'FIXED_PHASE')
    rid='win-x64' if os.name=='nt' else 'linux-x64';need(f['rid']==rid,'NATIVE_RID_ONLY')
    actual=kernel(f,root);fresh(out/'kernel.json',actual)
    packet_path=Path(f['packet']);need(sha(packet_path)==f['packetSha256'],'PACKET_BYTES');packet=read(packet_path)
    bound_packet(packet,f['contractSha256'])
    if phase=='negative':
        controls=[]
        for name,mutate,expected in [('wrong-source',lambda q:q['sourceHashes'].update({'tools/technology/worker.py':'0'*64}),'SOURCE_DRIFT'),('wrong-canonical-owner',lambda q:q.update(nonce='0'*32),'EXACT_CANONICAL_OWNER')]:
            q=copy.deepcopy(f);mutate(q)
            try:source(q)
            except RuntimeError as e:need(str(e)==expected,'EXPECTED_NEGATIVE_GUARD');controls.append({'name':name,'rejected':True,'guard':str(e),'SDKCalls':0})
            else:raise RuntimeError('NEGATIVE_ACCEPTED')
        target=path(packet['roots'][rid])/('dotnet.exe' if os.name=='nt' else 'dotnet');handles=[];budget=[0,0]
        try:held_file(target,'0'*64,target.stat().st_size,budget,handles)
        except RuntimeError as e:need(str(e)=='CONSUMING_BYTES_CHANGED','EXPECTED_BYTE_GUARD');controls.append({'name':'wrong-SDK-entry-bytes','rejected':True,'guard':str(e),'SDKCalls':0,'readBytes':budget[0]})
        else:raise RuntimeError('NEGATIVE_ACCEPTED')
        finally:
            for handle,_,_ in handles:handle.close()
        fresh(out/'result.json',{'status':'PASS_CHANGED_SERVICING_PHASE','phase':phase,'rid':rid,'controls':controls,'sourceCommit':f['sourceCommit'],'packetSHA256':f['packetSha256'],'formalVendorSupport':actual['formalVendorSupport'],'SDKCalls':0,'M1Calls':0,'Actions':0});return
    holds=[];budget=[0,0];commands=[];started=time.monotonic();run=None
    try:
        sdk,files=sdk_files(packet,rid,phase,budget,holds)
        fresh(out/'input-binding.json',{'sdk':str(sdk),'criticalFiles':files,'consumingReadBytes':budget[0],'consumingFiles':budget[1],'sealedInventoryReused':True,'fullSDKArchiveOrTreeRehashed':False,'globalSDKOrProviderClosureClaimed':False,'producerAdmissionTransferred':False,'packetSHA256':f['packetSha256']})
        env={**os.environ,'DOTNET_ROOT':str(sdk.parent),'DOTNET_CLI_HOME':f['cliHome'],'DOTNET_SKIP_FIRST_TIME_EXPERIENCE':'1','DOTNET_CLI_TELEMETRY_OPTOUT':'1','TESTINGPLATFORM_TELEMETRY_OPTOUT':'1','DOTNET_GENERATE_ASPNET_CERTIFICATE':'false','DOTNET_MULTILEVEL_LOOKUP':'0','DOTNET_NOLOGO':'1','DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE':'true','MSBUILDDISABLENODEREUSE':'1','DOTNET_ROLL_FORWARD':'Disable','DOTNET_CLI_USE_MSBUILD_SERVER':'0','NUGET_PACKAGES':f['packages'],'NUGET_HTTP_CACHE_PATH':f['httpCache'],'NUGET_SCRATCH':f['nugetScratch'],'TMPDIR':f['nativeTmp'],'TMP':f['nativeTmp'],'TEMP':f['nativeTmp'],'PYTHONDONTWRITEBYTECODE':'1','COMPlus_GCHeapHardLimit':'0x10000000','UseSharedCompilation':'false','BuildInParallel':'false','DOTNET_PROCESSOR_COUNT':'2'}
        for name in ['cliHome','packages']:Path(f[name]).mkdir(parents=True,exist_ok=True)
        env['HOME']=f['cliHome']
        if os.name=='nt':
            env.update(USERPROFILE=f['cliHome'],APPDATA=str(Path(f['cliHome'])/'appdata'),LOCALAPPDATA=str(Path(f['cliHome'])/'localappdata'))
            for name in ['APPDATA','LOCALAPPDATA']:Path(env[name]).mkdir(parents=True,exist_ok=True)
        (out/'tmp').mkdir(exist_ok=True)
        for name in ['nativeTmp','httpCache','nugetScratch']:Path(f[name]).mkdir(parents=True,exist_ok=True)
        before_storage=storage(f,root);fresh(out/'storage-before.json',before_storage)
        common=['-c','Release','--no-restore','-m:1','-p:UseSharedCompilation=false','-nodeReuse:false']
        if phase=='qualify':commands=[[str(sdk),'--info']]
        elif phase=='evaluate':commands=[[str(sdk),'msbuild','src/Bench.Cli/Bench.Cli.csproj','-getProperty:MSBuildProjectFullPath,MSBuildSDKsPath,TargetFramework,RuntimeIdentifier,RuntimeIdentifiers,RuntimeFrameworkVersion,UseWPF,UseWindowsForms,SelfContained','-getItem:FrameworkReference','-nodeReuse:false']]
        elif phase in ('runtime-verify','runtime-verify-linux-data'):
            target_rid='linux-x64' if phase=='runtime-verify-linux-data' else rid
            need(phase!='runtime-verify-linux-data' or rid=='win-x64','DATA_SIGNATURE_HOST_SCOPE')
            runtime=packet['runtimePackages'][target_rid];ref=runtime.get('archive',runtime)
            commands=[[str(sdk),'nuget','verify',str(path(ref)),'--all','--verbosity','detailed']]
        elif phase=='restore':commands=[[str(sdk),'restore','src/Bench.Cli/Bench.Cli.csproj','--locked-mode','--configfile',f['nugetConfig'],'--disable-parallel','--verbosity','normal']]
        elif phase=='restore-tests':commands=[[str(sdk),'restore','tests/Evidence.Tests/Evidence.Tests.csproj','--locked-mode','--configfile',f['nugetConfig'],'--disable-parallel','--verbosity','normal']]
        elif phase=='build':commands=[[str(sdk),'build','tests/Evidence.Tests/Evidence.Tests.csproj',*common]]
        elif phase=='test':commands=[[str(sdk),'run','--project','tests/Evidence.Tests','-c','Release','--no-build','--','-result-xml',str(out/'unit.xml')]]
        elif phase=='package':
            previous=Path(f['restoreFinal']);need(sha(previous)==f['restoreFinalSha256'],'RESTORE_RECEIPT_BYTES');restored=read(previous)
            need(restored['status']=='ACCEPTED_CHANGED_SERVICING_PHASE' and restored['phase']=='restore' and restored['rid']==rid and restored['packetSHA256']==f['packetSha256'],'OWN_EXACT_RESTORE_PREREQUISITE')
            unchanged=subprocess.run(['git','-C',str(root),'diff','--quiet',restored['sourceCommit'],f['sourceCommit'],'--','global.json','Directory.Build.props','src','tests','.config'],capture_output=True,timeout=5);need(unchanged.returncode==0,'RESTORE_PRODUCT_INPUTS_CHANGED')
            handoff=out/'restore-handoff.json';fresh(handoff,{'schema':'tail11-tech-restore-handoff/v1','sourceCommit':f['sourceCommit'],'restoreSourceCommit':restored['sourceCommit'],'rid':rid,'final':{'path':str(previous),'sha256':sha(previous)},'assetsSha256':sha(root/'src/Bench.Cli/obj/project.assets.json'),'lockedMode':True,'hostSupport':{'hostClass':actual.get('hostClass','OBSERVED_UBUNTU_24_04'),'formalVendorSupport':actual['formalVendorSupport'],'observedWindows':actual.get('observedWindows')},'packetSHA256':f['packetSha256']})
            commands=[[sys.executable,str(root/'tools/package.py'),'--commit',f['sourceCommit'],'--rid',rid,'--dotnet',str(sdk),'--work',f['packageWork'],'--out',f['packageOut'],'--restore-handoff',str(handoff),'--restore-handoff-sha',sha(handoff)]]
        elif phase=='package-check':commands=[[sys.executable,str(root/'tools/check_package.py'),'--package',f['packageDirectory'],'--commit',f['sourceCommit'],'--out',str(out/'package-check.json')]]
        results=[]
        for index,cmd in enumerate(commands):
            left=min(20-(time.monotonic()-started) if phase in ('qualify','runtime-verify','runtime-verify-linux-data') else 45,f['deadline']-time.time()-30,f['phaseDeadline']-time.time())
            need(left>0,'PHASE_CLOCK');log=out/('command-'+str(index)+'.log')
            with log.open('xb') as target:
                run=subprocess.Popen(cmd,cwd=root,env=env,stdin=subprocess.DEVNULL,stdout=target,stderr=subprocess.STDOUT)
                pid=run.pid
                if os.name=='nt':
                    k=ctypes.WinDLL('kernel32',use_last_error=True);k.OpenJobObjectW.restype=ctypes.c_void_p;k.OpenJobObjectW.argtypes=[ctypes.c_uint,ctypes.c_int,ctypes.c_wchar_p];k.IsProcessInJob.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.POINTER(ctypes.c_int)];k.GetProcessTimes.argtypes=[ctypes.c_void_p]*5;k.CloseHandle.argtypes=[ctypes.c_void_p]
                    j=k.OpenJobObjectW(4,False,'tail11-input-only-'+f['nonce']);member=ctypes.c_int();need(j and k.IsProcessInJob(int(run._handle),j,ctypes.byref(member)) and member.value,'SDK_CHILD_INHERITED_OWN_JOB')
                    c,e,kt,ut=(ctypes.c_ulonglong() for _ in range(4));need(k.GetProcessTimes(int(run._handle),ctypes.byref(c),ctypes.byref(e),ctypes.byref(kt),ctypes.byref(ut)),'SDK_CHILD_BIRTH');identity={'pid':pid,'birthFileTime':c.value,'actualMembership':True};k.CloseHandle(j)
                else:
                    text=(Path('/proc')/str(pid)/'stat').read_text();cg=(Path('/proc')/str(pid)/'cgroup').read_text().strip();need(cg.endswith('/'+os.environ['TAIL11_ROOT_UNIT']),'SDK_CHILD_INHERITED_OWN_CGROUP');identity={'pid':pid,'birthTicks':text[text.rfind(')')+2:].split()[19],'actualCgroup':cg}
                fresh(out/('command-'+str(index)+'-start.json'),{'argv':cmd,'identity':identity,'sourceCommit':f['sourceCommit'],'nativeScopeInherited':True,'originalWaitPending':True})
                try:exitcode=run.wait(timeout=left)
                except subprocess.TimeoutExpired:
                    run.kill();killed_code=run.wait(timeout=5)
                    fresh(out/('command-'+str(index)+'-timeout.json'),{'identity':identity,'status':'NATIVE_TIMEOUT_NOT_PASS','originalWaitReturnedAfterKill':True,'exitCode':killed_code,'nativeMaximumSeconds':20 if phase in ('qualify','runtime-verify','runtime-verify-linux-data') else 45})
                    raise
            need(log.stat().st_size<=1048576,'LOG_CAP')
            result={'pid':pid,'identity':identity,'argv':cmd,'originalPopenWaitReturned':True,'exitCode':exitcode,'logBytes':log.stat().st_size,'logSHA256':sha(log)}
            results.append(result);fresh(out/('command-'+str(index)+'.json'),result);need(exitcode==0,'COMMAND_EXIT_NONZERO')
            if phase=='qualify':
                text=log.read_text(encoding='utf-8');need('10.0.404' in text and '10.0.15' in text and str(sdk.parent) in text,'ACTUAL_SDK_RUNTIME_INFO')
            if phase in ('runtime-verify','runtime-verify-linux-data'):need(packet['runtimePackages'][target_rid]['normalizedContentHash'] in log.read_text(encoding='utf-8'),'ACTUAL_NORMALIZED_PACKAGE_IDENTITY')
        for handle,p,ident in holds:
            now=os.fstat(handle.fileno());need((now.st_dev,now.st_ino,now.st_size,now.st_mtime_ns)==ident,'HELD_INPUT_TERMINAL_IDENTITY')
        fresh(out/'result.json',{'status':'PASS_CHANGED_SERVICING_PHASE','phase':phase,'rid':rid,'seconds':time.monotonic()-started,'commands':results,'sourceCommit':f['sourceCommit'],'packetSHA256':f['packetSha256'],'formalVendorSupport':actual['formalVendorSupport'],'signatureTargetRid':target_rid if phase in ('runtime-verify','runtime-verify-linux-data') else None,'signatureHostRid':rid if phase in ('runtime-verify','runtime-verify-linux-data') else None,'signatureScope':'EXACT_PACKAGE_DATA_NOT_OTHER_OS_OR_HOST_ADMISSION' if phase in ('runtime-verify','runtime-verify-linux-data') else None,'storageBefore':before_storage,'storageAfter':storage(f,root),'globalAdmission':False,'M1Calls':0,'Actions':0})
    except Exception as e:
        fresh(out/'hold.json',{'status':'HOLD','phase':phase,'code':str(e) if isinstance(e,RuntimeError) else type(e).__name__,'exceptionType':type(e).__name__,'seconds':time.monotonic()-started,'M1Calls':0,'Actions':0})
        raise
    finally:
        for handle,_,_ in holds:handle.close()

if __name__=='__main__':main()
