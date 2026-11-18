"""Linux vendor/ELF metadata for one Tail signature role; NEVER admission."""
from pathlib import Path
import argparse,hashlib,json,os,re,stat,struct,subprocess,sys,time
import base64,ctypes,ctypes.wintypes,copy,importlib.util,resource,select,signal,ssl
import support as S
COMMAND_TERMINALS=[]

def need(v,c):
    if not v: raise S.Hold(c)

def elf(data):
    need(len(data)>=64 and data[:7]==b'\x7fELF\x02\x01\x01','ELF64_LE')
    typ,machine=struct.unpack_from('<HH',data,16)
    need(typ in (2,3) and machine==62,'ELF_AMD64')
    off=struct.unpack_from('<Q',data,32)[0];size,count=struct.unpack_from('<HH',data,54)
    need(size==56 and 0<count<=128 and off+size*count<=len(data),'ELF_PHDR_BOUND')
    loads=[];interp=None;dynamic=None
    for i in range(count):
        kind,flags,p,va,pa,fs,ms,align=struct.unpack_from('<IIQQQQQQ',data,off+i*size)
        need(p+fs<=len(data) and fs<=ms,'ELF_SEGMENT_BOUND')
        if kind==1:loads.append({'offset':p,'vaddr':va,'filesz':fs,'memsz':ms,'flags':flags})
        elif kind==3:
            need(fs<=512 and fs>1 and data[p+fs-1]==0,'ELF_INTERP');interp=data[p:p+fs-1].decode('ascii')
        elif kind==2:dynamic=(p,fs)
    def at(va,n):
        choices=[x['offset']+va-x['vaddr'] for x in loads if x['vaddr']<=va and va+n<=x['vaddr']+x['filesz']]
        need(len(choices)==1,'ELF_VA');return choices[0]
    tags={};needed=[]
    if dynamic:
        p,n=dynamic;need(n%16==0 and n<=1048576,'ELF_DYNAMIC_BOUND')
        for i in range(n//16):
            tag,value=struct.unpack_from('<qQ',data,p+16*i)
            if tag==0:break
            if tag==1:needed.append(value)
            else:tags[tag]=value
        need(5 in tags and 10 in tags and tags[10]<=4194304,'ELF_STRTAB')
        p=at(tags[5],tags[10]);strings=data[p:p+tags[10]]
        names=[]
        for value in needed:
            need(value<len(strings),'ELF_NEEDED_NAME');end=strings.find(b'\0',value);need(value<end<=value+256,'ELF_NEEDED_NAME');name=strings[value:end].decode('ascii');need(re.fullmatch('[A-Za-z0-9_.+-]+',name) is not None,'ELF_NEEDED_COMPONENT');names.append(name)
        need(22 not in tags and not (tags.get(30,0)&4),'ELF_TEXTREL_NOT_ALLOWED')
    else:names=[]
    return {'type':typ,'machine':machine,'interpreter':interp,'needed':names,'loads':loads}

def identity(st):return {'dev':st.st_dev,'ino':st.st_ino,'bytes':st.st_size,'mtimeNs':st.st_mtime_ns,'ctimeNs':st.st_ctime_ns,'mode':stat.S_IMODE(st.st_mode),'uid':st.st_uid,'gid':st.st_gid,'links':st.st_nlink}

def held_vendor(path,budget):
    p=Path(path).resolve(strict=True)
    need(str(p).startswith(('/usr/bin/','/usr/lib/','/lib/')),'VENDOR_PATH_SCOPE')
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as f:
        first=os.fstat(f.fileno());need(stat.S_ISREG(first.st_mode) and first.st_uid==0 and not first.st_mode&0o022 and 0<first.st_size<=16777216,'ROOT_OWNED_NONWRITABLE_VENDOR')
        need(budget[0]+first.st_size<=67108864,'VENDOR_READ64M');data=f.read(first.st_size);need(len(data)==first.st_size and identity(first)==identity(os.fstat(f.fileno())),'VENDOR_STABILITY');budget[0]+=len(data)
    return {'path':str(p),'identity':identity(first),'sha256':hashlib.sha256(data).hexdigest(),'installedMD5':hashlib.md5(data).hexdigest()},data

def bounded_command(argv,end,cap=65536):
    need(time.time()<end,'METADATA_CLOCK')
    p=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'})
    try:out,err=p.communicate(timeout=max(.001,min(10,end-time.time())))
    except subprocess.TimeoutExpired:
        p.kill();p.communicate(timeout=2);raise S.Hold('METADATA_COMMAND_TIMEOUT')
    need(len(out)+len(err)<=cap,'METADATA_STDIO_CAP')
    terminal={'argv':argv,'pid':p.pid,'originalPopenWaitReturned':True,'exitCode':p.returncode,'stdoutBytes':len(out),'stderrBytes':len(err),'stdoutSHA256':hashlib.sha256(out).hexdigest(),'stderrSHA256':hashlib.sha256(err).hexdigest()}
    COMMAND_TERMINALS.append(terminal)
    if p.returncode!=0:
        terminal.update(stdoutDiagnostic=out.decode('utf-8','replace')[:8192],stderrDiagnostic=err.decode('utf-8','replace')[:8192])
        raise S.Hold('METADATA_COMMAND_HOLD')
    return out.decode('utf-8','strict'),terminal

def main():
    a=argparse.ArgumentParser();a.add_argument('--frame',required=True);a.add_argument('--frame-sha',required=True);args=a.parse_args()
    raw=Path(args.frame).read_bytes();need(len(raw)<=32768 and hashlib.sha256(raw).hexdigest()==args.frame_sha,'FRAME_HASH');f=json.loads(raw)
    out=Path(f['guestOutputPath']);need(out.name=='tail11-linux-role-'+f['nonce'],'OWN_OUTPUT')
    result={'schema':'tail11-linux-role-metadata/v1','status':'HOLD','admitted':False,'fullClosureQualified':False,'networkCalls':0,'signatureInvocations':0,'nativeM1Calls':0,'nonce':f['nonce']}
    try:
        need(f['schema']=='tail11-linux-role-frame/v1' and f['mode']=='metadata' and f['limits']['memory']==536870912,'FIXED_METADATA_SCOPE')
        need(os.getuid()==1000 and os.getgid()==1000 and os.environ.get('WSL_DISTRO_NAME')=='Ubuntu-24.04','UBUNTU_UID_SCOPE')
        result['actualKernel']=S.actual_profile({'runNonce':f['nonce']},'linux-x64')
        for n,h in f['sourceHashes'].items():need(S.sha(Path(f['sourceDirectory'])/n)==h,'SOURCE_BINDING')
        start=time.monotonic();end=min(time.time()+20,f['window']['deadlineUnix']-30)
        osraw=Path('/etc/os-release').read_bytes();need(len(osraw)<=16384 and b'ID=ubuntu' in osraw and b'VERSION_ID="24.04"' in osraw,'UBUNTU24')
        result.update(bootId=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),pidNamespace=os.readlink('/proc/self/ns/pid'),osRelease=osraw.decode(),pid=os.getpid())
        need(not Path('/etc/ld.so.preload').exists() or not Path('/etc/ld.so.preload').read_text().strip(),'GLOBAL_PRELOAD_PRESENT_HOLD')
        budget=[0];vendor_modules={};own_sources={str((Path(f['sourceDirectory'])/n).resolve()) for n in f['sourceHashes']}
        for name,mod in sorted(list(sys.modules.items())):
            for value in (getattr(mod,'__file__',None),getattr(mod,'__cached__',None)):
                if not value or not Path(value).is_file():continue
                key=str(Path(value).resolve())
                if key in own_sources or key in vendor_modules:continue
                row,_=held_vendor(value,budget);vendor_modules[key]=row
        pyrow,_=held_vendor(sys.executable,budget);vendor_modules[pyrow['path']]=pyrow
        need(len(vendor_modules)<=256,'PYTHON_VENDOR_FILE_COUNT')
        root,data=held_vendor('/usr/bin/ssh-keygen',budget);pe=elf(data);need(pe['interpreter'] is not None,'ELF_LOADER_REQUIRED')
        loader,loader_data=held_vendor(pe['interpreter'],budget);elf(loader_data)
        listing,term=bounded_command([pe['interpreter'],'--list','/usr/bin/ssh-keygen'],end)
        need(len(listing)<=16384,'ELF_LIST_CAP');paths={'/usr/bin/ssh-keygen',pe['interpreter']}
        for line in listing.splitlines():
            if 'linux-vdso.so.1' in line:continue
            match=re.search(r'(?:=>\s*)?(/[^\s]+)\s+\(0x[0-9a-f]+\)',line)
            need(match is not None and 'not found' not in line,'UNRESOLVED_LOADER_EDGE');paths.add(match.group(1))
        need(0<len(paths)<=32,'FIXED_ELF_FILE_COUNT')
        files={root['path']:root,loader['path']:loader};elfs={root['path']:pe,loader['path']:elf(loader_data)}
        for path in sorted(paths):
            if str(Path(path).resolve()) in files:continue
            row,body=held_vendor(path,budget);files[row['path']]=row;elfs[row['path']]=elf(body)
        owners,ownerterm=bounded_command(['/usr/bin/dpkg-query','-S']+sorted(paths),end)
        packages={}
        for line in owners.splitlines():
            pkg,sep,path=line.rpartition(': ');need(sep and pkg and path.startswith('/'),'PACKAGE_OWNER_FORMAT');packages[str(Path(path).resolve())]=pkg
        need(all(p in packages for p in files),'VENDOR_PACKAGE_OWNER_REQUIRED')
        for path,row in files.items():
            pkg=packages[path];need(re.fullmatch('[a-zA-Z0-9.+:-]+',pkg) is not None,'PACKAGE_NAME')
            db=Path('/var/lib/dpkg/info')/(pkg+'.md5sums')
            if not db.exists():db=Path('/var/lib/dpkg/info')/(pkg.split(':')[0]+'.md5sums')
            st=db.stat();need(st.st_uid==0 and not st.st_mode&0o022 and st.st_size<=4194304,'PACKAGE_DB_SCOPE')
            text=db.read_bytes();need(budget[0]+len(text)<=67108864,'METADATA_READ64M');budget[0]+=len(text)
            matches=[]
            for line in text.decode().splitlines():
                digest,rel=line.split(None,1)
                if Path(rel).name!=Path(path).name:continue
                if str(Path('/'+rel).resolve())==path:matches.append(digest)
            need(matches==[row['installedMD5']],'INSTALLED_VENDOR_IDENTITY_MISMATCH');row.update(package=pkg,packageDatabase={'path':str(db),'sha256':hashlib.sha256(text).hexdigest()},vendorIdentityMatched=True)
        versions,versionterm=bounded_command(['/usr/bin/dpkg-query','-W','-f=${Package}\t${Version}\t${Architecture}\t${Status}\n']+sorted(set(packages.values())),end)
        need(all(line.endswith('install ok installed') for line in versions.splitlines()),'INSTALLED_PACKAGE_STATUS')
        need(time.time()<end and time.monotonic()-start<=20,'METADATA_ROLE20')
        result.update(status='METADATA_COMPLETE_NOT_ADMISSION',admitted=False,files=list(files.values()),pythonVendorFiles=list(vendor_modules.values()),elfHeaders=elfs,loaderListing=listing,packageVersions=versions,readBytes=budget[0],terminals=[term,ownerterm,versionterm],roleSeconds=time.monotonic()-start,toolPresent=True,sourceHashes=f['sourceHashes'])
    except Exception as e:
        result.update(code=str(e) if isinstance(e,S.Hold) else 'LINUX_METADATA_HOLD',exceptionType=type(e).__name__,commandTerminals=COMMAND_TERMINALS)
    S.fresh(out/'metadata.json',result,cap=262144)
    if result['status']!='METADATA_COMPLETE_NOT_ADMISSION':raise SystemExit(1)

if __name__=='__main__':main()
