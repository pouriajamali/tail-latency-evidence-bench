"""One owned Linux OpenSSH role. Native crypto only; unknown ELF state is HOLD."""
from pathlib import Path
import argparse,ctypes,hashlib,json,os,re,select,signal,stat,struct,sys,time
import support as S
from linux_role_probe import elf,identity
LAST_ELF_EVENT={}
OWNED_CHILDREN=[]
KERNEL_WITNESS=None

def need(v,c):
    if not v:raise S.Hold(c)

class Image:
    def __init__(self,path,body):
        self.path=path;self.body=body;self.header=elf(body);self.symbols=[];self.relocs=[];self.versions={0:None,1:None};self.dynamic=[];self.dynamicVA=None;self.dynamicWritable=False
        po=struct.unpack_from('<Q',body,32)[0];ps,pn=struct.unpack_from('<HH',body,54)
        for i in range(pn):
            kind,flags,p,va,_,fs,_,_=struct.unpack_from('<IIQQQQQQ',body,po+i*ps)
            if kind!=2:continue
            self.dynamicVA=va;self.dynamicWritable=bool(flags&2)
            for k in range(0,fs,16):
                tag,value=struct.unpack_from('<qQ',body,p+k)
                if not tag:break
                self.dynamic.append({'tag':tag,'value':value,'slotVA':va+k+8})
        off=struct.unpack_from('<Q',body,40)[0];size,count=struct.unpack_from('<HH',body,58)
        need(size==64 and 0<count<8192 and off+size*count<=len(body),'ELF_SECTION_BOUND')
        sections=[struct.unpack_from('<IIQQQQIIQQ',body,off+i*64) for i in range(count)]
        def section(s):
            p,n=s[4:6];need(p+n<=len(body),'ELF_SECTION_DATA');return body[p:p+n]
        def string(data,p):
            need(p<len(data),'ELF_STRING_BOUND');e=data.find(b'\0',p);need(p<=e<=p+1024,'ELF_STRING_BOUND');return data[p:e].decode('ascii')
        dyn=[(i,s) for i,s in enumerate(sections) if s[1]==11];need(len(dyn)==1,'ELF_DYNSYM_REQUIRED')
        si,syms=dyn[0];strings=section(sections[syms[6]])
        versym=None
        for s in sections:
            if s[1]==0x6fffffff and s[6]==si:versym=section(s)
            if s[1] not in (0x6ffffffd,0x6ffffffe):continue
            data=section(s);names=section(sections[s[6]]);pos=0;seen=set()
            while pos<len(data):
                need(pos not in seen and len(seen)<4096,'ELF_VERSION_BOUND');seen.add(pos)
                if s[1]==0x6ffffffd:
                    need(pos+20<=len(data),'ELF_VERDEF');_,flags,index,_,_,aux,nxt=struct.unpack_from('<HHHHIII',data,pos)
                    need(pos+aux+8<=len(data),'ELF_VERDEF_AUX');name,_=struct.unpack_from('<II',data,pos+aux)
                    if index>1:self.versions[index]=string(names,name)
                else:
                    need(pos+16<=len(data),'ELF_VERNEED');_,cnt,_,aux,nxt=struct.unpack_from('<HHIII',data,pos);ap=pos+aux
                    for _ in range(cnt):
                        need(ap+16<=len(data),'ELF_VERNEED_AUX');_,_,index,name,an=struct.unpack_from('<IHHII',data,ap);self.versions[index&0x7fff]=string(names,name)
                        if not an:break
                        ap+=an
                if not nxt:break
                pos+=nxt
        need(syms[9]==24 and syms[5]%24==0 and syms[5]//24<=100000,'ELF_SYMBOL_BOUND')
        data=section(syms)
        for i in range(len(data)//24):
            name,info,other,index,value,n=struct.unpack_from('<IBBHQQ',data,i*24)
            vi=struct.unpack_from('<H',versym,i*2)[0]&0x7fff if versym is not None else 0
            need(vi in self.versions,'ELF_SYMBOL_VERSION_UNKNOWN')
            self.symbols.append({'name':string(strings,name),'bind':info>>4,'type':info&15,'visibility':other&3,'section':index,'value':value,'size':n,'version':self.versions[vi]})
        for s in sections:
            if s[1]!=4 or s[6]!=si:continue
            data=section(s);need(s[9]==24 and len(data)%24==0 and len(self.relocs)+len(data)//24<=20000,'ELF_RELOCATION_BOUND')
            for p in range(0,len(data),24):
                address,info,addend=struct.unpack_from('<QQq',data,p);sym=info>>32;need(sym<len(self.symbols),'ELF_RELOCATION_SYMBOL')
                self.relocs.append({'offset':address,'type':info&0xffffffff,'symbol':sym,'addend':addend})
        for s in sections:
            if s[1]!=19:continue
            data=section(s);need(s[9]==8 and len(data)%8==0,'ELF_RELR_BOUND');cursor=None
            for (entry,) in struct.iter_unpack('<Q',data):
                if entry&1:
                    need(cursor is not None,'ELF_RELR_BITMAP_BASE');where=[cursor+i*8 for i in range(63) if (entry>>(i+1))&1];cursor+=63*8
                else:where=[entry];cursor=entry+8
                for address in where:
                    segments=[x for x in self.header['loads'] if x['vaddr']<=address and address+8<=x['vaddr']+x['filesz']];need(len(segments)==1,'ELF_RELR_FILE_ADDEND')
                    x=segments[0];value=struct.unpack_from('<Q',body,x['offset']+address-x['vaddr'])[0];self.relocs.append({'offset':address,'type':8,'symbol':0,'addend':value,'encoding':'RELR'})
        need(len(self.relocs)<=20000 and len({r['offset'] for r in self.relocs})==len(self.relocs),'ELF_RELOCATION_UNIQUE')

def maps(pid,known=None):
    raw=(Path('/proc')/str(pid)/'maps').read_bytes();need(len(raw)<=262144,'OWN_MAP_CAP');rows=[]
    for line in raw.decode().splitlines():
        a,perms,off,dev,ino,*name=line.split(None,5);lo,hi=(int(x,16) for x in a.split('-'));name=name[0] if name else ''
        need(not ('w' in perms and 'x' in perms),'WRITABLE_EXECUTABLE_MAP')
        if name.startswith('/'):
            need(not name.endswith(' (deleted)'),'DELETED_IMAGE_MAP');path=str(Path(name).resolve());st=Path(path).stat();major,minor=(int(x,16) for x in dev.split(':'))
            need(st.st_ino==int(ino) and os.major(st.st_dev)==major and os.minor(st.st_dev)==minor,'MAPPED_FILE_IDENTITY')
            if known is not None:need(path in known and identity(st)==known[path]['identity'],'UNDECLARED_ACTUAL_ELF_IMAGE')
        else:
            path=None;need('x' not in perms or name in ('[vdso]','[vsyscall]'),'ANONYMOUS_EXECUTABLE_MAP')
        rows.append({'start':lo,'end':hi,'perms':perms,'offset':int(off,16),'path':path,'kernelName':name})
    return rows,hashlib.sha256(raw).hexdigest()

def biases(rows,images):
    result={}
    for path,im in images.items():
        bases=[m for m in rows if m['path']==path and m['offset']==0]
        need(len(bases)==1 and im.header['loads'][0]['offset']==0,'ELF_ACTUAL_LOAD_BASE')
        result[path]=bases[0]['start']-(im.header['loads'][0]['vaddr']&~4095)
    return result

def memory(fd,address,n):
    need(0<n<=16777216,'OWN_MEMORY_READ_BOUND');b=os.pread(fd,n,address);need(len(b)==n,'OWN_MEMORY_SHORT_READ');return b

def binding_rows(trace,known):
    global LAST_ELF_EVENT
    result={};edges=[]
    pattern=re.compile(r"binding file (.+?) \[0\] to (.+?) \[0\]: (?:normal|protected) symbol [`']([^']+)'(?: \[([^]]+)\])?")
    for line in trace.splitlines():
        m=pattern.search(line)
        if not m:continue
        src,dst,name,version=m.groups()
        LAST_ELF_EVENT={'phase':'NATIVE_BINDING','from':src,'provider':dst,'symbol':name,'version':version}
        if src==dst=='linux-vdso.so.1':
            need(KERNEL_WITNESS and version=='LINUX_2.6' and name in KERNEL_WITNESS['verifiedSymbols'],'ACTUAL_KERNEL_VDSO_SELF_BINDING_REQUIRED')
            continue
        src=str(Path(src).resolve());dst=str(Path(dst).resolve());need(src in known and dst in known,'UNKNOWN_NATIVE_BINDING_PROVIDER')
        key=(src,name,version);result.setdefault(key,set()).add(dst)
    need(len(result)<=20000,'BINDING_COUNT')
    for key,providers in result.items():need(len(providers)==1,'AMBIGUOUS_NATIVE_BINDING')
    return {key:next(iter(v)) for key,v in result.items()}

def attest(pid,images,held,trace,end):
    global LAST_ELF_EVENT,KERNEL_WITNESS
    rows,mapsha=maps(pid,held);base=biases(rows,images)
    parentrows,_=maps(os.getpid());parentbase={}
    for path,im in images.items():
        candidates=[m for m in parentrows if m['path']==path and m['offset']==0]
        if len(candidates)==1:parentbase[path]=candidates[0]['start']-(im.header['loads'][0]['vaddr']&~4095)
    lib=ctypes.CDLL(None);lib.dlvsym.argtypes=[ctypes.c_void_p,ctypes.c_char_p,ctypes.c_char_p];lib.dlvsym.restype=ctypes.c_void_p
    lib.dlsym.argtypes=[ctypes.c_void_p,ctypes.c_char_p];lib.dlsym.restype=ctypes.c_void_p
    childfd=os.open('/proc/'+str(pid)+'/mem',os.O_RDONLY|os.O_CLOEXEC);parentfd=os.open('/proc/self/mem',os.O_RDONLY|os.O_CLOEXEC)
    count=robytes=0;details=[];patched={};readonly=[];checked=set();dynamic_count=0;resolver_code_verified=set()
    def in_rx(value,path,b=base,rs=rows):return any(m['path']==path and 'x' in m['perms'] and m['start']<=value<m['end'] for m in rs)
    def exported(src,s):
        key=(src,s['name'],s['version']);dst=native.get(key)
        if dst is None:
            if s['section'] and (s['bind']==0 or s['visibility'] in (2,3)):dst=src
            elif s['bind']==2 and not s['section']:return None,None,0
            else:raise S.Hold('NATIVE_BINDING_EDGE_NOT_PROVEN')
        defs=[x for x in images[dst].symbols if x['name']==s['name'] and x['section'] and (x['version']==s['version'] or s['version'] is None)]
        unique={(x['value'],x['type'],x['section']) for x in defs};need(len(unique)==1,'ELF_EXPORT_NOT_UNIQUE');value,typ,section=next(iter(unique))
        target=value if section==0xfff1 else base[dst]+value
        if typ==10:
            need(dst in parentbase,'IFUNC_NATIVE_REFERENCE_NOT_MAPPED')
            reference=lib.dlvsym(None,s['name'].encode(),s['version'].encode()) if s['version'] else lib.dlsym(None,s['name'].encode())
            need(reference,'IFUNC_NATIVE_REFERENCE')
            if in_rx(reference,dst,parentbase,parentrows):target=base[dst]+reference-parentbase[dst]
            else:
                aliases={'time':'__vdso_time','gettimeofday':'__vdso_gettimeofday','clock_gettime':'__vdso_clock_gettime','clock_getres':'__vdso_clock_getres','getcpu':'__vdso_getcpu'}
                alias=aliases.get(s['name']);need(KERNEL_WITNESS and alias in KERNEL_WITNESS['symbolRVAs'],'IFUNC_NATIVE_PROVIDER')
                rva=KERNEL_WITNESS['symbolRVAs'][alias]
                need(reference==KERNEL_WITNESS['parentStart']+rva,'IFUNC_EXACT_KERNEL_SYMBOL')
                target=KERNEL_WITNESS['childStart']+rva
        return dst,typ,target
    try:
        def vdso(who,rs,fd):
            raw=(Path('/proc')/str(who)/'auxv').read_bytes();need(len(raw)<=16384 and len(raw)%16==0,'OWN_AUXV_BOUND')
            values=dict(struct.iter_unpack('<QQ',raw));v=[m for m in rs if m['kernelName']=='[vdso]']
            need(len(v)==1 and values.get(33)==v[0]['start'] and v[0]['perms'].startswith('r-x') and v[0]['path'] is None,'ACTUAL_AT_SYSINFO_EHDR')
            m=v[0];need(0<m['end']-m['start']<=65536,'ACTUAL_VDSO_BOUND');body=memory(fd,m['start'],m['end']-m['start'])
            return Image('linux-vdso.so.1',body),body
        vi,vb=vdso(pid,rows,childfd);pi,pb=vdso(os.getpid(),parentrows,parentfd);need(vb==pb,'SAME_ACTUAL_KERNEL_VDSO_IMAGE')
        names=('__vdso_clock_gettime','__vdso_gettimeofday','__vdso_time','__vdso_getcpu','__vdso_clock_getres')
        for name in names:need(len([s for s in vi.symbols if s['name']==name and s['section'] and s['type']==2 and s['version']=='LINUX_2.6'])==1,'ACTUAL_VDSO_SYMBOL_DEFINITION')
        KERNEL_WITNESS={'kind':'EXISTING_KERNEL_TCB_VDSO_NOT_FILE_PROVIDER','bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'actualAuxv33Matches':True,'childMatchesParentKernelBytes':True,'sha256':hashlib.sha256(vb).hexdigest(),'bytes':len(vb),'verifiedSymbols':list(names),'symbolRVAs':{n:next(s['value'] for s in vi.symbols if s['name']==n and s['section']) for n in names},'parentStart':next(m['start'] for m in parentrows if m['kernelName']=='[vdso]'),'childStart':next(m['start'] for m in rows if m['kernelName']=='[vdso]')}
        native=binding_rows(trace,images)
        loader=next(p for p in images if Path(p).name=='ld-linux-x86-64.so.2')
        def loader_symbol(name):
            syms=[s for s in images[loader].symbols if s['name']==name and s['section']];need(len({s['value'] for s in syms})==1,'EXACT_LOADER_EXPORT');return base[loader]+syms[0]['value']
        debug=loader_symbol('_r_debug');version,linkmap,brk,state,ldbase=struct.unpack('<I4xQQI4xQ',memory(childfd,debug,40))
        need(version in (1,2) and brk==loader_symbol('_dl_debug_state') and state==0 and ldbase==base[loader],'ACTUAL_LOADER_DEBUG_STATE')
        link_rows=[];seen_links=set();previous=0
        def c_string(address):
            data=bytearray()
            for i in range(512):
                b=memory(childfd,address+i,1)
                if b==b'\0':return data.decode('ascii')
                data.extend(b)
            raise S.Hold('ACTUAL_LINK_MAP_NAME_BOUND')
        while linkmap:
            need(linkmap not in seen_links and len(seen_links)<16,'ACTUAL_LINK_MAP_BOUND');seen_links.add(linkmap)
            addr,nameptr,dyn,nxt,prev=struct.unpack('<QQQQQ',memory(childfd,linkmap,40));need(prev==previous,'ACTUAL_LINK_MAP_PREVIOUS')
            name=c_string(nameptr) if nameptr else ''
            if name=='linux-vdso.so.1':need(addr==KERNEL_WITNESS['childStart'] and dyn==addr+vi.dynamicVA,'ACTUAL_KERNEL_LINK_MAP');canonical=name
            else:
                canonical=str(Path(name).resolve()) if name else '/usr/bin/ssh-keygen'
                need(canonical in images and addr==base[canonical] and dyn==addr+images[canonical].dynamicVA,'ACTUAL_FILE_LINK_MAP')
            link_rows.append(canonical);previous=linkmap;linkmap=nxt
        need(len(link_rows)==len(set(link_rows)) and set(link_rows)==set(images)|{'linux-vdso.so.1'},'ACTUAL_LINK_MAP_CLOSURE')
        for path,im in images.items():
            need(time.time()<end,'SIGNATURE_ROLE20')
            for r in im.relocs:
                address=base[path]+r['offset'];typ=r['type'];s=im.symbols[r['symbol']]
                LAST_ELF_EVENT={'path':path,'relocationType':typ,'symbol':s['name'],'version':s['version'],'offset':r['offset']}
                ro=any(m['path']==path and 'r' in m['perms'] and 'w' not in m['perms'] and m['start']<=address< m['end'] for m in rows)
                imported=typ in (1,5,6,7,16,17,18)
                if not ro and not imported:continue
                if typ==0:continue
                if typ==8:expected=(base[path]+r['addend'])&((1<<64)-1)
                elif typ==37:
                    need(path in parentbase,'IRELATIVE_NATIVE_REFERENCE_NOT_MAPPED')
                    resolver=parentbase[path]+r['addend'];need(in_rx(resolver,path,parentbase,parentrows),'IRELATIVE_NATIVE_RESOLVER_RX')
                    if path not in resolver_code_verified:
                        need(identity(Path(path).stat())==held[path]['identity'],'NATIVE_RESOLVER_FILE_IDENTITY')
                        for seg in im.header['loads']:
                            if not seg['flags']&1:continue
                            code=memory(parentfd,parentbase[path]+seg['vaddr'],seg['filesz'])
                            need(code==im.body[seg['offset']:seg['offset']+seg['filesz']],'NATIVE_RESOLVER_CODE_BYTES')
                        resolver_code_verified.add(path)
                    # AMD64 R_IRELATIVE is a native no-argument resolver call.
                    # A previously relocated parent slot is not its canonical result.
                    pv=ctypes.CFUNCTYPE(ctypes.c_void_p)(resolver)()
                    targets=[p for p in parentbase if pv and in_rx(pv,p,parentbase,parentrows)]
                    LAST_ELF_EVENT.update(nativeResult=pv,nativeFileTargets=targets)
                    if pv is None:expected=0
                    elif len(targets)==1:
                        provider=targets[0];expected=base[provider]+pv-parentbase[provider]
                    else:
                        need(not targets and KERNEL_WITNESS,'IRELATIVE_NATIVE_PROVIDER')
                        rvas=[v for v in KERNEL_WITNESS['symbolRVAs'].values() if pv==KERNEL_WITNESS['parentStart']+v]
                        need(len(rvas)==1,'IRELATIVE_EXACT_KERNEL_SYMBOL');expected=KERNEL_WITNESS['childStart']+rvas[0]
                elif typ in (1,5,6,7):
                    dst,kind,target=exported(path,s)
                    if typ==5:
                        need(not ro and kind in (1,6) and s['size']>0,'COPY_RELOCATION_SCOPE')
                        details.append({'from':path,'name':s['name'],'kind':'MUTABLE_OBJECT_COPY_NATIVE_EDGE','provider':dst});continue
                    expected=(target+(r['addend'] if typ==1 else 0))&((1<<64)-1)
                elif typ in (16,17,18):
                    # No guessed TLS module IDs/offsets or blanket writable masks.
                    raise S.Hold('NATIVE_TLS_RELOCATION_WITNESS_REQUIRED')
                else:raise S.Hold('UNSUPPORTED_READONLY_ELF_RELOCATION')
                actual=struct.unpack('<Q',memory(childfd,address,8))[0];need(actual==expected,'ACTUAL_ELF_RELOCATION_SLOT_MISMATCH')
                patched[(path,address)]=struct.pack('<Q',expected);count+=1
                if imported:details.append({'from':path,'name':s['name'],'version':s['version'],'provider':dst,'relocationType':typ,'actualMatches':True})
            # Exact glibc dynamic-pointer adjustments, not masked bytes.
            pointer_tags={3,4,5,6,7,17,23,36,0x6ffffef5,0x6ffffff0}
            for d in im.dynamic:
                tag=d['tag'];value=d['value'];address=base[path]+d['slotVA']
                if tag==21:
                    need(path=='/usr/bin/ssh-keygen' and value==0,'DT_DEBUG_SCOPE');expected=debug
                elif im.dynamicWritable and base[path] and tag in pointer_tags and (value or tag not in (7,17)):expected=base[path]+value
                else:continue
                LAST_ELF_EVENT={'path':path,'phase':'TYPED_DYNAMIC_POINTER','tag':tag,'slotVA':d['slotVA']}
                need(struct.unpack('<Q',memory(childfd,address,8))[0]==expected,'ACTUAL_DYNAMIC_POINTER_MISMATCH')
                patched[(path,address)]=struct.pack('<Q',expected);dynamic_count+=1
            for seg in im.header['loads']:
                lo=base[path]+seg['vaddr'];hi=lo+seg['memsz']
                for m in rows:
                    if m['path']!=path or 'r' not in m['perms'] or 'w' in m['perms']:continue
                    a=max(lo,m['start']);z=min(hi,m['end'])
                    if a>=z:continue
                    LAST_ELF_EVENT={'path':path,'phase':'READONLY_LOAD_COMPARE','segmentVaddr':seg['vaddr'],'bytes':z-a}
                    need(robytes+z-a<=33554432,'READONLY_IMAGE_CAP');offset=a-lo;filebytes=max(0,min(z-a,seg['filesz']-offset))
                    expected=bytearray(im.body[seg['offset']+offset:seg['offset']+offset+filebytes]+bytes(z-a-filebytes))
                    for (p,where),value in patched.items():
                        if p==path and a<=where and where+8<=z:expected[where-a:where-a+8]=value
                    actual=memory(childfd,a,z-a)
                    if actual!=expected:
                        first=next(i for i,(x,y) in enumerate(zip(actual,expected)) if x!=y);LAST_ELF_EVENT.update(firstMismatchVaddr=a-base[path]+first,actualHex=actual[first:first+8].hex(),expectedHex=bytes(expected[first:first+8]).hex())
                        raise S.Hold('READONLY_ELF_IMAGE_MISMATCH')
                    robytes+=len(actual)
                    readonly.append({'path':path,'segmentVaddr':seg['vaddr'],'bytes':len(actual),'sha256':hashlib.sha256(actual).hexdigest()})
            checked.add(path)
        need(checked==set(images),'ACTUAL_CLOSURE_INCOMPLETE')
        # DT_NEEDED resolves only within the exact held/mapped closure.
        needed=[]
        for path,im in images.items():
            for name in im.header['needed']:
                matches=[p for p in images if Path(p).name==name or (name.startswith('libpcre2-8.so.') and Path(p).name==name+'.11.2')]
                need(len(matches)==1,'ACTUAL_DT_NEEDED_UNRESOLVED');needed.append({'from':path,'name':name,'provider':matches[0],'resolved':True})
        encoded=json.dumps(details,sort_keys=True,separators=(',',':')).encode()
        return {'schema':'tail11-owned-linux-elf-closure/v1','actualChildPID':pid,'mapsSHA256':mapsha,'mappedFiles':sorted(checked),'normalImportEdges':needed,'validatedRelocations':count,'validatedDynamicPointers':dynamic_count,'actualLinkMap':link_rows,'validatedImportSlots':len(details),'slotEvidenceSHA256':hashlib.sha256(encoded).hexdigest(),'readOnlyLoads':readonly,'readOnlyBytes':robytes,'readOnlyImageMatches':True,'kernelVDSO':KERNEL_WITNESS,'unresolved':[]}
    finally:os.close(childfd);os.close(parentfd)

def child_run(argv,data,guest,nonce,images,held,end,qualify):
    r,w=os.pipe();o=guest/('stdout-'+nonce);e=guest/('stderr-'+nonce);traceprefix=guest/('loader-'+nonce)
    pid=os.fork()
    if pid==0:
        try:
            os.close(w);os.dup2(r,0);os.close(r)
            of=os.open(o,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);ef=os.open(e,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.dup2(of,1);os.dup2(ef,2);os.close(of);os.close(ef)
            os.kill(os.getpid(),signal.SIGSTOP)
            env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','HOME':str(guest),'TMPDIR':str(guest),'LD_BIND_NOW':'1','LD_DEBUG':'libs,files,bindings','LD_DEBUG_OUTPUT':str(traceprefix)}
            os.execve('/usr/bin/ssh-keygen',argv,env)
        except BaseException:os._exit(126)
    os.close(r);pidfd=os.pidfd_open(pid);terminal=False;stopped=False;closure=None
    owned={'pid':pid,'originalHandleTerminal':False,'execResumed':False,'forced':False};OWNED_CHILDREN.append(owned)
    try:
        p,status=os.waitpid(pid,os.WUNTRACED);need(p==pid and os.WIFSTOPPED(status),'SSH_STOP_BEFORE_EXEC');stopped=True
        proc=Path('/proc')/str(pid);birth=(proc/'stat').read_text().split(') ',1)[1].split()[19]
        owned['birth']=birth
        need((proc/'cgroup').read_text()==Path('/proc/self/cgroup').read_text(),'SSH_SAME_CGROUP_BEFORE_EXEC')
        need(re.search(r'^Uid:\s+1000\s+1000\s+1000\s+1000$',(proc/'status').read_text(),re.M) is not None,'SSH_NONROOT_BEFORE_EXEC')
        tracefile=Path(str(traceprefix)+'.'+str(pid));tracefile.touch(exist_ok=False)
        os.kill(pid,signal.SIGCONT);stopped=False;owned['execResumed']=True
        # Wait only on the owned native-loader trace; stdin stays open without EOF.
        lib=ctypes.CDLL(None);lib.inotify_init1.argtypes=[ctypes.c_int];lib.inotify_add_watch.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_uint]
        watch=lib.inotify_init1(os.O_NONBLOCK|os.O_CLOEXEC);need(watch>=0,'NATIVE_TRACE_WATCH');need(lib.inotify_add_watch(watch,os.fsencode(guest),0x10a)>=0,'NATIVE_TRACE_WATCH')
        trace='';trace_offset=0
        def trace_append():
            nonlocal trace,trace_offset
            with tracefile.open('rb') as tf:
                tf.seek(trace_offset);part=tf.read(4194304-trace_offset+1)
            need(trace_offset+len(part)<=4194304,'NATIVE_TRACE_CAP');trace_offset+=len(part);trace+=part.decode('ascii')
        try:
            while True:
                need(time.time()<end,'SIGNATURE_ROLE20');trace_append()
                if 'transferring control:' in trace:break
                ready,_,_=select.select([watch,pidfd],[],[],min(.1,max(.001,end-time.time())))
                need(pidfd not in ready,'SSH_ENDED_BEFORE_IMAGE_WITNESS')
                if watch in ready:
                    try:os.read(watch,65536)
                    except BlockingIOError:pass
        finally:os.close(watch)
        if qualify:
            os.kill(pid,signal.SIGSTOP);p,status=os.waitpid(pid,os.WUNTRACED);need(p==pid and os.WIFSTOPPED(status),'SSH_HELD_FOR_IMAGE_WITNESS');stopped=True
            need((proc/'stat').read_text().split(') ',1)[1].split()[19]==birth,'SSH_ORIGINAL_BIRTH')
            closure=attest(pid,images,held,trace,end);os.kill(pid,signal.SIGCONT);stopped=False
        need(os.write(w,data)==len(data),'SIGNATURE_STDIN_BYTES');os.close(w);w=None
        ready,_,_=select.select([pidfd],[],[],max(.001,end-time.time()));need(bool(ready),'SSH_ORIGINAL_HANDLE_TIMEOUT')
        p,status=os.waitpid(pid,0);terminal=p==pid;code=os.waitstatus_to_exitcode(status)
        owned.update(originalHandleTerminal=terminal,exitCode=code)
        need(o.stat().st_size+e.stat().st_size<=262144 and tracefile.stat().st_size<=4194304,'SSH_OUTPUT_CAP')
        trace_append();finaltrace=trace;binding_rows(finaltrace,images)
        for line in finaltrace.splitlines():
            if 'calling init:' in line or 'calling fini:' in line:
                target=line.split(':',2)[-1].strip()
                if target.startswith('/'):need(str(Path(target).resolve()) in images,'LATE_UNKNOWN_ELF_PROVIDER')
        return {'pid':pid,'birth':birth,'exitCode':code,'originalHandleTerminal':terminal,'qualifiedImage':qualify,'closure':closure,'stdinBytes':len(data),'stdinSHA256':hashlib.sha256(data).hexdigest(),'stdoutSHA256':S.sha(o),'stderrSHA256':S.sha(e),'traceSHA256':S.sha(tracefile),'traceAndOutputReadBytes':2*trace_offset+o.stat().st_size+e.stat().st_size}
    finally:
        if w is not None:os.close(w)
        if not terminal:
            owned['forced']=True
            try:os.kill(pid,signal.SIGKILL)
            except ProcessLookupError:pass
            try:
                wp,status=os.waitpid(pid,0);owned.update(originalHandleTerminal=wp==pid,exitCode=os.waitstatus_to_exitcode(status))
            except ChildProcessError:pass
        os.close(pidfd)

def main():
    p=argparse.ArgumentParser();p.add_argument('--frame',required=True);p.add_argument('--frame-sha',required=True);a=p.parse_args();raw=Path(a.frame).read_bytes();need(hashlib.sha256(raw).hexdigest()==a.frame_sha,'FRAME_HASH');f=json.loads(raw);guest=Path(f['guestOutputPath'])
    result={'schema':'tail11-owned-linux-signature-proof/v1','status':'HOLD','admitted':False,'role':'LINUX_OPENSSH_MANIFEST_SIGNATURE_ONLY','nonce':f['nonce'],'nativeM1Calls':0,'networkCalls':0};handles=[];held={};images={};current=None
    try:
        need(f['mode']=='signature' and f['schema']=='tail11-linux-role-frame/v1','FIXED_SIGNATURE_SCOPE');result['actualKernel']=S.actual_profile({'runNonce':f['nonce']},'linux-x64')
        for n,h in f['sourceHashes'].items():need(S.sha(Path(f['sourceDirectory'])/n)==h,'SOURCE_BINDING')
        source=Path(f['sourceDirectory']);mp=Path(f['metadataInput']['path']);need(S.sha(mp)==f['metadataInput']['sha256'],'METADATA_INPUT_HASH');meta=S.read(mp,262144)
        need(meta['status']=='METADATA_COMPLETE_NOT_ADMISSION' and meta['admitted'] is False and len(meta['files'])==6,'METADATA_NOT_ROLE_ADMISSION')
        end=min(time.time()+20,f['window']['deadlineUnix']-30);budget=0
        for row in meta['files']:
            path=row['path'];current=path;fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC);handles.append(fd);st=os.fstat(fd)
            need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and not st.st_mode&0o022 and 0<st.st_size<=16777216,'ROOT_NONWRITABLE_ELF')
            body=os.pread(fd,st.st_size,0);budget+=len(body);need(len(body)==st.st_size and hashlib.sha256(body).hexdigest()==row['sha256'],'HELD_ELF_HASH_DRIFT');need(identity(st)==identity(os.fstat(fd)),'HELD_ELF_STABILITY')
            held[path]={'identity':identity(st),'sha256':row['sha256'],'fd':fd};images[path]=Image(path,body)
        need(budget<=33554432,'ELF_FILE_READ_BOUND')
        vp=source.parent/'verify_downloads.py';need(S.sha(vp)==S.VERIFIER_SHA,'FROZEN_VERIFIER');sys.path.insert(0,str(source.parent));import verify_downloads
        inputs={};expected={'SHA256SUMS.txt':('7ed7c353458a935439066a6a1d205520e5610458ec346dd8dbbf5c8882d28709',373),'SHA256SUMS.txt.sig':('bf4ff680a2c4816b08044c47bb05882f6268576dea30bc1a14e275cfab66e840',294),'SIGNING-PUBLIC-KEY.pub':('cc7038b2d98f856af97b58eb06619ff441fbe9b178da5396f61d1ccdf7a65e7c',113)}
        for n,(h,size) in expected.items():
            b=(source/'metadata'/n).read_bytes();need(len(b)==size and hashlib.sha256(b).hexdigest()==h,'PUBLIC_SIGNATURE_INPUT');inputs[n]=b
        key,fp=verify_downloads.canonical_key(inputs['SIGNING-PUBLIC-KEY.pub']);need(fp==S.FINGERPRINT,'KNOWN_FINGERPRINT')
        allowed=guest/'allowed-signers';allowed.write_bytes(('pouriajamali '+key+'\n').encode('ascii'));sig=guest/'checksum-signature';sig.write_bytes(inputs['SHA256SUMS.txt.sig'])
        argv=['/usr/bin/ssh-keygen','-Y','verify','-f',str(allowed),'-I','pouriajamali','-n','file','-s',str(sig)]
        allowed_hash=S.sha(allowed)
        current='OWNED_NATIVE_SIGNATURE';positive=child_run(argv,inputs['SHA256SUMS.txt'],guest,'positive',images,held,end,True);result['positive']=positive;need(positive['exitCode']==0,'NATIVE_SIGNATURE_REJECTED');need(S.sha(sig)==expected['SHA256SUMS.txt.sig'][0] and S.sha(allowed)==allowed_hash,'NATIVE_POSITIVE_INPUT_STABILITY')
        changed=bytearray(inputs['SHA256SUMS.txt']);changed[0]=ord('0') if changed[0]!=ord('0') else ord('1')
        negative=child_run(argv,bytes(changed),guest,'changed-manifest',images,held,end,False);need(negative['exitCode']!=0,'ALTERED_MANIFEST_NOT_REJECTED');result['negativeManifest']=negative
        changed=bytearray(inputs['SHA256SUMS.txt.sig']);i=changed.find(b'\n')+5;need(i<len(changed),'SIGNATURE_NEGATIVE_FRAMING');changed[i]=ord('A') if changed[i]!=ord('A') else ord('B');sig.write_bytes(changed)
        negative=child_run(argv,inputs['SHA256SUMS.txt'],guest,'changed-signature',images,held,end,False);need(negative['exitCode']!=0,'ALTERED_SIGNATURE_NOT_REJECTED');result['negativeSignature']=negative
        for path,row in held.items():
            st=os.fstat(row['fd']);need(identity(st)==row['identity'],'HELD_THROUGH_TERMINAL_IDENTITY');body=os.pread(row['fd'],st.st_size,0);budget+=len(body);need(hashlib.sha256(body).hexdigest()==row['sha256'],'HELD_THROUGH_TERMINAL_HASH')
        read_total=budget+positive['closure']['readOnlyBytes']+positive['closure']['validatedRelocations']*16+sum(r['traceAndOutputReadBytes'] for r in (positive,result['negativeManifest'],negative))+1048576
        need(read_total<=67108864 and time.time()<end,'SIGNATURE_ROLE_BOUNDS')
        result.update(status='QUALIFIED_LINUX_MANIFEST_SIGNATURE',admitted=True,fingerprint=fp,namespace='file',identity='pouriajamali',publicSignatureInputs={n:h for n,(h,_) in expected.items()},heldFilesThroughTerminal=True,readOnlyImageMatches=True,unresolved=[],metadataSHA256=f['metadataInput']['sha256'],sourceHashes=f['sourceHashes'],window=f['window'],roleSeconds=20-(end-time.time()),fileReadBytes=budget,readBytesWithConservativeReserve=read_total)
    except Exception as e:result.update(code=getattr(e,'code','LINUX_SIGNATURE_ROLE_HOLD'),exceptionType=type(e).__name__,errno=getattr(e,'errno',None),phaseOrPath=current,lastELFEvent=LAST_ELF_EVENT)
    finally:
        for fd in handles:os.close(fd)
    result['ownedChildren']=OWNED_CHILDREN;result['signatureExecAttempts']=sum(x['execResumed'] for x in OWNED_CHILDREN)
    S.fresh(guest/'signature-proof.json',result,cap=262144)
    if not result['admitted']:raise SystemExit(1)

if __name__=='__main__':main()
