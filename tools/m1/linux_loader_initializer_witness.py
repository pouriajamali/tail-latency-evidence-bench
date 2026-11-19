"""Debug-typed native initializer values; unknown fields still compare to file."""
from pathlib import Path
import ctypes,errno,hashlib,json,os,stat,struct
import support as S

LAST_EVENT={}
def rseq_values(layout,thread_pointer,configuration):
    members=[x for x in layout['members'] if x['name']=='rseq_area'];S.need(len(members)==1,'EXACT_DEBUG_RSEQ_MEMBER');member=members[0]
    offset=member['offset'];size=member['type']['bytes'];pointer,kernel_size,signature,flags,pad=configuration
    S.need(layout['bytes']==2368 and offset==2336 and size==32 and offset+size==layout['bytes'],'EXACT_DEBUG_RSEQ_LAYOUT')
    S.need(pointer==thread_pointer+offset and kernel_size==size and signature==0x53053053 and flags==pad==0,'KERNEL_OWN_CHILD_RSEQ_CONFIGURATION_MATCHES_TYPED_TLS')
    return offset,size
def dependency_scope(images,main):
    aliases={}
    for path,im in images.items():
        S.need(not any(x['tag'] in (0x7ffffffd,0x7fffffff) for x in im.dynamic),'NO_UNMODELED_FILTER_OR_AUXILIARY_SCOPE')
        names={Path(path).name};sonames=[x['value'] for x in im.dynamic if x['tag']==14]
        S.need(len(sonames)<=1,'UNIQUE_HELD_SONAME')
        if sonames:
            tables=[x['value'] for x in im.dynamic if x['tag']==5];sizes=[x['value'] for x in im.dynamic if x['tag']==10]
            S.need(len(tables)==len(sizes)==1 and 0<=sonames[0]<sizes[0]<=1048576,'BOUNDED_HELD_SONAME_TABLE')
            va=tables[0]+sonames[0];segments=[x for x in im.header['loads'] if x['vaddr']<=va< x['vaddr']+x['filesz']]
            S.need(len(segments)==1,'FILE_BACKED_HELD_SONAME');x=segments[0];off=x['offset']+va-x['vaddr'];end=im.body.find(b'\0',off,off+min(1025,sizes[0]-sonames[0]))
            S.need(end>=off,'BOUNDED_HELD_SONAME');names.add(im.body[off:end].decode('ascii'))
        for name in names:
            S.need(name not in aliases or aliases[name]==path,'UNAMBIGUOUS_HELD_DEPENDENCY_NAME');aliases[name]=path
    order=[main]
    for path in order:
        for name in images[path].header['needed']:
            S.need(name in aliases and '/' not in name and '$' not in name,'EXACT_HELD_NEEDED_PROVIDER');target=aliases[name]
            if target not in order:order.append(target)
    S.need(set(order)==set(images),'ALL_HELD_IMAGES_EXACT_NEEDED_CLOSURE')
    return order
def literal_field_producers(body,loads,field_va,candidates):
    result=[]
    def instruction(va,n):
        choices=[x for x in loads if x['vaddr']<=va and va+n<=x['vaddr']+x['filesz'] and x['flags']&1]
        if len(choices)!=1:return None
        x=choices[0];off=x['offset']+va-x['vaddr'];return body[off:off+n]
    for segment in loads:
        if not segment['flags']&1:continue
        for off in range(segment['offset'],segment['offset']+segment['filesz']-7):
            code=body[off:off+7]
            if code[0] not in (0x48,0x4c) or code[1]!=0x8d or code[2]&0xc7!=5:continue
            va=segment['vaddr']+off-segment['offset'];literal=va+7+struct.unpack_from('<i',code,3)[0]
            if literal not in candidates:continue
            source=((code[2]>>3)&7)+(8 if code[0]&4 else 0);next_va=va+7;jump=instruction(next_va,5);jump_va=None
            if jump and jump[0]==0xeb:jump_va=next_va;next_va+=2+struct.unpack_from('<b',jump,1)[0]
            elif jump and jump[0]==0xe9:jump_va=next_va;next_va+=5+struct.unpack_from('<i',jump,1)[0]
            store=instruction(next_va,7)
            if not store or store[0] not in (0x48,0x4c) or store[1]!=0x89 or store[2]&0xc7!=5:continue
            store_source=((store[2]>>3)&7)+(8 if store[0]&4 else 0)
            if source==store_source and next_va+7+struct.unpack_from('<i',store,3)[0]==field_va:result.append({'literalRVA':literal,'LEA_RVA':va,'unconditionalJumpRVA':jump_va,'storeRVA':next_va,'fieldRVA':field_va,'nativeRegisterIndex':source,'LEAHex':code.hex(),'storeHex':store.hex()})
    return result
def private_initializer_storage(address,length,loader,image,load_base,rows):
    if not 0<length<=65536:return None
    candidates=[m for m in rows if m['perms']=='rw-p' and m['start']<=address and address+length<=m['end']]
    if len(candidates)!=1:return None
    m=candidates[0]
    if m['path'] is None and m['kernelName'] in ('','[heap]','[stack]'):return 'OWN_PRIVATE_ANONYMOUS'
    # The existing minimal allocator starts in the unused final loader page.
    end=load_base+max(x['vaddr']+x['memsz'] for x in image.header['loads']);page_end=(end+4095)&~4095
    if m['path']==loader and end<=address and address+length<=page_end:return 'HELD_LOADER_ZERO_FILL_TAIL'
    return None
def pin_cpu_for_metadata(plan):
    with Path('/proc/cpuinfo').open('rb') as source:raw=source.read(262145)
    S.need(len(raw)<=262144,'BOUNDED_KERNEL_CPU_IDENTITY');matches=[];basic=plan['cpuBasic'];allowed=os.sched_getaffinity(0)
    for block in raw.decode('ascii').split('\n\n'):
        row={k.strip():v.strip() for line in block.splitlines() if ':' in line for k,v in [line.split(':',1)]}
        if 'processor' not in row:continue
        cpu=int(row['processor'])
        if cpu not in allowed or int(row.get('initial apicid','-1'))!=plan['cpuNativeAPICID']:continue
        S.need(row.get('vendor_id')=='GenuineIntel' and basic['kind']==1 and int(row['cpu family'])==basic['family'] and int(row['model'])==basic['model'] and int(row['stepping'])==basic['stepping'] and int(row['cpuid level'])==basic['max_cpuid'],'CURRENT_KERNEL_CPU_MATCHES_PUBLIC_NATIVE_DATA')
        matches.append((cpu,row))
    S.need(len(matches)==1,'SAME_NATIVE_LOGICAL_CPU_REQUIRED');cpu,row=matches[0];os.sched_setaffinity(0,{cpu});S.need(os.sched_getaffinity(0)=={cpu},'ACTUAL_MORE_RESTRICTIVE_OWN_CPU_AFFINITY')
    return {'cpu':cpu,'initialAPICID':plan['cpuNativeAPICID'],'actualAffinity':[cpu],'noCPUBytesMaskedOrRewritten':True,'kernelCPUIdentity':{k:row[k] for k in ('vendor_id','cpu family','model','stepping','cpuid level','initial apicid')},'CPUQuotaUnchanged':'200000 100000'}

def attest_initializers(plan,images,loader,base,links,link_order,rows,fd,read_memory,trace,startup,tls,tls_proof,relocated,tracefile,argv,env):
    global LAST_EVENT
    im=images[loader];S.need(hashlib.sha256(im.body).hexdigest()==plan['loaderSHA256'],'EXACT_NATIVE_PLAN_LOADER');S.need(plan['noParentMemoryValues'] is True,'NO_PARENT_MEMORY_REFERENCE')
    symbols=plan['symbols'];patch={};proof={'schema':'tail11-exact-typed-native-loader-initializers/v1','CPUReference':'Previously produced public native diagnostic, same exact loader and same kernel-identified logical CPU; no parent memory','fields':[]}
    def symbol(name,size=None):
        s=[x for x in symbols if x['name']==name];S.need(len(s)==1 and (size is None or s[0]['size']==size),'EXACT_DEBUG_INITIALIZER_SYMBOL');return s[0]
    def file_at(va,n):
        segs=[x for x in im.header['loads'] if x['vaddr']<=va and va+n<=x['vaddr']+x['filesz']];S.need(len(segs)==1,'EXACT_INITIALIZER_FILE_BYTES');x=segs[0];return im.body[x['offset']+va-x['vaddr']:x['offset']+va-x['vaddr']+n]
    def u64(at):return struct.unpack('<Q',read_memory(fd,at,8))[0]
    def private(at,n):
        return private_initializer_storage(at,n,loader,im,base[loader],rows) is not None
    def cstring(at,cap=512):
        data=bytearray()
        for k in range(cap):
            c=read_memory(fd,at+k,1)
            if c==b'\0':return bytes(data)
            data.extend(c)
        raise S.Hold('BOUNDED_TYPED_STRING')
    def put(va,value,label):
        global LAST_EVENT
        S.need(len(value)>0 and len(value)%8==0,'TYPED_ALIGNED_VALUE');actual=read_memory(fd,base[loader]+va,len(value));LAST_EVENT={'field':label,'RVA':va,'bytes':len(value),'actualSHA256':hashlib.sha256(actual).hexdigest(),'expectedSHA256':hashlib.sha256(value).hexdigest()}
        if actual!=value:
            k=next(i for i,(a,b) in enumerate(zip(actual,value)) if a!=b);LAST_EVENT.update(firstMismatch=va+k,actualHex=actual[k:k+16].hex(),expectedHex=value[k:k+16].hex());raise S.Hold('EXACT_NATIVE_TYPED_INITIALIZER_MISMATCH')
        for k in range(0,len(value),8):patch[(loader,base[loader]+va+k)]=value[k:k+8]
        proof['fields'].append({'name':label,'RVA':va,'bytes':len(value),'allBytesMatch':True,'sha256':hashlib.sha256(value).hexdigest()})
    def static_string(value,field_va=None):
        wanted=value.encode('ascii')+b'\0';matches=[]
        for x in im.header['loads']:
            if not x['flags']&4:continue
            block=im.body[x['offset']:x['offset']+x['filesz']];start=0
            while True:
                at=block.find(wanted,start)
                if at<0:break
                address=base[loader]+x['vaddr']+at
                if any(m['path']==loader and 'r' in m['perms'] and 'w' not in m['perms'] and m['start']<=address and address+len(wanted)<=m['end'] for m in rows):
                    S.need(read_memory(fd,address,len(wanted))==wanted,'TYPED_LITERAL_MATCHES_HELD_FILE');matches.append(x['vaddr']+at)
                start=at+1
        if len(matches)!=1 and field_va is not None:
            producers=literal_field_producers(im.body,im.header['loads'],field_va,set(matches));choices={x['literalRVA'] for x in producers};S.need(len(choices)==1,'EXACT_COMPILED_LITERAL_FIELD_PRODUCER');proof.setdefault('literalFieldProducers',[]).extend(producers);matches=list(choices)
        S.need(len(matches)==1,'UNIQUE_HELD_READONLY_NATIVE_LITERAL');return base[loader]+matches[0]
    # Exact hardware capability pairs, including their packed allocation layout.
    pub=plan['nativePublic'];S.need(pub['dl_hwcaps_subdirs']=='x86-64-v4:x86-64-v3:x86-64-v2' and pub['dl_hwcaps_subdirs_active']==7,'FIXED_ADMITTED_NATIVE_HWCAP_DATA')
    caps=[('glibc-hwcaps/'+x+'/').encode('ascii') for x in pub['dl_hwcaps_subdirs'].split(':')]+[b''];nc=len(caps);maximum=max(len(x) for x in caps)
    count_va=symbol('ncapstr',8)['RVA'];max_va=symbol('max_capstrlen',8)['RVA'];cap_va=symbol('capstr',8)['RVA'];cp=u64(base[loader]+cap_va);total=16*nc+sum(map(len,caps));LAST_EVENT={'field':'capstr allocation','pointer':cp,'bytes':total,'loaderDeclaredEnd':base[loader]+max(x['vaddr']+x['memsz'] for x in im.header['loads']),'containingMaps':[m for m in rows if m['start']<=cp<m['end']]};S.need(cp%16==0 and private(cp,total),'EXACT_PRIVATE_HWCAP_ALLOCATION')
    pairs=bytearray();strings=bytearray();at=cp+16*nc
    for value in caps:pairs.extend(struct.pack('<QQ',at,len(value)));strings.extend(value);at+=len(value)
    S.need(read_memory(fd,cp,total)==bytes(pairs+strings),'ALL_HWCAP_PAIR_AND_STRING_BYTES')
    proof['HWCAPReferentStorage']={'kind':private_initializer_storage(cp,total,loader,im,base[loader],rows),'bytes':total,'allPackedPairsAndStringsMatch':True,'noNewFileProvider':True}
    put(count_va,struct.pack('<Q',nc),'ncapstr');put(max_va,struct.pack('<Q',maximum),'max_capstrlen');put(cap_va,struct.pack('<Q',cp),'capstr_verified_complete_referent')
    # The four system-directory constants come from the held image, not parent data.
    sd=symbol('system_dirs',66);sl=symbol('system_dirs_len',32);raw_dirs=file_at(sd['RVA'],66);lengths=struct.unpack('<QQQQ',file_at(sl['RVA'],32));directories=[];off=0
    for length in lengths:
        name=raw_dirs[off:off+length];S.need(raw_dirs[off+length:off+length+1]==b'\0' and name.startswith(b'/') and name.endswith(b'/'),'PINNED_SYSTEM_DIRECTORY');directories.append((name.decode('ascii'),base[loader]+sd['RVA']+off,length));off+=length+1
    S.need(off==66,'EXACT_SYSTEM_DIRECTORY_PACKING')
    root=base[loader]+symbol('__rtld_search_dirs',16)['RVA'];directory_array=u64(root);S.need(directory_array%8==0 and private(directory_array,40),'PRIVATE_FIVE_POINTER_SEARCH_ARRAY');addresses=struct.unpack('<QQQQQ',read_memory(fd,directory_array,40));S.need(addresses[-1]==0 and addresses[0] and len(set(addresses[:4]))==4,'FOUR_SEARCH_ELEMENTS_AND_NULL')
    stride=((2*40-1+nc*4)//40)*40;S.need(40<=stride<=128 and addresses[:4]==tuple(addresses[0]+i*stride for i in range(4)) and private(addresses[0],4*stride),'EXACT_DEBUG_TYPED_SEARCH_STRIDE')
    what=static_string('system search path');attempted=set();system=False
    for line in trace.splitlines():
        if 'search path=' in line:system='(system search path)' in line
        elif 'search cache=' in line or 'find library=' in line:system=False
        if system and 'trying file=' in line:attempted.add(line.split('trying file=',1)[1].strip())
    cache=[]
    for i,(dirname,name_pointer,length) in enumerate(directories):
        next_pointer=addresses[i+1] if i<3 else 0;head=struct.pack('<QQQQQ',next_pointer,what,0,name_pointer,length);S.need(read_memory(fd,addresses[i],40)==head,'EXACT_SEARCH_ELEMENT_TOPOLOGY_AND_HELD_CONSTANTS')
        statuses=struct.unpack('<'+'I'*nc,read_memory(fd,addresses[i]+40,nc*4))
        for suffix,value in zip(caps,statuses):
            path=dirname+suffix.decode('ascii');seen=any(x.startswith(path) and '/' not in x[len(path):] for x in attempted)
            if value==0:S.need(not seen,'UNKNOWN_CACHE_MUST_HAVE_NO_SYSTEM_LOOKUP')
            else:
                S.need(value in (1,2) and seen,'CACHED_DIRECTORY_REQUIRES_ACTUAL_SYSTEM_SEARCH')
                try:isdir=stat.S_ISDIR(os.stat(path).st_mode)
                except OSError as e:S.need(e.errno in (errno.ENOENT,errno.ENOTDIR),'INDEPENDENT_DIRECTORY_STATE_UNKNOWN');isdir=False
                S.need((value==2)==isdir,'CACHED_STATE_EQUALS_INDEPENDENT_KERNEL_DIRECTORY_RESULT')
            cache.append({'path':path,'status':value,'systemLookupSeen':seen,'independentKernelDirectoryCheck':value!=0})
    put(symbol('__rtld_search_dirs',16)['RVA'],struct.pack('<Qi4x',directory_array,0),'__rtld_search_dirs_complete_typed_graph')
    put(symbol('__rtld_env_path_list',16)['RVA'],struct.pack('<Qi4x',(1<<64)-1,0),'__rtld_env_path_list_no_library_path')
    proof['directoryCache']=cache;proof['searchGraph']={'array':directory_array,'elements':list(addresses),'stride':stride,'allDeclaredFieldsMatched':True,'parentValuesUsed':False}
    # Numeric tunables: immutable defaults plus authenticated setter semantics.
    ts=symbol('tunable_list',5576);expected_table=bytearray(file_at(ts['RVA'],5576));S.need(len(startup.tunable_state)==41,'ALL_NATIVE_TUNABLE_STATES')
    for row,state in zip(plan['tunableRows'],startup.tunable_state):
        j=row['index']*136;default=bytes.fromhex(row['defaultHex']);expected_table[j+88:j+104]=default;typ=row['typeCode'];native=row['nativeDiagnostic']
        if typ==3:S.need(native=={'string':''} and default==bytes(16) and not state['initialized'],'EMPTY_UNTOUCHED_NATIVE_STRING_TUNABLE')
        else:
            S.need(state['value']==native['value']&((1<<64)-1) and state['min']==native['min']&((1<<64)-1) and state['max']==native['max']&((1<<64)-1),'NATIVE_CHILD_TUNABLE_TRANSCRIPT_MATCHES_INDEPENDENT_PUBLIC_DIAGNOSTIC')
            struct.pack_into('<QQ',expected_table,j+56,state['min'],state['max']);struct.pack_into('<Q',expected_table,j+88,state['value']);expected_table[j+104]=int(state['initialized'])
    # Preserve any independently checked ELF relocations in these typed objects.
    for (p,where),value in relocated.items():
        if p==loader and base[loader]+ts['RVA']<=where and where+8<=base[loader]+ts['RVA']+5576:expected_table[where-base[loader]-ts['RVA']:where-base[loader]-ts['RVA']+8]=value
    put(ts['RVA'],bytes(expected_table),'tunable_list_all41_typed_entries')
    # Private function-pointer slots have precise existing native ELF definitions.
    libc=next(p for p in images if Path(p).name=='libc.so.6')
    for slot,name in (('__rtld_calloc','calloc'),('__rtld_free','free'),('__rtld_malloc','malloc'),('__rtld_realloc','realloc'),('___rtld_mutex_lock','pthread_mutex_lock'),('___rtld_mutex_unlock','pthread_mutex_unlock')):
        defs=[s for s in images[libc].symbols if s['name']==name and s['section'] and s['type']==2];targets={s['value'] for s in defs};S.need(len(targets)==1,'EXACT_NATIVE_LIBC_PRIVATE_SLOT_PROVIDER');put(symbol(slot,8)['RVA'],struct.pack('<Q',base[libc]+next(iter(targets))),slot)
    secure=symbol('__libc_enable_secure',4)['RVA'];S.need(startup.auxv.get(23)==0,'SAME_NONSECURE_NATIVE_EXEC');put(secure,struct.pack('<I',0)+file_at(secure+4,4),'__libc_enable_secure_kernel_auxv')
    # Read the kernel's registration for this already held own native thread.
    # The tracer buffer is local; no target state or syscall result is changed.
    from linux_init_write_trace import api
    config=ctypes.create_string_buffer(24);fn=api();ctypes.set_errno(0);returned=fn(0x420f,startup.pid,ctypes.c_void_p(24),ctypes.c_void_p(ctypes.addressof(config)));error=ctypes.get_errno()
    S.need(returned==24 and error==0,'OWN_KERNEL_RSEQ_QUERY_SUPPORTED');configuration=struct.unpack('<QIIII',config.raw);offset,size=rseq_values(plan['layouts']['pthread'],startup.heldRegisters['fs_base'],configuration)
    rseq_tunable=next(x for x in plan['tunableRows'] if x['name']=='glibc.pthread.rseq');S.need(rseq_tunable['nativeDiagnostic']['value']==1,'DECLARED_RSEQ_ENABLED')
    put(symbol('__rseq_offset',8)['RVA'],struct.pack('<q',offset),'__rseq_offset_exact_debug_and_kernel_TLS')
    size_va=symbol('__rseq_size',4)['RVA'];put(size_va,struct.pack('<I',size)+file_at(size_va+4,4),'__rseq_size_exact_kernel_registration')
    proof['kernelRSEQ']={'query':'PTRACE_GET_RSEQ_CONFIGURATION','pid':startup.pid,'returnBytes':returned,'pointerEqualsHeldTLSMember':True,'offset':offset,'size':size,'signature':configuration[2],'flags':configuration[3],'noTargetStateWritten':True}
    S.need(len(startup.kernelRandom)==16,'ORIGINAL_KERNEL_AT_RANDOM_CAPTURE');guard=startup.kernelRandom[8:16]
    S.need(read_memory(fd,startup.heldRegisters['fs_base']+48,8)==guard,'NATIVE_TLS_POINTER_GUARD_EQUALS_ORIGINAL_KERNEL_RANDOM')
    put(symbol('__pointer_chk_guard_local',8)['RVA'],guard,'__pointer_chk_guard_local_original_kernel_AT_RANDOM')
    argc_va=symbol('_dl_argc',4)['RVA'];put(argc_va,struct.pack('<I',len(argv))+file_at(argc_va+4,4),'_dl_argc_declared_kernel_exec_vector')
    # Derive auxv position from the kernel-created argument/environment vector.
    ap=startup.kernelArgv;S.need(u64(ap-8)==len(argv),'KERNEL_ARGC_MATCH');actual_args=[u64(ap+8*i) for i in range(len(argv)+1)];S.need(actual_args[-1]==0 and [cstring(x).decode('ascii') for x in actual_args[:-1]]==argv,'KERNEL_ARGV_ALL_PUBLIC_INPUTS_MATCH')
    ep=ap+8*(len(argv)+1);actual_env=[]
    for k in range(17):
        pointer=u64(ep+8*k)
        if not pointer:aux_pointer=ep+8*(k+1);break
        actual_env.append(cstring(pointer,2048).decode('ascii'))
    else:raise S.Hold('BOUNDED_HERMETIC_NATIVE_ENVIRONMENT')
    S.need(set(actual_env)=={k+'='+v for k,v in env.items()} and len(actual_env)==len(env),'EXACT_DECLARED_NATIVE_ENVIRONMENT')
    raw_aux=Path('/proc')/str(startup.pid)/'auxv';aux=raw_aux.read_bytes();S.need(len(aux)<=16384 and read_memory(fd,aux_pointer,len(aux))==aux,'ACTUAL_KERNEL_STACK_AUXV_BYTES')
    gro=symbol('_rtld_global_ro',952)['RVA'];expected=bytearray(file_at(gro,952))
    for (p,where),value in relocated.items():
        if p==loader and base[loader]+gro<=where and where+8<=base[loader]+gro+952:expected[where-base[loader]-gro:where-base[loader]-gro+8]=value
    fields={f['name']:f for f in plan['layouts']['rtld_global_ro']['members']};S.need(plan['layouts']['rtld_global_ro']['bytes']==952 and len(fields)==51,'EXACT_GLOBAL_RO_DWARF')
    def set_int(name,value,size):
        f=fields[name];S.need(f['type'].get('bytes')==size,'EXACT_GLOBAL_FIELD_WIDTH');expected[f['offset']:f['offset']+size]=(value&((1<<(8*size))-1)).to_bytes(size,'little')
    set_int('_dl_debug_mask',0x47,4);set_int('_dl_lazy',0,4);set_int('_dl_platform',static_string(pub['dl_platform'],gro+fields['_dl_platform']['offset']),8);set_int('_dl_platformlen',len(pub['dl_platform']),8);set_int('_dl_pagesize',startup.auxv[6],8);set_int('_dl_minsigstacksize',startup.auxv.get(51,0),8);set_int('_dl_clktck',startup.auxv[17],4);set_int('_dl_auxv',aux_pointer,8)
    debug_fd=struct.unpack('<i',read_memory(fd,base[loader]+gro+fields['_dl_debug_fd']['offset'],4))[0];S.need(3<=debug_fd<256 and Path(os.readlink('/proc/'+str(startup.pid)+'/fd/'+str(debug_fd)))==tracefile and Path('/proc/'+str(startup.pid)+'/fd/'+str(debug_fd)).stat().st_ino==tracefile.stat().st_ino,'NATIVE_DEBUG_DESCRIPTOR_IS_EXACT_OWN_TRACE');set_int('_dl_debug_fd',debug_fd,4)
    for name,key in (('_dl_hwcap','dl_hwcap'),('_dl_hwcap2','dl_hwcap2'),('_dl_hwcap3','dl_hwcap3'),('_dl_hwcap4','dl_hwcap4')):set_int(name,pub[key],8)
    cpu=bytes.fromhex(plan['cpuExpectedHex']);S.need(len(cpu)==520 and fields['_dl_x86_cpu_features']['offset']==112,'EXACT_ALL_CPU_FIELDS');expected[112:632]=cpu
    main='/usr/bin/ssh-keygen';scope=u64(links[main]+760);count=struct.unpack('<I',read_memory(fd,links[main]+768,4))[0];scope_order=dependency_scope(images,main);LAST_EVENT={'field':'initial dependency scope','pointer':scope,'count':count,'expectedCount':len(scope_order),'expectedOrder':scope_order,'loadedObjectOrder':link_order};S.need(count==len(scope_order) and private(scope,count*8),'EXACT_INITIAL_SCOPE_GRAPH_SIZE');scope_bytes=struct.pack('<'+'Q'*count,*(links[p] for p in scope_order));S.need(read_memory(fd,scope,len(scope_bytes))==scope_bytes,'INITIAL_SCOPE_EQUALS_EXACT_HELD_NEEDED_BREADTH_FIRST_ORDER');expected[48:64]=struct.pack('<QI4x',scope,count);proof['initialScope']={'order':scope_order,'count':count,'allPointerBytesMatch':True,'source':'HELD_ELF_DT_NEEDED_BREADTH_FIRST_NO_PRELOAD','vDSOSeparateKernelObject':True}
    static_align=max([64]+[r['alignment'] for r in tls.values()]);static_used=max(r['offsetFromTP'] for r in tls.values());surplus=1664;static_size=((static_used+surplus+static_align-1)//static_align)*static_align+2368;set_int('_dl_tls_static_size',static_size,8);set_int('_dl_tls_static_align',static_align,8);set_int('_dl_tls_static_surplus',surplus,8)
    sort_row=next(x for x in plan['tunableRows'] if x['name']=='glibc.rtld.dynamic_sort');sort_name='dso_sort_algorithm_original' if sort_row['nativeDiagnostic']['value']==1 else 'dso_sort_algorithm_dfs';set_int('_dl_dso_sort_algo',fields['_dl_dso_sort_algo']['type']['values'][sort_name],4)
    # Exact four-directory topology has no RPATH/LD_LIBRARY_PATH additions here.
    S.need(all(not any(d['tag'] in (15,29) for d in x.dynamic) for x in images.values()),'NO_UNMODELED_RPATH_OR_RUNPATH')
    rg=symbol('_rtld_global',4352)['RVA'];S.need(u64(base[loader]+rg+2728)==addresses[0],'ALL_DIRS_EQUALS_VALIDATED_SYSTEM_TOPOLOGY');set_int('_dl_init_all_dirs',addresses[0],8)
    vdso=startup.auxv[33];set_int('_dl_sysinfo_dso',vdso,8);set_int('_dl_sysinfo_map',links['linux-vdso.so.1'],8)
    from linux_ssh_role import KERNEL_WITNESS
    names={'_dl_vdso_clock_gettime64':'__vdso_clock_gettime','_dl_vdso_gettimeofday':'__vdso_gettimeofday','_dl_vdso_time':'__vdso_time','_dl_vdso_getcpu':'__vdso_getcpu','_dl_vdso_clock_getres_time64':'__vdso_clock_getres'}
    for field,name in names.items():set_int(field,vdso+KERNEL_WITNESS['symbolRVAs'][name],8)
    set_int('_dl_find_object',base[loader]+symbol('_dl_find_object')['RVA'],8)
    put(gro,bytes(expected),'_rtld_global_ro_exact_typed_native_inputs')
    return patch,proof
