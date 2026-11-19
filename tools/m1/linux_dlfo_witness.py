"""Exact debug-bound initial object index; no arbitrary RELRO byte exemptions."""
import hashlib,struct
import support as S

DEBUG_SHA='ccb393c26fab978e94136e6875486e54eaafb0f021b766573c00d03c62532209'
LOADER_SHA='c20a2dc8917c755f02b94049356320fe1f62ac7d9f8994731f807d9df39302da'
OBJECTS={'_dlfo_nodelete_mappings':(222112,8),'_dlfo_nodelete_mappings_size':(222120,8),'_dlfo_nodelete_mappings_end':(222128,8),'_dlfo_main':(222144,32)}
LAST_EVENT={}

def attest_index(analysis,images,loader,base,rows,fd,vi,vdso_base,links,read_memory):
    global LAST_EVENT
    LAST_EVENT={'phase':'EXACT_DEBUG_AND_INITIALIZER_BINDING'}
    S.need(hashlib.sha256(images[loader].body).hexdigest()==LOADER_SHA,'DLFO_EXACT_LOADER')
    S.need(analysis['status']=='EXACT_DEBUG_DATA_STATIC_SYMBOLS_ONLY' and analysis['admitted'] is False and analysis['input']['sha256']==DEBUG_SHA and analysis['input']['buildID']=='0d77dbd4379bf0b5af3e05be7fb6af1e4cea7c96' and analysis['input']['debuglinkCRC32']=='7273804a','DLFO_EXACT_DEBUG_BINDING')
    for name,(va,n) in OBJECTS.items():
        matches=[s for s in analysis['symbols'] if s['name']==name]
        S.need(len(matches)==1 and matches[0]['RVA']==va and matches[0]['size']==n and matches[0]['type']==1 and matches[0]['section']==16,'DLFO_EXACT_PRIVATE_OBJECT')
    # The actual held loader contains a RIP-relative store into this exact object.
    S.need(images[loader].body[19363:19370]==bytes.fromhex('488905f6170300') and 19370+struct.unpack_from('<i',images[loader].body,19366)[0]==222112,'DLFO_NATIVE_INITIALIZER_STORE')
    def tuple_for(path,im,address):
        loads=im.header['loads'];S.need(loads and all(x['memsz']>0 for x in loads),'DLFO_LOAD_RANGES')
        first=min(x['vaddr']&~4095 for x in loads);last=max(x['vaddr']+x['memsz'] for x in loads)
        po=struct.unpack_from('<Q',im.body,32)[0];ps,pn=struct.unpack_from('<HH',im.body,54)
        eh=[]
        for i in range(pn):
            kind,flags,offset,va,_,fs,ms,align=struct.unpack_from('<IIQQQQQQ',im.body,po+i*ps)
            if kind==0x6474e550:eh.append(address+va)
        S.need(len(eh)<=1,'DLFO_UNIQUE_EH_FRAME')
        return (address+first,address+last,links[path],eh[0] if eh else 0)
    main='/usr/bin/ssh-keygen';S.need(set(links)==set(images)|{'linux-vdso.so.1'},'DLFO_COMPLETE_LINK_MAP')
    loads=sorted(images[main].header['loads'],key=lambda x:x['vaddr'])
    # Support only the exact contiguous initial executable case; unknown layouts HOLD.
    S.need(all(((a['vaddr']+a['memsz']+4095)&~4095)==(b['vaddr']&~4095) for a,b in zip(loads,loads[1:])),'DLFO_MAIN_CONTIGUOUS_PHDR_REQUIRED')
    main_tuple=tuple_for(main,images[main],base[main])
    wanted=[tuple_for(p,im,base[p]) for p,im in images.items() if p!=main]
    wanted.append(tuple_for('linux-vdso.so.1',vi,vdso_base));wanted.sort()
    S.need(1<=len(wanted)<=16 and all(a[1]<=b[0] for a,b in zip(wanted,wanted[1:])),'DLFO_SORTED_DISJOINT_EXPECTED_OBJECTS')
    def scalar(name):return struct.unpack('<Q',read_memory(fd,base[loader]+OBJECTS[name][0],8))[0]
    pointer=scalar('_dlfo_nodelete_mappings');count=scalar('_dlfo_nodelete_mappings_size');last=scalar('_dlfo_nodelete_mappings_end')
    LAST_EVENT={'phase':'DLFO_TYPED_HEADER','pointer':pointer,'count':count,'end':last,'expectedCount':len(wanted),'expectedEnd':wanted[-1][1]}
    S.need(count==len(wanted) and last==wanted[-1][1] and pointer%16==0,'DLFO_EXACT_COUNT_END_ALIGNMENT')
    regions=[m for m in rows if m['path'] is None and m['kernelName'] in ('','[heap]') and m['perms']=='rw-p' and m['start']<=pointer and pointer+32*count<=m['end']]
    S.need(len(regions)==1,'DLFO_PRIVATE_NONEXECUTABLE_TYPED_ALLOCATION')
    expected=b''.join(struct.pack('<QQQQ',*r) for r in wanted);actual=read_memory(fd,pointer,len(expected))
    LAST_EVENT.update(phase='DLFO_EXACT_REFERENT_COMPARE',actualObjects=[list(x) for x in struct.iter_unpack('<QQQQ',actual)],expectedObjects=[list(x) for x in wanted])
    S.need(actual==expected,'DLFO_ALL_REFERENT_FIELDS_FROM_HELD_PHDR_AND_ACTUAL_LINK_MAP')
    actual_main=read_memory(fd,base[loader]+OBJECTS['_dlfo_main'][0],32)
    LAST_EVENT.update(phase='DLFO_EXACT_MAIN_COMPARE',actualMain=list(struct.unpack('<QQQQ',actual_main)),expectedMain=list(main_tuple))
    S.need(actual_main==struct.pack('<QQQQ',*main_tuple),'DLFO_EXACT_MAIN_OBJECT_FIELDS')
    # Only the identified objects have typed expected values; all remaining bytes compare.
    patch={}
    values={'_dlfo_nodelete_mappings':struct.pack('<Q',pointer),'_dlfo_nodelete_mappings_size':struct.pack('<Q',len(wanted)),'_dlfo_nodelete_mappings_end':struct.pack('<Q',wanted[-1][1]),'_dlfo_main':struct.pack('<QQQQ',*main_tuple)}
    for name,value in values.items():
        va,n=OBJECTS[name];S.need(len(value)==n,'DLFO_TYPED_SIZE')
        for k in range(0,n,8):patch[(loader,base[loader]+va+k)]=value[k:k+8]
    proof={'schema':'tail11-exact-dlfo-initial-index/v1','debugSHA256':DEBUG_SHA,'loaderSHA256':LOADER_SHA,'nativeInitializerStoreRVA':19363,'pointerObjectRVA':222112,'privateAllocation':{'pointer':pointer,'bytes':len(expected),'perms':regions[0]['perms']},'count':count,'end':last,'main':list(main_tuple),'objects':[list(x) for x in wanted],'allReferentFieldsMatchHeldPHDRsAndActualLinkMap':True,'referentSHA256':hashlib.sha256(actual).hexdigest(),'typedBytes':sum(len(v) for v in values.values()),'remainingReadOnlyBytesExempted':0}
    return patch,proof
