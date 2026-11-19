"""Exact x86-64 child TLS identity from DWARF, PHDR, native FS and DTV."""
import struct
import support as S

OFFSETS={'l_tls_initimage':1120,'l_tls_initimage_size':1128,'l_tls_blocksize':1136,'l_tls_align':1144,'l_tls_firstbyte_offset':1152,'l_tls_offset':1160,'l_tls_modid':1168}
def attest_tls(layout,images,base,links,rows,fd,fs_base,read_memory):
    lm=layout['layouts']['link_map'];tc=layout['layouts']['pthread'];S.need(lm['bytes']==1208 and tc['bytes']==2368 and tc['alignment']==64,'EXACT_DEBUG_TLS_LAYOUT')
    for name,off in OFFSETS.items():
        fields=[x for x in lm['members'] if x['name']==name];S.need(len(fields)==1 and fields[0]['offset']==off and fields[0]['type']['bytes']==8,'EXACT_TLS_LINK_MAP_FIELD')
    def u64(address):return struct.unpack('<Q',read_memory(fd,address,8))[0]
    S.need(fs_base and fs_base%64==0 and u64(fs_base)==fs_base and u64(fs_base+16)==fs_base,'KERNEL_FS_NATIVE_TCB_IDENTITY')
    dtv=u64(fs_base+8);S.need(dtv%16==0,'NATIVE_DTV_ALIGNMENT');allocated=u64(dtv-16);S.need(1<=allocated<=256,'NATIVE_DTV_BOUNDED_LENGTH')
    result={};ids=set();proof=[]
    for path,im in images.items():
        po=struct.unpack_from('<Q',im.body,32)[0];ps,pn=struct.unpack_from('<HH',im.body,54);tls=[]
        for i in range(pn):
            p=struct.unpack_from('<IIQQQQQQ',im.body,po+i*ps)
            if p[0]==7:tls.append(p)
        S.need(len(tls)<=1,'ONE_TLS_PROGRAM_HEADER')
        if not tls:continue
        p=tls[0];_,flags,offset,va,pa,fs,ms,align=p;S.need(0<ms<=1048576 and align>0 and align&(align-1)==0,'BOUNDED_FILE_TLS_HEADER')
        actual={name:u64(links[path]+off) for name,off in OFFSETS.items()}
        S.need(actual['l_tls_initimage']==base[path]+va and actual['l_tls_initimage_size']==fs and actual['l_tls_blocksize']==ms and actual['l_tls_align']==align and actual['l_tls_firstbyte_offset']==va%(align or 1),'ACTUAL_TLS_LINK_MAP_EQUALS_HELD_FILE_PHDR')
        modid=actual['l_tls_modid'];static_offset=actual['l_tls_offset'];S.need(1<=modid<=allocated and modid not in ids and ms<=static_offset<=1048576,'UNIQUE_NATIVE_STATIC_TLS_MODULE');ids.add(modid)
        pointer=u64(dtv+16*modid);S.need(pointer==fs_base-static_offset and pointer%align==va%align,'NATIVE_DTV_AND_KERNEL_TP_AGREE')
        ranges=[m for m in rows if m['path'] is None and m['perms']=='rw-p' and m['start']<=pointer and pointer+ms<=m['end']]
        S.need(len(ranges)==1,'ACTUAL_PRIVATE_STATIC_TLS_RANGE')
        row={'provider':path,'moduleID':modid,'offsetFromTP':static_offset,'pointer':pointer,'fileVaddr':va,'fileBytes':fs,'memoryBytes':ms,'alignment':align,'nativeLinkMapPHDRAndDTVAgree':True};result[path]=row;proof.append(row)
    S.need(result,'NATIVE_STATIC_TLS_EXPECTED')
    return result,{'schema':'tail11-native-child-tls/v1','kernelFSBase':fs_base,'nativeDTV':dtv,'dtvAllocationEntries':allocated,'modules':proof,'writableTLSBytesClaimedEqual':False,'moduleIDsCopiedFromParent':False,'guessedOffsets':False,'TCBSize':tc['bytes'],'TCBAlignment':tc['alignment']}

def expected_slot(src,symbol,typ,addend,images,native,tls):
    if not symbol['name']:
        S.need(symbol is images[src].symbols[0] and all(symbol[k]==0 for k in ('bind','type','visibility','section','value','size')) and symbol['version'] is None,'EXACT_ELF_STN_UNDEF_LOCAL_TLS')
        provider=src;value=0;S.need(provider in tls,'CURRENT_NATIVE_TLS_MODULE')
        S.need((typ==16 and addend==0) or (typ in (17,18) and 0<=addend<tls[provider]['memoryBytes']),'LOCAL_TLS_ADDEND_WITHIN_BOUND_MODULE')
    else:
        provider=native.get((src,symbol['name'],symbol['version']))
        if provider is None and symbol['section'] and (symbol['bind']==0 or symbol['visibility'] in (2,3)):provider=src
        S.need(provider in tls,'ACTUAL_TLS_BINDING_PROVIDER')
        defs=[x for x in images[provider].symbols if x['name']==symbol['name'] and x['section'] and x['type']==6 and (symbol['version'] is None or x['version']==symbol['version'])]
        choices={(x['value'],x['size']) for x in defs};S.need(len(choices)==1,'EXACT_TLS_EXPORT');value,size=next(iter(choices));S.need(value+max(1,size)<=tls[provider]['memoryBytes'],'TLS_SYMBOL_WITHIN_BOUND_MODULE')
    S.need(provider in tls,'CURRENT_NATIVE_TLS_MODULE')
    if typ==16:expected=tls[provider]['moduleID']
    elif typ==17:expected=value+addend
    elif typ==18:expected=value+addend-tls[provider]['offsetFromTP']
    else:raise S.Hold('UNSUPPORTED_NATIVE_TLS_RELOCATION')
    return provider,expected&((1<<64)-1)
