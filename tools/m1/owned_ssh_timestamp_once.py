"""Timestamp prefix executed once; conditional SSH/mapping branch NOT executed or admitted."""
from pathlib import Path
import argparse, ctypes, hashlib, json, os, re, struct, subprocess, time, contextlib
import _winapi
import support as S
import qualifier as Q
from crypto_held_reader import input_held_read
from six_held_readers import input_held_read as six_held_read
from eset_held_reader import input_held_read as eset_held_read

TARGET = Path(r'C:\Windows\System32\libcrypto.dll')
SSH = Path(r'C:\Windows\System32\OpenSSH\ssh-keygen.exe')
FILE_SHA = 'f0ec94e4464dd4b1d376e47d5a1b2a09ff2545980be729bad37b66cc2c71bb68'
SSH_SHA = 'c9dc170cd161db87e75eb6cf282f1325005b9e35628b9a36cb19883a8be1a34f'
ESET = r'C:\Program Files\ESET\ESET Security\ebehmoni.dll'
KEY = 'SHA256:AgU5bZlJSjUu0KsWMmVEEr+BfXpcMVNroTA33bHcQdU'
DATA = {'schema': 'tail11-owned-ssh-all-gaps-proof/v1', 'status': 'HOLD',
        'providerAdmission': False, 'healthyTestsRepeated': 0, 'signatureInvocations': 0,
        'networkGETs': 0, 'dependencyBodiesRead': 0, 'moduleEnumerations': 0,
        'systemTrustOrProtectionChanged': False, 'unresolved': []}

class MI(ctypes.Structure):
    _fields_ = [('base', ctypes.c_void_p), ('size', ctypes.c_uint), ('entry', ctypes.c_void_p)]

def need(ok, code):
    if not ok:
        raise S.Hold(code)

def hx(data):
    return hashlib.sha256(data).hexdigest()

def api():
    k = ctypes.WinDLL('kernel32', use_last_error=True)
    p = ctypes.WinDLL('psapi', use_last_error=True)
    specs = {
        'GetCurrentProcess': ([], ctypes.c_void_p),
        'OpenJobObjectW': ([ctypes.c_uint, ctypes.c_int, ctypes.c_wchar_p], ctypes.c_void_p),
        'IsProcessInJob': ([ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p], ctypes.c_int),
        'GetProcessTimes': ([ctypes.c_void_p] * 5, ctypes.c_int),
        'ResumeThread': ([ctypes.c_void_p], ctypes.c_uint),
        'ReadProcessMemory': ([ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p], ctypes.c_int),
        'GetModuleHandleW': ([ctypes.c_wchar_p], ctypes.c_void_p),
        'GetProcAddress': ([ctypes.c_void_p, ctypes.c_void_p], ctypes.c_void_p),
        'GetModuleHandleExW': ([ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p], ctypes.c_int),
        'GetFinalPathNameByHandleW': ([ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint, ctypes.c_uint], ctypes.c_uint),
        'PeekNamedPipe': ([ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p], ctypes.c_int),
        'ReadFile': ([ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p], ctypes.c_int),
        'WriteFile': ([ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p], ctypes.c_int),
        'GetProcessMitigationPolicy': ([ctypes.c_void_p,ctypes.c_uint,ctypes.c_void_p,ctypes.c_size_t],ctypes.c_int),
        'VirtualQueryEx': ([ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_size_t],ctypes.c_size_t),
        'CloseHandle': ([ctypes.c_void_p], ctypes.c_int),
    }
    for name, (args, result) in specs.items():
        fn = getattr(k, name); fn.argtypes = args; fn.restype = result
    p.EnumProcessModulesEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_uint]
    p.GetModuleFileNameExW.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint]
    p.GetModuleInformation.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint]
    p.GetMappedFileNameW.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint]
    return k, p

def modules(p, process):
    array = (ctypes.c_void_p * 256)(); size = ctypes.c_uint()
    need(p.EnumProcessModulesEx(process, array, ctypes.sizeof(array), ctypes.byref(size), 3), 'OWN_SSH_MODULE_METADATA')
    DATA['moduleEnumerations'] += 1
    need(size.value <= ctypes.sizeof(array), 'OWN_SSH_MODULE_COUNT')
    rows = []
    for i in range(size.value // ctypes.sizeof(ctypes.c_void_p)):
        name = ctypes.create_unicode_buffer(1024); base = int(array[i]); mi = MI()
        n = p.GetModuleFileNameExW(process, base, name, len(name))
        need(0 < n < len(name) - 1 and p.GetModuleInformation(process, base, ctypes.byref(mi), ctypes.sizeof(mi)), 'OWN_SSH_MODULE_ROW')
        rows.append({'path': name.value, 'base': base, 'size': mi.size})
    return rows

def map_one(k, ps, process, rows, disk, nt_path, target, providers, only_rdata=False):
    found = [r for r in rows if r['path'].lower() == str(target).lower()]
    need(len(found) == 1, 'EXACT_CHILD_LIBCRYPTO_MAPPING')
    module = found[0]; base = module['base']; total = 0
    name = ctypes.create_unicode_buffer(1024)
    n = ps.GetMappedFileNameW(process, base, name, len(name))
    need(0 < n < len(name) - 1 and name.value.lower() == nt_path.lower(), 'OWN_SSH_BACKING_FILE')
    def memory(rva, count):
        nonlocal total
        need(OPERATION_CLOCK()>0,'OWNED_SSH_ABSOLUTE_WORK_CLOCK')
        if only_rdata:need((rva==0 and count<=4096) or (1273856<=rva and rva+count<=1273856+575188),'ONLY_APPROVED_LIBCRYPTO_RDATA_RANGE')
        if not only_rdata:
            need(DATA.get('newReadOnlyImageBytes',0)+count<=8388608,'NEW_IMAGE_COMBINED_8M');DATA['newReadOnlyImageBytes']=DATA.get('newReadOnlyImageBytes',0)+count
        need(0 <= rva and 0 <= count and rva + count <= module['size'] and total + count <= 16777216, 'OWN_SSH_LIBCRYPTO_READ_CAP')
        buf = ctypes.create_string_buffer(count); got = ctypes.c_size_t()
        need(k.ReadProcessMemory(process, base + rva, buf, count, ctypes.byref(got)) and got.value == count, 'OWN_SSH_LIBCRYPTO_READ')
        total += count
        return buf.raw
    pe = struct.unpack_from('<I', disk, 0x3c)[0]; opt = pe + 24
    count, optlen = struct.unpack_from('<H', disk, pe + 6)[0], struct.unpack_from('<H', disk, pe + 20)[0]
    need(disk[pe:pe+4] == b'PE\0\0' and struct.unpack_from('<H', disk, pe+4)[0] == 0x8664 and struct.unpack_from('<H', disk, opt)[0] == 0x20b, 'CRYPTO_AMD64_PE')
    preferred = struct.unpack_from('<Q', disk, opt+24)[0]
    image, headers = struct.unpack_from('<II', disk, opt+56)
    need(image == module['size'] and headers <= 4096, 'CRYPTO_IMAGE_SIZE')
    mapped_header = memory(0, headers); expected_header = bytearray(disk[:headers])
    mapped_base = struct.unpack_from('<Q', mapped_header, opt+24)[0]
    need(mapped_base in (preferred, base), 'CRYPTO_TYPED_HEADER_IMAGEBASE')
    struct.pack_into('<Q', expected_header, opt+24, mapped_base)
    need(mapped_header == expected_header, 'CRYPTO_HEADER_DIFFERENCE')
    sections = []
    for i in range(count):
        at = opt + optlen + 40*i; vs, rva, size, raw = struct.unpack_from('<IIII', disk, at+8)
        sections.append({'name': disk[at:at+8].rstrip(b'\0').decode('ascii'), 'rva': rva,
                         'bytes': min(size, vs or size), 'raw': raw, 'flags': struct.unpack_from('<I', disk, at+36)[0]})
    def raw_rva(rva, size):
        hits = [s['raw'] + rva - s['rva'] for s in sections if s['rva'] <= rva and rva-s['rva']+size <= s['bytes']]
        need(len(hits) == 1 and hits[0]+size <= len(disk), 'CRYPTO_FILE_RVA')
        return hits[0]
    relocs = []; rr, rs = struct.unpack_from('<II', disk, opt+112+5*8)
    if rr:
        at = raw_rva(rr, rs); stop = at+rs
        while at < stop:
            page, length = struct.unpack_from('<II', disk, at)
            need(length >= 8 and length % 2 == 0 and at+length <= stop, 'CRYPTO_RELOCATION_BLOCK')
            for offset in range(at+8, at+length, 2):
                item = struct.unpack_from('<H', disk, offset)[0]; kind = item >> 12
                if kind:
                    need(kind == 10, 'CRYPTO_RELOCATION_TYPE'); relocs.append(page+(item & 4095))
            at += length
    byname = {Path(r['path']).name.lower(): r for r in rows}
    parent = k.GetCurrentProcess()
    def parent_name(handle):
        buf = ctypes.create_unicode_buffer(1024); n = ps.GetModuleFileNameExW(parent, handle, buf, len(buf))
        return buf.value if 0 < n < len(buf)-1 else None
    def address(handle, thunk, label):
        if thunk >> 63:
            return k.GetProcAddress(handle, ctypes.c_void_p(thunk & 65535))
        buf = ctypes.create_string_buffer(label.encode('ascii') + b'\0')
        return k.GetProcAddress(handle, ctypes.cast(buf, ctypes.c_void_p))
    def translated(handle, thunk, label):
        if not handle:
            return None
        path = parent_name(handle)
        if not path or not Q.os_base_provider(Path(path)):
            return None
        value = address(handle, thunk, label)
        if not value:
            return None
        owner = ctypes.c_void_p()
        if not k.GetModuleHandleExW(6, value, ctypes.byref(owner)):
            return None
        ownerpath = parent_name(owner)
        if not ownerpath or not Q.os_base_provider(Path(ownerpath)):
            return None
        host = byname.get(Path(ownerpath).name.lower())
        if not host or not Q.os_base_provider(Path(host['path'])):
            return None
        offset = value-owner.value
        if not 0 <= offset < host['size']:
            return None
        return host['base']+offset, Path(ownerpath).name.lower(), offset
    imports = []; iat = []; ir, size = struct.unpack_from('<II', disk, opt+112+8)
    ip = raw_rva(ir, size)
    for descriptor in range(min(size//20, 1024)):
        lookup, _, _, name_rva, first = struct.unpack_from('<IIIII', disk, ip+20*descriptor)
        if not any((lookup, name_rva, first)):
            break
        at = raw_rva(name_rva, 1); end = disk.find(b'\0', at, at+129)
        need(end > at, 'CRYPTO_IMPORT_NAME'); dll = disk[at:end].decode('ascii').lower()
        imports.append({'name': dll, 'kind': 'normal'})
        lookup = lookup or first
        for i in range(1024):
            need(OPERATION_CLOCK()>0,'IMPORT_RESOLUTION_ABSOLUTE_CLOCK')
            thunk = struct.unpack_from('<Q', disk, raw_rva(lookup+8*i, 8))[0]
            if not thunk:
                break
            if thunk >> 63:
                label = 'ordinal-'+str(thunk & 65535)
            else:
                at = raw_rva(thunk+2, 1); end = disk.find(b'\0', at, at+257)
                need(end > at, 'CRYPTO_IMPORT_SYMBOL'); label = disk[at:end].decode('ascii')
            need(any(s['rva'] <= first+8*i and first+8*i+8 <= s['rva']+s['bytes'] and not s['flags'] & (0x80000000|0x02000000) for s in sections), 'CRYPTO_IAT_READONLY_SCOPE')
            value = struct.unpack('<Q', memory(first+8*i, 8))[0]
            candidates = []
            if dll.startswith(('api-ms-win-', 'ext-ms-')):
                # No API-set DLL load or dependency body read: match the named native
                # export against already mapped OS_BASE hosts and their child RVAs.
                handles = [k.GetModuleHandleW(dll)] + [k.GetModuleHandleW(Path(r['path']).name) for r in rows if Q.os_base_provider(Path(r['path']))]
            else:
                handles = [k.GetModuleHandleW(dll)] if dll in byname and Q.os_base_provider(Path(byname[dll]['path'])) else []
            dep=byname.get(dll)
            if dep and dep['path'].lower() in providers:
                resolved=approved_export_target(dll,thunk,label,providers,byname,translated,k,actual=value)
                if resolved and resolved[0]==value:candidates.append(resolved)
            for h in handles:
                item = translated(h, thunk, label)
                if item and item[0] == value and item not in candidates:
                    candidates.append(item)
            row = {'contract': dll, 'symbol': label, 'rva': first+8*i, 'bytes': 8, 'actual': value, 'resolved': bool(candidates)}
            if candidates:
                row.update(host=candidates[0][1], hostExportRVA=candidates[0][2])
            else:
                DATA['unresolved'].append({'from': Path(target).name, 'dependency': dll, 'symbol': label, 'code': 'IAT_TARGET_NOT_BOUND_TO_EXPECTED_NATIVE_OS_BASE_EXPORT'})
            iat.append(row)
        else:
            raise S.Hold('CRYPTO_THUNK_CAP')
    else:
        raise S.Hold('CRYPTO_IMPORT_DESCRIPTOR_CAP')
    need(imports == Q.pe_imports(disk), 'CRYPTO_DECLARED_IMPORT_PARSE')

    proof=[];state={'path':str(target),'base':base,'sections':[],'typed':[],'allOutsideTypedExact':True,'disk':disk,'preferred':preferred,'module':module}
    lr,ls=struct.unpack_from('<II',disk,opt+112+10*8)
    load_fields=[]
    if lr and ls>=128:
        lp=raw_rva(lr,min(ls,148));declared=struct.unpack_from('<I',disk,lp)[0];usable=min(ls,declared)
        guard_flags=struct.unpack_from('<I',disk,lp+144)[0] if usable>=148 else 0
        for off,kind in [(112,'GuardCFCheckFunctionPointer'),(120,'GuardCFDispatchFunctionPointer')]:
            if usable>=off+8:
                va=struct.unpack_from('<Q',disk,lp+off)[0]
                if va:
                    rv=va-preferred
                    if 0<=rv<image:load_fields.append({'kind':kind,'pointerVariableRVA':rv,'loadConfigRVA':lr,'guardFlags':guard_flags,'dllCharacteristics':struct.unpack_from('<H',disk,opt+70)[0]})
    for section in sections:
        if (only_rdata and section['name']!='.rdata') or not section['flags'] & 0x40000000 or section['flags'] & (0x80000000|0x02000000):continue
        expected=bytearray(disk[section['raw']:section['raw']+section['bytes']]);actual=bytearray(memory(section['rva'],section['bytes']));adjusted=slots=0
        for rva in relocs:
            if section['rva']<=rva<section['rva']+section['bytes']:
                at=rva-section['rva'];need(at+8<=len(expected),'CRYPTO_RELOCATION_RANGE');v=struct.unpack_from('<Q',expected,at)[0];struct.pack_into('<Q',expected,at,(v+base-preferred)&((1<<64)-1));adjusted+=1
        for row in iat:
            if row['resolved'] and section['rva']<=row['rva']<section['rva']+section['bytes']:
                at=row['rva']-section['rva'];need(at+8<=len(expected),'CRYPTO_IAT_RANGE');expected[at:at+8]=actual[at:at+8];slots+=1
        differences=[i for i in range(len(expected)) if expected[i]!=actual[i]]
        item={'name':section['name'],'bytes':len(expected),'rva':section['rva'],'relocations':adjusted,'verifiedIATSlots':slots,'beforeRuntimeFieldExpectedSHA256':hx(expected),'mappedSHA256':hx(actual),'preRuntimeMatches':expected==actual,'differenceCount':len(differences),'differences':[{'rva':section['rva']+i,'sectionOffset':i,'expected':expected[i],'actual':actual[i]} for i in differences[:128]],'differenceListTruncated':len(differences)>128,'runtimeNormalizations':[]}
        temp=bytearray(expected);typed=[]
        for fld in load_fields:
            rv=fld['pointerVariableRVA']
            if not section['rva']<=rv or rv+8>section['rva']+section['bytes']:continue
            at=rv-section['rva'];expected_ptr=struct.unpack_from('<Q',expected,at)[0];actual_ptr=struct.unpack_from('<Q',actual,at)[0]
            default_rva=expected_ptr-base
            default_local_rx=any(x['rva']<=default_rva<x['rva']+x['bytes'] and x['flags']&0x20000000 and not x['flags']&0x80000000 for x in sections)
            slotmeta=memory_metadata(k,process,base+rv);ptrmeta=memory_metadata(k,process,actual_ptr)
            host=next((r for r in rows if r['base']<=actual_ptr<r['base']+r['size']),None)
            field={**fld,'path':str(target),'section':section['name'],'sectionOffset':at,'expectedRelocatedDefault':expected_ptr,'actual':actual_ptr,'changed':actual_ptr!=expected_ptr,'defaultLocalExecutable':bool(default_local_rx),'slotReadOnlyImage':bool(slotmeta and slotmeta['state']==0x1000 and slotmeta['kind']==0x1000000 and slotmeta['allocationBase']==base and not slotmeta['protect']&(1|4|8|0x40|0x80|0x100)),'nativeTargetNTDLLRX':bool(host and Path(host['path']).name.lower()=='ntdll.dll' and Q.os_base_provider(Path(host['path'])) and ptrmeta and ptrmeta['allocationBase']==host['base'] and ptrmeta['state']==0x1000 and ptrmeta['kind']==0x1000000 and ptrmeta['protect'] in (0x10,0x20)),'nativeHostPath':host['path'] if host else None,'nativeHostRVA':actual_ptr-host['base'] if host else None,'normalizationAccepted':False}
            typed.append(field);state['typed'].append(field);temp[at:at+8]=actual[at:at+8]
        outside=temp==actual
        item['allOutsideDeclaredCFSlotsExact']=outside
        state['allOutsideTypedExact']=state['allOutsideTypedExact'] and outside
        state['sections'].append({'item':item,'expected':expected,'actual':actual,'typed':typed})
        proof.append(item)
    public={'path':str(target),'backingNtPath':name.value,'base':base,'imageSize':image,'headerImageBase':mapped_base,'headerAllOtherBytesExact':True,'sections':proof,'imports':imports,'iat':iat,'memoryBytesRead':total,'writableOrDiscardableSectionsRead':False,'typedLoadConfigFields':state['typed']}
    DATA.setdefault('mappings',[]).append(public);state['public']=public;MAPPED_STATES.append(state)

class MB(ctypes.Structure):
    _fields_=[('base',ctypes.c_void_p),('allocation',ctypes.c_void_p),('allocationProtect',ctypes.c_uint),('partition',ctypes.c_ushort),('region',ctypes.c_size_t),('state',ctypes.c_uint),('protect',ctypes.c_uint),('kind',ctypes.c_uint)]
MAPPED_STATES=[]
CURRENT_RECEIPT=None
OPERATION_CLOCK=lambda:0

def memory_metadata(k,process,address):
    value=MB()
    if not address or k.VirtualQueryEx(process,address,ctypes.byref(value),ctypes.sizeof(value))!=ctypes.sizeof(value):return None
    return {'allocationBase':value.allocation,'state':value.state,'protect':value.protect,'kind':value.kind}

def approved_export_target(dll,thunk,label,providers,byname,translated,k,seen=None,actual=None):
    seen=set() if seen is None else seen
    marker=(dll,label);need(len(seen)<8 and marker not in seen,'EXACT_FORWARD_EXPORT_CYCLE');seen.add(marker)
    module=byname.get(dll);row=providers.get(module['path'].lower()) if module else None
    if not row:
        candidate=translated(k.GetModuleHandleW(dll),thunk,label)
        if candidate and (actual is None or candidate[0]==actual):return candidate
        if dll.startswith(('api-ms-win-','ext-ms-')):
            for host in byname.values():
                if Q.os_base_provider(Path(host['path'])):
                    candidate=translated(k.GetModuleHandleW(Path(host['path']).name),thunk,label)
                    if candidate and (actual is None or candidate[0]==actual):return candidate
        return None
    b=row['data'];pe=struct.unpack_from('<I',b,0x3c)[0];opt=pe+24;n=struct.unpack_from('<H',b,pe+6)[0];ol=struct.unpack_from('<H',b,pe+20)[0];sections=[]
    for i in range(n):
        at=opt+ol+40*i;vs,va,sz,raw=struct.unpack_from('<IIII',b,at+8);sections.append((va,sz,raw))
    def rr(rva,size):
        hits=[raw+rva-va for va,sz,raw in sections if va<=rva and rva-va+size<=sz];need(len(hits)==1 and hits[0]+size<=len(b),'EXACT_EXPORT_RVA');return hits[0]
    er,es=struct.unpack_from('<II',b,opt+112)
    if not er:return None
    ep=rr(er,40);ordinal_base,nf,nn,funcs,names,ords=struct.unpack_from('<IIIIII',b,ep+16);need(nf<=65536 and nn<=65536,'EXPORT_TABLE_CAP')
    index=None
    if thunk>>63:index=(thunk&65535)-ordinal_base
    else:
        for i in range(nn):
            need(OPERATION_CLOCK()>0,'EXPORT_RESOLUTION_ABSOLUTE_CLOCK')
            name_rva=struct.unpack_from('<I',b,rr(names+4*i,4))[0];at=rr(name_rva,1);end=b.find(b'\0',at,at+257);need(end>at,'EXPORT_SYMBOL_NAME')
            if b[at:end].decode('ascii')==label:index=struct.unpack_from('<H',b,rr(ords+2*i,2))[0];break
    if index is None or not 0<=index<nf:return None
    rva=struct.unpack_from('<I',b,rr(funcs+4*index,4))[0]
    if er<=rva<er+es:
        at=rr(rva,1);end=b.find(b'\0',at,at+261);need(end>at,'EXPORT_FORWARDER');text=b[at:end].decode('ascii');host,symbol=text.rsplit('.',1);host=host.lower();host=host if host.endswith('.dll') else host+'.dll';it=(1<<63)|int(symbol[1:]) if symbol.startswith('#') else 0
        return approved_export_target(host,it,'ordinal-'+symbol[1:] if symbol.startswith('#') else symbol,providers,byname,translated,k,seen,actual)
    if not rva or rva>=module['size']:return None
    return module['base']+rva,dll,rva

def cfg_normalization_allowed(facts):
    return (facts['kind'] in ('GuardCFCheckFunctionPointer','GuardCFDispatchFunctionPointer') and facts['nativeCFGEnabled'] and facts['dllCharacteristics']&0x4040==0x4040 and facts['guardFlags']&0x100 and facts['defaultLocalExecutable'] and facts['slotReadOnlyImage'] and facts['nativeTargetNTDLLRX'] and facts['outsideTypedExact'] and facts['independentMatchingImages']>=2)

def cfg_boundary_checks():
    valid={'kind':'GuardCFDispatchFunctionPointer','nativeCFGEnabled':True,'dllCharacteristics':0x4040,'guardFlags':0x100,'defaultLocalExecutable':True,'slotReadOnlyImage':True,'nativeTargetNTDLLRX':True,'outsideTypedExact':True,'independentMatchingImages':2}
    need(cfg_normalization_allowed(valid),'CFG_POSITIVE_SYNTHETIC_CONTROL')
    checks=[]
    for key,value in [('kind','UNKNOWN'),('nativeCFGEnabled',False),('slotReadOnlyImage',False),('nativeTargetNTDLLRX',False),('outsideTypedExact',False),('independentMatchingImages',1)]:
        bad=dict(valid);bad[key]=value;need(not cfg_normalization_allowed(bad),'CFG_BOUNDARY_FALSE_ACCEPTANCE');checks.append(key+'_denied')
    return checks

def map_all_owned(k,ps,process,rows,disk,nt_path,providers):
    cfg=ctypes.c_uint();known=bool(k.GetProcessMitigationPolicy(process,7,ctypes.byref(cfg),ctypes.sizeof(cfg)))
    DATA['nativeCFGPolicy']={'querySucceeded':known,'flags':cfg.value if known else None,'changed':False}
    for row in providers.values():
        map_one(k,ps,process,rows,row['data'],row['ntPath'],row['path'],providers)
    map_one(k,ps,process,rows,disk,nt_path,str(TARGET),providers,True)
    DATA['newCFGNormalizerBoundaryControls']=cfg_boundary_checks()
    for state in MAPPED_STATES:
        for part in state['sections']:
            expected=part['expected'];actual=part['actual'];item=part['item']
            for field in part['typed']:
                peers=[other['path'] for other in MAPPED_STATES if other is not state and other['allOutsideTypedExact'] and any(x['kind']==field['kind'] and x['actual']==field['actual'] and x['slotReadOnlyImage'] and x['nativeTargetNTDLLRX'] and x['defaultLocalExecutable'] for x in other['typed'])]
                facts={**field,'nativeCFGEnabled':bool(known and cfg.value&1),'outsideTypedExact':state['allOutsideTypedExact'],'independentMatchingImages':len(set(peers))}
                accepted=bool(field['changed'] and cfg_normalization_allowed(facts))
                field.update(nativeCFGEnabled=facts['nativeCFGEnabled'],independentMatchingImages=len(set(peers)),independentPeerImages=sorted(set(peers)),normalizationAccepted=accepted)
                if accepted:
                    at=field['sectionOffset'];expected[at:at+8]=actual[at:at+8];item['runtimeNormalizations'].append({'kind':field['kind'],'rva':field['pointerVariableRVA'],'actual':field['actual'],'nativeHostPath':field['nativeHostPath'],'nativeHostRVA':field['nativeHostRVA'],'independentPeerImages':sorted(set(peers)),'evidence':'Immutable typed CFG slot + native CFG policy + actual read-only image slot + current NTDLL RX image metadata + matching same-kind slots in >=2 independently file-proved images; no private-function-name or writer attribution'})
            item['expectedSHA256']=hx(expected);item['matches']=expected==actual
            if not item['matches']:DATA['unresolved'].append({'from':Path(state['path']).name,'section':item['name'],'code':'NORMALIZED_READONLY_IMAGE_DIFFERS','differenceCount':sum(a!=b for a,b in zip(expected,actual))})
    DATA['normalizationMethodSources']=['https://learn.microsoft.com/en-us/windows/win32/secbp/pe-metadata','https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_load_config_directory64']
    DATA['normalizationScope']='Documented OS-loader CFG pointer slots only with all independent predicates; not a general NTDLL address mask or proof of private function identity/security absence.'
    saved=[];proof_total=0
    for row in DATA['mappings']:
        fp=Path(CURRENT_RECEIPT).parent/('mapping-'+Path(row['path']).name.lower()+'.json');S.fresh(fp,row,cap=262144);proof_total+=fp.stat().st_size
        saved.append({'path':row['path'],'proofPath':str(fp),'proofSHA256':S.sha(fp),'imageSize':row['imageSize'],'memoryBytesRead':row['memoryBytesRead'],'sections':row['sections'],'iatCount':len(row['iat']),'allIATResolved':all(x['resolved'] for x in row['iat'])})
    need(proof_total<=786432,'MAPPING_ROLE_PROOF_CAP');DATA['mappings']=saved



def six_file_phase(f, providers, k, out):
    need(len(providers)==2 and sum(len(x['data']) for x in providers.values())<=16777216,'SIX_AGGREGATE_FILE_CAP')
    need(S.sha(f['sixNativeSourcePath'])==f['sixNativeSourceSHA256'] and S.sha(f['sixNativeInspectorPath'])==f['sixNativeInspectorSHA256'],'SIX_NATIVE_SOURCES')
    nf=dict(f);nf.update(sourcePath=f['sixNativeSourcePath'],sourceSha256=f['sixNativeSourceSHA256'],receiptPath=str(out/'six-file-proofs.json'),profilePath=str(out/'six-file-profile.json'),phaseDeadlineUnix=min(f['phaseDeadlineUnix'],time.time()+20),providerInputs=[{k:v for k,v in r.items() if k not in ('data','stream')} for r in providers.values()])
    nframe=out/'six-file-frame.json';S.fresh(nframe,nf)
    hp=ht=job=None;start=time.monotonic();limit=min(20,max(0,nf['phaseDeadlineUnix']-time.time()));forced=False
    try:
        si=subprocess.STARTUPINFO()
        argv=[f['pwshPath'],'-NoProfile','-NonInteractive','-File',f['sixNativeInspectorPath'],'-Frame',str(nframe),'-FrameSha256',S.sha(nframe)]
        hp,ht,pid,tid=_winapi.CreateProcess(f['pwshPath'],subprocess.list2cmdline(argv),None,None,False,0x08000004,dict(os.environ),str(out),si)
        job=k.OpenJobObjectW(4,False,'tail11-input-only-'+f['nonce']);member=ctypes.c_int();need(job and k.IsProcessInJob(hp,job,ctypes.byref(member)) and member.value==1,'SIX_PROOF_JOB_BEFORE_RESUME')
        c,e,kt,ut=(ctypes.c_ulonglong() for _ in range(4));need(k.GetProcessTimes(hp,ctypes.byref(c),ctypes.byref(e),ctypes.byref(kt),ctypes.byref(ut)),'SIX_PROOF_BIRTH')
        S.fresh(nf['profilePath'],{'childPid':pid,'nonce':f['nonce'],'processCreationFileTime':c.value})
        need(k.ResumeThread(ht)!=0xffffffff,'SIX_PROOF_RESUME')
        wait=_winapi.WaitForSingleObject(hp,max(1,int(min(limit-(time.monotonic()-start),nf['phaseDeadlineUnix']-time.time())*1000)))
        if wait!=0:
            forced=True;_winapi.TerminateProcess(hp,124);_winapi.WaitForSingleObject(hp,2000)
        code=_winapi.GetExitCodeProcess(hp)
        DATA['fileProofTerminal']={'pid':pid,'birth':c.value,'exitCode':code,'originalHandleWaitReturned':wait==0,'forced':forced,'sameJobBeforeResume':True,'phaseSeconds':time.monotonic()-start}
        need(not forced and code==0 and Path(nf['receiptPath']).is_file(),'SIX_NATIVE_FILE_PROOF_PROCESS_HOLD')
        proof=S.read(nf['receiptPath'],262144);DATA['sixFileProofs']=proof;DATA['sixFileProofSHA256']=S.sha(nf['receiptPath'])
        return proof['status']=='ALL_EXACT_SIX_FILE_PROOFS_PASS'
    finally:
        if hp and _winapi.WaitForSingleObject(hp,0)!=0:
            _winapi.TerminateProcess(hp,126);_winapi.WaitForSingleObject(hp,2000)
        if ht:_winapi.CloseHandle(ht)
        if hp:_winapi.CloseHandle(hp)
        if job:k.CloseHandle(job)


def run(f):
    import base64, msvcrt
    profile = S.read(os.environ['TAIL11_ROOT_PROFILE'])
    need(profile['childPid'] == os.getpid() and profile['nonce'] == f['nonce'], 'OWN_INSPECTOR')
    DATA['actualInspectorKernel'] = S.input_kernel(profile)
    for key in ('catalogProof', 'fileProof'):
        row = f[key]; need(S.sha(row['path']) == row['sha256'], 'EXACT_CRYPTO_PROOF_HASH')
    catalog = S.read(f['catalogProof']['path']); prior = S.read(f['fileProof']['path'])
    need(catalog['catalogWinTrustStatus'] == '0x00000000' and catalog['chain']['cachedCurrentChainValid'] is True and not catalog['chain']['chainStatus'], 'EXACT_CRYPTO_CACHED_CATALOG_CHAIN')
    need(catalog['priorRawFileSHA256'] == prior['sha256'] == FILE_SHA and prior['stable'] is True, 'EXACT_CRYPTO_PRIOR_RAW_FILE')
    DATA['catalogProofSHA256'] = f['catalogProof']['sha256']
    need(f['actionSHA256']=='b1bb79cb22ec3f437280c0eaba45afb992a53c037f01e532dc0ebcfcda1666f0','EXACT_ALL_GAPS_ACTION')
    metadata = S.HERE/'metadata'
    pins = {'SHA256SUMS.txt': '7ed7c353458a935439066a6a1d205520e5610458ec346dd8dbbf5c8882d28709',
            'SHA256SUMS.txt.sig': 'bf4ff680a2c4816b08044c47bb05882f6268576dea30bc1a14e275cfab66e840',
            'SIGNING-PUBLIC-KEY.pub': 'cc7038b2d98f856af97b58eb06619ff441fbe9b178da5396f61d1ccdf7a65e7c'}
    blobs = {}
    for name, digest in pins.items():
        b = S.raw(metadata/name, 4096); need(hx(b) == digest, 'PUBLIC_SIGNATURE_INPUT'); blobs[name] = b
    parts = blobs['SIGNING-PUBLIC-KEY.pub'].strip().split()
    need(parts[0] == b'ssh-ed25519', 'PUBLIC_KEY_TYPE')
    blob = base64.b64decode(parts[1], validate=True)
    need(len(blob) == 51 and 'SHA256:'+base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('=') == KEY, 'PUBLIC_KEY_FINGERPRINT')
    out = Path(f['receiptPath']).parent; allowed = out/'allowed-signers'
    with allowed.open('xb') as file:
        file.write(b'pouriajamali ssh-ed25519 '+parts[1]+b'\n')
    sshbytes = S.raw(SSH, 1048576); need(len(sshbytes) == 861184 and hx(sshbytes) == SSH_SHA, 'PINNED_SSH_EXE')
    rootimports = Q.pe_imports(sshbytes); DATA['pinnedSSHExeSHA256'] = hx(sshbytes)
    k, ps = api(); hp = ht = job = None; handles = []; start_mono = time.monotonic()
    deadline = min(f['window']['deadlineUnix']-30, f['phaseDeadlineUnix'], time.time()+60)
    def left():
        return max(0, min(deadline-time.time(), 60-(time.monotonic()-start_mono)))
    def close(handle):
        if handle:
            _winapi.CloseHandle(handle)
            if handle in handles:
                handles.remove(handle)
    def output(handle):
        available = ctypes.c_uint(); pieces = []
        if k.PeekNamedPipe(handle, None, 0, None, ctypes.byref(available), None):
            need(available.value <= 8192, 'SSH_PUBLIC_OUTPUT_CAP')
            if available.value:
                buf = ctypes.create_string_buffer(available.value); got = ctypes.c_uint()
                need(k.ReadFile(handle, buf, len(buf), ctypes.byref(got), None), 'SSH_PUBLIC_OUTPUT')
                pieces.append(buf.raw[:got.value])
        return b''.join(pieces)
    try:
        with contextlib.ExitStack() as held_scope:
            providers={};aggregate=0
            for path in f['exactTimestampPaths']:
                stream6,id6=held_scope.enter_context(six_held_read(path));aggregate+=id6['bytes']
                need(id6['bytes']<=16777216 and aggregate<=16777216,'EXACT_SIX_RAW_CAP')
                providers[path.lower()]={'path':path,'identity':id6,'stream':stream6}
            for row in providers.values():
                body=row['stream'].read(row['identity']['bytes']+1);need(len(body)==row['identity']['bytes'],'SIX_HELD_FILE_LENGTH');row['data']=body;row['sha256']=hx(body)
                pe=struct.unpack_from('<I',body,0x3c)[0];need(body[pe:pe+4]==b'PE\0\0' and struct.unpack_from('<H',body,pe+4)[0]==0x8664,'SIX_AMD64_PE')
                row['architecture']='AMD64';row['imports']=Q.pe_imports(body)
                nt6=ctypes.create_unicode_buffer(1024);n6=k.GetFinalPathNameByHandleW(msvcrt.get_osfhandle(row['stream'].fileno()),nt6,len(nt6),2);need(0<n6<len(nt6)-1,'SIX_HELD_NT_PATH');row['ntPath']=nt6.value
            DATA['prestartNewFiles']=[{k:v for k,v in r.items() if k not in ('data','stream')} for r in providers.values()]
            if not six_file_phase(f,providers,k,out):
                DATA.update(status='HOLD_SIX_FILE_PROOFS_NO_SSH_STARTED',allNewFileProofsAccepted=False)
                return
            # Only after both supplements pass: four existing native proofs are
            # reused, then exact files are held/hashed solely for the approved mapping.
            expected_old=S.read(f['existingFileProofs']['path'])
            accepted={r['exactPath'].lower():r for r in expected_old['records'] if r['status']=='PASS_EXACT_FILE_NATIVE_SIGNATURE_CURRENT_CACHED_CHAIN'}
            need(len(accepted)==4,'FOUR_REUSED_FILE_PROOFS')
            for path in f['exactAdditionalPaths']:
                if path.lower() in providers:continue
                old=accepted.get(path.lower());need(old is not None,'FOUR_PROOF_PATH_BINDING')
                stream6,id6=held_scope.enter_context(six_held_read(path));aggregate+=id6['bytes'];need(aggregate<=16777216,'SIX_AGGREGATE_FILE_CAP')
                body=stream6.read(id6['bytes']+1);need(len(body)==id6['bytes'] and hx(body)==old['parentRawSHA256'],'REUSED_FILE_CURRENT_HASH')
                nt6=ctypes.create_unicode_buffer(1024);n6=k.GetFinalPathNameByHandleW(msvcrt.get_osfhandle(stream6.fileno()),nt6,len(nt6),2);need(0<n6<len(nt6)-1,'FOUR_HELD_NT_PATH')
                providers[path.lower()]={'path':path,'identity':id6,'stream':stream6,'data':body,'sha256':hx(body),'architecture':'AMD64','imports':Q.pe_imports(body),'ntPath':nt6.value}
            DATA['allNewFileProofsAccepted']=True
            stream,identity=held_scope.enter_context(input_held_read(TARGET))
            eset_stream,eset_id=held_scope.enter_context(eset_held_read(Path(ESET)));eb=eset_stream.read(309529);need(len(eb)==309528 and hx(eb)=='74ee1ab7ce1671b1679a1e1a6d41a48797189cba98fbbbb2ee045bcd0ad41056','ESET_PRESTART_HELD_CURRENT_HASH')
            DATA['prestartESET']={'identity':eset_id,'sha256':hx(eb)}
            need(identity['bytes'] == 1953792 and identity['volume'] == prior['fileAfter']['Volume'] and identity['fileIndex'] == ((prior['fileAfter']['IndexHi']<<32) | prior['fileAfter']['IndexLo']), 'CRYPTO_PRESTART_FILE_IDENTITY')
            disk = stream.read(1953793); need(len(disk) == 1953792 and hx(disk) == FILE_SHA, 'CRYPTO_PRESTART_FILE_HASH')
            nt = ctypes.create_unicode_buffer(1024)
            n = k.GetFinalPathNameByHandleW(msvcrt.get_osfhandle(stream.fileno()), nt, len(nt), 2)
            need(0 < n < len(nt)-1, 'CRYPTO_HELD_NT_PATH')
            DATA['prestartCrypto'] = {'identity': identity, 'sha256': hx(disk), 'ntPath': nt.value}
            rin, win = _winapi.CreatePipe(None, 4096)
            rout, wout = _winapi.CreatePipe(None, 4096)
            rerr, werr = _winapi.CreatePipe(None, 4096)
            handles.extend((rin, win, rout, wout, rerr, werr))
            for handle in (rin, wout, werr):
                os.set_handle_inheritable(handle, True)
            si = subprocess.STARTUPINFO(); si.dwFlags = subprocess.STARTF_USESTDHANDLES
            si.hStdInput, si.hStdOutput, si.hStdError = rin, wout, werr
            si.lpAttributeList = {'handle_list': [rin, wout, werr]}
            argv = [str(SSH), '-Y', 'verify', '-f', str(allowed), '-I', 'pouriajamali', '-n', 'file', '-s', str(metadata/'SHA256SUMS.txt.sig')]
            env = {key: os.environ[key] for key in ('SystemRoot','WINDIR','ComSpec','ProgramData','TEMP','TMP') if key in os.environ}
            env['PATH'] = r'C:\Windows\System32\OpenSSH'
            need(left() > 3, 'SSH_REMAINING_CLOCK')
            hp, ht, pid, tid = _winapi.CreateProcess(str(SSH), subprocess.list2cmdline(argv), None, None, True, 0x08000004, env, str(out), si)
            DATA['signatureInvocations'] = 1
            close(rin); close(wout); close(werr)
            job = k.OpenJobObjectW(4, False, 'tail11-input-only-'+f['nonce']); need(job, 'OWN_ROOT_JOB')
            member = ctypes.c_int()
            need(k.IsProcessInJob(hp, job, ctypes.byref(member)) and member.value == 1, 'SSH_INHERITED_ASSIGNMENT_BEFORE_RESUME')
            c, e, kt, ut = (ctypes.c_ulonglong() for _ in range(4))
            need(k.GetProcessTimes(hp, ctypes.byref(c), ctypes.byref(e), ctypes.byref(kt), ctypes.byref(ut)), 'SSH_BIRTH')
            DATA['ownedSSH'] = {'pid': pid, 'birth': c.value, 'sameRootJobBeforeResume': True,
                                'assignment': 'ACTUAL_KERNEL_INHERITED_SAME_JOB_BEFORE_RESUME',
                                'inheritedRootJobCaps': DATA['actualInspectorKernel'], 'capQueryProcessPID': os.getpid(), 'originalHandle': True}
            ssh_start=time.monotonic();ssh_deadline=min(deadline,time.time()+45)
            def ssh_left():return max(0,min(left(),ssh_deadline-time.time(),45-(time.monotonic()-ssh_start)))
            global OPERATION_CLOCK
            OPERATION_CLOCK=ssh_left
            need(k.ResumeThread(ht) != 0xffffffff, 'SSH_RESUME')
            # One bounded initialization wait, then one metadata enumeration.
            need(_winapi.WaitForSingleObject(hp, min(2000, int(ssh_left()*1000))) == 258, 'SSH_EXITED_BEFORE_METADATA')
            rows = modules(ps, hp); DATA['actualOwnedModules'] = rows
            names = {Path(row['path']).name.lower(): row for row in rows}
            allowed_exact = {str(SSH).lower(), str(TARGET).lower(), ESET.lower()} | set(providers)
            for row in rows:
                if row['path'].lower() not in allowed_exact and not Q.os_base_provider(Path(row['path'])):
                    DATA['unresolved'].append({'from': 'actual-owned-ssh', 'path': row['path'], 'code': 'UNADMITTED_PROVIDER'})
            DATA['rootImportEdges'] = []
            for edge in rootimports:
                match = names.get(edge['name']); ok = bool(match) and (match['path'].lower() == str(TARGET).lower() or Q.os_base_provider(Path(match['path'])))
                DATA['rootImportEdges'].append({**edge, 'mappedPath': match['path'] if match else None, 'resolved': ok})
                if not ok:
                    DATA['unresolved'].append({'from': 'ssh-keygen.exe', **edge, 'code': 'ROOT_IMPORT_MAPPING_UNRESOLVED'})
            map_all_owned(k,ps,hp,rows,disk,nt.value,providers)
            need(ssh_left() > 0, 'SSH_WORK_CLOCK')
            message = blobs['SHA256SUMS.txt']; buf = ctypes.create_string_buffer(message); written = ctypes.c_uint()
            need(k.WriteFile(win, buf, len(message), ctypes.byref(written), None) and written.value == len(message), 'SSH_PUBLIC_STDIN')
            close(win)
            need(_winapi.WaitForSingleObject(hp, int(ssh_left()*1000)) == 0, 'SSH_ABSOLUTE_DEADLINE')
            code = _winapi.GetExitCodeProcess(hp)
            stdout, stderr = output(rout), output(rerr)
            DATA['sshTerminal'] = {'exitCode': code, 'natural': True, 'originalHandleWaitReturned': True,
                                   'stdoutSHA256': hx(stdout), 'stderrSHA256': hx(stderr),
                                   'publicStdout': stdout.decode('ascii', 'replace')[:1024], 'publicStderr': stderr.decode('ascii', 'replace')[:1024]}
            stream.seek(0); after = stream.read(1953793)
            need(len(after) == 1953792 and hx(after) == FILE_SHA, 'CRYPTO_HELD_FINAL_HASH')
            for row in providers.values():
                row['stream'].seek(0);sealed=row['stream'].read(row['identity']['bytes']+1);need(len(sealed)==row['identity']['bytes'] and hx(sealed)==row['sha256'],'SIX_HELD_FINAL_HASH')
            eset_stream.seek(0);need(hx(eset_stream.read(309529))==DATA['prestartESET']['sha256'],'ESET_HELD_FINAL_HASH')
            need(2*aggregate+len(disk)+len(after)+2*len(eb)+len(sshbytes)+sum(len(x) for x in blobs.values())+DATA.get('newReadOnlyImageBytes',0)+sum(x['memoryBytesRead'] for x in DATA.get('mappings',[]) if x['path'].lower()==str(TARGET).lower())+DATA['sixFileProofs']['nativeSignatureReadBytes']<=67108864,'ALL_ACTION_READ_64M')
            DATA['allNewFilesHeldThroughTerminalAndAfterHashesMatch']=True
            DATA['explicitNewSixRawReadBytes']=2*aggregate
            DATA['heldThroughOriginalTerminal'] = True
            DATA['explicitCryptoReadBytes'] = len(disk)+len(after)
            DATA['publicSignatureInputs'] = pins
            DATA['fingerprint'] = KEY; DATA['namespace'] = 'file'
            if code != 0:
                DATA['unresolved'].append({'from': 'ssh-keygen.exe', 'code': 'PUBLIC_KNOWN_KEY_SIGNATURE_NOT_VERIFIED'})
            if not DATA['unresolved']:
                entries = {}
                for line in message.decode('ascii').splitlines():
                    m = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9._-]{1,160})', line)
                    need(m and m[2] not in entries and len(entries) < 64, 'SIGNED_CHECKSUM_FRAMING')
                    entries[m[2]] = m[1]
                DATA.update(status='PASS_EXACT_OWNED_SSH_SIGNATURE_AND_ALL_APPROVED_NECESSARY_MAPPING',
                            signedChecksums=entries, signatureVerificationTrustedForExactInputs=True)
            else:
                DATA['status'] = 'HOLD_ALL_OBSERVED_UNRESOLVED_IN_ONE_PACKET'
                DATA['signatureVerificationTrustedForExactInputs'] = False
    finally:
        if hp:
            if _winapi.WaitForSingleObject(hp, 0) != 0:
                _winapi.TerminateProcess(hp, 126); _winapi.WaitForSingleObject(hp, 2000)
                DATA['sshForcedCleanup'] = True
            DATA['ownedSSHOriginalHandleTerminal'] = _winapi.WaitForSingleObject(hp, 0) == 0
        if ht: close(ht)
        if hp: close(hp)
        if job: k.CloseHandle(job)
        for handle in list(handles): close(handle)

def entry():
    p = argparse.ArgumentParser(); p.add_argument('--frame', required=True); p.add_argument('--frame-sha', required=True)
    args = p.parse_args(); raw = Path(args.frame).read_bytes(); need(hx(raw) == args.frame_sha and len(raw) <= 32768, 'FRAME_HASH')
    frame = json.loads(raw)
    global CURRENT_RECEIPT
    CURRENT_RECEIPT=frame['receiptPath']
    try:
        run(frame)
    except Exception as error:
        DATA.update(status='HOLD', code=str(error) if isinstance(error, S.Hold) else 'OWNED_SSH_PROOF_HOLD', exceptionType=type(error).__name__)
    S.fresh(frame['receiptPath'], DATA, cap=262144)
    if not DATA['status'].startswith('PASS_'):
        raise SystemExit(1)
