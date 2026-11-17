"""One forward owned-module attestation; no DLL load, debugger, network or dependency bodies."""
from pathlib import Path
import ctypes,ctypes.wintypes,hashlib,json,os,struct,time,sys
import support as S,qualifier as Q
from fetch_extract import input_held_read
class MI(ctypes.Structure):_fields_=[('base',ctypes.c_void_p),('size',ctypes.c_uint),('entry',ctypes.c_void_p)]
class MB(ctypes.Structure):_fields_=[('base',ctypes.c_void_p),('alloc',ctypes.c_void_p),('allocProtect',ctypes.c_uint),('partition',ctypes.c_ushort),('region',ctypes.c_size_t),('state',ctypes.c_uint),('protect',ctypes.c_uint),('kind',ctypes.c_uint)]
def need(v,c):
 if not v:raise S.Hold(c)
def hx(b):return hashlib.sha256(b).hexdigest()
TARGET=Path(r'C:\Program Files\ESET\ESET Security\ebehmoni.dll')
FILE_SHA="74ee1ab7ce1671b1679a1e1a6d41a48797189cba98fbbbb2ee045bcd0ad41056"
CERT_SHA="f90f98b68e1e8d1d8a6ac452ce7d4ee76e8eaba36df9b72b42dfdb4f9c341ede"
PROOF_SHA={"signature":"bf3380ffd5f0087b1d40b6661291d36c82a20f66fbe6f660fd2d25f50e0b50df",
 "crl":"26ead6e5fb96214ff3de09c5ca7a0953ea8af5ebe469357e55fa0070eaf65a98",
 "mapping":"df9594501a26ace9fb7a4ffedd6f1ac086a0dee70e5826757cc1312befebe002"}

def validate_proofs(proofs,now):
 c=proofs['crl'];sig=proofs['signature'];mp=proofs['mapping'];signer=sig['signatures'][0]['signer']
 need(sig['sha256']==sig['afterSha256']==mp['currentFileSHA256']==FILE_SHA and sig['stable'] is True,'EXACT_PROVIDER_PROOF_FILE')
 need(sig['architecture']=='AMD64' and sig['osBuild']=='10.0.26300.0' and sig['winTrustStatus']=='0x00000000' and sig['winTrustCacheOnly'] is True and sig['signatures'][0]['cmsCryptographicSignatureValid'] is True,'EXACT_PROVIDER_SIGNATURE')
 need(signer['sha256']==c['leafSHA256']==CERT_SHA and signer['serial']==c['serial']=='0BC0CF65CDF1B3EA3086488A09BAAAA0','EXACT_PROVIDER_CERT')
 need(c['status']=='EXACT_ESET_LEAF_CURRENT_CRL_SUPPLEMENT_PASS' and c['leafSerialRevoked'] is False and c['thisUpdateUnix']<=c['verifiedAtUnix']<=now<c['nextUpdateUnix'],'EXACT_PROVIDER_CURRENT_CRL')
 need(mp['status']=='FORWARD_HELD_FILE_MAPPING_NECESSARY_DECLARED_CLOSURE_PASS' and mp['prestartHoldBound'] is True and mp['unadmittedMappedProviders']==[],'EXACT_PROVIDER_FORWARD_PROOF')
 need(sig['signatures'][0]['cachedChainBuildValid'] is False and c['previousWindowsCacheAPIResult'] is False,'CACHE_RESULT_NOT_RELABELLED')

def evidence(a):
 need(os.name=='nt' and os.environ.get('TAIL11_EXECUTION')=='LOCAL_CANONICAL' and a.get('execution')=='LOCAL_CANONICAL','EXACT_PROVIDER_LOCAL_ONLY')
 need(tuple(sys.getwindowsversion()[:3])==(10,0,26300),'EXACT_PROVIDER_OS_BUILD')
 f=a['exactProvider'];need(f['runNonce']==a['runNonce'] and f['window']==a['executionWindow'] and f['scope']=='EXACT_M1_FILE_ONLY','EXACT_PROVIDER_FRAME')
 proofs={};count=0
 need(set(f['proofs'])==set(PROOF_SHA),'EXACT_PROVIDER_PROOF_SET')
 for name,digest in PROOF_SHA.items():
  row=f['proofs'][name];raw=S.raw(row['path'],65536);count+=len(raw)
  need(hx(raw)==row['sha256']==digest,'EXACT_PROVIDER_PROOF_HASH');proofs[name]=json.loads(raw)
 validate_proofs(proofs,time.time())
 return f,proofs,count

def causal_controls(a):
 import copy
 f,p,proof_bytes=evidence(a);now=time.time();controls=[]
 for name,alter in [('wrong_file_hash_denied',lambda v:v['signature'].update(sha256='0'*64)),
                    ('wrong_signer_denied',lambda v:v['signature']['signatures'][0]['signer'].update(sha256='0'*64)),
                    ('stale_crl_denied',lambda v:v['crl'].update(nextUpdateUnix=int(now)-1)),
                    ('revoked_leaf_denied',lambda v:v['crl'].update(leafSerialRevoked=True)),
                    ('unknown_forward_mapping_denied',lambda v:v['mapping'].update(status='UNKNOWN'))]:
  bad=copy.deepcopy(p);alter(bad);denied=False
  try:validate_proofs(bad,now)
  except S.Hold:denied=True
  need(denied,'EXACT_PROVIDER_NEGATIVE_NOT_DENIED');controls.append(name)
 return controls,proof_bytes

def attest(a):
 DATA={'schema':'tail11-forward-held-provider-mapping/v1','providerAdmission':'EXACT_LOCAL_M1_ONLY','networkGETs':0,'dependencyBodiesRead':0,'healthyTestsRepeated':0}
 f,proofs,proof_bytes=evidence(a)
 profile=S.read(os.environ['TAIL11_ROOT_PROFILE']);need(profile['childPid']==os.getpid() and profile['nonce']==a['runNonce'],'EXACT_PROVIDER_OWN_CHILD');DATA['actualKernel']=S.input_kernel(profile)
 need(time.time()<a['executionWindow']['deadlineUnix']-30,'WORK_CLOCK')
 need(f['preheldFile']['sha256']==FILE_SHA and f['preheldFile']['volume']==3400468440 and f['preheldFile']['fileIndex']==389279892790845374,'EXACT_PROVIDER_PRESTART_IDENTITY')
 target=TARGET
 k=ctypes.WinDLL('kernel32',use_last_error=True);ps=ctypes.WinDLL('psapi',use_last_error=True)
 k.GetCurrentProcess.restype=ctypes.c_void_p;process=k.GetCurrentProcess();k.ReadProcessMemory.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p];k.GetModuleHandleW.argtypes=[ctypes.c_wchar_p];k.GetModuleHandleW.restype=ctypes.c_void_p;k.GetProcAddress.argtypes=[ctypes.c_void_p,ctypes.c_void_p];k.GetProcAddress.restype=ctypes.c_void_p
 ps.GetModuleInformation.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_uint];ps.GetMappedFileNameW.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_wchar_p,ctypes.c_uint]
 base=k.GetModuleHandleW(str(TARGET));need(bool(base),'EXACT_OWN_MODULE_NOT_MAPPED');mi=MI();need(ps.GetModuleInformation(process,base,ctypes.byref(mi),ctypes.sizeof(mi)) and mi.base==base,'MODULE_INFORMATION')
 name=ctypes.create_unicode_buffer(32768);n=ps.GetMappedFileNameW(process,base,name,len(name));need(0<n<len(name)-1 and name.value.lower()==f['preheldFile']['ntPath'].lower(),'MAPPED_BACKING_FILE_PATH')
 readbytes=0
 def memory(rva,n):
  nonlocal readbytes
  need(0<=rva and 0<=n and rva+n<=mi.size and readbytes+n<=16777216,'OWN_IMAGE_READ_CAP');buf=ctypes.create_string_buffer(n);got=ctypes.c_size_t();need(k.ReadProcessMemory(process,base+rva,buf,n,ctypes.byref(got)) and got.value==n,'OWN_IMAGE_MEMORY_READ');readbytes+=n;return buf.raw
 with input_held_read(target) as (stream,identity):
  need(identity['bytes']==309528,'EXACT_PROVIDER_SIZE');data=stream.read(identity['bytes']+1);need(len(data)==309528 and hx(data)==f['preheldFile']['sha256']=='74ee1ab7ce1671b1679a1e1a6d41a48797189cba98fbbbb2ee045bcd0ad41056','HELD_CURRENT_FILE_HASH')
  need(identity['volume']==f['preheldFile']['volume'] and identity['fileIndex']==f['preheldFile']['fileIndex'],'PRESTART_HELD_FILE_IDENTITY')
  pe=struct.unpack_from('<I',data,0x3c)[0];need(data[pe:pe+4]==b'PE\0\0','PE_SIGNATURE');machine,count,_,_,_,optlen,_=struct.unpack_from('<HHIIIHH',data,pe+4);opt=pe+24;need(machine==0x8664 and struct.unpack_from('<H',data,opt)[0]==0x20b,'AMD64_PE')
  imageBase=struct.unpack_from('<Q',data,opt+24)[0];imageSize,headers=struct.unpack_from('<II',data,opt+56);need(mi.size==imageSize==f['preheldFile']['imageSize'] and imageSize<=16777216,'IMAGE_SIZE')
  need(headers<=4096 and opt+32<=headers,'MAPPED_HEADER_BOUNDS')
  mapped_header=memory(0,headers);expected_header=bytearray(data[:headers])
  # Data observation: only ImageBase differed, and equals independently queried module base.
  # Do not infer which component updated it, or ignore any other header field.
  need(struct.unpack_from('<Q',mapped_header,opt+24)[0]==base,'MAPPED_HEADER_BASE_NOT_ACTUAL_MODULE')
  struct.pack_into('<Q',expected_header,opt+24,base)
  need(mapped_header==expected_header,'MAPPED_PE_HEADERS_DIFFER')
  DATA['headerAttestation']={'bytes':headers,'filePreferredImageBase':imageBase,'actualModuleBase':base,'mappedImageBase':struct.unpack_from('<Q',mapped_header,opt+24)[0],'ImageBaseOffset':opt+24,'allOtherHeaderBytesExact':True,'normalizedExpectedSHA256':hx(expected_header),'mappedHeaderSHA256':hx(mapped_header),'normalizationAuthority':'Exact typed ImageBase value bound to GetModuleInformation; no claim about writer and no arbitrary byte mask'}
  sections=[]
  for i in range(count):
   at=opt+optlen+40*i;vsize,rva,size,offset=struct.unpack_from('<IIII',data,at+8);flags=struct.unpack_from('<I',data,at+36)[0];sections.append({'rva':rva,'bytes':min(size,vsize or size),'raw':offset,'flags':flags,'name':data[at:at+8].rstrip(b'\0').decode('ascii','replace')})
  def raw_rva(rva,n):
   matches=[s['raw']+rva-s['rva'] for s in sections if s['rva']<=rva and rva-s['rva']+n<=s['bytes']];need(len(matches)==1 and matches[0]+n<=len(data),'FILE_RVA');return matches[0]
  delta=base-imageBase;relocs=[];rr,rs=struct.unpack_from('<II',data,opt+112+5*8)
  if rr:
   at=raw_rva(rr,rs);end=at+rs
   while at<end:
    page,block=struct.unpack_from('<II',data,at);need(block>=8 and block%2==0 and at+block<=end,'RELOCATION_BLOCK')
    for off in range(at+8,at+block,2):
     item=struct.unpack_from('<H',data,off)[0];kind=item>>12
     if kind:need(kind==10,'UNKNOWN_RELOCATION_TYPE');relocs.append(page+(item&4095))
    at+=block
  imports=Q.pe_imports(data);need(imports==[{'name':'ntdll.dll','kind':'normal'}],'PROVIDER_IMPORT_SET_CHANGED')
  bufpath=ctypes.create_unicode_buffer(32768);ih=k.GetModuleHandleW('ntdll.dll');ps.GetModuleFileNameExW.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_wchar_p,ctypes.c_uint];n=ps.GetModuleFileNameExW(process,ih,bufpath,len(bufpath));need(0<n<len(bufpath)-1,'NTDLL_MODULE_PATH');ntdll=bufpath.value;need(Q.os_base_provider(Path(ntdll)),'NTDLL_PROVIDER_ROOT')
  ih=k.GetModuleHandleW('ntdll.dll');need(bool(ih),'NTDLL_MAPPED');ir,isz=struct.unpack_from('<II',data,opt+112+8);ip=raw_rva(ir,isz);iat=[]
  lookup,_,_,_,first=struct.unpack_from('<IIIII',data,ip);lookup=lookup or first
  for i in range(1024):
   thunk=struct.unpack_from('<Q',data,raw_rva(lookup+8*i,8))[0]
   if thunk==0:break
   if thunk>>63:address=k.GetProcAddress(ih,ctypes.c_void_p(thunk&65535));label='ordinal-'+str(thunk&65535)
   else:
    op=raw_rva(thunk+2,1);end=data.find(b'\0',op,min(len(data),op+257));need(end>op,'IMPORT_FUNCTION_NAME');label=data[op:end].decode('ascii');buf=ctypes.create_string_buffer(data[op:end]+b'\0');address=k.GetProcAddress(ih,ctypes.cast(buf,ctypes.c_void_p))
   actual=struct.unpack('<Q',memory(first+8*i,8))[0];need(address and actual==address,'IAT_TARGET_NOT_RESOLVED_EXPECTED_NTDLL');iat.append({'rva':first+8*i,'name':label,'bytes':8})
  else:raise S.Hold('IMPORT_THUNK_BOUND')
  DATA['iatResolution']=iat
  sectionProof=[];DATA['sections']=sectionProof
  for s in sections:
   if not s['flags']&0x40000000 or s['flags']&0x80000000 or s['flags']&0x02000000:continue
   expected=bytearray(data[s['raw']:s['raw']+s['bytes']]);actual=bytearray(memory(s['rva'],s['bytes']));adjusted=0;masked=0
   for rva in relocs:
    if s['rva']<=rva<s['rva']+s['bytes']:
     at=rva-s['rva'];need(at+8<=len(expected),'RELOCATION_SECTION_RANGE');value=struct.unpack_from('<Q',expected,at)[0];struct.pack_into('<Q',expected,at,(value+delta)&((1<<64)-1));adjusted+=1
   for entry in iat:
    if s['rva']<=entry['rva']<s['rva']+s['bytes']:
     at=entry['rva']-s['rva'];need(at+8<=len(expected),'IAT_SECTION_RANGE');expected[at:at+8]=actual[at:at+8];masked+=1
   row={'name':s['name'],'rva':s['rva'],'bytes':s['bytes'],'relocationsApplied':adjusted,'resolvedIATSlots':masked,'expectedSHA256':hx(expected),'mappedSHA256':hx(actual),'matches':expected==actual};sectionProof.append(row)
   need(row['matches'],'READONLY_MAPPED_IMAGE_DIFFERS_FROM_HELD_FILE')
  need(sectionProof and any(x['name']=='.text' for x in sectionProof),'READONLY_CODE_ATTESTATION_MISSING')
 DATA.update(status='FORWARD_HELD_FILE_MAPPING_NECESSARY_DECLARED_CLOSURE_PASS',backingNtPath=name.value,currentFileIdentity=identity,currentFileSHA256=hx(data),prestartHoldBound=True,
  moduleBase=base,imageSize=imageSize,unadmittedMappedProviders=[],imports=imports,ntdllResolvedPath=ntdll,iatResolution=iat,ownMappedReadBytes=readbytes,
  readOnlyImageLoaderNormalization='AMD64 DIR64 relocations plus independently resolved exact NTDLL IAT slots only; no arbitrary mismatch ignored',
  mutableOrDiscardableSectionsNotRead=True,dependencyBodiesRead=0,closureScope='Declared import graph + actual owned warm consumer modules; not all future dynamic/security behavior',
  previousCacheAPIResult=False,independentCRLProofSHA256=PROOF_SHA['crl'],oldExitedChildByteIdentity='UNKNOWN_NOT_ATTRIBUTED')
 DATA['evidenceReadBytes']=proof_bytes;DATA['providerFileReadBytes']=len(data);DATA['currentFilePath']=str(TARGET)
 return DATA


def reused_controls(a):
 row=a['exactProvider']['reusedControls'];raw=S.raw(row['path'],8192)
 need(hx(raw)==row['sha256']=='783a93347441872b9bba921ea3db514965d022f70d7dd085fc358661e43329cd','EXACT_PROVIDER_CONTROL_REUSE_HASH')
 p=json.loads(raw);need(p['status']=='FIVE_PREVIOUS_EXECUTED_CONTROLS_REUSED' and p['sourceCommit']=='57cabc81304d4b631288a1d26722de54e40e98cf','EXACT_PROVIDER_CONTROL_REUSE_SCOPE')
 return p['controls'],len(raw)
