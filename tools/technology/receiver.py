"""Data-only SDK handoff receiver. No producer fact is consumer admission."""
import hashlib,json,re
from pathlib import Path, PurePosixPath

class Hold(ValueError):
    pass

def need(value, code):
    if not value: raise Hold(code)

def sha(p):
    h=hashlib.sha256()
    with Path(p).open('rb') as f:
        for b in iter(lambda:f.read(65536),b''):h.update(b)
    return h.hexdigest()

def read(p,cap=1048576):
    p=Path(p);need(p.is_file() and not p.is_symlink(),'REGULAR_DATA_FILE')
    b=p.read_bytes();need(len(b)<=cap,'DATA_CAP');return json.loads(b)

def packet(data, contract_sha):
    need(type(data) is dict and data.get('schema')=='tail11-sdk10-input-handoff/v1','PACKET_SCHEMA')
    need(data.get('consumerProjectId')=='11' and data.get('receiverContractSha256')==contract_sha,'CONSUMER_BINDING')
    need(data.get('sdkVersion')=='10.0.404' and data.get('runtimeVersion')=='10.0.15','EXACT_SERVICING_VERSIONS')
    need(data.get('dataOnly') is True and data.get('consumerAdmission') is False,'NO_TRANSFERRED_ADMISSION')
    need(data.get('formalVendorSupport')=='NOT_CONFIRMED','NO_FORGED_WINDOWS_SUPPORT')
    need(type(data.get('roots')) is dict and set(data['roots'])=={'win-x64','linux-x64'},'EXACT_RIDS')
    for rid,root in data['roots'].items():
        need(type(root.get('pathWindows')) is str and root['pathWindows'].replace('\\','/').startswith('E:/Codex WorkSpace/Git Projects/data-admission-gate/state/toolchain/'),'RETAINED_SDK_ROOT')
        need(root['pathWindows'].replace('\\','/').rstrip('/').endswith('/'+rid),'RID_ROOT_BINDING')
        need(root.get('pathLinux')=='/mnt/e/'+root['pathWindows'].replace('\\','/')[3:],'SAME_PHYSICAL_WORKSPACE_ROOT')
        need(root.get('memberInventory') and root.get('materializationReceipt') and root.get('archive'),'ROOT_DATA_REFERENCES')
        for key in ['memberInventory','materializationReceipt','archive']:
            ref=root[key];need(type(ref) is dict and type(ref.get('pathWindows')) is str and type(ref.get('bytes')) is int and ref['bytes']>0 and re.fullmatch('[0-9a-f]{64}',ref.get('sha256','')) is not None,'IDENTITY_BOUND_REFERENCE')
    need(type(data.get('runtimePackages')) is dict and set(data['runtimePackages'])==set(data['roots']),'RUNTIME_INPUT_SET')
    for rid,p in data['runtimePackages'].items():
        need(p.get('id')=='Microsoft.NETCore.App.Runtime.'+rid and p.get('version')=='10.0.15','RUNTIME_PACKAGE_IDENTITY')
        need(type(p.get('normalizedContentHash')) is str and len(p['normalizedContentHash'])==88 and re.fullmatch('[0-9a-f]{128}',p.get('rawSha512','')) is not None,'RAW_NORMALIZED_IDENTITIES_DISTINCT')
        need(p.get('noticeSource') and p.get('signatureEvidence') and p.get('advisoryEvidence'),'RUNTIME_EVIDENCE_REQUIRED')
    need(type(data.get('limitsAndUnknowns')) is list,'EXPLICIT_UNKNOWN_BOUNDARY')
    return {'status':'INPUT_DATA_BOUND_NOT_ADMISSION','rids':['win-x64','linux-x64'],'sdkVersion':'10.0.404','runtimeVersion':'10.0.15','formalVendorSupport':'NOT_CONFIRMED','consumerAdmission':False}
