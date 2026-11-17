"""Fixed M1 bindings and original current-kernel checks; no generic command interface."""
import hashlib,json,os,pathlib,re,sys,time
HERE=pathlib.Path(__file__).resolve().parent
ROOT=HERE.parent.parent
OUT=ROOT/"outputs/m1"
PIN="6158f7f8a9a8e4fd7c12ed575f427d7117b89801"
BASE="4003f255078bf2f1af5badead0dd81972c307260"
PROTOCOL_SHA="9120ca49a0d46673053aa0ec0cdbbc6f00731d71ea0b57ddab09e8fc3ac3ac8b"
FINGERPRINT="SHA256:AgU5bZlJSjUu0KsWMmVEEr+BfXpcMVNroTA33bHcQdU"
LIMITS={"memory":536870912,"active":16,"cpuRate":1000,"affinityMax":2,"whole":300,"work":270,"terminal":30,
        "role":20,"qualification":60,"scratch":1073741824,"proof":8388608,"read":67108864,"files":256,"roleProof":262144,"allRoleProof":1048576}
PINS={"python":"4d6f5f81a4bca11191c4c7c6b43632694d0a4ce74e068619d8fdc161d469859a",
      "pythonDLL":"9a0e3435aaa680d868150f87ab3e388ad2eebc22f87e036155c7b4eda8cd2120",
      "pwsh":"2a6769a3330dc1084d0154bfde7d164ab750ca7f700f313f9d417c1be78b2233",
      "ssh":"c9dc170cd161db87e75eb6cf282f1325005b9e35628b9a36cb19883a8be1a34f"}
ORACLE_SHA="82c6998225f6bd38d1df941ceb49e13d3adcfb16678780a6a25da17e56ebe1bf"
VERIFIER_SHA="53f5df7d21c1147f7eb4f8f5c4e4292d206ae09eba91939d7baeddc67aec66a4"
class Hold(ValueError):
    def __init__(self,code):
        self.code=code if type(code) is str and re.fullmatch("[A-Z0-9_]{1,100}",code) else "M1_TYPED_HOLD"
        super().__init__(self.code)
def need(v,code="M1_BINDING"):
    if not v:raise Hold(code)
def raw(path,cap=1048576):
    p=pathlib.Path(path);need(p.is_file() and not p.is_symlink(),"REGULAR_FILE")
    with p.open("rb") as f:value=f.read(cap+1)
    need(len(value)<=cap,"READ_CAP");return value
def sha(path):
    h=hashlib.sha256()
    with pathlib.Path(path).open("rb") as f:
        for b in iter(lambda:f.read(65536),b""):h.update(b)
    return h.hexdigest()
def read(path,cap=1048576):return json.loads(raw(path,cap))
def fresh(path,value,cap=1048576):
    p=pathlib.Path(path);p.parent.mkdir(parents=True,exist_ok=True)
    b=(json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode("utf-8")
    need(len(b)<=cap,"PROOF_CAP")
    with p.open("xb") as f:f.write(b);f.flush();os.fsync(f.fileno())
def ticket_path():
    mode=os.environ.get("TAIL11_EXECUTION","CI_HANDOFF")
    need(mode in ("CI_HANDOFF","LOCAL_CANONICAL"),"EXECUTION_MODE_UNKNOWN")
    return OUT/"local-ticket.json" if mode=="LOCAL_CANONICAL" else HERE/"lease-ticket.json"

def validate_ticket(t,now):
    need(t.get("execution","CI_HANDOFF") in ("CI_HANDOFF","LOCAL_CANONICAL"),"EXECUTION_MODE_UNKNOWN")
    need(t["schema"]=="tail11-canonical-ci-ticket/v1" and t["projectId"]=="11" and
         t["purpose"]=="ONE_FIXED_RECORD_CAP_M1" and t["limits"]==LIMITS,"TICKET_SCOPE")
    need(t["repository"]=="pouriajamali/tail-latency-evidence-bench" and
         t["branch"]=="codex/wave4-m1-record-cap-20261117","TICKET_REPOSITORY")
    need(t["protocolSha256"]==PROTOCOL_SHA and t["canonicalClaim"]=="LOCAL_CREATE_NEW_STILL_HELD","TICKET_LANE")
    need(type(t["nonce"]) is str and re.fullmatch("[0-9a-f]{32}",t["nonce"]),"NONCE")
    start,end=t["window"]["startUnix"],t["window"]["deadlineUnix"]
    need(type(start) is int and type(end) is int and end-start==300 and start<=now<end-30,"WHOLE_CLOCK")
    need(t["nativeOrder"]==["win-99","win-100","win-101","linux-99","linux-100","linux-101"],"CASE_ORDER")
    need(t["runtimeCommit"]==PIN and t["casePlanSha256"]=="7ac106ea67b7e990dfa19a4b3a0ae33b941b7b86a00b986f8ef56350c2bddf3a","FROZEN_INPUT")
    return t
def source_binding(ticket):
    need(sha(HERE/"source-manifest.json")==ticket["sourceManifestSha256"],"SOURCE_MANIFEST")
    m=read(HERE/"source-manifest.json")
    need(m["schema"]=="tail11-ci-source-manifest/v1" and len(m["files"])<=32,"SOURCE_SET")
    for name,digest in m["files"].items():
        p=(HERE/name).resolve();need(HERE in p.parents and sha(p)==digest,"SOURCE_DRIFT")
    need(sha(ROOT/"tools/oracle.py")==ORACLE_SHA and sha(ROOT/"tools/verify_downloads.py")==VERIFIER_SHA,"FROZEN_TOOLS")
    return m["files"]
def lane_guard(ticket,frame):
    local=ticket.get("execution","CI_HANDOFF")=="LOCAL_CANONICAL"
    need(local==(os.environ.get("TAIL11_EXECUTION","CI_HANDOFF")=="LOCAL_CANONICAL"),"EXECUTION_MODE_BINDING")
    if os.name=="nt" and not local:
        # Signed source-commit ticket is the approved controller handoff, not a copied lease.
        need(frame["signedTicketVerified"] is True and frame["sourceCommit"]==os.environ["GITHUB_SHA"] and
             str(frame["runId"])==os.environ["GITHUB_RUN_ID"] and frame["ticketSha256"]==sha(HERE/"lease-ticket.json"),"CI_HANDOFF")
    else:
        protocol=pathlib.Path(frame["canonicalProtocolPath"]).resolve()
        lease_path=pathlib.Path(frame["canonicalLeasePath"]).resolve()
        need(hashlib.sha256(str(protocol).encode()).hexdigest()==ticket["canonicalWindowsProtocolPathSha256" if os.name=="nt" else "canonicalLinuxProtocolPathSha256"] and
             hashlib.sha256(str(lease_path).encode()).hexdigest()==ticket["canonicalWindowsLeasePathSha256" if os.name=="nt" else "canonicalLinuxLeasePathSha256"],"CANONICAL_PATHS")
        need(sha(protocol)==PROTOCOL_SHA,"CANONICAL_PROTOCOL")
        policy=read(protocol,32768)
        need("11" in policy["participants"] and pathlib.Path(policy["canonicalLeaseWindows" if os.name=="nt" else "canonicalLeaseLinux"]).resolve()==lease_path and
             (os.name!="nt" or pathlib.Path(policy["authoritativePolicy"]).resolve()==protocol),"CANONICAL_POLICY")
        lease=read(lease_path,8192)
        need(lease["projectId"]=="11" and lease["randomToken"]==ticket["nonce"] and
             lease["ownerPID"]==ticket["ownerPID"] and lease["ownerProcessStartIdentity"]==ticket["ownerStartIdentity"],"CANONICAL_OWNER")
def load_frame(path,digest,phase=None,rid=None):
    p=pathlib.Path(path).resolve();need(OUT.resolve() in p.parents and sha(p)==digest,"FRAME_PATH")
    a=read(p);t=validate_ticket(read(ticket_path(),16384),int(time.time()))
    need(a["schema"]=="tail11-ci-runtime/v1" and a["projectId"]=="11" and
         a["runNonce"]==t["nonce"] and a["executionWindow"]==t["window"] and a["limits"]==LIMITS,"FRAME_SCOPE")
    need(a["sourceHashes"]==source_binding(t),"FRAME_SOURCE")
    need(a["ticketSha256"]==sha(ticket_path()),"FRAME_TICKET")
    lane_guard(t,a)
    if rid:need(rid==("win-x64" if os.name=="nt" else "linux-x64"),"PLATFORM")
    if phase in ("case","validate"):
        need(a["status"]=="ADMITTED_M1_DECLARED_SCOPE" and a["inputVerified"] is True and
             a["actualControllerAdmission"][rid]["status"]=="PASS_HELD_CHILD_TERMINAL_AND_IDENTITY_DENIAL","NOT_ADMITTED")
    return a
def actual_profile(a,rid):
    if os.name=="nt":
        p=read(os.environ["TAIL11_ROOT_PROFILE"],8192)
        need(p["childPid"]==os.getpid() and p["nonce"]==a["runNonce"],"CHILD_IDENTITY")
        return {"pid":os.getpid(),"nonce":p["nonce"],**input_kernel(p)}
    need(os.getuid()==1000 and os.environ.get("WSL_DISTRO_NAME")=="Ubuntu-24.04","UBUNTU_SCOPE")
    cg=next(x.split("::",1)[1] for x in pathlib.Path("/proc/self/cgroup").read_text().splitlines() if x.startswith("0::"))
    need(cg.endswith("/"+os.environ["TAIL11_ROOT_UNIT"]),"OWN_UNIT")
    root=pathlib.Path("/sys/fs/cgroup")/cg.lstrip("/")
    q,p=(root/"cpu.max").read_text().split()
    need(q!="max" and 0<int(q)<=2*int(p) and (root/"memory.max").read_text().strip()=="536870912" and
         (root/"memory.swap.max").read_text().strip()=="0" and (root/"pids.max").read_text().strip()=="64" and
         str(os.getpid()) in (root/"cgroup.procs").read_text().split(),"CGROUP_CAPS")
    text=pathlib.Path("/proc/self/stat").read_text()
    return {"pid":os.getpid(),"kernelStartTicks":text[text.rfind(")")+2:].split()[19],
            "cgroupSha256":hashlib.sha256(cg.encode()).hexdigest(),"memoryMax":536870912,"swapMax":0,"tasksMax":64,"cpuMax":[q,p]}
def storage_guard():
    total=proof=count=0
    for root in (HERE,OUT):
        if root.exists():
            for p in root.rglob("*"):
                need(not p.is_symlink(),"LINKED_OUTPUT")
                if p.is_file():
                    count+=1;n=p.stat().st_size;total+=n
                    if root==OUT:proof+=n
    need(count<=4096 and total<=1073741824 and proof<=8388608,"STORAGE_BOUND")
def input_kernel(profile):
    # Actual current-process membership/caps/birth; supplied READY/profile text alone is insufficient.
    import ctypes,ctypes.wintypes
    class BASIC(ctypes.Structure):
        _fields_=[("pu",ctypes.c_longlong),("ju",ctypes.c_longlong),("flags",ctypes.c_uint),
          ("min",ctypes.c_size_t),("max",ctypes.c_size_t),("active",ctypes.c_uint),
          ("affinity",ctypes.c_size_t),("priority",ctypes.c_uint),("scheduling",ctypes.c_uint)]
    class IO(ctypes.Structure):
        _fields_=[(name,ctypes.c_ulonglong) for name in ("ro","wo","oo","rb","wb","ob")]
    class EXT(ctypes.Structure):
        _fields_=[("basic",BASIC),("io",IO),("pm",ctypes.c_size_t),("jm",ctypes.c_size_t),
                  ("pp",ctypes.c_size_t),("pj",ctypes.c_size_t)]
    class CPU(ctypes.Structure):
        _fields_=[("flags",ctypes.c_uint),("rate",ctypes.c_uint)]
    k=ctypes.WinDLL("kernel32",use_last_error=True)
    k.OpenJobObjectW.argtypes=[ctypes.c_uint,ctypes.c_int,ctypes.c_wchar_p]
    k.OpenJobObjectW.restype=ctypes.c_void_p
    k.GetCurrentProcess.restype=ctypes.c_void_p
    k.IsProcessInJob.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.POINTER(ctypes.c_int)]
    k.QueryInformationJobObject.argtypes=[ctypes.c_void_p,ctypes.c_int,ctypes.c_void_p,ctypes.c_uint,ctypes.c_void_p]
    k.GetProcessTimes.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p]
    k.CloseHandle.argtypes=[ctypes.c_void_p]
    job=k.OpenJobObjectW(4,False,"tail11-input-only-"+profile["nonce"])
    need(bool(job),"actual input Job open")
    try:
        member=ctypes.c_int();process=k.GetCurrentProcess()
        need(k.IsProcessInJob(process,job,ctypes.byref(member)) and member.value==1,"actual input membership")
        ext=EXT();cpu=CPU()
        need(k.QueryInformationJobObject(job,9,ctypes.byref(ext),ctypes.sizeof(ext),None) and
             k.QueryInformationJobObject(job,15,ctypes.byref(cpu),ctypes.sizeof(cpu),None),"actual input caps query")
        need(ext.basic.flags==0x2218 and ext.basic.active==16 and ext.basic.affinity in (1,3) and
             ext.jm==536870912 and cpu.flags==5 and cpu.rate==1000,"actual input cap values")
        created=ctypes.c_ulonglong();exited=ctypes.c_ulonglong();kernel=ctypes.c_ulonglong();user=ctypes.c_ulonglong()
        need(k.GetProcessTimes(process,ctypes.byref(created),ctypes.byref(exited),ctypes.byref(kernel),ctypes.byref(user))
             and created.value==profile["processCreationFileTime"],"actual child birth")
        return {"actualMembership":True,"cpuRate":cpu.rate,"memoryBytes":ext.jm,
                "activeLimit":ext.basic.active,"affinityMask":ext.basic.affinity,
                "processCreationFileTime":created.value,"queryFromCurrentKernel":True}
    finally:k.CloseHandle(job)


def verify_current_modules(a):
    if os.name=="nt" and a.get("exactProvider"):
        import exact_provider
        exact_provider.attest(a)
    # Same-window stable files; no new process-module snapshot or policy expansion.
    owned={(HERE/n).resolve() for n in a["sourceHashes"]}
    owned|={(ROOT/"tools/oracle.py").resolve(),(ROOT/"tools/verify_downloads.py").resolve()}
    rows={pathlib.Path(r["path"]).resolve():r for r in a["consumingFiles"]}
    for name,m in list(sys.modules.items()):
        value=getattr(m,"__file__",None)
        if not value:continue
        p=pathlib.Path(value).resolve()
        if p in owned:continue
        need(p in rows,"UNQUALIFIED_MODULE")
        r=rows[p]
        if os.name=="nt":
            import fetch_extract
            with fetch_extract.input_held_read(p) as (stream,identity):
                need(identity==r["identity"],"CONSUMING_IDENTITY_DRIFT")
        else:
            need(p.is_file() and p.stat().st_size==r["bytes"] and sha(p)==r["sha256"],"CONSUMING_DRIFT")
def accept_run(run_id,attempt,runs):
    need(type(run_id) is int and run_id>0 and attempt==1 and 0<len(runs)<100,"RUN_IDENTITY")
    ids=[r["id"] for r in runs]
    need(run_id==min(ids) and len(ids)==len(set(ids)),"RUN_ALREADY_CONSUMED")

from pathlib import Path
def input_programdata_metadata(value):
    import ctypes,stat
    k=ctypes.WinDLL("kernel32",use_last_error=True)
    k.GetDriveTypeW.argtypes=[ctypes.c_wchar_p];k.GetDriveTypeW.restype=ctypes.c_uint
    drive_type=k.GetDriveTypeW(value[:3])
    need(drive_type==3,"ProgramData nonlocal drive denied before directory metadata")
    info=Path(value).lstat()
    return {"directory":stat.S_ISDIR(info.st_mode),
            "reparse":bool(getattr(info,"st_file_attributes",0)&0x400),
            "driveType":drive_type}

def input_programdata():
    # Exact actual parent value, never trim/default/alias/resolve.
    value=os.environ.get("ProgramData")
    need(type(value) is str and len(value)>0 and not any(c in value for c in ("\x00","\r","\n")),
         "ProgramData presence/control shape")
    need(len(value)>=3 and value[0] in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" and
         value[1]==":" and value[2] in "\\/" and Path(value).is_absolute(),
         "ProgramData local absolute shape")
    meta=input_programdata_metadata(value)
    need(meta["directory"] is True and meta["reparse"] is False and meta["driveType"]==3,
         "ProgramData fixed local nonreparse directory")
    proof={"present":True,"nonempty":True,"absolute":True,"localFixedDrive":True,
           "existingDirectory":True,"nonreparse":True,"noNulCrLf":True,
           "source":"ACTUAL_PARENT_PROCESS_ENVIRONMENT",
           "valueSha256":hashlib.sha256(value.encode("utf-8","surrogatepass")).hexdigest(),
           "hashEncoding":"UTF8_SURROGATEPASS"}
    return value,proof
