"""Purpose-specific M1 stages. No command, host or arbitrary dataset arguments."""
import argparse,hashlib,json,os,subprocess,sys,time
from pathlib import Path
WORK=Path(__file__).resolve().parent
ROOT=WORK.parent.parent
OUT=ROOT/"outputs/m1"
ACTIVE_ROLE='BEFORE_FRAME'
def need(v,why):
    if not v:raise ValueError(why)
def sha(p):
    h=hashlib.sha256()
    with Path(p).open("rb") as f:
        for b in iter(lambda:f.read(65536),b""):h.update(b)
    return h.hexdigest()
def read(p,cap=1048576):
    with Path(p).open("rb") as f:b=f.read(cap+1)
    need(len(b)<=cap,"BOUNDED_JSON")
    return json.loads(b)
def fresh(p,data):
    p.parent.mkdir(parents=True,exist_ok=True)
    b=(json.dumps(data,sort_keys=True)+"\n").encode()
    need(len(b)<=262144,"ROLE_PROOF_CAP")
    with p.open("xb") as f:f.write(b);f.flush();os.fsync(f.fileno())
def bootstrap(args):
    need(args.attachment.resolve().is_relative_to(OUT.resolve()) and sha(args.attachment)==args.attachment_sha,"FRAME_HASH")
    a=read(args.attachment)
    ticket=OUT/"local-ticket.json" if os.environ.get("TAIL11_EXECUTION")=="LOCAL_CANONICAL" else WORK/"lease-ticket.json"
    t=read(ticket,16384)
    need(a["runNonce"]==t["nonce"] and a["executionWindow"]==t["window"] and
         t["window"]["startUnix"]<=time.time()<t["window"]["deadlineUnix"]-30,"WHOLE_CLOCK")
    need(t["window"]["deadlineUnix"]-t["window"]["startUnix"]==300,"NO_CLOCK_RESET")
    need(sha(WORK/"source-manifest.json")==t["sourceManifestSha256"],"SOURCE_MANIFEST")
    m=read(WORK/"source-manifest.json")
    need(a["sourceHashes"]==m["files"],"SOURCES")
    for n,h in m["files"].items():need((WORK/n).resolve().is_relative_to(WORK) and sha(WORK/n)==h,"SOURCE_DRIFT")
    if os.name!="nt":
        pp=Path(a["canonicalProtocolPath"]);lp=Path(a["canonicalLeasePath"])
        need(hashlib.sha256(str(pp).encode()).hexdigest()==t["canonicalLinuxProtocolPathSha256"] and
             hashlib.sha256(str(lp).encode()).hexdigest()==t["canonicalLinuxLeasePathSha256"],"CANONICAL_PATHS")
        need(sha(pp)==t["protocolSha256"]=="9120ca49a0d46673053aa0ec0cdbbc6f00731d71ea0b57ddab09e8fc3ac3ac8b","CANONICAL_PROTOCOL")
        policy=read(pp);lease=read(lp,8192)
        need("11" in policy["participants"] and policy["canonicalLeaseLinux"]==str(lp) and
             lease["projectId"]=="11" and lease["randomToken"]==t["nonce"] and
             lease["ownerPID"]==t["ownerPID"] and lease["ownerProcessStartIdentity"]==t["ownerStartIdentity"],"CANONICAL_OWNER")
    return a

def qualify(a,args):
    # All qualified sources are committed and hash-bound before enabling the audit hook.
    sys.path[:0]=[str(WORK),str(ROOT/"tools")]
    import qualifier as q
    import support as s
    own=OUT/"qualification"
    source_paths={n:str(WORK/n) for n in a["sourceHashes"]}
    source_paths["oracle.py"]=str(ROOT/"tools/oracle.py")
    source_paths["verify_downloads.py"]=str(ROOT/"tools/verify_downloads.py")
    q.cache_policy(sys.pycache_prefix)
    lane_reads=[a["canonicalProtocolPath"],a["canonicalLeasePath"]] if a.get("execution")=="LOCAL_CANONICAL" else []
    if a.get('manifestSignatureSource'):
        need(a['manifestSignatureSource']=='PINNED_LINUX_MANIFEST_DATA_ONLY','MANIFEST_SIGNATURE_SOURCE_SCOPE')
        import signature_handoff
        _,signature_paths=signature_handoff.binding_paths();lane_reads += list(map(str,signature_paths))
    if a.get("exactProvider"):
        import exact_provider
        lane_reads += [str(exact_provider.TARGET),a["exactProvider"]["reusedControls"]["path"]]+[r["path"] for r in a["exactProvider"]["proofs"].values()]
    q.install_audit(str(Path(sys.executable).parent),str(OUT),lane_reads+list(source_paths.values())+
                    [str(args.attachment),str(WORK/"source-manifest.json"),str(s.ticket_path()),
                     os.environ["TAIL11_ROOT_PROFILE"],a["sshKeygen"]["path"]])
    started=time.monotonic()
    try:
        import ast,base64,importlib.util,ssl,ctypes.wintypes
        import fetch_extract as stage
        import experiment,preflight_witness,verify_downloads
        s.load_frame(args.attachment,args.attachment_sha,rid="win-x64")
        kernel=s.actual_profile(a,"win-x64")
        _,pd=s.input_programdata()
        need(pd["valueSha256"]==a["programDataSha256"],"PROGRAMDATA_CHAIN")
        plans=[];source_bytes=0
        for name in ("aggregate_worker.py","fetch_extract.py","support.py","experiment.py","preflight_witness.py"):
            text=(WORK/name).read_text();source_bytes+=len(text.encode())
            plans.append(q.source_sites(text,"worker" if name=="aggregate_worker.py" else "verifier"))
        text=(ROOT/"tools/verify_downloads.py").read_text();source_bytes+=len(text.encode())
        plans.append(q.source_sites(text,"verifier"))
        # These imports come only from the committed AST plans and frozen LAZY tuple.
        required=set(q.LAZY)
        for plan in plans:required.update(x["module"] for x in plan["literalImportSites"])
        for name in sorted(required):
            need(name not in ("site","ensurepip","pip"),"IMPORT_PLAN_DENIED")
            __import__(name)
        experiment.load_oracle(a,"win-x64")
        if args.role=="frozen-verifier-imports":
            blob=(11).to_bytes(4,"big")+b"ssh-ed25519"+(32).to_bytes(4,"big")+bytes(32)
            verify_downloads.canonical_key(b"ssh-ed25519 "+base64.b64encode(blob)+b"\n")
        hashlib.sha256(b"tail11-netless").hexdigest();json.loads('{"v":1}')
        ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        denied=False
        try:sys.audit("socket.getaddrinfo","SYNTHETIC_NO_TARGET",0,0,0,0)
        except q.Hold:denied=True
        need(denied,"AUDIT_DENIAL")
        previous=[];used=a["initialToolReadBytes"]
        if args.role=="frozen-verifier-imports":
            first=read(own/"input-worker-imports.json",262144)
            need(first["status"]=="QUALIFIER_ROLE_COMPLETE" and first["runNonce"]==a["runNonce"],"ROLE1")
            previous=first["consumingFiles"];used+=first["newlyReadBytes"]
        source_bytes+=2*sum((WORK/n).stat().st_size for n in a["sourceHashes"])
        source_bytes+=3*sum(p.stat().st_size for p in (args.attachment,WORK/"source-manifest.json",s.ticket_path()))
        b={"sourceHashes":a["sourceHashes"],"sourcePaths":source_paths,"qualifierPath":str(WORK/"qualifier.py"),
           "frozenVerifier":{"path":str(ROOT/"tools/verify_downloads.py"),"sha256":s.VERIFIER_SHA},
           "sshKeygen":a["sshKeygen"],"readBytesAlready":used+source_bytes,"priorConsumingFiles":previous}
        if a.get('manifestSignatureSource'):b['manifestSignatureSource']=a['manifestSignatureSource']
        if a.get("exactProvider"):
            if args.role=="input-worker-imports":
                b["queueCausalControl"]={'status':'UNCHANGED_QUEUE_CONTROL_NOT_REPLAYED','reason':'Only manifest-signature data routing changed; enqueue_provider and graph_queue_control retain their previous source.'}
                b["newProviderControls"],control_read=exact_provider.reused_controls(a)
                b["readBytesAlready"]+=control_read;source_bytes+=control_read
            b["exactProviderAttestation"]=exact_provider.attest(a)
        result=q.inventory(b,stage,args.role,plans)
        result["reusedProviderControls"]=b.get("newProviderControls",[])
        result["queueCausalControl"]=b.get("queueCausalControl")
        result["newlyReadBytes"]+=source_bytes
        need(time.monotonic()-started<=20 and not any(Path(sys.pycache_prefix).iterdir()),"ROLE20_OR_CACHE")
        result.update(status="QUALIFIER_ROLE_COMPLETE",role=args.role,runNonce=a["runNonce"],
                      window=a["executionWindow"],actualKernel=kernel,programDataShape=pd,
                      globalFullClosureQualified=False,advisoryQualified=False,auditDenial=True)
        fresh(own/(args.role+".json"),result)
        fresh(OUT/"public"/(args.role+".json"),{"status":"QUALIFIER_ROLE_COMPLETE","role":args.role,
             "consumingCount":len(result["consumingFiles"]),"newlyReadBytes":result["newlyReadBytes"],
             "unresolved":result["unresolved"],"proofSha256":sha(own/(args.role+".json")),
             "fullClosureQualified":False,"advisoryQualified":False})
    except Exception as e:
        code=getattr(e,"code",str(e) if isinstance(e,ValueError) and str(e).replace("_","").isalnum() and str(e).upper()==str(e) else "QUALIFIER_INTERNAL_HOLD")
        if not isinstance(code,str) or not code.isascii() or len(code)>100:code="QUALIFIER_INTERNAL_HOLD"
        fresh(OUT/"public"/(args.role+"-hold.json"),{"status":"HOLD","code":code,
             "role":args.role,"safeProviders":getattr(q,"LAST_SAFE_PROVIDERS",[]),"ownedSSHRole":getattr(q,"LAST_OWNED_SSH_ROLE",None),"newSnapshot":False})
        raise SystemExit(1) from None

def stage_inputs(a,args):
    sys.path[:0]=[str(WORK),str(ROOT/"tools")]
    import support as s,fetch_extract as stage,experiment
    s.load_frame(args.attachment,args.attachment_sha,rid=args.rid)
    s.actual_profile(a,args.rid);s.verify_current_modules(a)
    deadline=a["executionWindow"]["deadlineUnix"]-30
    route={"mode":"PUBLIC_API_NO_AUTH","authorityBinding":{"path":str(s.ticket_path()),"sha256":sha(s.ticket_path())},
           "retainedSmallAssets":{n:str(WORK/"metadata"/n) for n,_,_ in stage.ASSETS[:3]}}
    if a.get('archiveResume'):route['resume']=a['archiveResume']
    inputs=WORK/"inputs"/args.rid
    evidence=OUT/"staging"/args.rid
    raw=stage.acquire(read(WORK/"input-bindings.json"),inputs,evidence,deadline,route,args.rid)
    archive=stage.ASSETS[3 if args.rid=="win-x64" else 4][0]
    if a.get('manifestSignatureSource'):
        need(a['manifestSignatureSource']=='PINNED_LINUX_MANIFEST_DATA_ONLY','MANIFEST_SIGNATURE_SOURCE_SCOPE')
        import signature_handoff
        with signature_handoff.archive_conjunction(args.rid,raw,evidence,deadline) as signature_receipt:
            (inputs/'verification').mkdir(parents=True,exist_ok=True)
            result=stage.extract(args.rid,raw,inputs,evidence,signature_receipt,deadline)
        fresh(OUT/args.rid/'staged-input.json',result);s.storage_guard();return
    verifier=ROOT/"tools/verify_downloads.py"
    need(sha(verifier)==s.VERIFIER_SHA,"FROZEN_VERIFIER")
    ssh=Path(a["sshKeygen"]["path"])
    need(sha(ssh)==a["sshKeygen"]["sha256"],"SSH_DRIFT")
    os.environ["PATH"]=str(ssh.parent)
    need(not any((x/"ssh-keygen.exe").exists() for x in (Path(sys.executable).parent,WORK,Path("C:/Windows/System32"),Path("C:/Windows"))) if os.name=="nt" else ssh==Path("/usr/bin/ssh-keygen"),"SSH_RESOLUTION")
    experiment.DEADLINE=deadline
    verifywork=evidence/"actual-known-key"
    code,stdout,stderr=experiment.bounded_child([sys.executable,"-I","-S","-B",str(verifier),"--directory",str(raw),
      "--work",str(verifywork),"--trusted-fingerprint",s.FINGERPRINT,"--archive",archive])
    need(code==0,"SIGNATURE_HOLD")
    (inputs/"verification").mkdir(parents=True,exist_ok=True)
    result=stage.extract(args.rid,raw,inputs,evidence,verifywork/"receipt.json",deadline)
    fresh(OUT/args.rid/"staged-input.json",result)
    s.storage_guard()

def linux_profile():
    need(os.getuid()==1000 and os.environ.get("WSL_DISTRO_NAME")=="Ubuntu-24.04","UBUNTU_SCOPE")
    cg=next(x.split("::",1)[1] for x in Path("/proc/self/cgroup").read_text().splitlines() if x.startswith("0::"))
    need(cg.endswith("/"+os.environ["TAIL11_ROOT_UNIT"]),"OWN_UNIT")
    root=Path("/sys/fs/cgroup")/cg.lstrip("/")
    q,p=(root/"cpu.max").read_text().split()
    need(q!="max" and 0<int(q)<=2*int(p) and (root/"memory.max").read_text().strip()=="536870912" and
         (root/"memory.swap.max").read_text().strip()=="0" and (root/"pids.max").read_text().strip()=="64" and
         str(os.getpid()) in (root/"cgroup.procs").read_text().split(),"CGROUP_CAPS")
    return {"pid":os.getpid(),"cgroup":cg,"nonce":os.environ["TAIL11_ROOT_NONCE"]}

def linux_vendor_observation(a, attachment_sha, profile):
    """Closed vendor metadata ONLY: no project import, network call or target."""
    import platform  # Linux-only observer; no Windows WMI/provider dependency.
    import copy, importlib.util
    import csv, ctypes, ctypes.wintypes, fractions, gzip, io, math, re, runpy, select, shutil, base64, contextlib
    import ssl, stat, struct, tarfile, threading, urllib.request, zipfile, zlib
    policy=a["bootstrapObserver"]
    need(policy["mode"]=="LINUX_VENDOR_METADATA_THEN_BOUNDED_MANAGER_DERIVATION" and
         policy["targetsOnMetadataAlone"] is False, "closed observer not admitted")
    need(sha(policy["authorityBinding"]["path"])==policy["authorityBinding"]["sha256"],
         "closed observer authority changed")
    need(sys.flags.isolated==1 and sys.flags.no_site==1 and
         Path(sys.executable).resolve()==Path("/usr/bin/python3").resolve(), "vendor observer argv")
    os_data={}
    with Path("/etc/os-release").open("rb") as f: raw=f.read(16385)
    need(len(raw)<=16384,"os-release cap")
    for line in raw.decode().splitlines():
        if "=" in line:
            key,value=line.split("=",1);os_data[key]=value.strip('"')
    need(os_data.get("ID")=="ubuntu" and os_data.get("VERSION_ID")=="24.04","vendor Ubuntu24 only")
    def bounded_text(path,cap):
        with Path(path).open("rb") as f: data=f.read(cap+1)
        need(len(data)<=cap,"metadata cap");return data.decode("utf-8","replace")
    files={};modules=[]
    def bind_file(value):
        p=Path(value).resolve();key=str(p)
        if key in files: return
        need(p.is_file() and str(p).startswith(("/usr/lib/","/usr/bin/","/lib/")),
             "nonvendor consuming module")
        observed=p.stat();n=observed.st_size
        need(0<=n<=16777216,"consuming file cap")
        need(len(files)+1<=256 and sum(x["bytes"] for x in files.values())+n<=67108864,
             "bounded vendor metadata set before digest")
        fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        with os.fdopen(fd,"rb") as stream:
            first=os.fstat(stream.fileno())
            need(stat.S_ISREG(first.st_mode) and first.st_size==n and
                 (first.st_dev,first.st_ino)==(observed.st_dev,observed.st_ino),
                 "consuming file changed before digest")
            h=hashlib.sha256();remaining=n
            while remaining:
                block=stream.read(min(1048576,remaining))
                need(bool(block),"consuming file shortened during digest")
                h.update(block);remaining-=len(block)
            last=os.fstat(stream.fileno())
            need(last.st_size==n and last.st_mtime_ns==first.st_mtime_ns and
                 last.st_ctime_ns==first.st_ctime_ns,
                 "consuming file grew or changed during digest")
        files[key]={"path":key,"bytes":n,"sha256":h.hexdigest()}
    bind_file(sys.executable)
    bind_file('/usr/bin/ssh-keygen')
    for name,module in sorted(list(sys.modules.items())):
        origin=getattr(module,"__file__",None)
        if name=="__main__":
            modules.append({"name":name,"kind":"owned source","path":str(WORK/"aggregate_worker.py"),
                            "sha256":a["sourceHashes"]["aggregate_worker.py"]})
            continue
        item={"name":name,"origin":origin,"cached":getattr(module,"__cached__",None)}
        for value in (origin,item["cached"]):
            if value and Path(value).is_file(): bind_file(value)
        modules.append(item)
    consuming=sorted(files.values(),key=lambda x:x["path"])
    need(1<=len(consuming)<=256 and sum(x["bytes"] for x in consuming)<=67108864,
         "bounded vendor metadata set")
    statline=bounded_text("/proc/self/stat",65536)
    birth=statline[statline.rfind(")")+2:].split()[19]
    with Path("/proc/cpuinfo").open("rb") as cpu_file: cpu_bytes=cpu_file.read(65537)
    uname=os.uname()
    record={"schema":"tail11-linux-vendor-metadata/v1","projectId":"11","rid":"linux-x64",
            "runNonce":a["runNonce"],"attachmentSha256":attachment_sha,
            "observerSourceSha256":a["sourceHashes"]["aggregate_worker.py"],
            "window":a["executionWindow"],"pid":os.getpid(),"parentPid":os.getppid(),
            "kernelStartTicks":birth,"profile":profile,
            "python":{"path":"/usr/bin/python3","resolvedPath":str(Path(sys.executable).resolve()),
                      "sha256":files[str(Path(sys.executable).resolve())]["sha256"],"version":platform.python_version()},
            "consumingFiles":consuming,"modules":modules,"osRelease":os_data,
            "uname":{"sysname":uname.sysname,"release":uname.release,"version":uname.version,"machine":uname.machine},
            "cpuCount":os.cpu_count(),"cpuInfoExcerpt":cpu_bytes[:65536].decode("utf-8","replace"),
            "cpuInfoTruncated":len(cpu_bytes)>65536,
            "procCgroup":bounded_text("/proc/self/cgroup",65536),
            "qualification":"OBSERVATION_ONLY_NOT_ADMITTED",
            "fullClosureQualified":False,"advisoryQualified":False,
            "projectImports":0,"CLIOrFetchOrSDKCalls":0}
    fresh(OUT/"linux-x64"/"vendor-metadata-observation.json",record)


def pinned_plan(expected):
    need(sha(WORK/"case-plan.json")==expected,"CASE_PLAN_IDENTITY_DENIED")

def linux_resume_data(a):
    binding=a['resumeLinuxFrom'];required={'observation','observerTerminal','scopeTerminal','decision','controlAdmission','bootstrap','rootProfile'}
    need(set(binding)==required,'EXACT_RETAINED_LINUX_DATA_SET');values={}
    for name,row in binding.items():
        need(sha(row['path'])==row['sha256'],'RETAINED_LINUX_DATA_BYTES');values[name]=read(row['path'],262144)
    m,t,s,d,c,b,p=(values[n] for n in ('observation','observerTerminal','scopeTerminal','decision','controlAdmission','bootstrap','rootProfile'))
    need(m['qualification']=='OBSERVATION_ONLY_NOT_ADMITTED' and m['fullClosureQualified'] is False and m['advisoryQualified'] is False and m['CLIOrFetchOrSDKCalls']==0 and m['projectImports']==0,'REUSED_METADATA_NOT_HOST_ADMISSION')
    need(t['originalPopenWaitReturned'] and t['returncode']==0 and t['pid']==m['pid'] and m['parentPid']==p['pid'] and t['runNonce']==m['runNonce']==b['runNonce'] and t['observationSha256']==binding['observation']['sha256'] and t['rootAttachmentSha256']==m['attachmentSha256']==binding['bootstrap']['sha256'],'REUSED_OBSERVER_ORIGINAL_SCOPE')
    need(s['mainPid']==s['controlPid']==0 and s['emptyOrRemovedCgroup'] and s['rootAttachmentSha256']==binding['bootstrap']['sha256'] and s['proof'] in ('ORIGINAL_SYSTEMD_WAIT_AND_EMPTY_OR_REMOVED_CGROUP','ORIGINAL_SYSTEMD_WAIT_UNIT_COLLECTED_CGROUP_REMOVED'),'REUSED_LINUX_SCOPE_ACTUALLY_TERMINAL')
    need(m['observerSourceSha256']==b['sourceHashes']['aggregate_worker.py'] and d['status']=='ADMITTED_BOUNDED_STDLIB_FOR_PROJECT11' and d['qualificationScope']=='OBSERVED_VENDOR_FILES_ONLY_NOT_FULL_CLOSURE' and d['fullClosureQualified'] is False and d['advisoryQualified'] is False and d['consumingFiles']==m['consumingFiles'] and d['observationSha256']==binding['observation']['sha256'] and d['terminalSha256']==binding['observerTerminal']['sha256'],'REUSED_DECLARED_VENDOR_GRAPH_ONLY')
    need(c['status']=='PASS_HELD_CHILD_TERMINAL_AND_IDENTITY_DENIAL' and c['originalPopenWaitReturned'] and c['wrongIdentityDeniedBeforeChild'],'REUSED_LINUX_CONTROL_RECEIPT')
    fresh(OUT/'linux-x64/vendor-data-reused.json',{'status':'DECLARED_VENDOR_DATA_REUSED_CURRENT_CHILD_CHECKS_REMAIN','proofHashes':{n:r['sha256'] for n,r in binding.items()},'newMetadataSnapshot':False,'healthyTestsRepeated':0,'globalHostAdmissionTransferred':False})
    return m,d,Path(binding['controlAdmission']['path'])

def linux_root(a,args):
    profile=linux_profile()
    fresh(OUT/"linux-x64/aggregate-root-actual-profile.json",profile)
    resumed=bool(a.get('resumeLinuxFrom'))
    if resumed:meta,d,retained_admission=linux_resume_data(a)
    else:
        child=subprocess.Popen(["/usr/bin/python3","-I","-S","-B",str(WORK/"aggregate_worker.py"),
              "--attachment",str(args.attachment),"--attachment-sha",args.attachment_sha,"--role","linux-metadata-observer","--rid","linux-x64"],
              stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        code=child.wait(timeout=max(.001,min(20,a["executionWindow"]["deadlineUnix"]-30-time.time())))
        need(code==0,"METADATA_FAILED_NO_RETRY")
        observation=OUT/"linux-x64/vendor-metadata-observation.json"
        meta=read(observation)
        need(meta["pid"]==child.pid and meta["parentPid"]==os.getpid() and meta["runNonce"]==a["runNonce"] and
             meta["attachmentSha256"]==args.attachment_sha and meta["window"]==a["executionWindow"] and
             meta["observerSourceSha256"]==a["sourceHashes"]["aggregate_worker.py"],"METADATA_IDENTITY")
        fresh(OUT/"linux-x64/vendor-metadata-terminal.json",{"pid":child.pid,"returncode":code,"originalPopenWaitReturned":True,
              "runNonce":a["runNonce"],"observationSha256":sha(observation),"rootAttachmentSha256":args.attachment_sha})
        # Exactly one directory event wait; no snapshot, rerun or new timeout window.
        import ctypes,select
        libc=ctypes.CDLL(None,use_errno=True)
        libc.inotify_init1.argtypes=[ctypes.c_int];libc.inotify_init1.restype=ctypes.c_int
        libc.inotify_add_watch.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_uint32]
        libc.inotify_add_watch.restype=ctypes.c_int
        fd=libc.inotify_init1(os.O_CLOEXEC|os.O_NONBLOCK)
        need(fd>=0 and libc.inotify_add_watch(fd,os.fsencode(OUT/"linux-x64"),0x8|0x80)>=0,"ADMISSION_WATCH")
        decision_path=OUT/"linux-x64/linux-bounded-input-admission.json"
        try:
            while not decision_path.exists():
                left=a["executionWindow"]["deadlineUnix"]-30-time.time();need(left>0,"WHOLE_CLOCK")
                ready,_,_=select.select([fd],[],[],min(20,left))
                if ready:os.read(fd,65536)
        finally:os.close(fd)
        d=read(decision_path)
        need(d["status"]=="ADMITTED_BOUNDED_STDLIB_FOR_PROJECT11" and d["runNonce"]==a["runNonce"] and
             d["observationSha256"]==sha(observation) and d["terminalSha256"]==sha(OUT/"linux-x64/vendor-metadata-terminal.json") and
             d["consumingFiles"]==meta["consumingFiles"] and d["qualificationScope"]=="OBSERVED_VENDOR_FILES_ONLY_NOT_FULL_CLOSURE" and
             d["fullClosureQualified"] is False and d["advisoryQualified"] is False,"MANAGER_DERIVATION")
    sys.path[:0]=[str(WORK),str(ROOT/"tools")]
    import support as s,experiment,fetch_extract,preflight_witness
    a["consumingFiles"]=d["consumingFiles"]
    ssh=next(x for x in d["consumingFiles"] if x["path"]=="/usr/bin/ssh-keygen")
    a["sshKeygen"]={"path":ssh["path"],"sha256":ssh["sha256"]}
    need(sha(sys.executable)==meta["python"]["sha256"],"PYTHON_DRIFT")
    # Actual wrong-plan denial before target plus one held probe in the same cgroup.
    pinned_plan(a["casePlanSha256"])
    try:pinned_plan("0"*64)
    except ValueError:denied=True
    else:denied=False
    need(denied,"WRONG_IDENTITY_NOT_DENIED")
    def phase(frame,label,cap=99,mode="normal"):
        pinned_plan(a["casePlanSha256"])
        p=OUT/"linux-x64"/("frame-"+label+"-"+str(cap)+"-"+mode+".json");fresh(p,frame)
        entry="import sys;sys.path[:0]="+repr([str(WORK),str(ROOT/"tools")])+";import experiment;experiment.main()"
        experiment.DEADLINE=a["executionWindow"]["deadlineUnix"]-30
        code,_,_=experiment.bounded_child(["/usr/bin/python3","-I","-S","-B"]+(["-O"] if mode=="optimized" else [])+
          ["-c",entry,"--attachment",str(p),"--attachment-sha",sha(p),"--rid","linux-x64","--phase",label,"--cap",str(cap),"--mode",mode])
        need(code==0,"LINUX_PHASE_HOLD")
    if resumed:admission=retained_admission
    else:
        phase(a,"probe")
        admission=OUT/"linux-x64/control-admission.json"
        fresh(admission,{"status":"PASS_HELD_CHILD_TERMINAL_AND_IDENTITY_DENIAL","originalPopenWaitReturned":True,"wrongIdentityDeniedBeforeChild":True})
    stageframe=OUT/"linux-x64/stage-frame.json";fresh(stageframe,a)
    stage_inputs(a,argparse.Namespace(attachment=stageframe,attachment_sha=sha(stageframe),rid="linux-x64"))
    a["status"]="ADMITTED_M1_DECLARED_SCOPE";a["inputVerified"]=True
    a["inputs"]={"linux-x64":read(OUT/"linux-x64/staged-input.json")}
    a["actualControllerAdmission"]={"linux-x64":{"status":"PASS_HELD_CHILD_TERMINAL_AND_IDENTITY_DENIAL","path":str(admission),"sha256":sha(admission)}}
    for cap in (99,100,101):phase(a,"case",cap)
    for mode in ("normal","optimized"):phase(a,"validate",99,mode)
    s.storage_guard()
    fresh(OUT/"linux-x64/m1-finished.json",{"status":"RECORDED_ACCOUNTING_NOT_SPEED","nativeCalls":3,"negativeControls":12,
          "runNonce":a["runNonce"],"window":a["executionWindow"],"fullClosureQualified":False,"advisoryQualified":False})

def main():
    global ACTIVE_ROLE
    p=argparse.ArgumentParser();p.add_argument("--attachment",type=Path,required=True);p.add_argument("--attachment-sha",required=True)
    p.add_argument("--role",choices=["input-worker-imports","frozen-verifier-imports","stage","linux-root","linux-metadata-observer"],required=True)
    p.add_argument("--rid",choices=["win-x64","linux-x64"],required=True);args=p.parse_args()
    ACTIVE_ROLE=args.role;a=bootstrap(args)
    if args.role=="linux-metadata-observer":linux_vendor_observation(a,args.attachment_sha,linux_profile())
    elif args.role=="linux-root":linux_root(a,args)
    elif args.role=="stage":stage_inputs(a,args)
    else:qualify(a,args)
if __name__=="__main__":
    try:main()
    except SystemExit:raise
    except Exception as error:
        # Closed failure metadata only: no exception text/locals/URLs/environment.
        if os.name!='nt':
            code=getattr(error,'code',None);record=getattr(error,'record',{})
            if code is None and type(record) is dict:code=record.get('code')
            if not (type(code) is str and code.isascii() and 1<=len(code)<=100 and code.replace('_','').isalnum() and code.upper()==code):code='LINUX_OWNED_STAGE_HOLD'
            frames=[];tb=error.__traceback__
            while tb is not None:
                if tb.tb_frame.f_code.co_filename==__file__:frames.append({'function':tb.tb_frame.f_code.co_name,'line':tb.tb_lineno})
                tb=tb.tb_next
            try:fresh(OUT/'linux-x64/owned-stage-hold.json',{'status':'HOLD','role':ACTIVE_ROLE,'code':code,'exceptionType':type(error).__name__,'ownedSourceFrames':frames[-6:]})
            except Exception:pass
        raise SystemExit(1) from None
