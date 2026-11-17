"""Source-bound, finite import-only qualifier. No operational main, socket or SSH."""

import sys,os

AMENDMENT_SHA="49a3a12a746a333d4eaa65aaaaf9eb7aba3704002531a56a888fe9a4de98354f"

MODE="INPUT_ONLY_IMMUTABLE_PREFIX_RANGE"

ROLES=("input-worker-imports","frozen-verifier-imports")

LAZY=("ctypes.wintypes","http.client","urllib.parse","urllib.request","email.parser",
 "email.feedparser","email.message","ssl","socket","_ssl","_socket","_hashlib",
 "_ctypes","_winapi","msvcrt","select","_queue","encodings.idna","encodings.ascii",
 "encodings.utf_8","base64","struct","subprocess","threading","ntpath")

OS_BASE=frozenset(("ntdll.dll kernel32.dll kernelbase.dll advapi32.dll sechost.dll rpcrt4.dll "
 "bcrypt.dll bcryptprimitives.dll ucrtbase.dll vcruntime140.dll vcruntime140_1.dll "
 "crypt32.dll msasn1.dll ncrypt.dll ntasn1.dll sspicli.dll schannel.dll ws2_32.dll "
 "wintrust.dll normaliz.dll version.dll user32.dll win32u.dll gdi32.dll gdi32full.dll "
 "shlwapi.dll shell32.dll ole32.dll combase.dll oleaut32.dll cfgmgr32.dll devobj.dll "
 "setupapi.dll psapi.dll imm32.dll msvcrt.dll profapi.dll mswsock.dll cryptbase.dll "
 "iphlpapi.dll nsi.dll dnsapi.dll msvcp_win.dll clbcatq.dll powrprof.dll umpdc.dll "
 "winmmbase.dll winmm.dll dhcpcsvc.dll dhcpcsvc6.dll").split())

WORK_FUNCTIONS=frozenset(("input_admit","input_kernel","input_tools","input_verify",
 "input_programdata","input_programdata_metadata","input_ssh_resolution","input_source_qualification","input_cache_policy","input_empty_cache",
 "run_input_only","load_fixed","sha","read","need"))

FETCH_FUNCTIONS=frozenset(("input_require","input_failure","input_headers","input_url",
 "unique_header","input_response_headers","input_receive","input_held_read",
 "_file_identity","input_prefix_copy","input_windows","input_seal","input_frames"))

class Hold(ValueError):
    def __init__(self,code):self.code=code;super().__init__(code)

def require(ok,code):
    if not ok:raise Hold(code)

def install_audit(python_root,own_root,source_paths):
    allowed=tuple(os.path.normcase(os.path.abspath(x)) for x in (python_root,own_root))
    exact={os.path.normcase(os.path.abspath(x)) for x in source_paths}
    own=os.path.normcase(os.path.abspath(own_root))
    def under(path,root):return path==root or path.startswith(root+os.sep)
    def audit(event,args):
        if event.startswith(("socket.","subprocess.","os.exec","os.spawn","os.posix_spawn",
                             "http.client.","urllib.Request")) or event in ("os.system","pty.spawn"):
            raise Hold("NETLESS_OPERATION_DENIED")
        if event=="open":
            path=args[0]
            if isinstance(path,int):return
            require(isinstance(path,(str,bytes,os.PathLike)),"FILE_ORIGIN_UNKNOWN")
            path=os.fsdecode(path);p=os.path.normcase(os.path.abspath(path))
            mode=args[1] or "";flags=args[2] if len(args)>2 else 0
            write=(any(x in mode for x in "wax+") if isinstance(mode,str) else False)
            write=write or (isinstance(flags,int) and bool(flags & (os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND)))
            if write:require(under(p,own) and "cache-" not in p,"QUALIFIER_WRITE_DENIED")
            else:
                require(p in exact or any(under(p,x) for x in allowed),"QUALIFIER_READ_DENIED")
                if "__pycache__" in p:require(under(p,own),"OLD_CACHE_READ_DENIED")
        if event in ("os.remove","os.rmdir","os.rename","os.chmod","os.truncate"):
            raise Hold("QUALIFIER_MUTATION_DENIED")
    sys.addaudithook(audit)
    return audit

def cache_policy(expected):
    import pathlib
    p=pathlib.Path(expected)
    require(sys.flags.isolated==1 and sys.flags.no_site==1 and sys.dont_write_bytecode is True,
            "PYTHON_FLAGS")
    require(sys.pycache_prefix==expected and p.is_absolute() and p.is_dir(),"PYCACHE_POLICY")
    require(not any(p.iterdir()),"CACHE_NOT_EMPTY")
    require(all("site-packages" not in x.lower() for x in sys.path),"SITE_PATH")
    require("site" not in sys.modules,"SITE_IMPORTED")
    return {"isolated":True,"noSite":True,"dontWriteBytecode":True,
            "pycachePrefix":expected,"empty":True,"siteAbsent":True,
            "sysPath":list(sys.path)}

def source_sites(text,kind):
    import ast
    tree=ast.parse(text)
    permitted=WORK_FUNCTIONS if kind=="worker" else FETCH_FUNCTIONS
    roots=[];imports=[];dynamic=[];excluded=[]
    for node in tree.body:
        if isinstance(node,(ast.Import,ast.ImportFrom)):roots.append(node)
        elif isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)) and (kind=="verifier" or node.name in permitted):
            roots.append(node)
        elif isinstance(node,ast.ClassDef) and kind=="fetch" and node.name.startswith(("Input","_INPUT")):
            roots.append(node)
        elif isinstance(node,(ast.FunctionDef,ast.ClassDef)):
            excluded.append({"name":node.name,"line":node.lineno,"reason":"OUTSIDE_CLOSED_INPUT_ONLY_CALL_GRAPH"})
    for root in roots:
        for node in ast.walk(root):
            if isinstance(node,(ast.Import,ast.ImportFrom)):
                names=[x.name for x in node.names] if isinstance(node,ast.Import) else [node.module]
                require(all(isinstance(x,str) and x for x in names),"RELATIVE_IMPORT_UNMAPPED")
                imports.extend({"module":name,"line":node.lineno} for name in names)
            if isinstance(node,ast.Call):
                name=node.func.id if isinstance(node.func,ast.Name) else (
                    node.func.attr if isinstance(node.func,ast.Attribute) else "")
                if name in ("__import__","import_module"):
                    require(node.args and isinstance(node.args[0],ast.Constant) and
                            isinstance(node.args[0].value,str),"DYNAMIC_IMPORT_UNRESOLVED")
                    dynamic.append({"module":node.args[0].value,"line":node.lineno})
                if name in ("eval","exec"):raise Hold("DYNAMIC_CODE_UNMAPPED")
                if name=="spec_from_file_location":
                    if isinstance(root,ast.FunctionDef) and root.name=="load_fixed":
                        dynamic.append({"ownedSource":"fetch_extract.py","rule":"FIXED_LOAD_CALLER","line":node.lineno})
                    elif (isinstance(root,ast.FunctionDef) and root.name=="load_oracle" and
                          node.args and isinstance(node.args[0],ast.Constant) and node.args[0].value=="tail11_frozen_oracle"):
                        dynamic.append({"ownedOracle":"FROZEN_SHA256_82c699_ONLY","line":node.lineno})
                    elif node.args and isinstance(node.args[0],ast.Constant) and node.args[0].value=="tail11_provider_guard":
                        dynamic.append({"ownedQualifier":"EXACT_ROOT_BOUND_SHA","line":node.lineno})
                    else:raise Hold("DYNAMIC_SOURCE_LOADER_UNMAPPED")
                if name=="load_fixed":
                    require(node.args and isinstance(node.args[0],ast.Constant) and
                            node.args[0].value=="fetch_extract","OWNED_DYNAMIC_SOURCE_UNRESOLVED")
                    dynamic.append({"ownedSource":"fetch_extract.py","line":node.lineno})
    return {"kind":kind,"literalImportSites":imports,"mappedDynamicSites":dynamic,
            "excludedNonInputDefinitions":excluded,"closedInputOnlyGraph":True}

def pe_imports(data):
    import struct,re
    require(len(data)>=256 and data[:2]==b"MZ","PE_FORMAT")
    pe=struct.unpack_from("<I",data,0x3c)[0]
    require(0<pe<=len(data)-256 and data[pe:pe+4]==b"PE\0\0","PE_FORMAT")
    sections=struct.unpack_from("<H",data,pe+6)[0];optional=struct.unpack_from("<H",data,pe+20)[0]
    require(1<=sections<=96 and pe+24+optional+40*sections<=len(data),"PE_SECTIONS")
    opt=pe+24;magic=struct.unpack_from("<H",data,opt)[0]
    require(magic in (0x10b,0x20b),"PE_OPTIONAL")
    dd=opt+(112 if magic==0x20b else 96)
    count=struct.unpack_from("<I",data,opt+(108 if magic==0x20b else 92))[0]
    require(count>=14 and dd+14*8<=opt+optional,"PE_DIRECTORIES")
    imagebase=struct.unpack_from("<Q" if magic==0x20b else "<I",data,opt+(24 if magic==0x20b else 28))[0]
    size_headers=struct.unpack_from("<I",data,opt+60)[0]
    table=[]
    for index in range(sections):
        pos=opt+optional+40*index
        vs,va,raw_size,raw=struct.unpack_from("<IIII",data,pos+8)
        table.append((va,max(vs,raw_size),raw,raw_size))
    def rva(value,n=1):
        if value<size_headers:pos=value
        else:
            hits=[raw+value-va for va,size,raw,raw_size in table
                  if va<=value and value-va+n<=raw_size]
            require(len(hits)==1,"PE_RVA");pos=hits[0]
        require(0<=pos and pos+n<=len(data),"PE_BOUNDS")
        return pos
    def dllname(value):
        pos=rva(value);end=data.find(b"\0",pos,min(len(data),pos+129))
        require(end>pos,"PE_DLL_NAME")
        raw=data[pos:end];require(re.fullmatch(rb"[A-Za-z0-9_.-]{1,128}",raw) is not None,"PE_DLL_NAME")
        return raw.decode("ascii").lower()
    result=[]
    for slot,step,field in ((1,20,12),(13,32,4)):
        va,size=struct.unpack_from("<II",data,dd+slot*8)
        if not va:
            require(size==0,"PE_DIRECTORY");continue
        require(step<=size<=1048576,"PE_DIRECTORY")
        pos=rva(va,size);terminated=False
        for index in range(min(size//step,1024)):
            at=pos+index*step;row=data[at:at+step]
            if not any(row):terminated=True;break
            name=struct.unpack_from("<I",data,at+field)[0]
            if slot==13:
                attrs=struct.unpack_from("<I",data,at)[0]
                require(attrs in (0,1),"PE_DELAY_ATTR")
                if not attrs:name-=imagebase
                require(name>=0,"PE_DELAY_VA")
            result.append({"name":dllname(name),"kind":"delay" if slot==13 else "normal"})
        require(terminated and len(result)<=1024,"PE_IMPORT_LIMIT")
    return result

def process_modules():
    import ctypes,ctypes.wintypes
    k=ctypes.WinDLL("kernel32",use_last_error=True)
    p=ctypes.WinDLL("psapi",use_last_error=True)
    k.GetCurrentProcess.restype=ctypes.c_void_p
    k.GetModuleHandleW.argtypes=[ctypes.c_wchar_p];k.GetModuleHandleW.restype=ctypes.c_void_p
    p.EnumProcessModulesEx.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_uint,ctypes.c_void_p,ctypes.c_uint]
    p.GetModuleFileNameExW.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_wchar_p,ctypes.c_uint]
    process=k.GetCurrentProcess();array=(ctypes.c_void_p*512)();needed=ctypes.c_uint()
    require(p.EnumProcessModulesEx(process,array,ctypes.sizeof(array),ctypes.byref(needed),3),"MODULE_ENUM")
    require(needed.value<=ctypes.sizeof(array),"MODULE_LIMIT")
    def filename(handle):
        buf=ctypes.create_unicode_buffer(32768)
        n=p.GetModuleFileNameExW(process,handle,buf,len(buf))
        require(0<n<len(buf)-1,"MODULE_PATH")
        return buf.value
    rows=[{"handle":int(array[i]),"path":filename(array[i])}
          for i in range(needed.value//ctypes.sizeof(ctypes.c_void_p))]
    def resolve(name):
        handle=k.GetModuleHandleW(name)
        return filename(handle) if handle else None
    # Retain safe DATA from this same enumeration even if original admission fails.
    import hashlib,ntpath
    global LAST_SAFE_PROVIDERS
    def safe_name(raw):
        name=ntpath.basename(raw)
        import re
        return name if re.fullmatch(r"[A-Za-z0-9_.-]{1,128}",name) else "UNKNOWN_BASENAME"
    root=ntpath.normcase(os.path.dirname(sys.executable))
    LAST_SAFE_PROVIDERS=[{"basename":safe_name(r["path"]),
        "basenameSha256":hashlib.sha256(ntpath.basename(r["path"]).encode("utf-8","surrogatepass")).hexdigest(),
        "pathSha256":hashlib.sha256(r["path"].encode("utf-8","surrogatepass")).hexdigest(),
        "rootCategory":("PYTHON_VENDOR" if ntpath.normcase(r["path"]).startswith(root+"\\") else
          "OS_SYSTEM32" if ntpath.normcase(ntpath.dirname(r["path"]))==r"c:\windows\system32" else "OTHER"),
        "trust":"DATA_ONLY_NOT_ADMISSION"} for r in rows]
    return rows,resolve

def os_base_provider(path):
    return path.name.lower() in OS_BASE and str(path.parent).lower()==r"c:\windows\system32"

def inventory(bootstrap,stage,role,plans):
    import pathlib,hashlib,json,stat,time
    soft_stop=time.monotonic()+16
    def within_role():require(time.monotonic()<soft_stop,"ROLE_SOFT_DEADLINE")
    root=pathlib.Path(sys.executable).parent.resolve()
    own={str(pathlib.Path(x).resolve()) for x in bootstrap["sourcePaths"].values()}
    own.add(str(pathlib.Path(bootstrap["qualifierPath"]).resolve()))
    previous={}
    for item in bootstrap.get("verifiedVendorFiles",[]):previous[str(pathlib.Path(item["path"]).resolve())]=item
    for item in bootstrap.get("priorConsumingFiles",[]):previous[str(pathlib.Path(item["path"]).resolve())]=item
    files={};owned=[];modules=[];pe_edges=[];unresolved=[]
    new_bytes=0;cap=67108864-int(bootstrap.get("readBytesAlready",0))
    def bind(path):
        nonlocal new_bytes
        within_role()
        path=pathlib.Path(path).resolve();key=str(path)
        if key in files:return files[key],None
        require(len(files)<256,"CONSUMING_FILE_LIMIT")
        require(key in own or path==pathlib.Path(bootstrap["frozenVerifier"]["path"]).resolve() or
                path.is_relative_to(root),"UNAPPROVED_VENDOR_ORIGIN")
        with stage.input_held_read(path) as (source,identity):
            size=identity["bytes"];require(size<=33554432,"VENDOR_FILE_SIZE")
            old=previous.get(key)
            # Exact current-run stable identity can reuse a role hash. Bootstrap23
            # identities were freshly checked by the source-bound supervisor.
            reusable=(old is not None and old.get("identity")==identity and
                      old.get("bytes")==size and isinstance(old.get("sha256"),str))
            data=None
            if reusable:digest=old["sha256"];method="SAME_WINDOW_IDENTITY_BOUND_REUSE"
            else:
                require(new_bytes+size<=cap,"NEW_HASH_READ_CAP")
                data=source.read(size+1);require(len(data)==size,"VENDOR_SIZE_CHANGED")
                digest=hashlib.sha256(data).hexdigest();new_bytes+=size;method="NEW_HELD_HASH"
                if old is not None:require(digest==old["sha256"],"BOOTSTRAP_OR_ROLE_HASH_DRIFT")
            row={"path":key,"bytes":size,"sha256":digest,"identity":identity,"hashMethod":method}
            if path.suffix.lower() in (".dll",".pyd",".exe"):
                # PE bytes are newly read only when needed; reuse exact current-run
                # parsed edge evidence as well, never a count or an old generic PASS.
                if reusable and isinstance(old.get("peImports"),list):imports=old["peImports"]
                else:
                    if data is None:
                        require(new_bytes+size<=cap,"NEW_PE_READ_CAP")
                        data=source.read(size+1);require(len(data)==size,"VENDOR_PE_SIZE")
                        new_bytes+=size
                    imports=pe_imports(data)
                row["peImports"]=imports;pe_edges.extend({"from":key,**item} for item in imports)
            files[key]=row
            return row,data
    for name,module in sorted(list(sys.modules.items())):
        origin=getattr(module,"__file__",None);spec=getattr(module,"__spec__",None)
        spec_origin=getattr(spec,"origin",None)
        if origin:
            text=str(origin)
            require(".zip\\" not in text.lower() and ".zip/" not in text.lower(),"PYTHON_ZIP_UNBOUND")
            path=pathlib.Path(text)
            require(path.is_file(),"MODULE_ORIGIN_MISSING")
            row,_=bind(path)
            modules.append({"name":name,"kind":"file","path":row["path"],"sha256":row["sha256"]})
        else:
            require(spec_origin in ("built-in","frozen",None) and
                    (spec_origin is not None or name in ("__main__",)),"MODULE_ORIGIN_UNKNOWN")
            modules.append({"name":name,"kind":spec_origin or "owned-main",
                            "tiedTo":["python.exe","python312.dll"]})
        cached=getattr(module,"__cached__",None)
        if cached:
            c=pathlib.Path(cached)
            require(c.is_relative_to(pathlib.Path(sys.pycache_prefix)) and not c.exists(),"CACHE_ORIGIN_UNBOUND")
    bind(sys.executable);bind(root/"python312.dll")
    loaded,resolve=process_modules()
    # Fixed SSH is an OS-base critical tool, not a vendor singlelink file and
    # never launched by qualification. Its PE dependencies remain explicit.
    ssh=pathlib.Path(bootstrap["sshKeygen"]["path"])
    require(str(ssh).lower()==r"c:\windows\system32\openssh\ssh-keygen.exe","SSH_TOOL_PATH")
    ssh_before=ssh.stat()
    require(ssh_before.st_size==861184 and new_bytes+861184<=cap,"SSH_TOOL_BOUND")
    ssh_data=ssh.read_bytes();new_bytes+=len(ssh_data)
    require(hashlib.sha256(ssh_data).hexdigest()==bootstrap["sshKeygen"]["sha256"]==
            "c9dc170cd161db87e75eb6cf282f1325005b9e35628b9a36cb19883a8be1a34f","SSH_TOOL_HASH")
    ssh_after=ssh.stat()
    require((ssh_before.st_dev,ssh_before.st_ino,ssh_before.st_size,ssh_before.st_mtime_ns)==
            (ssh_after.st_dev,ssh_after.st_ino,ssh_after.st_size,ssh_after.st_mtime_ns),"SSH_TOOL_DRIFT")
    ssh_imports=pe_imports(ssh_data)
    pe_edges.extend({"from":str(ssh),**item} for item in ssh_imports)
    # Collect any newly found Python/native providers to a finite fixed point.
    todo=list(loaded);seen=set();os_refs={}
    for turn in range(512):
        if not todo:break
        item=todo.pop(0);path=pathlib.Path(item["path"]).resolve();key=str(path)
        if key in seen:continue
        seen.add(key)
        if path.is_relative_to(root):
            bind(path)
        else:
            name=path.name.lower()
            require(os_base_provider(path),
                    "UNEXPECTED_OS_PROVIDER")
            # OS hardlinks are permitted only in this explicit actual module/build TCB.
            info=path.stat()
            os_refs[key]={"path":key,"name":name,"bytes":info.st_size,"mtimeNs":info.st_mtime_ns,
                          "fileIndex":info.st_ino,"volume":info.st_dev,"links":info.st_nlink,
                          "scope":"EXPLICIT_CURRENT_LOADED_OS_BASE_TCB","hardlinksAllowed":True}
        # Newly bound vendor PE edges resolve using actual current process handles.
        for edge in list(pe_edges):
            within_role()
            marker=(edge["from"],edge["kind"],edge["name"])
            if any(x.get("edge")==list(marker) for x in unresolved):continue
            provider=resolve(edge["name"])
            if provider:
                edge["resolvedPath"]=provider
                if str(pathlib.Path(provider).resolve()) not in seen:todo.append({"path":provider})
            elif "resolvedPath" not in edge:
                unresolved.append({"edge":list(marker),"code":"UNRESOLVED_NORMAL_OR_DELAY_PROVIDER"})
    require(not todo,"PROVIDER_FIXED_POINT_LIMIT")
    require(not unresolved,"PROVIDER_MAPPING_UNRESOLVED")
    return {"consumingFiles":list(files.values()),"modules":modules,"peDependencies":pe_edges,
            "osBaseTCB":list(os_refs.values()),"windowsBuild":list(sys.getwindowsversion()),
            "newlyReadBytes":new_bytes,"unresolved":[],"completeCoverageForDeclaredInputGraph":True,
            "staticImportPlans":plans,"criticalSSH":{"bytes":861184,"sha256":bootstrap["sshKeygen"]["sha256"],"peImports":ssh_imports,"executed":False}}
