"""Project11 inert proposed fixed-input staging; no generic URLs/commands."""

import hashlib

import json

import os

from pathlib import Path, PurePosixPath

import shutil

import stat

import tarfile

import time

import urllib.request

from urllib.parse import urlsplit

import zipfile

CAP = 75 * 1024 * 1024

INFLATED = 384 * 1024 * 1024

PREFIX = "https://github.com/pouriajamali/tail-latency-evidence-bench/releases/download/v0.1.0-preview.1/"

KEY = "SHA256:AgU5bZlJSjUu0KsWMmVEEr+BfXpcMVNroTA33bHcQdU"

ASSETS = [
 ("SHA256SUMS.txt",373,"7ed7c353458a935439066a6a1d205520e5610458ec346dd8dbbf5c8882d28709"),
 ("SHA256SUMS.txt.sig",294,"bf4ff680a2c4816b08044c47bb05882f6268576dea30bc1a14e275cfab66e840"),
 ("SIGNING-PUBLIC-KEY.pub",113,"cc7038b2d98f856af97b58eb06619ff441fbe9b178da5396f61d1ccdf7a65e7c"),
 ("tail-latency-evidence-bench-v0.1.0-preview.1-win-x64.zip",35871273,"e5374e478cd5416707ba3dc009e9aa20cb4fdc912adba0d9c8f8ae944d2b9958"),
 ("tail-latency-evidence-bench-v0.1.0-preview.1-linux-x64.tar.gz",35409385,"352604eb282c253495251f5731518184171ab08b485b084fb95baf9ece16ebba")]

RUNTIME = "6158f7f8a9a8e4fd7c12ed575f427d7117b89801"

def need(ok, why):
    if not ok: raise ValueError(why)

def sha(p):
    h = hashlib.sha256()
    with Path(p).open("rb") as s:
        for block in iter(lambda:s.read(1048576), b""): h.update(block)
    return h.hexdigest()

def fresh(p, value):
    p = Path(p); p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("x",encoding="utf-8",newline="\n") as s:
        json.dump(value,s,indent=2);s.write("\n")

def clock(deadline):
    need(time.time() < deadline, "common300s deadline; no extension")

API_PREFIX = "https://api.github.com/repos/pouriajamali/tail-latency-evidence-bench/releases/assets/"

API_ASSETS = {
 ASSETS[3][0]: (728783293,ASSETS[3][1],ASSETS[3][2]),
 ASSETS[4][0]: (728783300,ASSETS[4][1],ASSETS[4][2])}

STORAGE_HOSTS = {"release-assets.githubusercontent.com","objects.githubusercontent.com",
                 "github-releases.githubusercontent.com"}

class RouteError(ValueError):
    def __init__(self, code, phase, asset=None, **safe):
        self.record={"schema":"tail11-fixed-api-cause/v1","code":code,"phase":phase,
                     "assetId":asset,**safe}
        # Never include request/response bodies, credential output,headers or signed URLs.
        super().__init__(json.dumps(self.record,sort_keys=True))

def api_clock(deadline, phase, asset=None, received=0, started=None):
    now=time.time()
    if now >= deadline:
        detail={"bytesReceived":received}
        if started is not None:
            detail["elapsedMs"]=int(max(0,min(300000,(now-started)*1000)))
        raise RouteError("TRANSPORT_DEADLINE" if phase=="body" else "DEADLINE_EXCEEDED",
                         phase,asset,**detail)

FRAME_FUNCTIONS={
 "tail11.fetch_extract":frozenset({"clock","api_clock","api_stage_failure",
  "redirect_request","http_error_302","public_opener","receive_binary",
  "_acquire_public_api","acquire"}),
 "urllib.request":frozenset({"open","_open","_call_chain","error","http_error_302",
  "redirect_request","do_request_","do_open","https_open"}),
 "urllib.parse":frozenset({"urlsplit","urlparse","urljoin","port","_checknetloc",
  "_check_bracketed_netloc","_check_bracketed_host"}),
 "http.client":frozenset({"__init__","connect","request","_send_request","putrequest",
  "_encode_request","_validate_method","_validate_path","putheader","endheaders",
  "_send_output","send","getresponse","begin","read","readinto","_read_chunked",
  "_safe_read","_get_hostport"}),
 "ssl":frozenset({"wrap_socket","_create","do_handshake","read","recv","recv_into"}),
 "socket":frozenset({"create_connection","readinto","__init__"})}

def api_frames(error):
    # Only traceback code identity; no source lines, locals, args or exception text.
    modules={"tail11.fetch_extract":__file__,"urllib.request":urllib.request.__file__,
             "urllib.parse":urllib.parse.__file__,
             "http.client":urllib.request.http.client.__file__,
             "ssl":urllib.request.ssl.__file__,"socket":urllib.request.socket.__file__}
    allowed={str(Path(path).resolve()):name for name,path in modules.items()}
    rows=[]
    tb=error.__traceback__
    while tb is not None:
        code=tb.tb_frame.f_code
        module=allowed.get(str(Path(code.co_filename).resolve()))
        if module in FRAME_FUNCTIONS and code.co_name in FRAME_FUNCTIONS[module]:
            rows.append({"module":module,"function":code.co_name,"line":tb.tb_lineno})
        tb=tb.tb_next
    return rows[-6:]

def bounded_frames(value):
    if type(value) is not list:return []
    result=[]
    for row in value[:6]:
        if type(row) is not dict:continue
        module=row.get("module");name=row.get("function");line=row.get("line")
        if (type(module) is str and module in FRAME_FUNCTIONS and type(name) is str and
            name in FRAME_FUNCTIONS[module] and type(line) is int and 1<=line<=100000):
            result.append({"module":module,"function":name,"line":line})
    return result

def api_stage_failure(error, phase, asset):
    codes={"request_open":"REQUEST_OPEN_EXCEPTION","part_open":"PART_OPEN_EXCEPTION",
           "receive":"RECEIVE_BOUNDARY_EXCEPTION","body_read":"BODY_READ_EXCEPTION",
           "body_write":"BODY_WRITE_EXCEPTION"}
    status=getattr(error,"code",None)
    return RouteError(codes[phase],phase,asset,causeType=type(error).__name__,
                      httpStatus=status if type(status) is int and 100<=status<=599 else None,frames=api_frames(error))

class Redirects(urllib.request.HTTPRedirectHandler):
    def __init__(self): self.chain=[]
    def http_error_302(self,req,fp,code,msg,headers):
        try:return super().http_error_302(req,fp,code,msg,headers)
        except RouteError:raise
        except ValueError:
            raise RouteError("REDIRECT_RESPONSE_VALUE_ERROR_UNCLASSIFIED","redirect") from None
    http_error_301=http_error_303=http_error_307=http_error_308=http_error_302
    def redirect_request(self,req,fp,code,msg,headers,url):
        try:p=urlsplit(url)
        except ValueError:
            raise RouteError("REDIRECT_TARGET_PARSE_VALUE_ERROR","redirect") from None
        try:port=p.port
        except ValueError:
            raise RouteError("REDIRECT_PORT_VALUE_ERROR","redirect") from None
        allowed=(p.scheme=="https" and p.username is None and p.password is None and
                 port in (None,443) and
                 (p.hostname in STORAGE_HOSTS or url in
                  {API_PREFIX+str(x[0]) for x in API_ASSETS.values()}))
        if not allowed or len(self.chain)>=5:
            raise RouteError("REDIRECT_POLICY","redirect")
        self.chain.append(p.hostname)
        redirected=super().redirect_request(req,fp,code,msg,headers,url)
        if redirected is None: raise RouteError("REDIRECT_REFUSED","redirect")
        # Strip on EVERY redirect, including redirects back to api.github.com.
        for forbidden in ("Authorization","Proxy-Authorization"):
            redirected.remove_header(forbidden)
            redirected.unredirected_hdrs.pop(forbidden,None)
        for mapping in (redirected.headers,redirected.unredirected_hdrs):
            for key in list(mapping):
                if key.lower() in ("authorization","proxy-authorization"): del mapping[key]
        no_auth_headers(redirected)
        return redirected

def no_auth_headers(request):
    for mapping in (request.headers,request.unredirected_hdrs):
        if any(key.lower() in ("authorization","proxy-authorization") for key in mapping):
            raise RouteError("AUTH_HEADER_FORBIDDEN","request")

def public_opener(policy):
    # Explicit director: no ambient ProxyHandler, auth/password/cookie handlers or netrc.
    director=urllib.request.OpenerDirector()
    for handler in (urllib.request.HTTPSHandler(),urllib.request.HTTPDefaultErrorHandler(),
                    policy,urllib.request.HTTPErrorProcessor()):
        director.add_handler(handler)
    return director

def receive_binary(response,stream,expected_size,expected_sha,deadline,asset_id,budget,started=None):
    if response.status!=200:raise RouteError("HTTP_STATUS","GET",asset_id,httpStatus=response.status)
    content_type=response.headers.get("Content-Type","").split(";",1)[0].lower().strip()
    if content_type=="application/json" or content_type.endswith("+json"):
        raise RouteError("JSON_NOT_ARCHIVE","body",asset_id)
    declared=response.headers.get("Content-Length")
    if declared is not None:
        if not isinstance(declared,str) or not 1<=len(declared)<=20 or any(c not in "0123456789" for c in declared):
            raise RouteError("CONTENT_LENGTH_INVALID_DECIMAL","response_headers",asset_id)
        if int(declared)!=expected_size:
            raise RouteError("DECLARED_SIZE","body",asset_id)
    total=0;digest=hashlib.sha256()
    while True:
        api_clock(deadline,"body",asset_id,total,started)
        try:chunk=response.read(min(65536,expected_size-total+1))
        except RouteError:raise
        except Exception as error:
            raise api_stage_failure(error,"body_read",asset_id) from None
        if not chunk:break
        total+=len(chunk);budget[0]+=len(chunk)
        if total>expected_size or budget[0]>CAP:
            raise RouteError("BODY_BYTE_CAP","body",asset_id,bytesReceived=total)
        try:stream.write(chunk)
        except RouteError:raise
        except Exception as error:
            raise api_stage_failure(error,"body_write",asset_id) from None
        digest.update(chunk)
    if total!=expected_size:raise RouteError("SHORT_BODY","body",asset_id,bytesReceived=total)
    if digest.hexdigest()!=expected_sha:raise RouteError("BODY_SHA256","body",asset_id,bytesReceived=total)
    return total

def _acquire_public_api(bindings,inputs,evidence,deadline,route,rid):
    """ONE fixed API GET per archive; retained small files ONLY, no archive cache scan."""
    need(rid in ("win-x64","linux-x64"),"fixed RID")
    need(route["mode"]=="PUBLIC_API_NO_AUTH","fixed public no-auth route")
    need(sha(route["authorityBinding"]["path"])==route["authorityBinding"]["sha256"],"public route authority binding")
    need(bindings["releaseId"]==439576568 and bindings["tag"]=="v0.1.0-preview.1","fixed release")
    expected={n:(size,h) for n,size,h in ASSETS}
    declared=bindings["archives"]+bindings["smallAssets"]
    need(len(declared)==5 and {x["name"]:(x["bytes"],x["sha256"]) for x in declared}==expected,
         "fixed input set differs")
    need(bindings["fingerprint"]==KEY,"known key")
    for item in bindings["archives"]:
        asset_id,size,digest=API_ASSETS[item["name"]]
        need(item["assetId"]==asset_id and item["url"]==API_PREFIX+str(asset_id),
             "fixed API asset binding")
    raw=inputs/"raw";raw.mkdir(parents=True,exist_ok=False)
    budget=[0]
    try:
        # These three retained source paths are exact bindings, never searched/refetched.
        need(set(route["retainedSmallAssets"])=={x[0] for x in ASSETS[:3]},"retained small set")
        for name,size,digest in ASSETS[:3]:
            api_clock(deadline,"guard")
            source=Path(route["retainedSmallAssets"][name])
            need(source.is_file() and not source.is_symlink() and
                 source.stat().st_size==size and sha(source)==digest,"retained small identity")
            with source.open("rb") as s,(raw/name).open("xb") as d:
                shutil.copyfileobj(s,d,4096)
        for name,(asset_id,size,digest) in API_ASSETS.items():
            if name!=ASSETS[3 if rid=="win-x64" else 4][0]:continue
            api_clock(deadline,"request_open",asset_id)
            fresh(evidence/("api-attempt-"+str(asset_id)+".json"),
                  {"assetId":asset_id,"url":API_PREFIX+str(asset_id),"attempts":1})
            redirects=Redirects()
            opener=public_opener(redirects)
            request=urllib.request.Request(API_PREFIX+str(asset_id),headers={
                "User-Agent":"tail11-fixed-api-lab","Accept":"application/octet-stream",
                "X-GitHub-Api-Version":"2022-11-28"})
            no_auth_headers(request)
            started=time.time()
            stop=min(deadline,started+45)
            part=raw/(name+".api.part")
            stage="request_open"
            try:
                api_clock(stop,stage,asset_id)
                with opener.open(request,timeout=max(.001,min(15,stop-time.time()))) as response:
                    stage="part_open"
                    with part.open("xb") as stream:
                        stage="receive"
                        receive_binary(response,stream,size,digest,stop,asset_id,budget,started)
            except RouteError:raise
            except Exception as error:
                raise api_stage_failure(error,stage,asset_id) from None
            target=raw/name;part.rename(target)
            fresh(evidence/("api-acquired-"+str(asset_id)+".json"),
                  {"assetId":asset_id,"bytes":size,"sha256":digest,
                   "redirectHosts":redirects.chain,"authorizationForwardedToStorage":False})
        return raw
    except Exception as error:
        safe=safe_api_failure(error).record

        try:fresh(evidence/"fixed-api-acquisition-cause.json",safe)
        except FileExistsError:pass
        if isinstance(error,RouteError):raise
        raise RouteError("FIXED_API_GUARD_EXCEPTION","guard",causeType=type(error).__name__) from None

SAFE_API_CODES=frozenset({
 "REDIRECT_TARGET_PARSE_VALUE_ERROR","REDIRECT_PORT_VALUE_ERROR",
 "REDIRECT_RESPONSE_VALUE_ERROR_UNCLASSIFIED","REDIRECT_POLICY","REDIRECT_REFUSED",
 "AUTH_HEADER_FORBIDDEN","HTTP_STATUS","JSON_NOT_ARCHIVE","DECLARED_SIZE",
 "CONTENT_LENGTH_INVALID_DECIMAL","BODY_BYTE_CAP","SHORT_BODY","BODY_SHA256",
 "TRANSPORT_DEADLINE","DEADLINE_EXCEEDED","REQUEST_OPEN_EXCEPTION","PART_OPEN_EXCEPTION",
 "RECEIVE_BOUNDARY_EXCEPTION","BODY_READ_EXCEPTION","BODY_WRITE_EXCEPTION",
 "FIXED_API_GUARD_EXCEPTION","FIXED_API_BOUNDARY_EXCEPTION"})

SAFE_API_PHASES=frozenset({"redirect","request","GET","body","guard","acquisition",
 "request_open","part_open","receive","response_headers","body_read","body_write"})

SAFE_API_TYPES=frozenset({"ValueError","TypeError","OSError","FileNotFoundError",
 "FileExistsError","PermissionError","TimeoutError","ConnectionError","URLError",
 "HTTPError","SSLError","SSLCertVerificationError","IncompleteRead","RemoteDisconnected",
 "RouteError","OverflowError","UnicodeError","UnicodeEncodeError","UnicodeDecodeError",
 "AttributeError","KeyError","RuntimeError"})

def safe_api_failure(error):
    """Only fixed enums and bounded scalars cross this boundary; never exception text."""
    raw=getattr(error,"record",{}) if isinstance(error,RouteError) else {}
    if type(raw) is not dict:raw={}
    status=raw.get("httpStatus")
    if type(status) is not int or not 100<=status<=599:status=None
    code=raw.get("code")
    if type(code) is not str or code not in SAFE_API_CODES:code="FIXED_API_BOUNDARY_EXCEPTION"
    phase=raw.get("phase")
    if type(phase) is not str or phase not in SAFE_API_PHASES:phase="acquisition"
    kind=raw.get("causeType",type(error).__name__)
    if type(kind) is not str or kind not in SAFE_API_TYPES:kind="OTHER_EXCEPTION"
    asset=raw.get("assetId")
    if type(asset) is not int or asset not in (728783293,728783300):asset=None
    result=RouteError(code,phase,asset,causeType=kind,httpStatus=status)
    count=raw.get("bytesReceived")
    if type(count) is int and 0<=count<=CAP+65536:result.record["bytesReceived"]=count
    elapsed=raw.get("elapsedMs")
    if type(elapsed) is int and 0<=elapsed<=300000:result.record["elapsedMs"]=elapsed
    result.record["frames"]=bounded_frames(raw.get("frames",api_frames(error)))
    return result

def acquire(bindings,inputs,evidence,deadline,route,rid):
    try:
        return _acquire_public_api(bindings,inputs,evidence,deadline,route,rid)
    except Exception as error:
        safe=safe_api_failure(error)
        try:fresh(evidence/"fixed-api-acquisition-cause.json",safe.record)
        except Exception:pass
        raise safe from None

def safe_name(value, names):
    need(type(value) is str and value and "\\" not in value and ":" not in value and
         not value.startswith("/") and "\x00" not in value,"unsafe archive path")
    value=value.rstrip("/")
    parts=value.split("/")
    need(all(p not in ("",".","..") and not p.endswith((" ",".")) for p in parts),"path normalization")
    # Prevent Windows device-name ambiguity, even when extracting on Linux.
    reserved={"CON","PRN","AUX","NUL"}|{"COM"+str(n) for n in range(1,10)}|{"LPT"+str(n) for n in range(1,10)}
    need(all(p.split(".")[0].upper() not in reserved for p in parts),"device path")
    normalized=PurePosixPath(value).as_posix()
    need(normalized.casefold() not in names,"duplicate/case-colliding archive member")
    names.add(normalized.casefold())
    return normalized

def extract(rid, raw, inputs, evidence, signature_receipt, deadline):
    index=3 if rid=="win-x64" else 4
    name,size,hashvalue=ASSETS[index]
    archive=raw/name
    need(archive.stat().st_size==size and sha(archive)==hashvalue,"archive changed before extract")
    # Signature receipt must be the immutable hash-bound actual receipt admitted by the parent.
    sig=json.loads(Path(signature_receipt).read_text())
    need(sig["status"]=="PINNED_SIGNATURE_AND_PRESENT_ARCHIVES_VERIFIED" and
         sig["fingerprint"]==KEY and name in sig["archives"],"unsigned extraction denied")
    target=inputs/"extracted"/rid
    target.mkdir(parents=True,exist_ok=False)
    stop=min(deadline,time.time()+60)
    names=set();members=[];archive_entries=[];inflated=0;entries=0
    def emit(member_name,is_dir,member_size,mode,open_stream):
        nonlocal inflated,entries
        clock(stop);entries+=1
        need(entries<=1024 and member_size>=0,"member entry cap")
        relative=safe_name(member_name,names)
        dest=target/relative
        archive_entries.append({"path":relative,"type":"directory" if is_dir else "file","bytes":member_size})
        need(target.resolve() in dest.resolve().parents,"outside extraction root")
        if is_dir:
            dest.mkdir(parents=True,exist_ok=True);return
        need(len(members)<512 and inflated+member_size<=INFLATED,"inflated/member cap")
        inflated+=member_size;dest.parent.mkdir(parents=True,exist_ok=True)
        h=hashlib.sha256();total=0
        with open_stream() as source,dest.open("xb") as output:
            while True:
                clock(stop)
                block=source.read(min(65536,member_size-total+1))
                if not block: break
                total+=len(block);need(total<=member_size,"inflated size exceeds member declaration")
                output.write(block);h.update(block)
        need(total==member_size,"short member")
        if os.name!="nt": os.chmod(dest,0o755 if mode&0o111 else 0o644)
        members.append({"relativePath":relative,"bytes":total,"sha256":h.hexdigest()})
    if rid=="win-x64":
        with zipfile.ZipFile(archive) as z:
            need(len(z.infolist())<=1024,"ZIP entry cap")
            for item in z.infolist():
                mode=(item.external_attr>>16)&0xffff
                need(not stat.S_ISLNK(mode) and stat.S_IFMT(mode) in (0,stat.S_IFREG,stat.S_IFDIR),
                     "ZIP link/special member")
                need(not item.flag_bits&1,"encrypted archive")
                emit(item.filename,item.is_dir(),item.file_size,mode,lambda item=item:z.open(item))
    else:
        with tarfile.open(archive,"r|gz") as tar:
            for item in tar:
                need(item.isdir() or item.isfile(),"TAR link/special member")
                emit(item.name,item.isdir(),item.size,item.mode,lambda item=item:tar.extractfile(item))
    filename="tail-evidence.exe" if rid=="win-x64" else "tail-evidence"
    cli=[target/x["relativePath"] for x in members if PurePosixPath(x["relativePath"]).name==filename]
    need(len(cli)==1,"exactly one native CLI")
    inventory=inputs/"verification"/(rid+".members.json")
    fresh(inventory,sorted(members,key=lambda x:x["relativePath"]))
    entries_path=inputs/"verification"/(rid+".archive-entries.json")
    fresh(entries_path,archive_entries)
    receipt=inputs/"verification"/(rid+".json")
    fresh(receipt,{"status":"PASS_ARCHIVE_KEY_MANIFEST","rid":rid,"archiveSha256":hashvalue,
                  "trustedFingerprint":KEY,"safeArchiveMembers":True,"runtimeCommit":RUNTIME,
                  "memberInventorySha256":sha(inventory),"signatureReceiptSha256":sha(signature_receipt),
                  "inflatedBytes":inflated,"memberCount":len(members),
                  "fullArchiveEntriesSha256":sha(entries_path),"entryCount":entries})
    return {"archiveSha256":hashvalue,"packageRoot":str(target),"cliPath":str(cli[0]),
            "cliSha256":sha(cli[0]),"verificationReceipt":{"path":str(receipt),"sha256":sha(receipt)},
            "memberInventory":{"path":str(inventory),"sha256":sha(inventory)}}

import contextlib

import ctypes

import ctypes.wintypes

import http.client

import socket

import ssl

import threading

import urllib.parse

INPUT_CODES=frozenset({
 "INPUT_GUARD","INPUT_CLOCK","TRANSPORT_DEADLINE","INPUT_HEADER","INPUT_STATUS",
 "INPUT_RANGE","INPUT_ENCODING","INPUT_LENGTH","INPUT_BODY_SHORT","INPUT_BODY_LONG",
 "INPUT_SHA","INPUT_PREFIX","INPUT_FILE","INPUT_BUDGET","INPUT_REDIRECT",
 "INPUT_TRANSPORT","INPUT_TOOL","INPUT_SIGNATURE","INPUT_SEAL","INPUT_INTERNAL"})

INPUT_PHASES=frozenset({"admission","windows","linux","redirect","headers","body",
 "prefix","signature","seal","terminal"})

INPUT_TYPES=frozenset({"ValueError","OSError","PermissionError","TimeoutError",
 "HTTPException","SSLError","ConnectionError","InputFailure","RuntimeError",
 "FileExistsError","FileNotFoundError","IncompleteRead","RemoteDisconnected"})

FRAME_FUNCTIONS["tail11.fetch_extract"] |= frozenset({
 "input_require","input_failure","input_headers","input_url","unique_header",
 "input_response_headers","input_receive","input_held_read","_file_identity",
 "input_prefix_copy","input_windows","input_seal","check","remaining","timeout","get","__init__","charge"})

FRAME_FUNCTIONS["tail11.aggregate_worker"]=frozenset({
 "input_admit","input_kernel","input_tools","input_verify","run_input_only"})

def input_frames(error):
    modules={str(Path(__file__).resolve()):"tail11.fetch_extract",
             str(Path(__file__).with_name("aggregate_worker.py").resolve()):"tail11.aggregate_worker",
             str(Path(http.client.__file__).resolve()):"http.client",
             str(Path(ssl.__file__).resolve()):"ssl",
             str(Path(socket.__file__).resolve()):"socket",
             str(Path(urllib.parse.__file__).resolve()):"urllib.parse"}
    rows=[];tb=error.__traceback__
    while tb is not None:
        code=tb.tb_frame.f_code;module=modules.get(str(Path(code.co_filename).resolve()))
        if module in FRAME_FUNCTIONS and code.co_name in FRAME_FUNCTIONS[module]:
            rows.append({"module":module,"function":code.co_name,"line":tb.tb_lineno})
        tb=tb.tb_next
    return rows[-6:]

class InputFailure(ValueError):
    def __init__(self,code,phase="admission",**data):
        self.code=code if code in INPUT_CODES else "INPUT_INTERNAL"
        self.phase=phase if phase in INPUT_PHASES else "admission"
        self.data=data
        super().__init__(self.code)

def input_require(ok,code="INPUT_GUARD",phase="admission"):
    if not ok:raise InputFailure(code,phase)

def input_failure(error):
    code=error.code if isinstance(error,InputFailure) else "INPUT_INTERNAL"
    phase=error.phase if isinstance(error,InputFailure) else "admission"
    raw=error.data if isinstance(error,InputFailure) else {}
    result={"schema":"tail11-input-only-failure/v1","status":"HOLD_NO_RETRY",
            "code":code if code in INPUT_CODES else "INPUT_INTERNAL",
            "phase":phase if phase in INPUT_PHASES else "admission",
            "causeType":type(error).__name__ if type(error).__name__ in INPUT_TYPES else "OTHER_EXCEPTION"}
    for key,limit in (("bytesReceived",CAP+65536),("elapsedMs",300000),("httpStatus",599)):
        value=raw.get(key)
        if type(value) is int and 0<=value<=limit:result[key]=value
    # Reuse the previous allowlist of code identities, never serialize exception text.
    frames=input_frames(error)
    result["frames"]=bounded_frames(frames)
    return result

class _INPUT_FILE_INFO(ctypes.Structure):
    _fields_=[("attrs",ctypes.wintypes.DWORD),("created",ctypes.wintypes.FILETIME),
      ("accessed",ctypes.wintypes.FILETIME),("written",ctypes.wintypes.FILETIME),
      ("volume",ctypes.wintypes.DWORD),("sizeHigh",ctypes.wintypes.DWORD),
      ("sizeLow",ctypes.wintypes.DWORD),("links",ctypes.wintypes.DWORD),
      ("indexHigh",ctypes.wintypes.DWORD),("indexLow",ctypes.wintypes.DWORD)]

def _file_identity(kernel,handle):
    info=_INPUT_FILE_INFO()
    input_require(bool(kernel.GetFileInformationByHandle(handle,ctypes.byref(info))),"INPUT_FILE","prefix")
    input_require(not info.attrs & (0x10|0x400) and info.links==1,"INPUT_FILE","prefix")
    return {"volume":info.volume,"fileIndex":(info.indexHigh<<32)|info.indexLow,
            "bytes":(info.sizeHigh<<32)|info.sizeLow,
            "created":(info.created.dwHighDateTime<<32)|info.created.dwLowDateTime,
            "written":(info.written.dwHighDateTime<<32)|info.written.dwLowDateTime}

@contextlib.contextmanager
def input_held_read(path):
    import msvcrt
    input_require(os.name=="nt","INPUT_FILE","prefix")
    kernel=ctypes.WinDLL("kernel32",use_last_error=True)
    kernel.CreateFileW.argtypes=[ctypes.wintypes.LPCWSTR,ctypes.wintypes.DWORD,
      ctypes.wintypes.DWORD,ctypes.c_void_p,ctypes.wintypes.DWORD,
      ctypes.wintypes.DWORD,ctypes.wintypes.HANDLE]
    kernel.CreateFileW.restype=ctypes.wintypes.HANDLE
    kernel.GetFileInformationByHandle.argtypes=[ctypes.wintypes.HANDLE,ctypes.POINTER(_INPUT_FILE_INFO)]
    kernel.CloseHandle.argtypes=[ctypes.wintypes.HANDLE]
    handle=kernel.CreateFileW(str(path),0x80000000,1,None,3,0x00200000,None)
    input_require(handle not in (None,ctypes.c_void_p(-1).value),"INPUT_FILE","prefix")
    stream=None
    try:
        first=_file_identity(kernel,handle)
        fd=msvcrt.open_osfhandle(handle,os.O_RDONLY|os.O_BINARY)
        stream=os.fdopen(fd,"rb");handle=None
        yield stream,first
        actual=_file_identity(kernel,msvcrt.get_osfhandle(stream.fileno()))
        input_require(actual==first,"INPUT_FILE","prefix")
    finally:
        if stream is not None:stream.close()
        elif handle is not None:kernel.CloseHandle(handle)
