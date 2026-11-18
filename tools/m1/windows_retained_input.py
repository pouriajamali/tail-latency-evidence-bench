"""Fixed retained/official debug-data reader in the existing Windows Job."""
from pathlib import Path
import argparse,hashlib,http.client,json,os,ssl,threading,time,zlib
import support as S
from linux_loader_symbols import split_debug,BUILD
OLD_NONCE='688b49f3a606dffeaff278d42311086c'
ROOT=Path(r'\\wsl.localhost\Ubuntu-24.04\home\ubuntu')/('tail11-linux-role-'+OLD_NONCE)
URL_PATH='/buildid/'+BUILD+'/debuginfo'

def main():
    p=argparse.ArgumentParser();p.add_argument('--frame',required=True);p.add_argument('--frame-sha',required=True);a=p.parse_args();raw=S.raw(a.frame,32768);S.need(hashlib.sha256(raw).hexdigest()==a.frame_sha,'FRAME_HASH');f=json.loads(raw);out=Path(f['hostOutputWindowsPath'])
    result={'schema':'tail11-windows-retained-symbol-data/v1','status':'HOLD','admitted':False,'ABIValueAccepted':False,'M1NativeCalls':0,'signatureInvocations':0,'networkCalls':0,'nonce':f['nonce'],'retainedGuestNonce':OLD_NONCE,'retainedFiles':[]};phase='INITIAL'
    try:
        S.need(os.name=='nt' and f['mode']=='windows-data' and f['schema']=='tail11-linux-role-frame/v1','FIXED_WINDOWS_DATA_SCOPE')
        S.need(S.sha(f['protocolWindowsPath'])==S.PROTOCOL_SHA,'CANONICAL_PROTOCOL');lease=S.read(f['leaseWindowsPath'],16384)
        S.need(lease['projectId']=='11' and lease['randomToken']==f['nonce'] and lease['ownerPID']==f['ownerPID'] and lease['ownerProcessStartIdentity']==f['ownerBirth'],'CANONICAL_OWNER')
        profile=S.read(f['profilePath'],8192);S.need(profile['childPid']==os.getpid() and profile['nonce']==f['nonce'],'ORIGINAL_CHILD_PROFILE');result['actualKernel']=S.input_kernel(profile)
        for n,h in f['sourceHashes'].items():S.need(S.sha(Path(f['sourceDirectoryWindows'])/n)==h,'SOURCE_BINDING')
        end=min(f['phaseDeadlineUnix'],f['window']['deadlineUnix']-30);S.need(time.time()<end,'DATA_ROLE20')
        S.fresh(out/'windows-data-start.json',{'nonce':f['nonce'],'phaseDeadlineUnix':end,'retainedDirectory':str(ROOT),'firstOperation':'EXACT_RETAINED_FILES_ONLY','networkCalls':0},65536)
        body=None;phase='RETAINED_FIXED_DIRECTORY';unavailable=f.get('retainedUnavailableReceipt')
        if unavailable:
            prior=Path(S.ROOT).parent/'outputs/wave4-m1-record-cap-20261116/windows-retained-debug-frame-binding-fix-20261118';tp=prior/'terminal-retained-and-one-official-debug-data.json'
            S.need(str(tp)==unavailable['path'] and S.sha(tp)==unavailable['sha256']=='57d2ae654b4efc0a69d0b7bcf9283683788dfdffdaf25b0d616b5f7760053b17','EXACT_RETAINED_TIMEOUT_PROOF');v=S.read(tp,8192)
            S.need(v['forced'] is True and v['exitCode']==124 and v['active']==0 and v['originalWait']==258 and not (prior/'windows-public-debug-request.json').exists(),'PRIOR_RETAINED_READ_ONLY_TIMEOUT')
            S.need(S.sha(Path(S.ROOT).parent/'outputs/wave4-m1-record-cap-20261116/WINDOWS-RETAINED-TIMEOUT-SOURCE-20261118.py')==unavailable['oldSourceSHA256'],'FROZEN_RETAINED_STAGE_SOURCE')
            exists=False;result.update(retainedDirectoryObserved=None,retainedReadState='PRIOR_HARD_TIMEOUT_UNKNOWN_NOT_ABSENT',priorPossibleLinuxDebugRequestCount='UNKNOWN_MAX1',retainedReadReplayed=False)
        else:
            exists=ROOT.is_dir();result['retainedDirectoryObserved']=exists
        if exists:
            for name in ('frame.json','loader-symbols-request0.json','loader-symbols.json','loader.debug'):
                path=ROOT/name
                if not path.exists():continue
                cap=1048576 if name=='loader.debug' else 262144
                S.need(path.is_file() and not path.is_symlink(),'RETAINED_REGULAR_FILE');st=path.stat();S.need(st.st_size<=cap,'RETAINED_FILE_CAP')
                with path.open('rb') as source:
                    first=os.fstat(source.fileno());b=source.read(cap+1);after=os.fstat(source.fileno())
                S.need(len(b)<=cap and (first.st_size,first.st_mtime_ns,first.st_ino)==(after.st_size,after.st_mtime_ns,after.st_ino),'RETAINED_FILE_STABLE')
                row={'name':name,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()};result['retainedFiles'].append(row)
                if name=='loader.debug':body=b
                else:
                    value=json.loads(b)
                    if name=='frame.json':S.need(value['nonce']==OLD_NONCE and value['mode']=='loader-debug','EXACT_RETAINED_FRAME')
                    if name=='loader-symbols-request0.json':S.need(value['url']=='https://debuginfod.ubuntu.com'+URL_PATH,'EXACT_RETAINED_REQUEST');result['priorHTTPIntentObserved']=True
                    if name=='loader-symbols.json':result['priorProducerState']={k:value.get(k) for k in ('status','code','networkCalls','responses')}
                S.need(time.time()<end,'DATA_ROLE20')
        result['retainedCompleteBodyObserved']='UNKNOWN_UNAVAILABLE' if unavailable else body is not None
        if body is None:
            phase='ONE_OFFICIAL_DEBUG_GET';S.need(end-time.time()>6,'NO_TIME_FOR_FIVE_SECOND_GET')
            S.fresh(out/'windows-public-debug-request.json',{'url':'https://debuginfod.ubuntu.com'+URL_PATH,'attempts':1,'bodyCap':1048576,'requestSeconds':5,'retainedCompleteBodyObserved':result['retainedCompleteBodyObserved'],'noRedirects':True,'noCredentials':True,'admitted':False},65536)
            result['networkCalls']=1;done=threading.Event()
            def timed_out():
                if not done.is_set():
                    try:S.fresh(out/'windows-network-timeout.json',{'status':'EXACT_FIVE_SECOND_REQUEST_TIMEOUT','networkCalls':1,'admitted':False,'nonce':f['nonce']},65536)
                    finally:os._exit(124)
            timer=threading.Timer(5,timed_out);timer.daemon=True;timer.start();conn=None
            try:
                ctx=ssl.create_default_context();S.need(ctx.check_hostname and ctx.verify_mode==ssl.CERT_REQUIRED,'EXISTING_TLS_VERIFICATION_REQUIRED')
                conn=http.client.HTTPSConnection('debuginfod.ubuntu.com',443,timeout=5,context=ctx);conn.request('GET',URL_PATH,headers={'Accept':'application/octet-stream','Accept-Encoding':'identity','User-Agent':'Tail11-bounded-static-data/1'})
                response=conn.getresponse();length=response.getheader('Content-Length');result['response']={'status':response.status,'contentLength':length,'contentType':response.getheader('Content-Type'),'redirected':False}
                S.need(sum(len(k)+len(v)+4 for k,v in response.getheaders())<=32768,'DEBUG_HEADERS_CAP');S.need(response.status==200,'DEBUG_HTTP_200_REQUIRED');S.need(response.getheader('Content-Encoding','identity').lower()=='identity','DEBUG_IDENTITY_BYTES');S.need(length is None or length.isdecimal() and int(length)<=1048576,'DEBUG_LENGTH_CAP')
                body=response.read(1048577);S.need(0<len(body)<=1048576 and (length is None or len(body)==int(length)),'DEBUG_BODY_CAP_OR_FRAMING');result['TLSHostnameVerified']=True;result['TLSVerifyMode']=int(ctx.verify_mode)
            finally:
                done.set();timer.cancel()
                if conn is not None:conn.close()
        phase='STATIC_DEBUG_VALIDATION';result.update(debugBytes=len(body),debugSHA256=hashlib.sha256(body).hexdigest(),debugCRC32=hex(zlib.crc32(body)))
        result['selectedSections']=split_debug(body,out);S.need(time.time()<end,'DATA_ROLE20')
        result.update(status='EXACT_DEBUG_SYMBOL_DATA_ONLY',buildID=BUILD,debuglinkCRC32='7273804a',sourceHashes=f['sourceHashes'])
    except Exception as e:result.update(code=getattr(e,'code','WINDOWS_RETAINED_DATA_HOLD'),exceptionType=type(e).__name__,errno=getattr(e,'errno',None),phase=phase)
    S.fresh(out/'windows-retained-input.json',result,262144)
    if result['status']!='EXACT_DEBUG_SYMBOL_DATA_ONLY':raise SystemExit(1)

if __name__=='__main__':main()
