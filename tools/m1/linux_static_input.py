"""One exact public loader-data transfer; never target/image admission."""
from pathlib import Path
import argparse,hashlib,json,os,stat,time
import support as S

def main():
    p=argparse.ArgumentParser();p.add_argument('--frame',required=True);p.add_argument('--frame-sha',required=True);a=p.parse_args()
    raw=S.raw(a.frame,32768);S.need(hashlib.sha256(raw).hexdigest()==a.frame_sha,'FRAME_HASH');f=json.loads(raw);out=Path(f['guestOutputPath'])
    result={'schema':'tail11-exact-loader-data/v1','status':'HOLD','admitted':False,'nativeM1Calls':0,'signatureInvocations':0,'networkCalls':0,'nonce':f['nonce']}
    try:
        S.need(f['schema']=='tail11-linux-role-frame/v1' and f['mode']=='loader-static','FIXED_DATA_SCOPE');result['actualKernel']=S.actual_profile({'runNonce':f['nonce']},'linux-x64');end=min(time.time()+20,f['window']['deadlineUnix']-30)
        for name,h in f['sourceHashes'].items():S.need(S.sha(Path(f['sourceDirectory'])/name)==h,'SOURCE_BINDING')
        path=Path('/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2');S.need(path.resolve()==path,'EXACT_CANONICAL_LOADER_DATA')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        with os.fdopen(fd,'rb') as source:
            st=os.fstat(source.fileno());S.need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and not st.st_mode&0o022 and st.st_size==236616,'EXACT_LOADER_DATA_IDENTITY')
            body=source.read(262145);S.need(len(body)==236616 and hashlib.sha256(body).hexdigest()=='c20a2dc8917c755f02b94049356320fe1f62ac7d9f8994731f807d9df39302da','EXACT_LOADER_DATA_HASH')
            after=os.fstat(source.fileno());S.need((st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),'HELD_LOADER_DATA_STABILITY')
        with (out/'loader.elf').open('xb') as target:target.write(body);target.flush();os.fsync(target.fileno())
        S.need(time.time()<end,'DATA_ROLE20');result.update(status='EXACT_LOADER_DATA_ONLY',path=str(path),bytes=len(body),sha256=hashlib.sha256(body).hexdigest(),uid=st.st_uid,mode=stat.S_IMODE(st.st_mode),sourceHashes=f['sourceHashes'])
    except Exception as e:result.update(code=getattr(e,'code','LOADER_DATA_HOLD'),exceptionType=type(e).__name__)
    S.fresh(out/'loader-static.json',result,262144)
    if result['status']!='EXACT_LOADER_DATA_ONLY':raise SystemExit(1)

if __name__=='__main__':main()
