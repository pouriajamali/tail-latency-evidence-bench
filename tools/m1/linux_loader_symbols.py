"""Two exact official Ubuntu ELF sections, data only. No install or admission."""
from pathlib import Path
import argparse,hashlib,http.client,json,os,signal,ssl,struct,time,zlib
import support as S
BUILD='0d77dbd4379bf0b5af3e05be7fb6af1e4cea7c96'

def split_debug(body,out):
    S.need(body[:7]==b'\x7fELF\x02\x01\x01' and struct.unpack_from('<H',body,18)[0]==62,'MATCHING_DEBUG_ELF')
    S.need(zlib.crc32(body)==0x7273804a,'PINNED_DEBUGLINK_CRC')
    off=struct.unpack_from('<Q',body,40)[0];size,count=struct.unpack_from('<HH',body,58);S.need(size==64 and 0<count<=8192 and off+64*count<=len(body),'DEBUG_SECTION_BOUND')
    sections=[struct.unpack_from('<IIQQQQIIQQ',body,off+i*64) for i in range(count)]
    def data(s):
        S.need(s[1]!=8 and s[4]+s[5]<=len(body),'DEBUG_SECTION_DATA_BOUND');return body[s[4]:s[4]+s[5]]
    ni=struct.unpack_from('<H',body,62)[0];S.need(ni<count,'DEBUG_NAMES_INDEX');names=data(sections[ni]);found={};bid=[]
    for index,s in enumerate(sections):
        S.need(s[0]<len(names),'DEBUG_SECTION_NAME');end=names.find(b'\0',s[0]);S.need(end>=s[0],'DEBUG_SECTION_NAME');name=names[s[0]:end].decode('ascii')
        if name in ('.symtab','.strtab'):found[name]=(index,s,data(s))
        if s[1]==7:
            raw=data(s);p=0
            while p+12<=len(raw):
                ns,ds,kind=struct.unpack_from('<III',raw,p);p+=12;owner=raw[p:p+ns];p=(p+ns+3)&~3;desc=raw[p:p+ds];p=(p+ds+3)&~3
                if owner.rstrip(b'\0')==b'GNU' and kind==3:bid.append(desc.hex())
    S.need(BUILD in bid and set(found)=={'.symtab','.strtab'},'DEBUG_BUILDID_AND_SYMBOLS')
    S.need(found['.symtab'][1][1]==2 and found['.symtab'][1][6]==found['.strtab'][0] and found['.symtab'][1][9]==24 and found['.strtab'][1][1]==3,'DEBUG_SYMBOL_LINK')
    rows=[]
    for name,(_,_,raw) in found.items():
        S.need(0<len(raw)<=262144,'DEBUG_SELECTED_SECTION_CAP');target=out/('loader'+name)
        with target.open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
        rows.append({'name':target.name,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()})
    return rows

def main():
    p=argparse.ArgumentParser();p.add_argument('--frame',required=True);p.add_argument('--frame-sha',required=True);a=p.parse_args();raw=S.raw(a.frame,32768);S.need(hashlib.sha256(raw).hexdigest()==a.frame_sha,'FRAME_HASH');f=json.loads(raw);out=Path(f['guestOutputPath'])
    result={'schema':'tail11-official-loader-symbol-data/v1','status':'HOLD','admitted':False,'ABIValueAccepted':False,'signatureInvocations':0,'nativeM1Calls':0,'networkCalls':0,'nonce':f['nonce'],'buildID':BUILD,'responses':[]}
    start=time.monotonic();end=min(time.time()+20,f['window']['deadlineUnix']-30)
    try:
        S.need(f['schema']=='tail11-linux-role-frame/v1' and f['mode'] in ('loader-symbols','loader-debug'),'FIXED_SYMBOL_DATA_SCOPE');result['actualKernel']=S.actual_profile({'runNonce':f['nonce']},'linux-x64');full=f['mode']=='loader-debug';cap=1048576 if full else 262144
        for n,h in f['sourceHashes'].items():S.need(S.sha(Path(f['sourceDirectory'])/n)==h,'SOURCE_BINDING')
        signal.signal(signal.SIGALRM,signal.SIG_DFL);signal.setitimer(signal.ITIMER_REAL,max(.001,end-time.time()))
        ctx=ssl.create_default_context();S.need(ctx.check_hostname and ctx.verify_mode==ssl.CERT_REQUIRED,'EXISTING_TLS_VERIFICATION_REQUIRED')
        for index,section in enumerate((None,) if full else ('.symtab','.strtab')):
            path='/buildid/'+BUILD+('/debuginfo' if full else '/section/'+section);url='https://debuginfod.ubuntu.com'+path;started=time.time()
            S.fresh(out/('loader-symbols-request'+str(index)+'.json'),{'url':url,'index':index,'requestAttempts':1,'method':'GET','bodyCap':cap,'requestSeconds':5,'redirectsAllowed':False,'credentials':False,'admitted':False},65536)
            result['networkCalls']+=1;signal.setitimer(signal.ITIMER_REAL,max(.001,min(5,end-time.time())))
            conn=http.client.HTTPSConnection('debuginfod.ubuntu.com',443,timeout=5,context=ctx)
            try:
                conn.request('GET',path,headers={'Accept':'application/octet-stream','Accept-Encoding':'identity','User-Agent':'Tail11-bounded-static-data/1'})
                response=conn.getresponse();headers=response.getheaders();S.need(sum(len(k)+len(v)+4 for k,v in headers)<=32768,'SYMBOL_HEADERS_CAP')
                row={'url':url,'status':response.status,'index':index,'redirected':False,'contentLength':response.getheader('Content-Length'),'contentType':response.getheader('Content-Type')};result['responses'].append(row)
                S.need(response.status==200,'SYMBOL_HTTP_200_REQUIRED');S.need(response.getheader('Content-Encoding','identity').lower()=='identity','SYMBOL_IDENTITY_BYTES')
                length=response.getheader('Content-Length');S.need(length is None or (length.isdecimal() and int(length)<=cap),'SYMBOL_LENGTH_CAP')
                body=response.read(cap+1);S.need(len(body)<=cap and len(body)>0 and (length is None or len(body)==int(length)),'SYMBOL_BODY_CAP_OR_FRAMING')
                name='loader.debug' if full else 'loader'+section
                with (out/name).open('xb') as target:target.write(body);target.flush();os.fsync(target.fileno())
                row.update(name=name,bytes=len(body),sha256=hashlib.sha256(body).hexdigest(),seconds=time.time()-started)
                if full:result.update(selectedSections=split_debug(body,out),debuglinkCRC32='7273804a',retrievalFormat='FULL_ELF_DATA_ONLY')
            finally:conn.close()
            signal.setitimer(signal.ITIMER_REAL,max(.001,end-time.time()))
        S.need(time.time()<end and time.monotonic()-start<=20,'SYMBOL_DATA_ROLE20')
        result.update(status='EXACT_UBUNTU_SYMBOL_SECTIONS_DATA_ONLY',totalBytes=sum(r['bytes'] for r in result['responses']),roleSeconds=time.monotonic()-start,TLSHostnameVerified=True,TLSVerifyMode=int(ctx.verify_mode),sourceHashes=f['sourceHashes'])
    except Exception as e:result.update(code=getattr(e,'code','SYMBOL_DATA_HOLD'),exceptionType=type(e).__name__)
    finally:signal.setitimer(signal.ITIMER_REAL,0)
    S.fresh(out/'loader-symbols.json',result,262144)
    if result['status']!='EXACT_UBUNTU_SYMBOL_SECTIONS_DATA_ONLY':raise SystemExit(1)

if __name__=='__main__':main()
