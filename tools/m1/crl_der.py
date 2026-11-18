"""Exact bounded structural functions reused from producer04; not crypto authority. Source SHA256 e882af75dc56a5a0f9eb9b4101f2ccaf88141fa3ced9037ea0fd7b1eb357ed74"""
import hashlib,datetime,re
class Hold(RuntimeError):pass

def need(v,code):
 if not v:raise Hold(code)

def sha(b):return hashlib.sha256(b).hexdigest()

def tlv(data,pos=0,stop=None):
 stop=len(data) if stop is None else stop;begin=pos;need(pos+2<=stop,'DER_FRAME');tag=data[pos];pos+=1;need(tag&31!=31,'DER_HIGH_TAG');first=data[pos];pos+=1
 if first&128:
  n=first&127;need(1<=n<=4 and pos+n<=stop and data[pos]!=0,'DER_LENGTH');size=int.from_bytes(data[pos:pos+n],'big');pos+=n;need(size>=128,'DER_NONMINIMAL')
 else:size=first
 end=pos+size;need(end<=stop,'DER_FRAME');return (tag,begin,pos,end)

def children(data,node):
 need(node[0]&32,'DER_CONSTRUCTED');out=[];p=node[2]
 while p<node[3]:
  need(len(out)<20000,'DER_CHILD_BOUND');n=tlv(data,p,node[3]);out.append(n);p=n[3]
 need(p==node[3],'DER_FRAME');return out

def raw(data,n):return data[n[1]:n[3]]

def value(data,n):return data[n[2]:n[3]]

def oid(data,n):
 need(n[0]==6,'DER_OID');out=[];v=0
 for c in value(data,n):
  v=(v<<7)|(c&127);need(v<2**63,'DER_OID')
  if not c&128:out.append(v);v=0
 need(out and not value(data,n)[-1]&128,'DER_OID');x=out.pop(0);head=[0,x] if x<40 else [1,x-40] if x<80 else [2,x-80];return '.'.join(map(str,head+out))

def der_time(data,n):
 b=value(data,n);need(n[0] in (23,24),'DER_TIME');fmt='%y%m%d%H%M%SZ' if n[0]==23 else '%Y%m%d%H%M%SZ'
 need(re.fullmatch(rb'[0-9]{12}Z' if n[0]==23 else rb'[0-9]{14}Z',b) is not None,'DER_TIME')
 try:return int(datetime.datetime.strptime(b.decode(),fmt).replace(tzinfo=datetime.timezone.utc).timestamp())
 except ValueError:raise Hold('DER_TIME') from None

def extensions(data,node,critical=None):
 out={}
 for e in children(data,node):
  f=children(data,e);need(len(f) in (2,3) and f[-1][0]==4,'DER_EXTENSION');o=oid(data,f[0]);need(o not in out,'DER_EXTENSION_DUPLICATE');out[o]=value(data,f[-1])
  if len(f)==3:
   need(f[1][0]==1 and value(data,f[1])==b'\xff','DER_EXTENSION_CRITICAL_BOOLEAN')
   if critical is not None:critical.add(o)
 return out

def name_parts(data,node):
 labels={'2.5.4.6':'C','2.5.4.8':'ST','2.5.4.7':'L','2.5.4.10':'O','2.5.4.11':'OU','2.5.4.3':'CN','1.2.840.113549.1.9.1':'emailAddress'};items=[]
 for rdn in children(data,node):
  vals=children(data,rdn);need(len(vals)==1,'DN_MULTIVALUED_UNSUPPORTED');f=children(data,vals[0]);need(len(f)==2 and f[1][0] in (12,19,22),'DN_ENCODING');key=oid(data,f[0]);need(key in labels,'DN_ATTRIBUTE_UNSUPPORTED')
  try:text=value(data,f[1]).decode('ascii')
  except UnicodeError:raise Hold('DN_ENCODING') from None
  need(text and text==text.strip() and all(32<=ord(c)<127 for c in text),'DN_ESCAPING_UNSUPPORTED');items.append((labels[key],text))
 return items

def scope_fullnames(data,node):
 # RFC5280 6.3.3(b)(2): support only direct, all-reason fullName URI scope.
 # Any extra IDP flag/reasons/indirect form remains unsupported, not ignored.
 fields=children(data,node);need(len(fields)==1 and fields[0][0]==160,'CRL_INDIRECT_DELTA_OR_SCOPE_UNSUPPORTED');names=children(data,fields[0]);need(len(names)==1 and names[0][0]==160,'CRL_INDIRECT_DELTA_OR_SCOPE_UNSUPPORTED');items=children(data,names[0]);need(1<=len(items)<=8 and all(n[0]==134 for n in items),'CRL_INDIRECT_DELTA_OR_SCOPE_UNSUPPORTED');uris=[value(data,n) for n in items];need(len(set(uris))==len(uris) and all(0<len(u)<=1024 and all(32<c<127 for c in u) for u in uris),'CRL_SCOPE_URI');return uris

def cert_dp_uris(ext):
 if '2.5.29.31' not in ext:return []
 data=ext['2.5.29.31'];root=tlv(data);need(root[0]==48 and root[3]==len(data),'CERT_DP_FRAME');points=children(data,root);need(1<=len(points)<=8,'CERT_DP_BOUND');out=[]
 for point in points:need(point[0]==48,'CERT_DP_FRAME');out.extend(scope_fullnames(data,point))
 return out

def certificate(data):
 need(len(data)<=32768,'CERTIFICATE_BOUND');n=tlv(data);need(n[0]==48 and n[3]==len(data),'CERTIFICATE_FRAME');f=children(data,n);need(len(f)==3,'CERTIFICATE_FRAME');t=children(data,f[0]);off=1 if t[0][0]==160 else 0;need(len(t)>=off+6,'CERTIFICATE_TBS');serial=t[off];issuer=t[off+2];valid=children(data,t[off+3]);subject=t[off+4]
 need(serial[0]==2 and len(valid)==2,'CERTIFICATE_SERIAL_VALIDITY');ext={}
 for box in t[off+6:]:
  if box[0]==163:
   seq=children(data,box);need(len(seq)==1,'CERTIFICATE_EXTENSIONS');ext=extensions(data,seq[0])
 ski=None;aki=None
 if '2.5.29.14' in ext:ski=value(ext['2.5.29.14'],tlv(ext['2.5.29.14'])).hex()
 if '2.5.29.35' in ext:
  b=ext['2.5.29.35'];ids=[value(b,x).hex() for x in children(b,tlv(b)) if x[0]==128];need(len(ids)<=1,'CERTIFICATE_AKI');aki=ids[0] if ids else None
 try:parts=name_parts(data,subject)
 except Hold:parts=None
 return {'sha256':sha(data),'der':data,'serialDER':raw(data,serial),'issuerDER':raw(data,issuer),'subjectDER':raw(data,subject),'subjectParts':parts,'crlDistributionPointExtension':ext.get('2.5.29.31'),'notBefore':der_time(data,valid[0]),'notAfter':der_time(data,valid[1]),'SKI':ski,'AKI':aki}

def crl_data(data,fixed_time):
 need(len(data)<=16777216,'CRL_BOUND');root=tlv(data);need(root[0]==48 and root[3]==len(data),'CRL_FRAME');outer=children(data,root);need(len(outer)==3,'CRL_FRAME');f=children(data,outer[0]);off=1 if f[0][0]==2 else 0;need(len(f)>=off+4,'CRL_TBS');issuer=f[off+1];this=f[off+2];nxt=f[off+3];need(nxt[0] in (23,24),'CRL_NEXT_UPDATE_REQUIRED');ext={};critical=set()
 for n in f[off+4:]:
  if n[0]==160:
   seq=children(data,n);need(len(seq)==1,'CRL_EXTENSIONS');ext=extensions(data,seq[0],critical)
 need('2.5.29.27' not in ext,'CRL_INDIRECT_DELTA_OR_SCOPE_UNSUPPORTED');scope=[]
 need(not critical-{'2.5.29.28'},'CRL_UNKNOWN_CRITICAL_EXTENSION')
 need('2.5.29.28' not in ext or '2.5.29.28' in critical,'CRL_IDP_MUST_BE_CRITICAL')
 if '2.5.29.28' in ext:
  data_idp=ext['2.5.29.28'];node_idp=tlv(data_idp);need(node_idp[0]==48 and node_idp[3]==len(data_idp),'CRL_IDP_FRAME');scope=scope_fullnames(data_idp,node_idp)
 need('2.5.29.35' in ext,'CRL_AKI_REQUIRED');b=ext['2.5.29.35'];ids=[value(b,n).hex() for n in children(b,tlv(b)) if n[0]==128];need(len(ids)==1,'CRL_AKI_REQUIRED');start=der_time(data,this);end=der_time(data,nxt);need(start<=fixed_time+300 and end>fixed_time and start<end,'CRL_NOT_CURRENT')
 return {'der':data,'sha256':sha(data),'issuerDER':raw(data,issuer),'AKI':ids[0],'thisUpdate':start,'nextUpdate':end,'scopeURIs':scope,'signatureStatus':'UNVERIFIED_UNTIL_NATIVE_VERIFY'}
