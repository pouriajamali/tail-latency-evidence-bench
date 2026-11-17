using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;
public sealed class Tail11ExactProvider : IDisposable {
 public const string ExactPath=@"C:\Program Files\ESET\ESET Security\ebehmoni.dll";
 [StructLayout(LayoutKind.Sequential)] public struct FT {public uint Lo,Hi; public ulong Value=>(ulong)Hi<<32|Lo;}
 [StructLayout(LayoutKind.Sequential)] public struct FI {public uint Attr;public FT Created,Accessed,Written;public uint Volume,SizeHi,SizeLo,Links,IndexHi,IndexLo;}
 [StructLayout(LayoutKind.Sequential)] public struct IO {public ulong Reads,Writes,Other,ReadBytes,WriteBytes,OtherBytes;}
 [StructLayout(LayoutKind.Sequential)] struct WF {public uint Size;public IntPtr Path,File,KnownSubject;}
 [StructLayout(LayoutKind.Sequential)] struct WT {public uint Size;public IntPtr Policy,Sip;public uint UI,Revocation,Choice;public IntPtr File;public uint State;public IntPtr StateData,Url;public uint Flags,Context;public IntPtr SignatureSettings;}
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateFileW(string p,uint access,uint share,IntPtr sa,uint disposition,uint flags,IntPtr template);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(IntPtr h,out FI info);
 [DllImport("kernel32.dll",SetLastError=true)] static extern uint GetFileType(IntPtr h);
 [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetProcessIoCounters(IntPtr h,out IO io);
 [DllImport("wintrust.dll",ExactSpelling=true)] static extern int WinVerifyTrust(IntPtr hwnd,[In]ref Guid action,[In,Out]ref WT data);
 [StructLayout(LayoutKind.Sequential)] struct BASIC {public long P,J;public uint Flags;public UIntPtr Min,Max;public uint Active;public UIntPtr Affinity;public uint Priority,Scheduling;}
 [StructLayout(LayoutKind.Sequential)] struct EXT {public BASIC Basic;public IO Io;public UIntPtr PM,JM,PP,PJ;}
 [StructLayout(LayoutKind.Sequential)] struct CPU {public uint Flags,Rate;}
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr OpenJobObjectW(uint access,bool inherit,string name);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool IsProcessInJob(IntPtr process,IntPtr job,out bool member);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr job,int cls,IntPtr data,uint length,IntPtr returned);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetProcessTimes(IntPtr process,out FT created,out FT exited,out FT kernel,out FT user);
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
 static T Query<T>(IntPtr h,int cls) where T:struct {int n=Marshal.SizeOf<T>();IntPtr p=Marshal.AllocHGlobal(n);try{Need(QueryInformationJobObject(h,cls,p,(uint)n,IntPtr.Zero),"KERNEL_QUERY");return Marshal.PtrToStructure<T>(p);}finally{Marshal.FreeHGlobal(p);}}
 public static object CurrentKernel(string nonce,ulong birth){
  IntPtr h=OpenJobObjectW(4,false,"tail11-input-only-"+nonce);Need(h!=IntPtr.Zero,"OWN_JOB");
  try{bool member;Need(IsProcessInJob(GetCurrentProcess(),h,out member)&&member,"ACTUAL_MEMBERSHIP");EXT e=Query<EXT>(h,9);CPU c=Query<CPU>(h,15);FT b,x,k,u;
   Need(GetProcessTimes(GetCurrentProcess(),out b,out x,out k,out u)&&b.Value==birth,"ACTUAL_BIRTH");
   Need(e.Basic.Flags==0x2218&&e.Basic.Active==16&&(e.Basic.Affinity.ToUInt64()==1||e.Basic.Affinity.ToUInt64()==3)&&e.JM.ToUInt64()==536870912&&c.Flags==5&&c.Rate==1000,"ACTUAL_CAPS");
   return new {actualMembership=true,flags=e.Basic.Flags,activeLimit=e.Basic.Active,affinity=e.Basic.Affinity.ToUInt64(),memory=e.JM.ToUInt64(),cpuFlags=c.Flags,cpuRate=c.Rate,birth=b.Value,readFromCurrentKernel=true};
  }finally{CloseHandle(h);}
 }
 public string WinTrustStatusHex=>"0x"+unchecked((uint)WinTrustStatus).ToString("X8");
 public uint ImageSize,EntryRva;public string ImageBaseHex;public List<Dictionary<string,object>> Sections=new List<Dictionary<string,object>>();
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint GetFinalPathNameByHandleW(IntPtr h,StringBuilder b,uint n,uint flags);
 public string HeldNtPath {get{var b=new StringBuilder(32768);uint n=GetFinalPathNameByHandleW(safe.DangerousGetHandle(),b,32768,2);Need(n>0&&n<32767,"HELD_NT_PATH");return b.ToString();}}
 public FI Before,After;public string Sha256,AfterSha256;public ushort Machine,Characteristics;public string Architecture;
 public List<Dictionary<string,string>> Imports=new List<Dictionary<string,string>>();
 public List<byte[]> EmbeddedSignatures=new List<byte[]>();public int WinTrustStatus;public bool WinTrustCalled,Stable;
 public ulong ExplicitFileReadBytes,ObservedIoReadBytes;public uint WinTrustFlags=0x1080;
 SafeFileHandle safe;FileStream stream;byte[] bytes;IO ioBefore;
 static void Need(bool v,string c){if(!v)throw new InvalidDataException(c);}
 static string Hash(byte[] b)=>Convert.ToHexString(SHA256.HashData(b)).ToLowerInvariant();
 public Tail11ExactProvider(string path){
  Need(String.Equals(path,ExactPath,StringComparison.Ordinal),"EXACT_PATH_ONLY");
  Need(GetProcessIoCounters(GetCurrentProcess(),out ioBefore),"IO_COUNTERS");
  IntPtr h=CreateFileW(path,0x80000000,1,IntPtr.Zero,3,0x00200000,IntPtr.Zero);
  Need(h!=IntPtr.Zero&&h!=new IntPtr(-1),"EXACT_FILE_OPEN");safe=new SafeFileHandle(h,true);
  try{
   Need(GetFileType(h)==1&&GetFileInformationByHandle(h,out Before),"FILE_IDENTITY");
   ulong size=((ulong)Before.SizeHi<<32)|Before.SizeLo;
   Need((Before.Attr&0x400)==0&&Before.Links==1&&size>0&&size<=16777216,"FILE_METADATA_BOUND");
   stream=new FileStream(safe,FileAccess.Read,65536,false);bytes=new byte[(int)size];stream.ReadExactly(bytes);Need(stream.ReadByte()==-1,"FILE_LENGTH");
   ExplicitFileReadBytes=size;Sha256=Hash(bytes);ParsePE();
  }catch{Dispose();throw;}
 }
 int Pos(int p,int n){Need(p>=0&&n>=0&&p<=bytes.Length-n,"PE_BOUNDS");return p;}
 ushort U16(int p)=>BitConverter.ToUInt16(bytes,Pos(p,2));
 uint U32(int p)=>BitConverter.ToUInt32(bytes,Pos(p,4));
 ulong U64(int p)=>BitConverter.ToUInt64(bytes,Pos(p,8));
 int Rva(uint value,int n,List<uint[]> sections,uint headers){
  if(value<headers)return Pos(checked((int)value),n);
  int pos=-1,count=0;
  foreach(var s in sections)if(value>=s[0]&&(ulong)value-s[0]+(uint)n<=s[2]){pos=checked((int)(s[1]+value-s[0]));count++;}
  Need(count==1,"PE_RVA");return Pos(pos,n);
 }
 string DllName(uint rva,List<uint[]> sections,uint headers){
  int p=Rva(rva,1,sections,headers),end=p;
  while(end<bytes.Length&&end<p+129&&bytes[end]!=0)end++;
  Need(end>p&&end<bytes.Length&&end<p+129,"PE_IMPORT_NAME");
  string n=Encoding.ASCII.GetString(bytes,p,end-p).ToLowerInvariant();
  foreach(char c in n)Need(c>='a'&&c<='z'||c>='0'&&c<='9'||c=='_'||c=='.'||c=='-',"PE_IMPORT_NAME");return n;
 }
 void ParsePE(){
  Need(bytes.Length>=256&&U16(0)==0x5a4d,"PE_MZ");int pe=checked((int)U32(0x3c));Need(U32(pe)==0x4550,"PE_SIGNATURE");
  Machine=U16(pe+4);Architecture=Machine==0x8664?"AMD64":Machine==0x14c?"I386":Machine==0xaa64?"ARM64":"UNKNOWN";
  int sections=U16(pe+6),optional=U16(pe+20),opt=pe+24;Characteristics=U16(pe+22);ushort magic=U16(opt);
  Need(sections>=1&&sections<=96&&(magic==0x20b||magic==0x10b),"PE_HEADERS");Pos(opt,optional+40*sections);
  int dd=opt+(magic==0x20b?112:96);uint directories=U32(opt+(magic==0x20b?108:92));Need(directories>=14&&dd+14*8<=opt+optional,"PE_DIRECTORIES");
  ulong imageBase=magic==0x20b?U64(opt+24):U32(opt+28);ImageBaseHex="0x"+imageBase.ToString("X");ImageSize=U32(opt+56);EntryRva=U32(opt+16);uint headers=U32(opt+60);var table=new List<uint[]>();
  for(int i=0;i<sections;i++){int p=opt+optional+40*i;table.Add(new uint[]{U32(p+12),U32(p+20),U32(p+16)});uint flags=U32(p+36);
   Sections.Add(new Dictionary<string,object>{{"nameHex",Convert.ToHexString(bytes.AsSpan(p,8))},{"rva",U32(p+12)},{"virtualBytes",U32(p+8)},{"rawOffset",U32(p+20)},{"rawBytes",U32(p+16)},{"flags","0x"+flags.ToString("X8")},{"readable",(flags&0x40000000)!=0},{"writable",(flags&0x80000000)!=0},{"executable",(flags&0x20000000)!=0}});
  }
  foreach(int slot in new[]{1,13}){
   uint va=U32(dd+slot*8),size=U32(dd+slot*8+4);int step=slot==1?20:32,field=slot==1?12:4;
   if(va==0){Need(size==0,"PE_IMPORT_DIRECTORY");continue;}
   Need(size>=step&&size<=1048576,"PE_IMPORT_DIRECTORY");int pos=Rva(va,checked((int)size),table,headers);bool ended=false;
   for(int i=0;i<Math.Min(size/(uint)step,1024);i++){
    int at=pos+i*step;bool zero=true;for(int j=0;j<step;j++)if(bytes[at+j]!=0){zero=false;break;}
    if(zero){ended=true;break;}
    uint name=U32(at+field);
    if(slot==13){uint attr=U32(at);Need(attr<=1,"PE_DELAY_ATTR");if(attr==0){Need(name>=imageBase,"PE_DELAY_VA");name=checked((uint)((ulong)name-imageBase));}}
    Imports.Add(new Dictionary<string,string>{{"name",DllName(name,table,headers)},{"kind",slot==1?"normal":"delay"}});Need(Imports.Count<=1024,"PE_IMPORT_LIMIT");
   }
   Need(ended,"PE_IMPORT_TERMINATOR");
  }
  uint offset=U32(dd+4*8),length=U32(dd+4*8+4);
  if(offset==0&&length==0)return;
  Need(length>=8&&length<=1048576,"EMBEDDED_SIGNATURE_CAP");int start=Pos(checked((int)offset),checked((int)length)),end=start+(int)length;
  for(int at=start;at<end;){
   Need(at<=end-8&&EmbeddedSignatures.Count<4,"WIN_CERTIFICATE_HEADER");uint size=U32(at);Need(size>=8&&size<=end-at,"WIN_CERTIFICATE_LENGTH");
   Need(U16(at+4)==0x200&&U16(at+6)==2,"WIN_CERTIFICATE_TYPE");byte[] sig=new byte[size-8];Buffer.BlockCopy(bytes,at+8,sig,0,sig.Length);EmbeddedSignatures.Add(sig);
   at=checked(at+(int)((size+7)&~7u));Need(at<=end,"WIN_CERTIFICATE_ALIGNMENT");
  }
 }
 public int VerifyCacheOnly(){
  WF f=new WF{Size=(uint)Marshal.SizeOf<WF>(),Path=Marshal.StringToCoTaskMemUni(ExactPath),File=safe.DangerousGetHandle()};
  IntPtr fp=Marshal.AllocHGlobal(Marshal.SizeOf<WF>());Marshal.StructureToPtr(f,fp,false);
  WT d=new WT{Size=(uint)Marshal.SizeOf<WT>(),UI=2,Revocation=0,Choice=1,File=fp,State=1,Flags=WinTrustFlags};Guid action=new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
  try{WinTrustCalled=true;WinTrustStatus=WinVerifyTrust(new IntPtr(-1),ref action,ref d);return WinTrustStatus;}
  finally{try{d.State=2;WinVerifyTrust(new IntPtr(-1),ref action,ref d);}finally{Marshal.FreeHGlobal(fp);Marshal.FreeCoTaskMem(f.Path);}}
 }
 public void SealStable(){
  stream.Position=0;AfterSha256=Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();ExplicitFileReadBytes+=((ulong)Before.SizeHi<<32)|Before.SizeLo;
  Need(GetFileInformationByHandle(safe.DangerousGetHandle(),out After),"FILE_IDENTITY_AFTER");
  Stable=Before.Attr==After.Attr&&Before.Volume==After.Volume&&Before.IndexHi==After.IndexHi&&Before.IndexLo==After.IndexLo&&Before.Links==After.Links&&Before.SizeHi==After.SizeHi&&Before.SizeLo==After.SizeLo&&Before.Created.Value==After.Created.Value&&Before.Written.Value==After.Written.Value&&Sha256==AfterSha256;
  Need(Stable,"CURRENT_DISK_FILE_CHANGED");IO after;Need(GetProcessIoCounters(GetCurrentProcess(),out after),"IO_COUNTERS_AFTER");ObservedIoReadBytes=after.ReadBytes-ioBefore.ReadBytes;
  Need(ExplicitFileReadBytes<=67108864&&ObservedIoReadBytes<=67108864,"READ64M_CAP");
 }
 public void Dispose(){if(stream!=null){stream.Dispose();stream=null;}else if(safe!=null)safe.Dispose();bytes=null;}
 public static string[] PublicUris(byte[] der){
  Need(der!=null&&der.Length<=65536,"CERT_EXTENSION_CAP");var uris=new List<string>();int nodes=0;
  Walk(der,0,der.Length,0,uris,ref nodes);return uris.ToArray();
 }
 static void Walk(byte[] b,int start,int end,int depth,List<string> uris,ref int nodes){
  Need(depth<=16,"CERT_DER_DEPTH");int p=start;
  while(p<end){Need(++nodes<=512&&p<=end-2,"CERT_DER_NODE");int tag=b[p++],len=b[p++];Need((tag&31)!=31,"CERT_DER_TAG");
   if((len&128)!=0){int n=len&127;Need(n>=1&&n<=4&&p<=end-n,"CERT_DER_LENGTH");long total=0;for(int i=0;i<n;i++)total=(total<<8)|b[p++];Need(total<=65536,"CERT_DER_LENGTH");len=(int)total;}
   Need(len>=0&&p<=end-len,"CERT_DER_BOUNDS");
   if(tag==0x86){Need(len>0&&len<=2048&&uris.Count<16,"PUBLIC_URI_BOUND");for(int i=p;i<p+len;i++)Need(b[i]>=0x21&&b[i]<=0x7e,"PUBLIC_URI_ASCII");uris.Add(Encoding.ASCII.GetString(b,p,len));}
   else if((tag&0x20)!=0)Walk(b,p,p+len,depth+1,uris,ref nodes);
   p+=len;
  }
  Need(p==end,"CERT_DER_END");
 }

}
