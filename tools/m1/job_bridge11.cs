using System;
using System.Runtime.InteropServices;
public static class Tail11DiagnosticJob {
 [StructLayout(LayoutKind.Sequential)] public struct BASIC {
  public long ProcessUser,JobUser; public uint Flags; public UIntPtr MinWS,MaxWS;
  public uint ActiveLimit; public UIntPtr Affinity; public uint Priority,Scheduling;
 }
 [StructLayout(LayoutKind.Sequential)] public struct IO {
  public ulong ReadOps,WriteOps,OtherOps,ReadBytes,WriteBytes,OtherBytes;
 }
 [StructLayout(LayoutKind.Sequential)] public struct EXT {
  public BASIC Basic; public IO IO; public UIntPtr ProcessMemory,JobMemory,PeakProcess,PeakJob;
 }
 [StructLayout(LayoutKind.Sequential)] public struct CPU {public uint Flags,Rate;}
 [StructLayout(LayoutKind.Sequential)] public struct COMPLETION {public UIntPtr Key;public IntPtr Port;}
 [StructLayout(LayoutKind.Sequential)] public struct ACCOUNT {
  public long User,Kernel,PeriodUser,PeriodKernel;
  public uint PageFaults,TotalProcesses,ActiveProcesses,TerminatedProcesses;
 }
 [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] public struct STARTUP {
  public uint cb; public string Reserved,Desktop,Title; public uint X,Y,XSize,YSize,XChars,YChars,Fill,Flags;
  public ushort Show,Reserved2; public IntPtr ReservedPtr,StdIn,StdOut,StdErr;
 }
 [StructLayout(LayoutKind.Sequential)] public struct PI {public IntPtr Process,Thread; public uint Pid,Tid;}
 [StructLayout(LayoutKind.Sequential)] public struct FT {public uint Low,High;}
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] public static extern IntPtr CreateJobObject(IntPtr sa,string name);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool SetInformationJobObject(IntPtr job,int cls,IntPtr data,uint length);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool QueryInformationJobObject(IntPtr job,int cls,IntPtr data,uint length,IntPtr result);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool AssignProcessToJobObject(IntPtr job,IntPtr process);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool IsProcessInJob(IntPtr process,IntPtr job,out bool member);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] public static extern bool CreateProcess(
 string app,System.Text.StringBuilder cmd,IntPtr pa,IntPtr ta,bool inherit,uint flags,IntPtr environment,string directory,ref STARTUP startup,out PI pi);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern uint ResumeThread(IntPtr thread);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern uint WaitForSingleObject(IntPtr handle,uint ms);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool GetExitCodeProcess(IntPtr process,out uint code);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool GetProcessTimes(IntPtr process,out FT created,out FT exited,out FT kernel,out FT user);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool TerminateJobObject(IntPtr job,uint code);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool TerminateProcess(IntPtr process,uint code);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern IntPtr CreateIoCompletionPort(IntPtr file,IntPtr existing,UIntPtr key,uint threads);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool GetQueuedCompletionStatus(IntPtr port,out uint message,out UIntPtr key,out IntPtr pid,uint timeout);
 [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr handle);
 public static void Check(bool value,string name){if(!value)throw new Exception(name+" win32="+Marshal.GetLastWin32Error());}
 public static void Set<T>(IntPtr job,int cls,T value) where T:struct {
  int n=Marshal.SizeOf(typeof(T));IntPtr p=Marshal.AllocHGlobal(n);
  try{Marshal.StructureToPtr(value,p,false);Check(SetInformationJobObject(job,cls,p,(uint)n),"SetJob");}finally{Marshal.FreeHGlobal(p);}
 }
 public static T Get<T>(IntPtr job,int cls) where T:struct {
  int n=Marshal.SizeOf(typeof(T));IntPtr p=Marshal.AllocHGlobal(n);
  try{Check(QueryInformationJobObject(job,cls,p,(uint)n,IntPtr.Zero),"QueryJob");return (T)Marshal.PtrToStructure(p,typeof(T));}finally{Marshal.FreeHGlobal(p);}
 }
 public static string Quote(string s) {
  if(s.Length>0 && s.IndexOfAny(new char[]{' ','\t','"'})<0)return s;
  var b=new System.Text.StringBuilder("\"");int slashes=0;
  foreach(char c in s){if(c=='\\'){slashes++;continue;}if(c=='"'){b.Append('\\',slashes*2+1).Append(c);slashes=0;continue;}b.Append('\\',slashes).Append(c);slashes=0;}
  return b.Append('\\',slashes*2).Append('"').ToString();
 }
}
