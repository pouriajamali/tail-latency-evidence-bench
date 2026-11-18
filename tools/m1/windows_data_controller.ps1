param([Parameter(Mandatory=$true)][string]$FramePath,[Parameter(Mandatory=$true)][string]$FrameSha,[Parameter(Mandatory=$true)][string]$ExpectedNonce)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$entryUtc=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()/1000.0;$entryWatch=[Diagnostics.Stopwatch]::StartNew();$work=$PSScriptRoot
function Hash([string]$p){(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()}
function Need($v,[string]$c){if(-not $v){throw $c}}
function Fresh([string]$p,$v){$b=[Text.UTF8Encoding]::new($false).GetBytes(($v|ConvertTo-Json -Depth 30 -Compress)+"`n");Need ($b.Length -le 262144) 'PROOF_CAP';$f=[IO.File]::Open($p,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$f.Write($b);$f.Flush($true)}finally{$f.Dispose()}}
$children=0;$terminal=$true;$jobs=@();$Local=$true;$sourceCommit='SOURCE_DATA_ONLY';$runId='NO_ACTIONS';$code='WINDOWS_DATA_CONTROLLER_HOLD';$out=[IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($FramePath));$nonce=$ExpectedNonce
try{
 Need ((Hash $FramePath) -ceq $FrameSha) 'FRAME_HASH';$frame=Get-Content -LiteralPath $FramePath -Raw|ConvertFrom-Json -AsHashtable
 Need ($frame.nonce -ceq $ExpectedNonce -and $frame.schema -ceq 'tail11-linux-role-frame/v1' -and $frame.mode -ceq 'windows-data') 'FIXED_DATA_SCOPE'
 $nonce=$frame.nonce;$out=$frame.hostOutputWindowsPath;$public=$out;$tmp=Join-Path $out 'tmp';[IO.Directory]::CreateDirectory($tmp)|Out-Null;$deadline=[double]$frame.window.deadlineUnix;$t=@{casePlanSha256=$frame.sourceManifestSHA256}
 function TimeLeft([int]$reserve=30){[Math]::Max(0,[Math]::Min($deadline-[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()/1000.0-$reserve,$deadline-$entryUtc-$entryWatch.Elapsed.TotalSeconds-$reserve))}
 Need ($frame.window.deadlineUnix-$frame.window.startUnix -eq 300 -and (TimeLeft) -gt 0) 'WHOLE_CLOCK'
 function Pinned-Plan([string]$expected){Need ((Hash (Join-Path $work 'source-manifest.json')) -ceq $expected) 'SOURCE_MANIFEST'}
 Pinned-Plan $frame.sourceManifestSHA256
 foreach($n in $frame.sourceHashes.Keys){$p=[IO.Path]::GetFullPath((Join-Path $work $n));Need ($p.StartsWith($work+[IO.Path]::DirectorySeparatorChar) -and (Hash $p) -ceq $frame.sourceHashes[$n]) 'SOURCE_BINDING'}
 Need ((Hash $frame.protocolWindowsPath) -ceq '9120ca49a0d46673053aa0ec0cdbbc6f00731d71ea0b57ddab09e8fc3ac3ac8b') 'CANONICAL_PROTOCOL'
 $holder=Get-Content -LiteralPath $frame.leaseWindowsPath -Raw|ConvertFrom-Json -AsHashtable
 Need ($holder.projectId -ceq '11' -and $holder.randomToken -ceq $nonce -and $holder.ownerPID -eq $frame.ownerPID -and $holder.ownerProcessStartIdentity -ceq $frame.ownerBirth) 'CANONICAL_OWNER'
 Need ((Hash (Get-Process -Id $PID).Path) -ceq '2a6769a3330dc1084d0154bfde7d164ab750ca7f700f313f9d417c1be78b2233') 'CRITICAL_POWERSHELL'
 $python=$frame.pythonPath;Need ((Hash $python) -ceq '4d6f5f81a4bca11191c4c7c6b43632694d0a4ce74e068619d8fdc161d469859a') 'CRITICAL_PYTHON'
 Need ((Hash (Join-Path (Split-Path -Parent $python) 'python312.dll')) -ceq '9a0e3435aaa680d868150f87ab3e388ad2eebc22f87e036155c7b4eda8cd2120') 'CRITICAL_PYTHON_DLL'
 Need ((Hash (Join-Path $work 'job_bridge11.cs')) -ceq 'b58fbe31353d3b09cacfc3e98068e10d0c2789156737cf2f1d3d47e3b4b93feb') 'EXISTING_JOB_BRIDGE'
 Add-Type -TypeDefinition (Get-Content -LiteralPath (Join-Path $work 'job_bridge11.cs') -Raw)
 function Run-Phase([string]$label,[string]$script,[string[]]$arguments,[int]$maximum,[string]$mode='normal'){
  Need ((TimeLeft) -gt 0) 'WHOLE_CLOCK'
  Pinned-Plan $t.casePlanSha256
  $frame["phaseDeadlineUnix"]=[Math]::Min($deadline-30,[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()/1000.0+[Math]::Min($maximum,(TimeLeft)))
  $fp=Join-Path $out ("frame-$label.json");$frame['profilePath']=Join-Path $out ("profile-$label.json");Fresh $fp $frame
  $profilePath=Join-Path $out ("profile-$label.json")
  $cache=Join-Path $out ("cache-$label");[IO.Directory]::CreateDirectory($cache)|Out-Null
  $job=[IntPtr]::Zero;$pi=[Tail11DiagnosticJob+PI]::new();$environment=[IntPtr]::Zero;$assigned=$false;$resumed=$false;$clean=$false
  try{
   $job=[Tail11DiagnosticJob]::CreateJobObject([IntPtr]::Zero,"tail11-input-only-$nonce")
   $createError=[Runtime.InteropServices.Marshal]::GetLastWin32Error()
   Need ($job -ne [IntPtr]::Zero) 'JOB_CREATE'
   if($createError -eq 183){[void][Tail11DiagnosticJob]::CloseHandle($job);$job=[IntPtr]::Zero;throw 'EXISTING_JOB_NO_REUSE'}
   $ext=[Tail11DiagnosticJob+EXT]::new();$basic=[Tail11DiagnosticJob+BASIC]::new();$basic.Flags=0x2218;$basic.ActiveLimit=16
   $affinity=if([Environment]::ProcessorCount -ge 2){3}else{1};$basic.Affinity=[UIntPtr]::new([uint64]$affinity);$ext.Basic=$basic;$ext.JobMemory=[UIntPtr]::new([uint64]536870912)
   [Tail11DiagnosticJob]::Set[Tail11DiagnosticJob+EXT]($job,9,$ext)
   $cpu=[Tail11DiagnosticJob+CPU]::new();$cpu.Flags=5;$cpu.Rate=1000;[Tail11DiagnosticJob]::Set[Tail11DiagnosticJob+CPU]($job,15,$cpu)
   $actual=[Tail11DiagnosticJob]::Get[Tail11DiagnosticJob+EXT]($job,9);$rate=[Tail11DiagnosticJob]::Get[Tail11DiagnosticJob+CPU]($job,15)
   Need ($actual.Basic.Flags -eq 0x2218 -and $actual.Basic.ActiveLimit -eq 16 -and $actual.Basic.Affinity.ToUInt64() -eq $affinity -and $actual.JobMemory.ToUInt64() -eq 536870912 -and $rate.Flags -eq 5 -and $rate.Rate -eq 1000) 'ACTUAL_JOB_CAPS'
   $map=[Collections.Generic.SortedDictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
   foreach($k in @('SystemRoot','WINDIR','ComSpec','ProgramData')){$map[$k]=[Environment]::GetEnvironmentVariable($k)}
   $map['PATH']='C:\Windows\System32\OpenSSH';$map['TEMP']=$tmp;$map['TMP']=$tmp;$map['PYTHONDONTWRITEBYTECODE']='1'
   $map['TAIL11_ROOT_PROFILE']=$profilePath;$map['TAIL11_ROOT_NONCE']=$nonce;if($Local){$map['TAIL11_EXECUTION']='LOCAL_CANONICAL'}else{$map['GITHUB_SHA']=$sourceCommit;$map['GITHUB_RUN_ID']=$runId}
   $block=($map.GetEnumerator()|ForEach-Object{"$($_.Key)=$($_.Value)"}) -join [char]0
   $environment=[Runtime.InteropServices.Marshal]::StringToHGlobalUni($block+[char]0+[char]0)
   $entry="import sys;sys.path[:0]=[sys.argv.pop(1),sys.argv.pop(1)];import windows_retained_input;windows_retained_input.main()"
   $argv=@($python,'-I','-S','-B','-c',$entry,$work,$frame.supportDirectory,'--frame',$fp,'--frame-sha',(Hash $fp))
   $command=[Text.StringBuilder]::new((($argv|ForEach-Object{[Tail11DiagnosticJob]::Quote([string]$_)}) -join ' '))
   $si=[Tail11DiagnosticJob+STARTUP]::new();$si.cb=[Runtime.InteropServices.Marshal]::SizeOf($si)
   [Tail11DiagnosticJob]::Check([Tail11DiagnosticJob]::CreateProcess($python,$command,[IntPtr]::Zero,[IntPtr]::Zero,$false,0x08000404,$environment,$work,[ref]$si,[ref]$pi),'CREATE_SUSPENDED')
   $script:children++;$script:terminal=$false
   [Tail11DiagnosticJob]::Check([Tail11DiagnosticJob]::AssignProcessToJobObject($job,$pi.Process),'ASSIGN_BEFORE_RESUME');$assigned=$true
   $member=$false;[Tail11DiagnosticJob]::Check([Tail11DiagnosticJob]::IsProcessInJob($pi.Process,$job,[ref]$member),'MEMBERSHIP');Need $member 'MEMBER'
   $created=[Tail11DiagnosticJob+FT]::new();$exited=[Tail11DiagnosticJob+FT]::new();$kernel=[Tail11DiagnosticJob+FT]::new();$user=[Tail11DiagnosticJob+FT]::new()
   [Tail11DiagnosticJob]::Check([Tail11DiagnosticJob]::GetProcessTimes($pi.Process,[ref]$created,[ref]$exited,[ref]$kernel,[ref]$user),'BIRTH')
   $profile=@{nonce=$nonce;childPid=$pi.Pid;processCreationFileTime=(([uint64]$created.High -shl 32) -bor $created.Low);jobMembership=$member;cpuRate=$rate.Rate;jobMemoryBytes=$actual.JobMemory.ToUInt64();activeProcessLimit=$actual.Basic.ActiveLimit;affinityMask=$affinity;killOnClose=$true;breakawayDisabled=$true;beforeResume=$true;officialDebugRequest=$frame.officialDebugRequest}
   Fresh $profilePath $profile
   Need ((TimeLeft) -gt 0) 'WHOLE_CLOCK'
   Need ([Tail11DiagnosticJob]::ResumeThread($pi.Thread) -ne [uint32]::MaxValue) 'RESUME';$resumed=$true
   $wait=[Tail11DiagnosticJob]::WaitForSingleObject($pi.Process,[uint32](1000*[Math]::Min($maximum,(TimeLeft))))
   $forced=$wait -ne 0
   if($forced){[Tail11DiagnosticJob]::Check([Tail11DiagnosticJob]::TerminateJobObject($job,124),'OWNED_TIMEOUT');[void][Tail11DiagnosticJob]::WaitForSingleObject($pi.Process,5000)}
   $exitCode=[uint32]0;[Tail11DiagnosticJob]::Check([Tail11DiagnosticJob]::GetExitCodeProcess($pi.Process,[ref]$exitCode),'EXIT')
   $account=[Tail11DiagnosticJob]::Get[Tail11DiagnosticJob+ACCOUNT]($job,1)
   if($account.ActiveProcesses -ne 0){$forced=$true;[Tail11DiagnosticJob]::Check([Tail11DiagnosticJob]::TerminateJobObject($job,125),'OWNED_RESIDUAL');[void][Tail11DiagnosticJob]::WaitForSingleObject($pi.Process,5000)}
   $account=[Tail11DiagnosticJob]::Get[Tail11DiagnosticJob+ACCOUNT]($job,1);$clean=$account.ActiveProcesses -eq 0
   $script:terminal=$clean
   $proof=@{label=$label;childPid=$pi.Pid;birth=$profile.processCreationFileTime;caps=$profile;exitCode=$exitCode;originalWait=$wait;forced=$forced;active=$account.ActiveProcesses;naturalTerminal=($clean -and -not $forced);deadline=$deadline}
   Fresh (Join-Path $public ("terminal-$label.json")) $proof
   $script:jobs+=@($proof)
   Need ($clean -and -not $forced -and $exitCode -eq 0) 'CHILD_HOLD'
  }finally{
   if($pi.Process -ne [IntPtr]::Zero -and -not $assigned){[void][Tail11DiagnosticJob]::TerminateProcess($pi.Process,126);[void][Tail11DiagnosticJob]::WaitForSingleObject($pi.Process,5000)}
   if($job -ne [IntPtr]::Zero){
    if(-not $clean){[void][Tail11DiagnosticJob]::TerminateJobObject($job,126);if($pi.Process -ne [IntPtr]::Zero){[void][Tail11DiagnosticJob]::WaitForSingleObject($pi.Process,5000)}
     $script:terminal=([Tail11DiagnosticJob]::Get[Tail11DiagnosticJob+ACCOUNT]($job,1)).ActiveProcesses -eq 0}
    [void][Tail11DiagnosticJob]::CloseHandle($job)
   }
   if($pi.Thread -ne [IntPtr]::Zero){[void][Tail11DiagnosticJob]::CloseHandle($pi.Thread)}
   if($pi.Process -ne [IntPtr]::Zero){[void][Tail11DiagnosticJob]::CloseHandle($pi.Process)}
   if($environment -ne [IntPtr]::Zero){[Runtime.InteropServices.Marshal]::FreeHGlobal($environment)}
  }
 }
 Run-Phase 'retained-and-one-official-debug-data' $frame.inspectorPath @() 20
 $code='WINDOWS_DATA_COMPLETED_NOT_ADMITTED'
}catch{$c=$_.Exception.Message;if($c -cmatch '^[A-Z][A-Z0-9_]{0,99}$'){$code=$c}}
finally{if($null -ne $out){Fresh (Join-Path $out 'windows-data-terminal.json') @{status=$code;nonce=$nonce;childrenStarted=$children;allOwnedTerminal=$terminal;GitHubActions=0;providerAdmission=$false}}}
if($code -cne 'WINDOWS_DATA_COMPLETED_NOT_ADMITTED'){exit 1}
