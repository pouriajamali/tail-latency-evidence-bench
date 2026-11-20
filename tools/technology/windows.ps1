param([Parameter(Mandatory=$true)][string]$FramePath,[Parameter(Mandatory=$true)][string]$FrameSha)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
function Need($v,[string]$c){if(-not $v){throw $c}}
function Hash([string]$p){(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()}
function Fresh([string]$p,$v){$b=[Text.UTF8Encoding]::new($false).GetBytes(($v|ConvertTo-Json -Depth 25)+"`n");Need ($b.Length -le 262144) 'PROOF_CAP';$f=[IO.File]::Open($p,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$f.Write($b);$f.Flush($true)}finally{$f.Dispose()}}
Need ((Hash $FramePath) -ceq $FrameSha) 'FRAME_HASH';$f=Get-Content -LiteralPath $FramePath -Raw|ConvertFrom-Json -AsHashtable
Need ($f.schema -ceq 'tail11-technology-frame/v1' -and $f.rid -ceq 'win-x64') 'FRAME_SCOPE'
$root=$f.workspace;$out=$f.output;$nonce=$f.nonce;$python='C:\Users\Office\AppData\Local\Programs\Python\Python312\python.exe'
try{
Need ((Hash $python) -ceq '4d6f5f81a4bca11191c4c7c6b43632694d0a4ce74e068619d8fdc161d469859a') 'PYTHON_PIN'
Need ((Hash (Join-Path (Split-Path $python) 'python312.dll')) -ceq '9a0e3435aaa680d868150f87ab3e388ad2eebc22f87e036155c7b4eda8cd2120') 'PYTHON_DLL_PIN'
Need ((Hash (Get-Process -Id $PID).Path) -ceq '2a6769a3330dc1084d0154bfde7d164ab750ca7f700f313f9d417c1be78b2233') 'POWERSHELL_PIN'
Need ($f.sourceHashes.Count -le 32 -and (Hash $f.protocol) -ceq 'fca40422e6abb4aa552759d7aadfd63fda6eccde4a8be3b272ff480fa72a6035') 'PROTOCOL_SOURCE_SCOPE'
foreach($n in $f.sourceHashes.Keys){Need ((Hash (Join-Path $root $n)) -ceq $f.sourceHashes[$n]) 'SOURCE_DRIFT'}
$h=Get-Content -LiteralPath $f.lease -Raw|ConvertFrom-Json -AsHashtable
Need ($h.projectId -ceq '11' -and $h.randomToken -ceq $nonce -and $h.ownerPID -eq $f.ownerPID -and $h.ownerProcessStartIdentity -ceq $f.ownerBirth) 'CANONICAL_OWNER'
Need (('FILETIME:'+((Get-Process -Id $f.ownerPID).StartTime.ToUniversalTime().ToFileTimeUtc())) -ceq $f.ownerBirth) 'ACTUAL_OWNER_BIRTH'
Need ($f.deadline-$f.started -eq 300 -and [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()/1000.0 -lt $f.deadline-30) 'POST_CLAIM_CLOCK'
$bridge=Join-Path $root 'tools/m1/job_bridge11.cs';Need ((Hash $bridge) -ceq '64c1986b4af44610c4f790ed50a65135cdc57521614ddcb8f53fbb2255a40ebb') 'EXISTING_JOB_BRIDGE'
Add-Type -TypeDefinition (Get-Content -LiteralPath $bridge -Raw)
}catch{Fresh (Join-Path $out 'terminal.json') @{schema='tail11-technology-terminal/v1';nonce=$nonce;noOwnedChildCreated=$true;active=0;allOwnedTerminal=$true;forced=$false;exitCode=1;originalWait=$null;phaseError=$_.Exception.Message;SDKCalls=0;Actions=0};throw}
$job=[IntPtr]::Zero;$port=[IntPtr]::Zero;$environment=[IntPtr]::Zero;$pi=[Tail11DiagnosticJob+PI]::new();$clean=$false;$resumed=$false;$clock=[Diagnostics.Stopwatch]::StartNew();$birth=$null;$wait=$null;$failure=$null
try{
 $job=[Tail11DiagnosticJob]::CreateJobObject([IntPtr]::Zero,('tail11-input-only-'+$nonce));$err=[Runtime.InteropServices.Marshal]::GetLastWin32Error();if($err -eq 183){[void][Tail11DiagnosticJob]::CloseHandle($job);$job=[IntPtr]::Zero;throw 'EXISTING_JOB_NO_REUSE'};Need ($job -ne [IntPtr]::Zero) 'NEW_OWN_JOB'
 $ext=[Tail11DiagnosticJob+EXT]::new();$basic=[Tail11DiagnosticJob+BASIC]::new();$basic.Flags=0x2218;$basic.ActiveLimit=16;$basic.Affinity=[UIntPtr]::new([uint64]3);$ext.Basic=$basic;$ext.JobMemory=[UIntPtr]::new([uint64]536870912);[Tail11DiagnosticJob]::Set[Tail11DiagnosticJob+EXT]($job,9,$ext)
 $cpu=[Tail11DiagnosticJob+CPU]::new();$cpu.Flags=5;$cpu.Rate=1000;[Tail11DiagnosticJob]::Set[Tail11DiagnosticJob+CPU]($job,15,$cpu)
 $actual=[Tail11DiagnosticJob]::Get[Tail11DiagnosticJob+EXT]($job,9);$rate=[Tail11DiagnosticJob]::Get[Tail11DiagnosticJob+CPU]($job,15)
 Need ($actual.Basic.Flags -eq 0x2218 -and $actual.Basic.ActiveLimit -eq 16 -and $actual.Basic.Affinity.ToUInt64() -eq 3 -and $actual.JobMemory.ToUInt64() -eq 536870912 -and $rate.Flags -eq 5 -and $rate.Rate -eq 1000) 'ACTUAL_CAPS_BEFORE_RESUME'
 $port=[Tail11DiagnosticJob]::CreateIoCompletionPort([IntPtr]::new(-1),[IntPtr]::Zero,[UIntPtr]::Zero,1);Need ($port -ne [IntPtr]::Zero) 'OWN_COMPLETION_PORT';$associate=[Tail11DiagnosticJob+COMPLETION]::new();$associate.Key=[UIntPtr]::new([uint64]1);$associate.Port=$port;[Tail11DiagnosticJob]::Set[Tail11DiagnosticJob+COMPLETION]($job,7,$associate)
 $map=[Collections.Generic.SortedDictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
 foreach($k in @('SystemRoot','WINDIR','ComSpec','ProgramData','ProgramFiles','ProgramFiles(x86)','ProgramW6432')){$map[$k]=[Environment]::GetEnvironmentVariable($k)}
 $map['PATH']='C:\Windows\System32;C:\Program Files\Git\cmd;C:\Windows\System32\OpenSSH';$map['PYTHONDONTWRITEBYTECODE']='1';$map['TAIL11_ROOT_NONCE']=$nonce;$map['TAIL11_ROOT_PROFILE']=Join-Path $out 'profile.json'
 $block=($map.GetEnumerator()|ForEach-Object{"$($_.Key)=$($_.Value)"}) -join [char]0;$environment=[Runtime.InteropServices.Marshal]::StringToHGlobalUni($block+[char]0+[char]0)
 $entry='import sys;sys.path.insert(0,sys.argv.pop(1));import worker;worker.main()';$argv=@($python,'-I','-S','-B','-c',$entry,(Join-Path $root 'tools/technology'),'--frame',$FramePath,'--frame-sha',$FrameSha)
 $command=[Text.StringBuilder]::new((($argv|ForEach-Object{[Tail11DiagnosticJob]::Quote($_)}) -join ' '));$si=[Tail11DiagnosticJob+STARTUP]::new();$si.cb=[Runtime.InteropServices.Marshal]::SizeOf($si)
 [Tail11DiagnosticJob]::Check([Tail11DiagnosticJob]::CreateProcess($python,$command,[IntPtr]::Zero,[IntPtr]::Zero,$false,0x08000404,$environment,$root,[ref]$si,[ref]$pi),'CREATE_SUSPENDED')
 [Tail11DiagnosticJob]::Check([Tail11DiagnosticJob]::AssignProcessToJobObject($job,$pi.Process),'ASSIGN_BEFORE_RESUME');$member=$false;[Tail11DiagnosticJob]::Check([Tail11DiagnosticJob]::IsProcessInJob($pi.Process,$job,[ref]$member),'ACTUAL_MEMBERSHIP');Need $member 'MEMBER'
 $created=[Tail11DiagnosticJob+FT]::new();$exited=[Tail11DiagnosticJob+FT]::new();$kernel=[Tail11DiagnosticJob+FT]::new();$user=[Tail11DiagnosticJob+FT]::new();[Tail11DiagnosticJob]::Check([Tail11DiagnosticJob]::GetProcessTimes($pi.Process,[ref]$created,[ref]$exited,[ref]$kernel,[ref]$user),'ACTUAL_BIRTH');$birth=(([uint64]$created.High -shl 32) -bor $created.Low)
 Fresh (Join-Path $out 'profile.json') @{childPid=$pi.Pid;processCreationFileTime=$birth;nonce=$nonce;beforeResume=$true;member=$member;actualMemoryBytes=536870912;actualProcesses=16;actualCPU=1000;actualAffinity=3;noBreakaway=$true;killOnClose=$true;frameSHA256=$FrameSha;hostClass='OBSERVED_EXPERIMENTAL';formalVendorSupport='NOT_CONFIRMED'}
 $remaining=[Math]::Min(60,([Math]::Min($f.phaseDeadline,$f.deadline-30)-[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()/1000.0));Need ($remaining -gt 0) 'PHASE_CLOCK'
 Need ([Tail11DiagnosticJob]::ResumeThread($pi.Thread) -ne [uint32]::MaxValue) 'RESUME';$resumed=$true;$wait=[Tail11DiagnosticJob]::WaitForSingleObject($pi.Process,[uint32]($remaining*1000));$forced=$wait -ne 0
 if($forced){[void][Tail11DiagnosticJob]::TerminateJobObject($job,124);[void][Tail11DiagnosticJob]::WaitForSingleObject($pi.Process,5000)}
 $code=[uint32]0;[Tail11DiagnosticJob]::Check([Tail11DiagnosticJob]::GetExitCodeProcess($pi.Process,[ref]$code),'EXIT');$account=[Tail11DiagnosticJob]::Get[Tail11DiagnosticJob+ACCOUNT]($job,1);$events=0
 while(-not $forced -and $account.ActiveProcesses -ne 0 -and $clock.Elapsed.TotalSeconds -lt 60 -and $events -lt 128){$msg=[uint32]0;$key=[UIntPtr]::Zero;$hint=[IntPtr]::Zero;[void][Tail11DiagnosticJob]::GetQueuedCompletionStatus($port,[ref]$msg,[ref]$key,[ref]$hint,100);$events++;$account=[Tail11DiagnosticJob]::Get[Tail11DiagnosticJob+ACCOUNT]($job,1)}
 if($account.ActiveProcesses -ne 0){$forced=$true;[void][Tail11DiagnosticJob]::TerminateJobObject($job,125);[void][Tail11DiagnosticJob]::WaitForSingleObject($pi.Process,5000)}
 $account=[Tail11DiagnosticJob]::Get[Tail11DiagnosticJob+ACCOUNT]($job,1);$clean=$account.ActiveProcesses -eq 0;$peak=[Tail11DiagnosticJob]::Get[Tail11DiagnosticJob+EXT]($job,9)
 Fresh (Join-Path $out 'terminal.json') @{schema='tail11-technology-terminal/v1';nonce=$nonce;pid=$pi.Pid;birthFileTime=$birth;originalWait=$wait;exitCode=$code;forced=$forced;active=$account.ActiveProcesses;allOwnedTerminal=$clean;seconds=$clock.Elapsed.TotalSeconds;peakJobMemoryBytes=$peak.PeakJob.ToUInt64();totalProcesses=$account.TotalProcesses;cpuUser100ns=$account.User;cpuKernel100ns=$account.Kernel;ioReadBytes=$peak.IO.ReadBytes;ioWriteBytes=$peak.IO.WriteBytes;caps=@{memory=536870912;processes=16;cpuRate=1000;affinity=3};formalVendorSupport='NOT_CONFIRMED';controllerPID=$PID;controllerWorkingSetBytes=(Get-Process -Id $PID).WorkingSet64;Actions=0;M1Calls=0}
 Need ($clean -and -not $forced -and $code -eq 0) 'PHASE_HOLD'
}catch{$failure=$_.Exception.Message;throw}finally{
 if(-not $resumed -and $pi.Process -ne [IntPtr]::Zero){[void][Tail11DiagnosticJob]::TerminateProcess($pi.Process,126);[void][Tail11DiagnosticJob]::WaitForSingleObject($pi.Process,5000)}
 if($job -ne [IntPtr]::Zero){if(-not $clean){[void][Tail11DiagnosticJob]::TerminateJobObject($job,126);if($pi.Process -ne [IntPtr]::Zero){[void][Tail11DiagnosticJob]::WaitForSingleObject($pi.Process,5000)};$account=[Tail11DiagnosticJob]::Get[Tail11DiagnosticJob+ACCOUNT]($job,1);$end=[DateTimeOffset]::UtcNow.AddSeconds(5);while($account.ActiveProcesses -ne 0 -and [DateTimeOffset]::UtcNow -lt $end){$msg=[uint32]0;$key=[UIntPtr]::Zero;$hint=[IntPtr]::Zero;[void][Tail11DiagnosticJob]::GetQueuedCompletionStatus($port,[ref]$msg,[ref]$key,[ref]$hint,100);$account=[Tail11DiagnosticJob]::Get[Tail11DiagnosticJob+ACCOUNT]($job,1)};$clean=$account.ActiveProcesses -eq 0};if(-not(Test-Path -LiteralPath (Join-Path $out 'terminal.json'))){Fresh (Join-Path $out 'terminal.json') @{schema='tail11-technology-terminal/v1';nonce=$nonce;pid=$pi.Pid;birthFileTime=$birth;originalWait=$wait;allOwnedTerminal=$clean;active=$account.ActiveProcesses;forced=$true;exitCode=1;phaseError=$failure;noOwnedChildCreated=($pi.Process -eq [IntPtr]::Zero);Actions=0}};[void][Tail11DiagnosticJob]::CloseHandle($job)}
 elseif(-not(Test-Path -LiteralPath (Join-Path $out 'terminal.json'))){Fresh (Join-Path $out 'terminal.json') @{schema='tail11-technology-terminal/v1';nonce=$nonce;originalWait=$null;allOwnedTerminal=($pi.Process -eq [IntPtr]::Zero);active=0;forced=$false;exitCode=1;phaseError=$failure;noOwnedChildCreated=($pi.Process -eq [IntPtr]::Zero);Actions=0}}
 if($port -ne [IntPtr]::Zero){[void][Tail11DiagnosticJob]::CloseHandle($port)};if($pi.Thread -ne [IntPtr]::Zero){[void][Tail11DiagnosticJob]::CloseHandle($pi.Thread)};if($pi.Process -ne [IntPtr]::Zero){[void][Tail11DiagnosticJob]::CloseHandle($pi.Process)};if($environment -ne [IntPtr]::Zero){[Runtime.InteropServices.Marshal]::FreeHGlobal($environment)}
}
