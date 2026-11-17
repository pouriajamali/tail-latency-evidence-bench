# Fixed opt-in M1 controller; no generic command/host/asset arguments.
param([switch]$Local)
$ErrorActionPreference='Stop'
$entryUtc=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()/1000.0
$entryWatch=[Diagnostics.Stopwatch]::StartNew()
Set-StrictMode -Version Latest
$work=$PSScriptRoot
$repo=Split-Path -Parent (Split-Path -Parent $work)
$out=Join-Path $repo 'outputs/m1'
$public=Join-Path $out 'public'
$ticketFile=if($Local){Join-Path $out 'local-ticket.json'}else{Join-Path $work 'lease-ticket.json'}
[IO.Directory]::CreateDirectory($public)|Out-Null
function Hash([string]$p){(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()}
function Need($v,[string]$code){if(-not $v){throw $code}}
function Pinned-Plan([string]$expected){Need ((Hash (Join-Path $work 'case-plan.json')) -ceq $expected) 'CASE_PLAN_IDENTITY_DENIED'}
function Fresh([string]$p,$value){
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($value|ConvertTo-Json -Depth 35 -Compress)+"`n")
 Need ($bytes.Length -le 262144) 'PROOF_CAP'
 [IO.Directory]::CreateDirectory((Split-Path -Parent $p))|Out-Null
 $f=[IO.File]::Open($p,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
 try{$f.Write($bytes);$f.Flush($true)}finally{$f.Dispose()}
}
$providerHeld=$null
$code='CI_CONTROLLER_HOLD';$children=0;$terminal=$true;$jobs=@();$runId=$env:GITHUB_RUN_ID
$ticketSha=$null;$nonce=$null;$sourceCommit=$env:GITHUB_SHA
try{
 $t=Get-Content -LiteralPath $ticketFile -Raw|ConvertFrom-Json -AsHashtable
 $ticketSha=Hash $ticketFile;$nonce=$t.nonce
 Need ($t.schema -ceq 'tail11-canonical-ci-ticket/v1' -and $t.projectId -ceq '11' -and $t.purpose -ceq 'ONE_FIXED_RECORD_CAP_M1') 'TICKET_SCOPE'
 Need ($nonce -cmatch '^[0-9a-f]{32}$' -and $t.canonicalClaim -ceq 'LOCAL_CREATE_NEW_STILL_HELD') 'TICKET_LANE'
 if($Local){
  Need ($t.execution -ceq 'LOCAL_CANONICAL') 'EXECUTION_MODE_UNKNOWN'
  $sourceCommit=$t.sourceHead;$runId='LOCAL-'+$nonce
  $canonicalProtocol=[IO.Path]::GetFullPath($t.canonicalProtocolPath)
  $canonicalLease=[IO.Path]::GetFullPath($t.canonicalLeasePath)
  Need ((Hash $canonicalProtocol) -ceq '9120ca49a0d46673053aa0ec0cdbbc6f00731d71ea0b57ddab09e8fc3ac3ac8b') 'CANONICAL_PROTOCOL'
  $policy=Get-Content -LiteralPath $canonicalProtocol -Raw|ConvertFrom-Json -AsHashtable
  Need ($policy.authoritativePolicy -ceq $canonicalProtocol -and $policy.canonicalLeaseWindows -ceq $canonicalLease -and '11' -cin $policy.participants) 'CANONICAL_PATHS'
  $holder=Get-Content -LiteralPath $canonicalLease -Raw|ConvertFrom-Json -AsHashtable
  Need ($holder.projectId -ceq '11' -and $holder.randomToken -ceq $nonce -and $holder.ownerPID -eq $t.ownerPID -and $holder.ownerProcessStartIdentity -ceq $t.ownerStartIdentity) 'CANONICAL_OWNER'
  $owner=Get-Process -Id $t.ownerPID
  Need (('FILETIME:'+$owner.StartTime.ToUniversalTime().ToFileTimeUtc()) -ceq $t.ownerStartIdentity) 'OWNER_BIRTH'
 }else{
 Need ($t.repository -ceq 'pouriajamali/tail-latency-evidence-bench' -and $env:GITHUB_REPOSITORY -ceq $t.repository -and $env:GITHUB_REF -ceq ('refs/heads/'+$t.branch) -and $env:GITHUB_ACTOR -ceq $t.actor) 'CI_IDENTITY'
 Need ($env:GITHUB_EVENT_NAME -ceq 'workflow_dispatch' -and $env:GITHUB_RUN_ATTEMPT -ceq '1' -and $sourceCommit -cmatch '^[0-9a-f]{40}$') 'SINGLE_DISPATCH'
 }
 $start=[long]$t.window.startUnix;$deadline=[long]$t.window.deadlineUnix
 function TimeLeft([int]$reserve=30){[Math]::Max(0,[Math]::Min($deadline-[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()/1000.0-$reserve,$deadline-$entryUtc-$entryWatch.Elapsed.TotalSeconds-$reserve))}
 Need ($deadline-$start -eq 300 -and [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() -ge $start -and (TimeLeft) -gt 0) 'WHOLE_CLOCK'
 $expectedLimits=@{memory=536870912;active=16;cpuRate=1000;affinityMax=2;whole=300;work=270;terminal=30;role=20;qualification=60;scratch=1073741824;proof=8388608;read=67108864;files=256;roleProof=262144;allRoleProof=1048576}
 Need ($t.limits.Count -eq $expectedLimits.Count) 'LIMITS'
 foreach($k in $expectedLimits.Keys){Need ($t.limits[$k] -eq $expectedLimits[$k]) 'LIMITS'}
 Need ($t.protocolSha256 -ceq '9120ca49a0d46673053aa0ec0cdbbc6f00731d71ea0b57ddab09e8fc3ac3ac8b') 'PROTOCOL_PIN'
 Need ($t.runtimeCommit -ceq '6158f7f8a9a8e4fd7c12ed575f427d7117b89801' -and $t.casePlanSha256 -ceq '7ac106ea67b7e990dfa19a4b3a0ae33b941b7b86a00b986f8ef56350c2bddf3a') 'FROZEN_INPUT'
 Need (($t.nativeOrder -join ',') -ceq 'win-99,win-100,win-101,linux-99,linux-100,linux-101') 'CASE_ORDER'
 Need ((Hash (Join-Path $work 'source-manifest.json')) -ceq $t.sourceManifestSha256) 'SOURCE_MANIFEST'
 $manifest=Get-Content -LiteralPath (Join-Path $work 'source-manifest.json') -Raw|ConvertFrom-Json -AsHashtable
 Need ($manifest.schema -ceq 'tail11-ci-source-manifest/v1' -and $manifest.files.Count -le 32) 'SOURCE_SET'
 foreach($n in $manifest.files.Keys){
  $p=[IO.Path]::GetFullPath((Join-Path $work $n));Need ($p.StartsWith($work+[IO.Path]::DirectorySeparatorChar) -and (Hash $p) -ceq $manifest.files[$n]) 'SOURCE_DRIFT'
 }
 Need ((Hash (Join-Path $repo 'tools/oracle.py')) -ceq '82c6998225f6bd38d1df941ceb49e13d3adcfb16678780a6a25da17e56ebe1bf' -and
       (Hash (Join-Path $repo 'tools/verify_downloads.py')) -ceq '53f5df7d21c1147f7eb4f8f5c4e4292d206ae09eba91939d7baeddc67aec66a4') 'FROZEN_TOOLS'
 # Preinstalled only: no setup-python, package installation or alternate executable search.
 $python=if($Local){Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Programs/Python/Python312/python.exe'}else{Join-Path $env:RUNNER_TOOL_CACHE 'Python/3.12.10/x64/python.exe'}
 $pwsh=(Get-Process -Id $PID).Path
 $ssh='C:\Windows\System32\OpenSSH\ssh-keygen.exe'
 $pins=[ordered]@{
  python=@($python,'4d6f5f81a4bca11191c4c7c6b43632694d0a4ce74e068619d8fdc161d469859a')
  pythonDLL=@((Join-Path (Split-Path -Parent $python) 'python312.dll'),'9a0e3435aaa680d868150f87ab3e388ad2eebc22f87e036155c7b4eda8cd2120')
  pwsh=@($pwsh,'2a6769a3330dc1084d0154bfde7d164ab750ca7f700f313f9d417c1be78b2233')
  ssh=@($ssh,'c9dc170cd161db87e75eb6cf282f1325005b9e35628b9a36cb19883a8be1a34f')
 }
 $toolRows=@();$initialRead=0;$toolsMatch=$true
 foreach($k in $pins.Keys){
  Need ((TimeLeft) -gt 0) 'WHOLE_CLOCK'
  $p=$pins[$k][0];$h=$null;$size=0
  if(Test-Path -LiteralPath $p -PathType Leaf){$size=(Get-Item -LiteralPath $p).Length;Need ($size -le 33554432 -and $initialRead+$size -le 67108864) 'TOOL_READ_CAP';$h=Hash $p;$initialRead+=$size}
  $match=$h -ceq $pins[$k][1];if(-not $match){$toolsMatch=$false}
  $toolRows+=@{tool=$k;bytes=$size;sha256=$h;expectedSha256=$pins[$k][1];matches=$match}
 }
 Fresh (Join-Path $public 'critical-tools.json') @{status=$(if($toolsMatch){'EXACT_PINS_MATCH'}else{'HOLD_CRITICAL_TOOL_IDENTITY'});tools=$toolRows;imageVersion=$(if($Local){'LOCAL_EXISTING_WINDOWS'}else{$env:ImageVersion});runnerOS=$(if($Local){'Windows'}else{$env:RUNNER_OS});nativeCalls=0;SDK=0;trustChanged=$false}
 Need $toolsMatch 'CRITICAL_TOOL_IDENTITY'
 if(-not $Local){
 # Existing independently trusted public key; this file is never a new key or account setting.
 $keyLine=(Get-Content -LiteralPath (Join-Path $work 'metadata/SIGNING-PUBLIC-KEY.pub') -Raw).Trim()
 $blob=[Convert]::FromBase64String(($keyLine -split ' ')[1]);$fingerprint='SHA256:'+([Convert]::ToBase64String([Security.Cryptography.SHA256]::HashData($blob))).TrimEnd('=')
 Need ($fingerprint -ceq 'SHA256:AgU5bZlJSjUu0KsWMmVEEr+BfXpcMVNroTA33bHcQdU') 'SIGNER'
 $signers=Join-Path $out 'source-signers';[IO.File]::WriteAllText($signers,'pouriajamali '+(($keyLine -split ' ')[0..1] -join ' ')+"`n",[Text.UTF8Encoding]::new($false))
 & git -C $repo -c "gpg.ssh.allowedSignersFile=$signers" -c "gpg.ssh.program=$ssh" verify-commit $sourceCommit 2>$null |Out-Null
 Need ($LASTEXITCODE -eq 0) 'SIGNED_COMMIT'
 # Old attempts are immutable: neither workflow rerun nor a second dispatch may consume this ticket.
 $headers=@{Authorization='Bearer '+$env:M1_API_TOKEN;Accept='application/vnd.github+json';'X-GitHub-Api-Version'='2026-03-10'}
 $uri='https://api.github.com/repos/'+$t.repository+'/actions/workflows/verify.yml/runs?event=workflow_dispatch&head_sha='+$sourceCommit+'&per_page=100'
 $runs=Invoke-RestMethod -Uri $uri -Headers $headers -TimeoutSec ([Math]::Min(10,(TimeLeft)))
 $ids=@($runs.workflow_runs|Where-Object {$_.head_sha -ceq $sourceCommit}|ForEach-Object {[long]$_.id})
 Need ($runs.total_count -lt 100 -and $ids.Count -gt 0 -and $ids.Count -eq @($ids|Select-Object -Unique).Count -and ($ids|Measure-Object -Minimum).Minimum -eq [long]$runId) 'RUN_ALREADY_CONSUMED'
 $headers.Clear();$env:M1_API_TOKEN=$null
 }
 Add-Type -TypeDefinition (Get-Content -LiteralPath (Join-Path $work 'job_bridge11.cs') -Raw)
 $tmp=Join-Path $out 'tmp';[IO.Directory]::CreateDirectory($tmp)|Out-Null
 $frame=[ordered]@{schema='tail11-ci-runtime/v1';projectId='11';runNonce=$nonce;executionWindow=$t.window;limits=$t.limits;sourceHashes=$manifest.files;
  signedTicketVerified=(-not $Local);sourceCommit=$sourceCommit;runId=$runId;ticketSha256=$ticketSha;runtimeCommit=$t.runtimeCommit;casePlanSha256=$t.casePlanSha256;
  legacyException='PRIVATE_6158_10.0.14_ONLY';status='QUALIFICATION_ONLY';inputVerified=$false;initialToolReadBytes=$initialRead;
  programDataSha256=([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($env:ProgramData)))).ToLowerInvariant();
  sshKeygen=@{path=$ssh;sha256=$pins.ssh[1]};oracle=@{'win-x64'=@{path=(Join-Path $repo 'tools/oracle.py');sha256='82c6998225f6bd38d1df941ceb49e13d3adcfb16678780a6a25da17e56ebe1bf'}}}
 if($Local){
  $frame['execution']='LOCAL_CANONICAL';$frame['canonicalProtocolPath']=$canonicalProtocol;$frame['canonicalLeasePath']=$canonicalLease
  Need ($t.exactProvider.scope -ceq 'EXACT_M1_FILE_ONLY') 'EXACT_PROVIDER_SCOPE'
  Add-Type -TypeDefinition (Get-Content -LiteralPath (Join-Path $work 'provider_file_reader.cs') -Raw)
  $providerHeld=[Tail11ExactProvider]::new([Tail11ExactProvider]::ExactPath)
  Need ($providerHeld.Sha256 -ceq '74ee1ab7ce1671b1679a1e1a6d41a48797189cba98fbbbb2ee045bcd0ad41056' -and $providerHeld.Before.Volume -eq 3400468440 -and (([uint64]$providerHeld.Before.IndexHi -shl 32) -bor $providerHeld.Before.IndexLo) -eq 389279892790845374 -and $providerHeld.Before.SizeLo -eq 309528 -and $providerHeld.Before.SizeHi -eq 0) 'EXACT_PROVIDER_PRESTART_PIN'
  $frame['exactProvider']=@{scope='EXACT_M1_FILE_ONLY';runNonce=$nonce;window=$t.window;proofs=$t.exactProvider.proofs;reusedControls=$t.exactProvider.reusedControls;
    preheldFile=@{sha256=$providerHeld.Sha256;volume=$providerHeld.Before.Volume;fileIndex=(([uint64]$providerHeld.Before.IndexHi -shl 32) -bor $providerHeld.Before.IndexLo);ntPath=$providerHeld.HeldNtPath;imageSize=$providerHeld.ImageSize}}
  Fresh (Join-Path $out 'provider-held-before-any-child.json') $frame.exactProvider
 }
 function Run-Phase([string]$label,[string]$script,[string[]]$arguments,[int]$maximum,[string]$mode='normal'){
  Need ((TimeLeft) -gt 0) 'WHOLE_CLOCK'
  Pinned-Plan $t.casePlanSha256
  $fp=Join-Path $out ("frame-$label.json");Fresh $fp $frame
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
   # Direct fixed-module entry avoids runpy/pkgutil synthetic namespaces. No new origin is admitted.
   Need ($script -cin @('aggregate_worker.py','experiment.py','local_binding_checks.py')) 'FIXED_ENTRY_MODULE'
   $module=if($script -ceq 'aggregate_worker.py'){'aggregate_worker'}elseif($script -ceq 'experiment.py'){'experiment'}else{'local_binding_checks'}
   $entry="import sys;sys.path[:0]=[sys.argv.pop(1),sys.argv.pop(1)];import $module as m;m.main()"
   $argv=@($python,'-I','-S','-B','-X',"pycache_prefix=$cache");if($mode -ceq 'optimized'){$argv+='-O'}
   $argv+=@('-c',$entry,$work,(Join-Path $repo 'tools'),'--attachment',$fp,'--attachment-sha',(Hash $fp))+$arguments
   $command=[Text.StringBuilder]::new((($argv|ForEach-Object{[Tail11DiagnosticJob]::Quote([string]$_)}) -join ' '))
   $si=[Tail11DiagnosticJob+STARTUP]::new();$si.cb=[Runtime.InteropServices.Marshal]::SizeOf($si)
   [Tail11DiagnosticJob]::Check([Tail11DiagnosticJob]::CreateProcess($python,$command,[IntPtr]::Zero,[IntPtr]::Zero,$false,0x08000404,$environment,$work,[ref]$si,[ref]$pi),'CREATE_SUSPENDED')
   $script:children++;$script:terminal=$false
   [Tail11DiagnosticJob]::Check([Tail11DiagnosticJob]::AssignProcessToJobObject($job,$pi.Process),'ASSIGN_BEFORE_RESUME');$assigned=$true
   $member=$false;[Tail11DiagnosticJob]::Check([Tail11DiagnosticJob]::IsProcessInJob($pi.Process,$job,[ref]$member),'MEMBERSHIP');Need $member 'MEMBER'
   $created=[Tail11DiagnosticJob+FT]::new();$exited=[Tail11DiagnosticJob+FT]::new();$kernel=[Tail11DiagnosticJob+FT]::new();$user=[Tail11DiagnosticJob+FT]::new()
   [Tail11DiagnosticJob]::Check([Tail11DiagnosticJob]::GetProcessTimes($pi.Process,[ref]$created,[ref]$exited,[ref]$kernel,[ref]$user),'BIRTH')
   $profile=@{nonce=$nonce;childPid=$pi.Pid;processCreationFileTime=(([uint64]$created.High -shl 32) -bor $created.Low);jobMembership=$member;cpuRate=$rate.Rate;jobMemoryBytes=$actual.JobMemory.ToUInt64();activeProcessLimit=$actual.Basic.ActiveLimit;affinityMask=$affinity;killOnClose=$true;breakawayDisabled=$true;beforeResume=$true}
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
 if($Local){
  Need ((Hash $t.reuseLocalControls.path) -ceq $t.reuseLocalControls.sha256 -and $t.reuseLocalControls.sha256 -ceq '9ff5e090a3954da50cd769ab811956168cdce35dddc1fb8709eecc5f523e0cb9') 'REUSE_EXISTING_LOCAL_CONTROLS'
  Fresh (Join-Path $public 'local-controls-reused.json') @{status='PRIOR_NINE_HEALTHY_CONTROLS_REUSED_NOT_REPEATED';receiptSHA256=$t.reuseLocalControls.sha256;sourceCommit='426cd5043c2f6863c3d05739b8da0b8d4a752694';testsReplayed=0}
 }
 $qualStart=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
 foreach($role in @('input-worker-imports','frozen-verifier-imports')){Run-Phase $role 'aggregate_worker.py' @('--role',$role,'--rid','win-x64') 20}
 Need ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds()-$qualStart -le 60) 'QUALIFICATION60'
 $union=@{};$read=$initialRead;$proofBytes=0
 foreach($role in @('input-worker-imports','frozen-verifier-imports')){
  $p=Join-Path $out "qualification/$role.json";$proofBytes+=(Get-Item -LiteralPath $p).Length;$q=Get-Content -LiteralPath $p -Raw|ConvertFrom-Json -AsHashtable
  Need ($q.status -ceq 'QUALIFIER_ROLE_COMPLETE' -and $q.runNonce -ceq $nonce -and $q.unresolved.Count -eq 0) 'ROLE_BINDING'
  $read+=$q.newlyReadBytes;foreach($r in $q.consumingFiles){$union[$r.path]=$r}
 }
 Need ($read -le 67108864 -and $union.Count -le 256 -and $proofBytes -le 1048576) 'QUALIFIER_UNION_CAPS'
 $frame['consumingFiles']=@($union.Values)
 # Same wrong-plan predicate as the source-bound worker, before any target child.
 $actualPlan=Hash (Join-Path $work 'case-plan.json');$wrong='0'*64
 Pinned-Plan $t.casePlanSha256
 $denied=$false
 try{Pinned-Plan $wrong}catch{if($_.Exception.Message -ceq 'CASE_PLAN_IDENTITY_DENIED'){$denied=$true}else{throw}}
 Need $denied 'IDENTITY_DENIAL'
 Fresh (Join-Path $public 'identity-denial.json') @{status='IDENTITY_DENIED_BEFORE_CHILD_START';wrongExpected=$wrong;actual=$actualPlan;nativeCalls=0}
 Run-Phase 'held-probe' 'experiment.py' @('--rid','win-x64','--phase','probe','--cap','99','--mode','normal') 20
 $admission=Join-Path $out 'control-admission.json'
 Fresh $admission @{status='PASS_HELD_CHILD_TERMINAL_AND_IDENTITY_DENIAL';originalHandleWait=$true;active=0;wrongIdentityDenied=$true}
 Run-Phase 'stage-input' 'aggregate_worker.py' @('--role','stage','--rid','win-x64') 60
 $frame['status']='ADMITTED_M1_DECLARED_SCOPE';$frame['inputVerified']=$true
 $frame['inputs']=@{'win-x64'=(Get-Content -LiteralPath (Join-Path $out 'win-x64/staged-input.json') -Raw|ConvertFrom-Json -AsHashtable)}
 $frame['actualControllerAdmission']=@{'win-x64'=@{status='PASS_HELD_CHILD_TERMINAL_AND_IDENTITY_DENIAL';path=$admission;sha256=(Hash $admission)}}
 foreach($cap in @(99,100,101)){Run-Phase "case-$cap" 'experiment.py' @('--rid','win-x64','--phase','case','--cap',"$cap",'--mode','normal') 60}
 foreach($mode in @('normal','optimized')){Run-Phase "validate-$mode" 'experiment.py' @('--rid','win-x64','--phase','validate','--cap','99','--mode',$mode) 60 $mode}
 # Public data copies only: full role/provider/attachment paths remain private to the ephemeral VM.
 foreach($cap in @(99,100,101)){
  [IO.Directory]::CreateDirectory((Join-Path $public "win-x64/cap-$cap"))|Out-Null
  foreach($n in @('summary.json','raw.csv')){Copy-Item -LiteralPath (Join-Path $out "win-x64/cap-$cap/$n") -Destination (Join-Path $public "win-x64/cap-$cap/$n") -ErrorAction Stop}
 }
 foreach($mode in @('normal','optimized')){$v=Get-Content -LiteralPath (Join-Path $out "win-x64/validators-$mode.json") -Raw|ConvertFrom-Json -AsHashtable;$v.Remove('profile');Fresh (Join-Path $public "validators-$mode.json") $v}
 $code='WINDOWS_M1_RECORDED_NOT_SPEED'
}catch{
 $candidate=[string]$_.Exception.Message
 if($candidate -cmatch '^[A-Z][A-Z0-9_]{0,99}$'){$code=$candidate}
}finally{
 if($null -ne $providerHeld){
  try{
   Need $terminal 'PROVIDER_TERMINAL_UNKNOWN'
   $providerHeld.SealStable()
   Need ($providerHeld.Stable -and $providerHeld.AfterSha256 -ceq $providerHeld.Sha256) 'PROVIDER_FINAL_HELD_DRIFT'
   Fresh (Join-Path $out 'provider-held-after-all-terminal.json') @{stable=$providerHeld.Stable;sha256=$providerHeld.AfterSha256;allOwnedTerminal=$terminal;allChildren=$children;explicitFileReadBytes=$providerHeld.ExplicitFileReadBytes}
  }catch{$code='PROVIDER_FINAL_HOLD'}finally{$providerHeld.Dispose()}
 }
 $env:M1_API_TOKEN=$null
 $files=@();$proofSize=0
 foreach($p in Get-ChildItem -LiteralPath $public -Recurse -File){$proofSize+=$p.Length;$files+=@{name=[IO.Path]::GetRelativePath($public,$p.FullName).Replace('\','/');bytes=$p.Length;sha256=(Hash $p.FullName)}}
 if($proofSize -gt 8388608){$code='PUBLIC_PROOF_CAP'}
 Fresh (Join-Path $public 'result.json') @{schema=$(if($Local){'tail11-local-terminal/v1'}else{'tail11-ci-terminal/v1'});status=$code;projectId='11';runNonce=$nonce;sourceCommit=$sourceCommit;runId=$runId;attempt=$env:GITHUB_RUN_ATTEMPT;ticketSha256=$ticketSha;
  allOwnedTerminal=$terminal;childrenStarted=$children;nativeCalls=$(if(Test-Path -LiteralPath (Join-Path $out 'win-x64')){@(Get-ChildItem -LiteralPath (Join-Path $out 'win-x64') -Filter 'attempt-cap-*.json' -File).Count}else{0});files=$files;proofBytes=$proofSize;trustChanged=$false;securityChanged=$false;healthyReplay=0;SDK=0}
}
if($code -cne 'WINDOWS_M1_RECORDED_NOT_SPEED'){Write-Host "M1 HOLD: $code";exit 1}
Write-Host 'Windows fixed M1 evidence recorded; local canonical controller owns final acceptance.'
