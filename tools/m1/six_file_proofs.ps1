param([Parameter(Mandatory)][string]$Frame,[Parameter(Mandatory)][string]$FrameSha256)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
function Need($v,[string]$c){if(-not $v){throw $c}}
function Hash([string]$p){(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()}
$f=Get-Content -LiteralPath $Frame -Raw|ConvertFrom-Json -AsHashtable
Need ((Hash $Frame) -ceq $FrameSha256 -and $f.schema -ceq 'tail11-exact-provider-read-frame/v1') 'FRAME_IDENTITY'
Need ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() -lt $f.window.deadlineUnix-30) 'WORK_DEADLINE'
Need ((Hash $f.scopePath) -ceq $f.scopeSha256 -and (Hash $f.sourcePath) -ceq $f.sourceSha256) 'READ_SCOPE_AND_SOURCE'
$profile=Get-Content -LiteralPath $f.profilePath -Raw|ConvertFrom-Json -AsHashtable
Need ($profile.childPid -eq $PID -and $profile.nonce -ceq $f.nonce) 'ACTUAL_CHILD_IDENTITY'
Need ((Hash $f.protocolPath) -ceq '9120ca49a0d46673053aa0ec0cdbbc6f00731d71ea0b57ddab09e8fc3ac3ac8b') 'ACTUAL_PROTOCOL'
$holder=Get-Content -LiteralPath $f.leasePath -Raw|ConvertFrom-Json -AsHashtable
Need ($holder.projectId -ceq '11' -and $holder.randomToken -ceq $f.nonce -and $holder.ownerPID -eq $f.ownerPID -and $holder.ownerProcessStartIdentity -ceq $f.ownerStartIdentity) 'ACTUAL_CANONICAL_OWNER'
Add-Type -TypeDefinition (Get-Content -LiteralPath $f.sourcePath -Raw)
$kernel=[Tail11ExactProvider]::CurrentKernel($f.nonce,[uint64]$profile.processCreationFileTime)
function CertData($cert){
 $raw=$cert.RawData;Need ($raw.Length -le 65536 -and -not $cert.HasPrivateKey) 'PUBLIC_CERT_BOUND'
 [ordered]@{subject=$cert.Subject;issuer=$cert.Issuer;serial=$cert.SerialNumber;sha256=([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($raw))).ToLowerInvariant();notBeforeUtc=$cert.NotBefore.ToUniversalTime().ToString('o');notAfterUtc=$cert.NotAfter.ToUniversalTime().ToString('o');hasPrivateKey=$false}
}
$records=@();$chainCache=@{};$chainBuildCalls=0;$phaseStart=[Diagnostics.Stopwatch]::StartNew();$ioStart=[Tail11ExactProvider]::CurrentReadBytes()
Need ($f.providerInputs.Count -eq 6) 'EXACT_SIX_COUNT'
foreach($inputRow in $f.providerInputs){
 $held=$null;$record=@{exactPath=$inputRow.path;status='HOLD'}
 try{
  Need ([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()/1000.0 -lt $f.phaseDeadlineUnix -and $phaseStart.Elapsed.TotalSeconds -lt 20) 'FILE_PHASE_CLOCK'
  $held=[Tail11ExactProvider]::new($inputRow.path,$true)
  $i=$inputRow.identity
  Need ($held.Before.Volume -eq $i.volume -and (([uint64]$held.Before.IndexHi -shl 32) -bor $held.Before.IndexLo) -eq $i.fileIndex -and (([uint64]$held.Before.SizeHi -shl 32) -bor $held.Before.SizeLo) -eq $i.bytes -and $held.Before.Links -eq $i.links -and $held.Before.Created.Value -eq $i.created -and $held.Before.Written.Value -eq $i.written) 'PARENT_HELD_EXACT_FILE_IDENTITY'
  $fileStatus=$held.VerifyCacheOnly();$mode='EMBEDDED_NATIVE';$native=$fileStatus
  if($held.WinTrustStatusHex -ceq '0x800B0100'){$native=$held.VerifyCatalogCacheOnly();$mode='EXISTING_LOCAL_CATALOG'}
  $record['embeddedWinTrustStatus']=$held.WinTrustStatusHex;$record['nativeSignatureMode']=$mode;$record['nativeWinTrustStatus']=('0x{0:X8}' -f [uint32]([int64]$native -band 0xffffffffL));$record['catalogPath']=$held.CatalogPath;$record['catalogMemberSHA256']=$held.CatalogMemberHash
  Need ($native -eq 0 -and $held.CatalogSignerError -eq 0 -and $held.CatalogChainDER.Count -ge 1) 'NATIVE_SIGNATURE_NOT_ACCEPTED'
  $certs=@();$certHashes=@();foreach($der in $held.CatalogChainDER){$cert=[Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]]$der);$certs+=$cert;$certHashes+=(CertData $cert).sha256}
  try{
   $cacheKey=$certHashes -join ':'
   if($chainCache.ContainsKey($cacheKey)){$chainRecord=$chainCache[$cacheKey];$record['independentChainReuseFrom']=$chainRecord.exactFirstPath}
   else{
    $chain=[Security.Cryptography.X509Certificates.X509Chain]::new($true)
    try{
     $chain.ChainPolicy.DisableCertificateDownloads=$true;$chain.ChainPolicy.RevocationMode=[Security.Cryptography.X509Certificates.X509RevocationMode]::Offline;$chain.ChainPolicy.RevocationFlag=[Security.Cryptography.X509Certificates.X509RevocationFlag]::ExcludeRoot;$chain.ChainPolicy.VerificationFlags=[Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag;$chain.ChainPolicy.UrlRetrievalTimeout=[TimeSpan]::Zero
     [void]$chain.ChainPolicy.ApplicationPolicy.Add([Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.3'));foreach($cert in $certs){[void]$chain.ChainPolicy.ExtraStore.Add($cert)}
     $chainBuildCalls++;$valid=$chain.Build($certs[0]);Need ($chain.ChainElements.Count -le 12) 'CHAIN_DEPTH_BOUND';$elements=@();foreach($e in $chain.ChainElements){$elements+=@{certificate=(CertData $e.Certificate);statuses=@($e.ChainElementStatus|ForEach-Object {$_.Status.ToString()})}}
     $chainRecord=@{cachedCurrentChainValid=$valid;chainStatus=@($chain.ChainStatus|ForEach-Object {$_.Status.ToString()});signer=(CertData $certs[0]);elements=$elements;verificationTimeUtc=$chain.ChainPolicy.VerificationTime.ToUniversalTime().ToString('o');disableCertificateDownloads=$true;revocationMode='Offline';verificationFlags='NoFlag';exactFirstPath=$inputRow.path}
     if($valid){$chainCache[$cacheKey]=$chainRecord}
    }finally{$chain.Dispose()}
   }
   $record['chain']=$chainRecord;Need ($chainRecord.cachedCurrentChainValid -and $chainRecord.chainStatus.Count -eq 0) 'CURRENT_CACHED_CHAIN_NOT_ACCEPTED'
  }finally{foreach($cert in $certs){$cert.Dispose()}}
  $held.SealMetadataOnly();Need $held.Stable 'HELD_FILE_DRIFT';$record['fileBefore']=$held.Before;$record['fileAfter']=$held.After;$record['stableMetadata']=$held.Stable;$record['parentRawSHA256']=$inputRow.sha256;$record['architecture']=$inputRow.architecture;$record['status']='PASS_EXACT_FILE_NATIVE_SIGNATURE_CURRENT_CACHED_CHAIN'
 }catch{$c=$_.Exception.Message;if($c -cnotmatch '^[A-Z][A-Z0-9_]{0,99}$'){$c='SIX_FILE_NATIVE_PROOF_HOLD'};$record['code']=$c}
 finally{if($null -ne $held){$held.Dispose()};$records+=,$record}
 Need ([Tail11ExactProvider]::CurrentReadBytes()-$ioStart -le 67108864) 'NATIVE_SIGNATURE_IO64M'
}
$passed=@($records|Where-Object {$_.status -ceq 'PASS_EXACT_FILE_NATIVE_SIGNATURE_CURRENT_CACHED_CHAIN'}).Count -eq 6
$outcome=@{schema='tail11-six-exact-file-native-proofs/v1';status=$(if($passed){'ALL_EXACT_SIX_FILE_PROOFS_PASS'}else{'HOLD_SIX_FILE_PROOFS_NO_SSH_ALLOWED'});actualKernel=$kernel;records=$records;nativeSignatureReadBytes=([Tail11ExactProvider]::CurrentReadBytes()-$ioStart);rawBodyExplicitReadBytes=0;independentChainBuilds=$chainBuildCalls;successfulUniqueChainCacheEntries=$chainCache.Count;systemTrustOrProtectionChanged=$false;networkGETs=0;sourceSha256=$f.sourceSha256;nonce=$f.nonce;providerAdmission=$false}
$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($outcome|ConvertTo-Json -Depth 30 -Compress)+"`n");Need ($bytes.Length -le 262144) 'PROOF_CAP';$w=[IO.File]::Open($f.receiptPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$w.Write($bytes);$w.Flush($true)}finally{$w.Dispose()}
