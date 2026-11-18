param([Parameter(Mandatory)][string]$Frame,[Parameter(Mandatory)][string]$FrameSha256)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
function Need($v,[string]$c){if(-not $v){throw $c}}
function Hash([string]$p){(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()}
$f=Get-Content -LiteralPath $Frame -Raw|ConvertFrom-Json -AsHashtable
Need ((Hash $Frame) -ceq $FrameSha256 -and (Hash $f.sourcePath) -ceq $f.sourceSha256) 'FRAME_SOURCE'
Need ((Hash $f.timestampActionPath) -ceq '1d38f2af453d2664b15974b24381293f0b35f203a6d5e3a8040fdc6126232a32') 'TIMESTAMP_ACTION'
$action=Get-Content -LiteralPath $f.timestampActionPath -Raw|ConvertFrom-Json -AsHashtable
Need ((Hash $f.existingFileProofs.path) -ceq $f.existingFileProofs.sha256 -and $f.existingFileProofs.sha256 -ceq $action.existingFileProofs.sha256) 'EXISTING_FILE_PROOF'
$old=Get-Content -LiteralPath $f.existingFileProofs.path -Raw|ConvertFrom-Json -AsHashtable
Need (@($old.records|Where-Object {$_.status -ceq 'PASS_EXACT_FILE_NATIVE_SIGNATURE_CURRENT_CACHED_CHAIN'}).Count -eq 4) 'FOUR_REUSED_PROOFS'
$profile=Get-Content -LiteralPath $f.profilePath -Raw|ConvertFrom-Json -AsHashtable
Need ($profile.childPid -eq $PID -and $profile.nonce -ceq $f.nonce) 'CHILD_IDENTITY'
$holder=Get-Content -LiteralPath $f.leasePath -Raw|ConvertFrom-Json -AsHashtable
Need ((Hash $f.protocolPath) -ceq '9120ca49a0d46673053aa0ec0cdbbc6f00731d71ea0b57ddab09e8fc3ac3ac8b' -and $holder.projectId -ceq '11' -and $holder.randomToken -ceq $f.nonce -and $holder.ownerPID -eq $f.ownerPID -and $holder.ownerProcessStartIdentity -ceq $f.ownerStartIdentity) 'CANONICAL_OWNER'
Add-Type -TypeDefinition (Get-Content -LiteralPath $f.sourcePath -Raw)
$kernel=[Tail11ExactProvider]::CurrentKernel($f.nonce,[uint64]$profile.processCreationFileTime)
$watch=[Diagnostics.Stopwatch]::StartNew();$io=[Tail11ExactProvider]::CurrentReadBytes()
function Clock {Need ($watch.Elapsed.TotalSeconds -lt 20 -and [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()/1000.0 -lt $f.phaseDeadlineUnix -and [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() -lt $f.window.deadlineUnix-30) 'ABSOLUTE_ROLE_CLOCK'}
function CertData($c){@{subject=$c.Subject;issuer=$c.Issuer;serial=$c.SerialNumber;sha256=([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($c.RawData))).ToLowerInvariant();notBeforeUtc=$c.NotBefore.ToUniversalTime().ToString('o');notAfterUtc=$c.NotAfter.ToUniversalTime().ToString('o')}}
function Independent($ders,[datetime]$at,[string]$eku){
 Clock;$certs=@();foreach($der in $ders){$certs+=[Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]]$der)}
 $chain=[Security.Cryptography.X509Certificates.X509Chain]::new($true)
 try{
  $chain.ChainPolicy.DisableCertificateDownloads=$true;$chain.ChainPolicy.RevocationMode=[Security.Cryptography.X509Certificates.X509RevocationMode]::Offline;$chain.ChainPolicy.RevocationFlag=[Security.Cryptography.X509Certificates.X509RevocationFlag]::ExcludeRoot;$chain.ChainPolicy.VerificationFlags=[Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag;$chain.ChainPolicy.UrlRetrievalTimeout=[TimeSpan]::Zero;$chain.ChainPolicy.VerificationTime=$at
  [void]$chain.ChainPolicy.ApplicationPolicy.Add([Security.Cryptography.Oid]::new($eku));foreach($c in $certs){[void]$chain.ChainPolicy.ExtraStore.Add($c)}
  $valid=$chain.Build($certs[0]);Need ($chain.ChainElements.Count -ge 2 -and $chain.ChainElements.Count -le 12) 'INDEPENDENT_CHAIN_BOUND';$els=@();foreach($e in $chain.ChainElements){$els+=@{certificate=(CertData $e.Certificate);statuses=@($e.ChainElementStatus|ForEach-Object {$_.Status.ToString()})}}
  return @{valid=$valid;statuses=@($chain.ChainStatus|ForEach-Object {$_.Status.ToString()});elements=$els;referenceUtc=$at.ToUniversalTime().ToString('o');native=[Tail11ExactProvider]::ReadChain($chain.ChainContext);revocationMode='Offline';verificationFlags='NoFlag';disableCertificateDownloads=$true;rootMode='ExistingSystemRoots'}
 }finally{$chain.Dispose();foreach($c in $certs){$c.Dispose()}}
}
function CurrentRevocation($chain,[uint64]$now){
 if(-not $chain.native.present -or $chain.native.simpleChains.Count -ne 1){return $false}
 $els=$chain.native.simpleChains[0].elements
 if($els.Count -ne $chain.elements.Count){return $false}
 for($j=0;$j -lt $els.Count-1;$j++){
  $e=$els[$j]
  if($e.sha256 -cne $chain.elements[$j].certificate.sha256 -or -not $e.revocationPresent -or $e.revocationResult -ne 0 -or -not $e.crlInfoPresent -or -not $e.ContainsKey('baseCRL') -or $null -eq $e.baseCRL -or $e.revokedEntryPresent){return $false}
  foreach($crl in @($e.baseCRL,$e.deltaCRL)) {if($null -ne $crl -and -not ($crl.thisUpdateFileTime -le $now -and $now -lt $crl.nextUpdateFileTime)){return $false}}
 }
 return $true
}
Need ($f.providerInputs.Count -eq 2) 'EXACT_TWO_COUNT'
$records=@();$explicit=0
foreach($inputRow in $f.providerInputs){
 $held=$null;$record=@{exactPath=$inputRow.path;status='HOLD';originalCurrentChainValid=$false;originalCurrentChainStatus=@('NotTimeValid')}
 try{
  Clock;$expected=@($action.exactFailedInputs|Where-Object {$_.path -ieq $inputRow.path});Need ($expected.Count -eq 1) 'EXACT_TWO_PATH';$expected=$expected[0]
  Need ($inputRow.sha256 -ceq $expected.rawSHA256) 'PARENT_HELD_RAW_SHA256'
  foreach($key in @('bytes','volume','fileIndex','links','created','written')){Need ($inputRow.identity[$key] -eq $expected.identity[$key]) 'PARENT_EXACT_IDENTITY'}
  $held=[Tail11ExactProvider]::new($inputRow.path,$true);$i=$expected.identity
  Need ($held.Before.Volume -eq $i.volume -and (([uint64]$held.Before.IndexHi -shl 32) -bor $held.Before.IndexLo) -eq $i.fileIndex -and (([uint64]$held.Before.SizeHi -shl 32) -bor $held.Before.SizeLo) -eq $i.bytes -and $held.Before.Links -eq $i.links -and $held.Before.Created.Value -eq $i.created -and $held.Before.Written.Value -eq $i.written) 'HELD_CURRENT_IDENTITY'
  $native=$held.VerifyCacheOnly();$mode='EMBEDDED_NATIVE';if($held.WinTrustStatusHex -ceq '0x800B0100'){$native=$held.VerifyCatalogCacheOnly();$mode='EXISTING_LOCAL_CATALOG'}
  $record.nativeStatus=('0x{0:X8}' -f [uint32]([int64]$native -band 0xffffffffL));$record.nativeMode=$mode;$record.signerError=$held.CatalogSignerError;$record.primaryVerifyAsOfFileTime=$held.PrimaryVerifyAsOfFileTime;$record.timestamps=@($held.TimestampMetadata);$record.counterSignerCount=$held.CounterSignerCount
  Need ($native -eq 0 -and $held.CatalogSignerError -eq 0 -and $held.CatalogChainDER.Count -ge 2) 'NATIVE_SIGNATURE'
  $leaf=[Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]]$held.CatalogChainDER[0]);try{Need ((CertData $leaf).sha256 -ceq $expected.signer.sha256) 'EXACT_SIGNER'}finally{$leaf.Dispose()}
  # Collect both current and historical chains even if a later predicate fails.
  $now=[datetime]::UtcNow;$nowFT=[uint64]$now.ToFileTimeUtc()
  $record.currentSignerChain=Independent $held.CatalogChainDER $now '1.3.6.1.5.5.7.3.3'
  $record.currentSignerNonrevocation=CurrentRevocation $record.currentSignerChain $nowFT
  Need ($held.CounterSignerCount -eq 1) 'AUTHENTICATED_TIMESTAMP_MISSING_OR_AMBIGUOUS'
  $ts=$held.TimestampMetadata[0];Need ($ts.type -eq 16 -and $ts.error -eq 0 -and $ts.hasChainContext -and $ts.certificateCount -ge 2 -and $ts.verifyAsOfFileTime -eq $held.PrimaryVerifyAsOfFileTime -and $ts.verifyAsOfFileTime -lt $nowFT) 'AUTHENTICATED_TIMESTAMP_STATE'
  $at=[datetime]::FromFileTimeUtc([long]$held.PrimaryVerifyAsOfFileTime);$record.authenticatedReferenceUtc=$at.ToString('o')
  $tders=[Collections.Generic.List[byte[]]]::new();foreach($der in $ts.chainDER){$tders.Add([Convert]::FromBase64String($der))}
  $record.signerAtTimestamp=Independent $held.CatalogChainDER $at '1.3.6.1.5.5.7.3.3'
  $record.timestampAtTimestamp=Independent $tders $at '1.3.6.1.5.5.7.3.8'
  $record.currentTimestampChain=Independent $tders $now '1.3.6.1.5.5.7.3.8'
  $record.currentTimestampNonrevocation=CurrentRevocation $record.currentTimestampChain $nowFT
  Need ($record.signerAtTimestamp.valid -and $record.signerAtTimestamp.statuses.Count -eq 0 -and $record.timestampAtTimestamp.valid -and $record.timestampAtTimestamp.statuses.Count -eq 0) 'HISTORICAL_NOFLAG_CHAIN_NOT_ACCEPTED'
  Need ($record.currentSignerNonrevocation -and $record.currentTimestampNonrevocation) 'PRESENT_TIME_NONREVOCATION_NOT_PROVEN'
  # No errors other than the separately preserved current-time validity result.
  Need (@($record.currentSignerChain.statuses|Where-Object {$_ -cne 'NotTimeValid'}).Count -eq 0 -and @($record.currentTimestampChain.statuses|Where-Object {$_ -cne 'NotTimeValid'}).Count -eq 0) 'CURRENT_CHAIN_OTHER_ERROR'
  $record.status='PASS_EXACT_AUTHENTICATED_TIMESTAMP_AND_CURRENT_NONREVOCATION'
 }catch{$code=$_.Exception.Message;if($code -cnotmatch '^[A-Z][A-Z0-9_]{0,99}$'){$code='TIMESTAMP_SUPPLEMENT_HOLD'};$record.code=$code;$record.exceptionType=$_.Exception.GetType().Name}
 finally{if($null -ne $held){try{$held.SealMetadataOnly();$record.stableMetadata=$held.Stable}catch{$record.status='HOLD';$record.code='HELD_IDENTITY_SEAL_FAILED'};$held.Dispose()};$records+=,$record}
 Need ([Tail11ExactProvider]::CurrentReadBytes()-$io -le 67108864) 'ROLE_READ_CAP'
}
$pass=@($records|Where-Object {$_.status -ceq 'PASS_EXACT_AUTHENTICATED_TIMESTAMP_AND_CURRENT_NONREVOCATION'}).Count -eq 2
$proof=@{schema='tail11-exact-two-timestamp-supplement/v1';status=$(if($pass){'ALL_EXACT_SIX_FILE_PROOFS_PASS'}else{'HOLD_TWO_TIMESTAMP_PROOFS_NO_SSH_ALLOWED'});records=$records;actualKernel=$kernel;nativeSignatureReadBytes=([Tail11ExactProvider]::CurrentReadBytes()-$io);fourHealthyProofsReusedSHA256=$f.existingFileProofs.sha256;fourHealthyProofsReplayed=0;networkGETs=0;systemTrustClockCacheOrProtectionChanged=$false;nonce=$f.nonce;sourceSha256=$f.sourceSha256}
$b=[Text.UTF8Encoding]::new($false).GetBytes(($proof|ConvertTo-Json -Depth 40 -Compress)+"`n");Need ($b.Length -le 262144) 'ROLE_PROOF_CAP';$w=[IO.File]::Open($f.receiptPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$w.Write($b);$w.Flush($true)}finally{$w.Dispose()}
