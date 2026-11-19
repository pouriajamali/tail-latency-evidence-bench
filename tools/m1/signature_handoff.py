"""Pinned Linux signature fact plus each consumer's own archive hash. No SSH."""
from pathlib import Path
import contextlib,hashlib,json,os,re,stat
import support as S
INPUTS={'SHA256SUMS.txt':'7ed7c353458a935439066a6a1d205520e5610458ec346dd8dbbf5c8882d28709','SHA256SUMS.txt.sig':'bf4ff680a2c4816b08044c47bb05882f6268576dea30bc1a14e275cfab66e840','SIGNING-PUBLIC-KEY.pub':'cc7038b2d98f856af97b58eb06619ff441fbe9b178da5396f61d1ccdf7a65e7c'}
CRITICAL={'linux_ssh_role.py','linux_role_probe.py','linux_cgroup_launcher.py','support.py','linux_systemd_role.py','linux_dlfo_witness.py','linux_init_write_trace.py','linux_tls_witness.py','linux_loader_initializer_witness.py'}
NAMES=('signature-proof.json','linux-role-terminal.json','FINAL.json','frame.json')

def digest_shape(value):return type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None

def binding_paths():
    path=S.HERE/'metadata/linux-signature-bindings.json';b=S.read(path,32768)
    S.need(b.get('schema')=='tail11-linux-signature-bindings/v1' and b.get('state')=='PINNED_ACTUAL_LINUX_SIGNATURE_RESULT','LINUX_SIGNATURE_RESULT_NOT_PINNED')
    name=b['producerDirectoryName'];S.need(name=='linux-owned-ssh-negative-kernel-reference-fix-once-20261119','LINUX_PRODUCER_DIRECTORY_SCOPE')
    root=S.ROOT.parent/'outputs/wave4-m1-record-cap-20261116';directory=root/name
    S.need(directory.resolve().parent==root.resolve() and not directory.is_symlink(),'LINUX_PRODUCER_PATH_SCOPE')
    S.need(b['reusedDirectoryName']=='linux-owned-ssh-lifecycle-parser-fix-once-20261119','REUSED_PRODUCER_DIRECTORY_SCOPE')
    paths=[directory/n for n in NAMES]+[root/'linux-role-metadata-exact-package-fix-20261118/metadata.json']+[root/b['reusedDirectoryName']/n for n in NAMES]
    return b,paths

def validate_manifest_binding(expected_sources=None):
    b,paths=binding_paths();sources=expected_sources if expected_sources is not None else S.read(S.HERE/'source-manifest.json')['files']
    S.need(set(b['producerCriticalSourceHashes'])==CRITICAL and all(digest_shape(b['producerCriticalSourceHashes'][n]) and b['producerCriticalSourceHashes'][n]==sources.get(n) for n in CRITICAL),'LINUX_SIGNATURE_POLICY_SOURCE_DRIFT')
    S.need(set(b['proofHashes'])==set(NAMES) and all(digest_shape(v) for v in b['proofHashes'].values()),'LINUX_SIGNATURE_PROOF_PINS')
    values=[];read=0
    S.need(set(b['reusedProofHashes'])==set(NAMES),'REUSED_PROOF_PIN_SET')
    for i,p in enumerate(paths):
        raw=S.raw(p,262144);read+=len(raw);expected=(b['proofHashes'][p.name] if i<4 else '8b1d6345f7ae58a9357aa194ced570458c76e799d056fe8e034daa3c0f2b9bef' if i==4 else b['reusedProofHashes'][p.name])
        S.need(hashlib.sha256(raw).hexdigest()==expected,'LINUX_SIGNATURE_PROOF_BYTES');values.append(json.loads(raw))
    p,t,f,frame,meta,prior,pt,pf,pframe=values
    S.need(p.get('schema')=='tail11-owned-linux-signature-proof/v1' and p.get('status')=='QUALIFIED_LINUX_MANIFEST_SIGNATURE' and p.get('admitted') is True and p.get('role')=='LINUX_OPENSSH_MANIFEST_SIGNATURE_ONLY','LINUX_SIGNATURE_ROLE_NOT_ADMITTED')
    nonce=p['nonce'];S.need(type(nonce) is str and re.fullmatch('[0-9a-f]{32}',nonce) and nonce==b['producerNonce']==t['nonce'],'LINUX_SIGNATURE_PRODUCER_NONCE')
    S.need(p.get('fingerprint')==S.FINGERPRINT and p.get('namespace')=='file' and p.get('identity')=='pouriajamali' and p.get('publicSignatureInputs')==INPUTS,'LINUX_SIGNATURE_EXACT_INPUTS')
    S.need(all(p['sourceHashes'].get(n)==b['producerCriticalSourceHashes'][n] for n in CRITICAL),'LINUX_SIGNATURE_ACTUAL_SOURCE')
    S.need(p.get('heldFilesThroughTerminal') is True and p.get('readOnlyImageMatches') is True and p.get('unresolved')==[] and p.get('signatureExecAttempts')==1,'LINUX_SIGNATURE_COMPLETE_ROLE_REQUIRED')
    S.need(p['roleSeconds']<=20 and p['readBytesWithConservativeReserve']<=67108864 and p['nativeM1Calls']==0 and p['networkCalls']==0,'LINUX_SIGNATURE_ROLE_CAPS')
    kernel=p['actualKernel'];S.need(kernel['memoryMax']==536870912 and kernel['swapMax']==0 and kernel['tasksMax']==64 and kernel['cpuMax']==['200000','100000'],'LINUX_SIGNATURE_ACTUAL_KERNEL_CAPS')
    children=p['ownedChildren'];S.need(len(children)==1 and all(c['originalHandleTerminal'] is True and c['execResumed'] is True and c['forced'] is False for c in children),'LINUX_SIGNATURE_ORIGINAL_CHILD_TERMINALS')
    positive=p['positive'];negative=p['negativeManifest'];bad_signature=p['negativeSignature'];closure=positive['closure']
    S.need(positive['exitCode']==0 and positive['qualifiedImage'] is True and positive['originalHandleTerminal'] is True and positive['stdinBytes']==373 and positive['stdinSHA256']==INPUTS['SHA256SUMS.txt'],'LINUX_SIGNATURE_POSITIVE_CRYPTO')
    S.need(negative['exitCode']!=0 and negative['stdinBytes']==373 and negative['stdinSHA256']!=INPUTS['SHA256SUMS.txt'] and bad_signature['exitCode']!=0 and bad_signature['stdinSHA256']==INPUTS['SHA256SUMS.txt'] and all(c['originalHandleTerminal'] is True for c in (negative,bad_signature)),'LINUX_SIGNATURE_NEGATIVE_CONTROLS')
    S.need(bad_signature['earlyMalformedSignatureRejection'] is True and bad_signature['stdinBytes']==0 and bad_signature['stdinOfferedBytes']==373 and bad_signature['qualifiedImage'] is False and bad_signature['closure'] is None,'ACTUAL_EARLY_MALFORMED_SIGNATURE_REJECTION')
    S.need(children[0]['pid']==bad_signature['pid'] and closure['actualChildPID']==positive['pid'],'LINUX_SIGNATURE_CHILD_BINDING')
    reuse=p['reusedNativeControls'];S.need(reuse['healthyNativeTestsRepeated']==0 and reuse['oldHoldNotRelabeled'] is True and prior['status']=='HOLD' and pf['status']=='ROLE_HOLD','OLD_HOLD_NOT_RELABELLED')
    S.need(prior['exceptionType']=='BrokenPipeError' and prior['errno']==32 and prior['positive']==positive and prior['negativeManifest']==negative and reuse['priorNonce']==prior['nonce']==pt['nonce']==pframe['nonce'],'REUSED_ORIGINAL_NATIVE_FACTS')
    S.need(len(reuse['reusedOriginalChildren'])==2 and reuse['reusedOriginalChildren']==prior['ownedChildren'][:2] and all(c['originalHandleTerminal'] and not c['forced'] for c in reuse['reusedOriginalChildren']) and [c['pid'] for c in reuse['reusedOriginalChildren']]==[positive['pid'],negative['pid']],'REUSED_NATIVE_ORIGINAL_WAITS')
    S.need(all(reuse['files'][n]['sha256']==b['reusedProofHashes'][n] for n in NAMES) and pt['frameSHA256']==b['reusedProofHashes']['frame.json'] and pf['observationSHA256']==b['reusedProofHashes']['signature-proof.json'] and pf['terminalSHA256']==b['reusedProofHashes']['linux-role-terminal.json'],'REUSED_SCOPE_HASH_BINDINGS')
    S.need(pt['allOwnedTerminal'] and pt['originalWaitpidReturned'] and pt['cgroupEmpty'] and pt['cgroupRemoved'] and pf['allOwnedTerminal'] and pf['originalPopenWaitReturned'],'REUSED_SCOPE_ACTUALLY_TERMINAL')
    S.need(all(pframe['sourceHashes'][n]==frame['sourceHashes'][n] for n in CRITICAL-{'linux_ssh_role.py'}) and pframe['sourceHashes']['linux_ssh_role.py']==reuse['priorRoleSourceSHA256'],'REUSED_WITNESS_SOURCE_IDENTITY')
    S.need(closure['schema']=='tail11-owned-linux-elf-closure/v1' and closure['unresolved']==[] and closure['readOnlyImageMatches'] is True and closure['validatedImportSlots']>0 and closure['validatedRelocations']>0 and closure['readOnlyBytes']>0,'LINUX_SIGNATURE_ACTUAL_ELF_CLOSURE')
    files=meta['files'];S.need(meta['status']=='METADATA_COMPLETE_NOT_ADMISSION' and meta['admitted'] is False and len(files)==6 and set(closure['mappedFiles'])=={r['path'] for r in files} and p['metadataSHA256']=='8b1d6345f7ae58a9357aa194ced570458c76e799d056fe8e034daa3c0f2b9bef','LINUX_SIGNATURE_METADATA_NOT_ADMISSION')
    S.need(closure['normalImportEdges'] and all(e['resolved'] is True and e['provider'] in closure['mappedFiles'] for e in closure['normalImportEdges']),'LINUX_SIGNATURE_NORMAL_EDGES')
    S.need(t.get('schema')=='tail11-linux-role-terminal/v1' and t.get('status')=='ROLE_COMPLETED' and t['returncode']==0 and t['allOwnedTerminal'] is True and t['originalWaitpidReturned'] is True and t['cgroupEmpty'] is True and t['cgroupRemoved'] is True and t['forced'] is False and t['worker']['pid']==kernel['pid'],'LINUX_SIGNATURE_SCOPE_TERMINAL')
    S.need(t['frameSHA256']==b['proofHashes']['frame.json'] and frame['sourceHashes']==p['sourceHashes'] and frame['nonce']==nonce and t['wholeOwnServiceCollected'] is True and t['originalWaitTarget']=='OWN_SYSTEMD_RUN_STARTER','CURRENT_EXACT_SYSTEMD_SCOPE_BINDING')
    S.need(f.get('status')=='QUALIFIED_LINUX_MANIFEST_SIGNATURE' and f['admissionClaimed'] is True and f['originalPopenWaitReturned'] is True and f['allOwnedTerminal'] is True and f['returncode']==0 and f['observationSHA256']==b['proofHashes'][NAMES[0]] and f['terminalSHA256']==b['proofHashes'][NAMES[1]] and f['window']==p['window'],'LINUX_SIGNATURE_OWNER_TERMINAL')
    sums=S.raw(S.HERE/'metadata/SHA256SUMS.txt',373);read+=len(sums);S.need(len(sums)==373 and hashlib.sha256(sums).hexdigest()==INPUTS['SHA256SUMS.txt'],'SIGNED_MANIFEST_BYTES')
    entries={}
    for line in sums.decode('ascii').splitlines():
        m=re.fullmatch('([0-9a-f]{64})  ([A-Za-z0-9._-]{1,160})',line);S.need(m is not None and m[2] not in entries and len(entries)<64,'SIGNED_MANIFEST_FRAMING');entries[m[2]]=m[1]
    ssh=next(r for r in files if r['path']=='/usr/bin/ssh-keygen')
    return {'schema':'tail11-linux-manifest-data-handoff/v1','role':'LINUX_MANIFEST_SIGNATURE_DATA_NOT_WINDOWS_SSH_ADMISSION','fingerprint':S.FINGERPRINT,'manifestSHA256':INPUTS['SHA256SUMS.txt'],'entries':entries,'producerProofSHA256':b['proofHashes'][NAMES[0]],'producerTerminalSHA256':b['proofHashes'][NAMES[1]],'sshSHA256':ssh['sha256'],'sshBytes':ssh['identity']['bytes'],'readBytes':read,'WindowsSSHAdmitted':False,'globalHostAdmitted':False}

@contextlib.contextmanager
def archive_conjunction(rid,raw,evidence,deadline):
    import fetch_extract as stage
    bundle=validate_manifest_binding();name,size,expected=stage.ASSETS[3 if rid=='win-x64' else 4];path=Path(raw)/name
    S.need(rid in ('win-x64','linux-x64') and bundle['entries'].get(name)==expected,'SIGNED_REQUIRED_ARCHIVE_ENTRY')
    @contextlib.contextmanager
    def held():
        if os.name=='nt':
            with stage.input_held_read(path) as pair:yield pair
        else:
            S.need(path.is_file() and not path.is_symlink(),'ARCHIVE_REGULAR_FILE')
            with path.open('rb') as stream:
                st=os.fstat(stream.fileno());S.need(stat.S_ISREG(st.st_mode) and st.st_nlink==1,'ARCHIVE_FILE_IDENTITY');identity=(st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns);yield stream,{'bytes':st.st_size,'linuxIdentity':list(identity)}
                st=os.fstat(stream.fileno());S.need((st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns)==identity,'ARCHIVE_TERMINAL_IDENTITY')
    with held() as (stream,identity):
        S.need(identity['bytes']==size,'ARCHIVE_EXACT_SIZE');digest=hashlib.sha256();total=0
        while True:
            stage.clock(deadline);block=stream.read(65536)
            if not block:break
            total+=len(block);S.need(total<=size,'ARCHIVE_BOUND');digest.update(block)
        S.need(total==size and digest.hexdigest()==expected,'LOCAL_CONSUMER_ARCHIVE_DIGEST')
        receipt=Path(evidence)/'linux-signature-local-digest.json';S.fresh(receipt,{'schema':'tail11-cross-platform-archive-conjunction/v1','status':'LINUX_SIGNATURE_AND_LOCAL_ARCHIVE_DIGEST_VERIFIED','producerPlatform':'linux-x64','consumerPlatform':rid,'fingerprint':S.FINGERPRINT,'producerProofSHA256':bundle['producerProofSHA256'],'manifestSHA256':bundle['manifestSHA256'],'requiredArchive':name,'archiveBytes':size,'archiveSHA256':expected,'archiveIdentity':identity,'frozenVerifierMainExecuted':False,'nativeSSHExecutedInConsumer':False},262144)
        yield receipt

def validate_conjunction(receipt,rid,name,size,digest):
    bundle=validate_manifest_binding()
    S.need(receipt.get('schema')=='tail11-cross-platform-archive-conjunction/v1' and receipt.get('status')=='LINUX_SIGNATURE_AND_LOCAL_ARCHIVE_DIGEST_VERIFIED' and receipt.get('producerPlatform')=='linux-x64' and receipt.get('consumerPlatform')==rid and receipt.get('fingerprint')==S.FINGERPRINT,'CROSS_PLATFORM_RECEIPT_SCOPE')
    S.need(receipt['producerProofSHA256']==bundle['producerProofSHA256'] and receipt['manifestSHA256']==bundle['manifestSHA256'] and receipt['requiredArchive']==name and receipt['archiveBytes']==size and receipt['archiveSHA256']==digest==bundle['entries'].get(name) and receipt['frozenVerifierMainExecuted'] is False and receipt['nativeSSHExecutedInConsumer'] is False,'CROSS_PLATFORM_RECEIPT_CONJUNCTION')
    return True
