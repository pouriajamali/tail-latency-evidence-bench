"""One fixed public SSH verification and its owned libcrypto mapping proof."""
from pathlib import Path
import argparse, ctypes, hashlib, json, os, re, struct, subprocess, time
import _winapi
import support as S
import qualifier as Q
from crypto_held_reader import input_held_read

TARGET = Path(r'C:\Windows\System32\libcrypto.dll')
SSH = Path(r'C:\Windows\System32\OpenSSH\ssh-keygen.exe')
FILE_SHA = 'f0ec94e4464dd4b1d376e47d5a1b2a09ff2545980be729bad37b66cc2c71bb68'
SSH_SHA = 'c9dc170cd161db87e75eb6cf282f1325005b9e35628b9a36cb19883a8be1a34f'
ESET = r'C:\Program Files\ESET\ESET Security\ebehmoni.dll'
KEY = 'SHA256:AgU5bZlJSjUu0KsWMmVEEr+BfXpcMVNroTA33bHcQdU'
DATA = {'schema': 'tail11-owned-ssh-libcrypto-proof/v1', 'status': 'HOLD',
        'providerAdmission': False, 'healthyTestsRepeated': 0, 'signatureInvocations': 0,
        'networkGETs': 0, 'dependencyBodiesRead': 0, 'moduleEnumerations': 0,
        'systemTrustOrProtectionChanged': False, 'unresolved': []}

class MI(ctypes.Structure):
    _fields_ = [('base', ctypes.c_void_p), ('size', ctypes.c_uint), ('entry', ctypes.c_void_p)]

def need(ok, code):
    if not ok:
        raise S.Hold(code)

def hx(data):
    return hashlib.sha256(data).hexdigest()

def api():
    k = ctypes.WinDLL('kernel32', use_last_error=True)
    p = ctypes.WinDLL('psapi', use_last_error=True)
    specs = {
        'GetCurrentProcess': ([], ctypes.c_void_p),
        'OpenJobObjectW': ([ctypes.c_uint, ctypes.c_int, ctypes.c_wchar_p], ctypes.c_void_p),
        'IsProcessInJob': ([ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p], ctypes.c_int),
        'GetProcessTimes': ([ctypes.c_void_p] * 5, ctypes.c_int),
        'ResumeThread': ([ctypes.c_void_p], ctypes.c_uint),
        'ReadProcessMemory': ([ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p], ctypes.c_int),
        'GetModuleHandleW': ([ctypes.c_wchar_p], ctypes.c_void_p),
        'GetProcAddress': ([ctypes.c_void_p, ctypes.c_void_p], ctypes.c_void_p),
        'GetModuleHandleExW': ([ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p], ctypes.c_int),
        'GetFinalPathNameByHandleW': ([ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint, ctypes.c_uint], ctypes.c_uint),
        'PeekNamedPipe': ([ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p], ctypes.c_int),
        'ReadFile': ([ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p], ctypes.c_int),
        'WriteFile': ([ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p], ctypes.c_int),
        'CloseHandle': ([ctypes.c_void_p], ctypes.c_int),
    }
    for name, (args, result) in specs.items():
        fn = getattr(k, name); fn.argtypes = args; fn.restype = result
    p.EnumProcessModulesEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_uint]
    p.GetModuleFileNameExW.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint]
    p.GetModuleInformation.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint]
    p.GetMappedFileNameW.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint]
    return k, p

def modules(p, process):
    array = (ctypes.c_void_p * 256)(); size = ctypes.c_uint()
    need(p.EnumProcessModulesEx(process, array, ctypes.sizeof(array), ctypes.byref(size), 3), 'OWN_SSH_MODULE_METADATA')
    DATA['moduleEnumerations'] += 1
    need(size.value <= ctypes.sizeof(array), 'OWN_SSH_MODULE_COUNT')
    rows = []
    for i in range(size.value // ctypes.sizeof(ctypes.c_void_p)):
        name = ctypes.create_unicode_buffer(1024); base = int(array[i]); mi = MI()
        n = p.GetModuleFileNameExW(process, base, name, len(name))
        need(0 < n < len(name) - 1 and p.GetModuleInformation(process, base, ctypes.byref(mi), ctypes.sizeof(mi)), 'OWN_SSH_MODULE_ROW')
        rows.append({'path': name.value, 'base': base, 'size': mi.size})
    return rows

def map_crypto(k, ps, process, rows, disk, nt_path):
    found = [r for r in rows if r['path'].lower() == str(TARGET).lower()]
    need(len(found) == 1, 'EXACT_CHILD_LIBCRYPTO_MAPPING')
    module = found[0]; base = module['base']; total = 0
    name = ctypes.create_unicode_buffer(1024)
    n = ps.GetMappedFileNameW(process, base, name, len(name))
    need(0 < n < len(name) - 1 and name.value.lower() == nt_path.lower(), 'OWN_SSH_BACKING_FILE')
    def memory(rva, count):
        nonlocal total
        need(0 <= rva and 0 <= count and rva + count <= module['size'] and total + count <= 16777216, 'OWN_SSH_LIBCRYPTO_READ_CAP')
        buf = ctypes.create_string_buffer(count); got = ctypes.c_size_t()
        need(k.ReadProcessMemory(process, base + rva, buf, count, ctypes.byref(got)) and got.value == count, 'OWN_SSH_LIBCRYPTO_READ')
        total += count
        return buf.raw
    pe = struct.unpack_from('<I', disk, 0x3c)[0]; opt = pe + 24
    count, optlen = struct.unpack_from('<H', disk, pe + 6)[0], struct.unpack_from('<H', disk, pe + 20)[0]
    need(disk[pe:pe+4] == b'PE\0\0' and struct.unpack_from('<H', disk, pe+4)[0] == 0x8664 and struct.unpack_from('<H', disk, opt)[0] == 0x20b, 'CRYPTO_AMD64_PE')
    preferred = struct.unpack_from('<Q', disk, opt+24)[0]
    image, headers = struct.unpack_from('<II', disk, opt+56)
    need(image == module['size'] and headers <= 4096, 'CRYPTO_IMAGE_SIZE')
    mapped_header = memory(0, headers); expected_header = bytearray(disk[:headers])
    mapped_base = struct.unpack_from('<Q', mapped_header, opt+24)[0]
    need(mapped_base in (preferred, base), 'CRYPTO_TYPED_HEADER_IMAGEBASE')
    struct.pack_into('<Q', expected_header, opt+24, mapped_base)
    need(mapped_header == expected_header, 'CRYPTO_HEADER_DIFFERENCE')
    sections = []
    for i in range(count):
        at = opt + optlen + 40*i; vs, rva, size, raw = struct.unpack_from('<IIII', disk, at+8)
        sections.append({'name': disk[at:at+8].rstrip(b'\0').decode('ascii'), 'rva': rva,
                         'bytes': min(size, vs or size), 'raw': raw, 'flags': struct.unpack_from('<I', disk, at+36)[0]})
    def raw_rva(rva, size):
        hits = [s['raw'] + rva - s['rva'] for s in sections if s['rva'] <= rva and rva-s['rva']+size <= s['bytes']]
        need(len(hits) == 1 and hits[0]+size <= len(disk), 'CRYPTO_FILE_RVA')
        return hits[0]
    relocs = []; rr, rs = struct.unpack_from('<II', disk, opt+112+5*8)
    if rr:
        at = raw_rva(rr, rs); stop = at+rs
        while at < stop:
            page, length = struct.unpack_from('<II', disk, at)
            need(length >= 8 and length % 2 == 0 and at+length <= stop, 'CRYPTO_RELOCATION_BLOCK')
            for offset in range(at+8, at+length, 2):
                item = struct.unpack_from('<H', disk, offset)[0]; kind = item >> 12
                if kind:
                    need(kind == 10, 'CRYPTO_RELOCATION_TYPE'); relocs.append(page+(item & 4095))
            at += length
    byname = {Path(r['path']).name.lower(): r for r in rows}
    parent = k.GetCurrentProcess()
    def parent_name(handle):
        buf = ctypes.create_unicode_buffer(1024); n = ps.GetModuleFileNameExW(parent, handle, buf, len(buf))
        return buf.value if 0 < n < len(buf)-1 else None
    def address(handle, thunk, label):
        if thunk >> 63:
            return k.GetProcAddress(handle, ctypes.c_void_p(thunk & 65535))
        buf = ctypes.create_string_buffer(label.encode('ascii') + b'\0')
        return k.GetProcAddress(handle, ctypes.cast(buf, ctypes.c_void_p))
    def translated(handle, thunk, label):
        if not handle:
            return None
        path = parent_name(handle)
        if not path or not Q.os_base_provider(Path(path)):
            return None
        value = address(handle, thunk, label)
        if not value:
            return None
        owner = ctypes.c_void_p()
        if not k.GetModuleHandleExW(6, value, ctypes.byref(owner)):
            return None
        ownerpath = parent_name(owner)
        if not ownerpath or not Q.os_base_provider(Path(ownerpath)):
            return None
        host = byname.get(Path(ownerpath).name.lower())
        if not host or not Q.os_base_provider(Path(host['path'])):
            return None
        offset = value-owner.value
        if not 0 <= offset < host['size']:
            return None
        return host['base']+offset, Path(ownerpath).name.lower(), offset
    imports = []; iat = []; ir, size = struct.unpack_from('<II', disk, opt+112+8)
    ip = raw_rva(ir, size)
    for descriptor in range(min(size//20, 1024)):
        lookup, _, _, name_rva, first = struct.unpack_from('<IIIII', disk, ip+20*descriptor)
        if not any((lookup, name_rva, first)):
            break
        at = raw_rva(name_rva, 1); end = disk.find(b'\0', at, at+129)
        need(end > at, 'CRYPTO_IMPORT_NAME'); dll = disk[at:end].decode('ascii').lower()
        imports.append({'name': dll, 'kind': 'normal'})
        lookup = lookup or first
        for i in range(1024):
            thunk = struct.unpack_from('<Q', disk, raw_rva(lookup+8*i, 8))[0]
            if not thunk:
                break
            if thunk >> 63:
                label = 'ordinal-'+str(thunk & 65535)
            else:
                at = raw_rva(thunk+2, 1); end = disk.find(b'\0', at, at+257)
                need(end > at, 'CRYPTO_IMPORT_SYMBOL'); label = disk[at:end].decode('ascii')
            need(any(s['rva'] <= first+8*i and first+8*i+8 <= s['rva']+s['bytes'] and not s['flags'] & (0x80000000|0x02000000) for s in sections), 'CRYPTO_IAT_READONLY_SCOPE')
            value = struct.unpack('<Q', memory(first+8*i, 8))[0]
            candidates = []
            if dll.startswith(('api-ms-win-', 'ext-ms-')):
                # No API-set DLL load or dependency body read: match the named native
                # export against already mapped OS_BASE hosts and their child RVAs.
                handles = [k.GetModuleHandleW(dll)] + [k.GetModuleHandleW(Path(r['path']).name) for r in rows if Q.os_base_provider(Path(r['path']))]
            else:
                handles = [k.GetModuleHandleW(dll)] if dll in byname and Q.os_base_provider(Path(byname[dll]['path'])) else []
            for h in handles:
                item = translated(h, thunk, label)
                if item and item[0] == value and item not in candidates:
                    candidates.append(item)
            row = {'contract': dll, 'symbol': label, 'rva': first+8*i, 'bytes': 8, 'actual': value, 'resolved': bool(candidates)}
            if candidates:
                row.update(host=candidates[0][1], hostExportRVA=candidates[0][2])
            else:
                DATA['unresolved'].append({'from': 'libcrypto.dll', 'dependency': dll, 'symbol': label, 'code': 'IAT_TARGET_NOT_BOUND_TO_EXPECTED_NATIVE_OS_BASE_EXPORT'})
            iat.append(row)
        else:
            raise S.Hold('CRYPTO_THUNK_CAP')
    else:
        raise S.Hold('CRYPTO_IMPORT_DESCRIPTOR_CAP')
    need(imports == Q.pe_imports(disk), 'CRYPTO_DECLARED_IMPORT_PARSE')
    proof = []
    for section in sections:
        if not section['flags'] & 0x40000000 or section['flags'] & (0x80000000 | 0x02000000):
            continue
        expected = bytearray(disk[section['raw']:section['raw']+section['bytes']])
        actual = bytearray(memory(section['rva'], section['bytes'])); adjusted = 0; slots = 0
        for rva in relocs:
            if section['rva'] <= rva < section['rva']+section['bytes']:
                at = rva-section['rva']; need(at+8 <= len(expected), 'CRYPTO_RELOCATION_RANGE')
                v = struct.unpack_from('<Q', expected, at)[0]
                struct.pack_into('<Q', expected, at, (v+base-preferred) & ((1<<64)-1)); adjusted += 1
        for row in iat:
            if row['resolved'] and section['rva'] <= row['rva'] < section['rva']+section['bytes']:
                at = row['rva']-section['rva']; need(at+8 <= len(expected), 'CRYPTO_IAT_RANGE')
                expected[at:at+8] = actual[at:at+8]; slots += 1
        item = {'name': section['name'], 'bytes': len(expected), 'rva': section['rva'], 'relocations': adjusted,
                'verifiedIATSlots': slots, 'expectedSHA256': hx(expected), 'mappedSHA256': hx(actual), 'matches': expected == actual}
        proof.append(item)
        if not item['matches']:
            DATA['unresolved'].append({'from': 'libcrypto.dll', 'section': section['name'], 'code': 'NORMALIZED_READONLY_IMAGE_DIFFERS'})
    DATA.update(mapping={'backingNtPath': name.value, 'base': base, 'imageSize': image,
                         'headerImageBase': mapped_base, 'headerAllOtherBytesExact': True,
                         'sections': proof, 'imports': imports, 'iat': iat, 'memoryBytesRead': total,
                         'writableOrDiscardableSectionsRead': False})

def run(f):
    import base64, msvcrt
    profile = S.read(os.environ['TAIL11_ROOT_PROFILE'])
    need(profile['childPid'] == os.getpid() and profile['nonce'] == f['nonce'], 'OWN_INSPECTOR')
    DATA['actualInspectorKernel'] = S.input_kernel(profile)
    for key in ('catalogProof', 'fileProof'):
        row = f[key]; need(S.sha(row['path']) == row['sha256'], 'EXACT_CRYPTO_PROOF_HASH')
    catalog = S.read(f['catalogProof']['path']); prior = S.read(f['fileProof']['path'])
    need(catalog['catalogWinTrustStatus'] == '0x00000000' and catalog['chain']['cachedCurrentChainValid'] is True and not catalog['chain']['chainStatus'], 'EXACT_CRYPTO_CACHED_CATALOG_CHAIN')
    need(catalog['priorRawFileSHA256'] == prior['sha256'] == FILE_SHA and prior['stable'] is True, 'EXACT_CRYPTO_PRIOR_RAW_FILE')
    DATA['catalogProofSHA256'] = f['catalogProof']['sha256']
    metadata = S.HERE/'metadata'
    pins = {'SHA256SUMS.txt': '7ed7c353458a935439066a6a1d205520e5610458ec346dd8dbbf5c8882d28709',
            'SHA256SUMS.txt.sig': 'bf4ff680a2c4816b08044c47bb05882f6268576dea30bc1a14e275cfab66e840',
            'SIGNING-PUBLIC-KEY.pub': 'cc7038b2d98f856af97b58eb06619ff441fbe9b178da5396f61d1ccdf7a65e7c'}
    blobs = {}
    for name, digest in pins.items():
        b = S.raw(metadata/name, 4096); need(hx(b) == digest, 'PUBLIC_SIGNATURE_INPUT'); blobs[name] = b
    parts = blobs['SIGNING-PUBLIC-KEY.pub'].strip().split()
    need(parts[0] == b'ssh-ed25519', 'PUBLIC_KEY_TYPE')
    blob = base64.b64decode(parts[1], validate=True)
    need(len(blob) == 51 and 'SHA256:'+base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('=') == KEY, 'PUBLIC_KEY_FINGERPRINT')
    out = Path(f['receiptPath']).parent; allowed = out/'allowed-signers'
    with allowed.open('xb') as file:
        file.write(b'pouriajamali ssh-ed25519 '+parts[1]+b'\n')
    sshbytes = S.raw(SSH, 1048576); need(len(sshbytes) == 861184 and hx(sshbytes) == SSH_SHA, 'PINNED_SSH_EXE')
    rootimports = Q.pe_imports(sshbytes); DATA['pinnedSSHExeSHA256'] = hx(sshbytes)
    k, ps = api(); hp = ht = job = None; handles = []; start_mono = time.monotonic()
    deadline = min(f['window']['deadlineUnix']-30, time.time()+45)
    def left():
        return max(0, min(deadline-time.time(), 45-(time.monotonic()-start_mono)))
    def close(handle):
        if handle:
            _winapi.CloseHandle(handle)
            if handle in handles:
                handles.remove(handle)
    def output(handle):
        available = ctypes.c_uint(); pieces = []
        if k.PeekNamedPipe(handle, None, 0, None, ctypes.byref(available), None):
            need(available.value <= 8192, 'SSH_PUBLIC_OUTPUT_CAP')
            if available.value:
                buf = ctypes.create_string_buffer(available.value); got = ctypes.c_uint()
                need(k.ReadFile(handle, buf, len(buf), ctypes.byref(got), None), 'SSH_PUBLIC_OUTPUT')
                pieces.append(buf.raw[:got.value])
        return b''.join(pieces)
    try:
        with input_held_read(TARGET) as (stream, identity):
            need(identity['bytes'] == 1953792 and identity['volume'] == prior['fileAfter']['Volume'] and identity['fileIndex'] == ((prior['fileAfter']['IndexHi']<<32) | prior['fileAfter']['IndexLo']), 'CRYPTO_PRESTART_FILE_IDENTITY')
            disk = stream.read(1953793); need(len(disk) == 1953792 and hx(disk) == FILE_SHA, 'CRYPTO_PRESTART_FILE_HASH')
            nt = ctypes.create_unicode_buffer(1024)
            n = k.GetFinalPathNameByHandleW(msvcrt.get_osfhandle(stream.fileno()), nt, len(nt), 2)
            need(0 < n < len(nt)-1, 'CRYPTO_HELD_NT_PATH')
            DATA['prestartCrypto'] = {'identity': identity, 'sha256': hx(disk), 'ntPath': nt.value}
            rin, win = _winapi.CreatePipe(None, 4096)
            rout, wout = _winapi.CreatePipe(None, 4096)
            rerr, werr = _winapi.CreatePipe(None, 4096)
            handles.extend((rin, win, rout, wout, rerr, werr))
            for handle in (rin, wout, werr):
                os.set_handle_inheritable(handle, True)
            si = subprocess.STARTUPINFO(); si.dwFlags = subprocess.STARTF_USESTDHANDLES
            si.hStdInput, si.hStdOutput, si.hStdError = rin, wout, werr
            si.lpAttributeList = {'handle_list': [rin, wout, werr]}
            argv = [str(SSH), '-Y', 'verify', '-f', str(allowed), '-I', 'pouriajamali', '-n', 'file', '-s', str(metadata/'SHA256SUMS.txt.sig')]
            env = {key: os.environ[key] for key in ('SystemRoot','WINDIR','ComSpec','ProgramData','TEMP','TMP') if key in os.environ}
            env['PATH'] = r'C:\Windows\System32\OpenSSH'
            need(left() > 3, 'SSH_REMAINING_CLOCK')
            hp, ht, pid, tid = _winapi.CreateProcess(str(SSH), subprocess.list2cmdline(argv), None, None, True, 0x08000004, env, str(out), si)
            DATA['signatureInvocations'] = 1
            close(rin); close(wout); close(werr)
            job = k.OpenJobObjectW(4, False, 'tail11-input-only-'+f['nonce']); need(job, 'OWN_ROOT_JOB')
            member = ctypes.c_int()
            need(k.IsProcessInJob(hp, job, ctypes.byref(member)) and member.value == 1, 'SSH_INHERITED_ASSIGNMENT_BEFORE_RESUME')
            c, e, kt, ut = (ctypes.c_ulonglong() for _ in range(4))
            need(k.GetProcessTimes(hp, ctypes.byref(c), ctypes.byref(e), ctypes.byref(kt), ctypes.byref(ut)), 'SSH_BIRTH')
            DATA['ownedSSH'] = {'pid': pid, 'birth': c.value, 'sameRootJobBeforeResume': True,
                                'assignment': 'ACTUAL_KERNEL_INHERITED_SAME_JOB_BEFORE_RESUME',
                                'inheritedRootJobCaps': DATA['actualInspectorKernel'], 'capQueryProcessPID': os.getpid(), 'originalHandle': True}
            need(k.ResumeThread(ht) != 0xffffffff, 'SSH_RESUME')
            # One bounded initialization wait, then one metadata enumeration.
            need(_winapi.WaitForSingleObject(hp, min(2000, int(left()*1000))) == 258, 'SSH_EXITED_BEFORE_METADATA')
            rows = modules(ps, hp); DATA['actualOwnedModules'] = rows
            names = {Path(row['path']).name.lower(): row for row in rows}
            allowed_exact = {str(SSH).lower(), str(TARGET).lower(), ESET.lower()}
            for row in rows:
                if row['path'].lower() not in allowed_exact and not Q.os_base_provider(Path(row['path'])):
                    DATA['unresolved'].append({'from': 'actual-owned-ssh', 'path': row['path'], 'code': 'UNADMITTED_PROVIDER'})
            DATA['rootImportEdges'] = []
            for edge in rootimports:
                match = names.get(edge['name']); ok = bool(match) and (match['path'].lower() == str(TARGET).lower() or Q.os_base_provider(Path(match['path'])))
                DATA['rootImportEdges'].append({**edge, 'mappedPath': match['path'] if match else None, 'resolved': ok})
                if not ok:
                    DATA['unresolved'].append({'from': 'ssh-keygen.exe', **edge, 'code': 'ROOT_IMPORT_MAPPING_UNRESOLVED'})
            map_crypto(k, ps, hp, rows, disk, nt.value)
            need(left() > 0, 'SSH_WORK_CLOCK')
            message = blobs['SHA256SUMS.txt']; buf = ctypes.create_string_buffer(message); written = ctypes.c_uint()
            need(k.WriteFile(win, buf, len(message), ctypes.byref(written), None) and written.value == len(message), 'SSH_PUBLIC_STDIN')
            close(win)
            need(_winapi.WaitForSingleObject(hp, int(left()*1000)) == 0, 'SSH_ABSOLUTE_DEADLINE')
            code = _winapi.GetExitCodeProcess(hp)
            stdout, stderr = output(rout), output(rerr)
            DATA['sshTerminal'] = {'exitCode': code, 'natural': True, 'originalHandleWaitReturned': True,
                                   'stdoutSHA256': hx(stdout), 'stderrSHA256': hx(stderr),
                                   'publicStdout': stdout.decode('ascii', 'replace')[:1024], 'publicStderr': stderr.decode('ascii', 'replace')[:1024]}
            stream.seek(0); after = stream.read(1953793)
            need(len(after) == 1953792 and hx(after) == FILE_SHA, 'CRYPTO_HELD_FINAL_HASH')
            DATA['heldThroughOriginalTerminal'] = True
            DATA['explicitCryptoReadBytes'] = len(disk)+len(after)
            DATA['publicSignatureInputs'] = pins
            DATA['fingerprint'] = KEY; DATA['namespace'] = 'file'
            if code != 0:
                DATA['unresolved'].append({'from': 'ssh-keygen.exe', 'code': 'PUBLIC_KNOWN_KEY_SIGNATURE_NOT_VERIFIED'})
            if not DATA['unresolved']:
                entries = {}
                for line in message.decode('ascii').splitlines():
                    m = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9._-]{1,160})', line)
                    need(m and m[2] not in entries and len(entries) < 64, 'SIGNED_CHECKSUM_FRAMING')
                    entries[m[2]] = m[1]
                DATA.update(status='PASS_EXACT_OWNED_SSH_SIGNATURE_AND_LIBCRYPTO_NECESSARY_MAPPING',
                            signedChecksums=entries, signatureVerificationTrustedForExactInputs=True)
            else:
                DATA['status'] = 'HOLD_ALL_OBSERVED_UNRESOLVED_IN_ONE_PACKET'
                DATA['signatureVerificationTrustedForExactInputs'] = False
    finally:
        if hp:
            if _winapi.WaitForSingleObject(hp, 0) != 0:
                _winapi.TerminateProcess(hp, 126); _winapi.WaitForSingleObject(hp, 2000)
                DATA['sshForcedCleanup'] = True
            DATA['ownedSSHOriginalHandleTerminal'] = _winapi.WaitForSingleObject(hp, 0) == 0
        if ht: close(ht)
        if hp: close(hp)
        if job: k.CloseHandle(job)
        for handle in list(handles): close(handle)

def entry():
    p = argparse.ArgumentParser(); p.add_argument('--frame', required=True); p.add_argument('--frame-sha', required=True)
    args = p.parse_args(); raw = Path(args.frame).read_bytes(); need(hx(raw) == args.frame_sha and len(raw) <= 32768, 'FRAME_HASH')
    frame = json.loads(raw)
    try:
        run(frame)
    except Exception as error:
        DATA.update(status='HOLD', code=str(error) if isinstance(error, S.Hold) else 'OWNED_SSH_PROOF_HOLD', exceptionType=type(error).__name__)
    S.fresh(frame['receiptPath'], DATA)
    if not DATA['status'].startswith('PASS_'):
        raise SystemExit(1)
