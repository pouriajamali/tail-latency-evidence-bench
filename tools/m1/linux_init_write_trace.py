"""Fixed own-child native initializer transcript; no injected code/data writes."""
from pathlib import Path
import ctypes,hashlib,os,signal,struct,time
import support as S

FIELDS={'start_time':227936,'load_time':227944,'__libc_stack_end':227904}
REGISTERS=('r15','r14','r13','r12','rbp','rbx','r11','r10','r9','r8','rax','rcx','rdx','rsi','rdi','orig_rax','rip','cs','eflags','rsp','ss','fs_base','gs_base','ds','es','fs','gs')
GPRS=('rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi','r8','r9','r10','r11','r12','r13','r14','r15')
MASK=(1<<64)-1
LAST_EVENT={}
def api():
    lib=ctypes.CDLL(None,use_errno=True);lib.ptrace.restype=ctypes.c_long;lib.ptrace.argtypes=[ctypes.c_ulong,ctypes.c_ulong,ctypes.c_void_p,ctypes.c_void_p];return lib.ptrace
def call(fn,request,pid,address=0,data=0):
    ctypes.set_errno(0);v=fn(request,pid,ctypes.c_void_p(address),ctypes.c_void_p(data));err=ctypes.get_errno()
    if v==-1 and err:
        error=S.Hold('OWN_PTRACE_NATIVE_REQUEST');error.errno=err;raise error
    S.need(request==3 or v==0,'OWN_PTRACE_RETURN_CONTRACT');return v&MASK
def trace_me():call(api(),0,0)

def decode_store(code,store_rva,slot_rva,registers,old):
    S.need(len(code)==7 and code[0] in (0x48,0x4c) and code[1] in (0x89,0x01) and code[2]&0xc7==5,'EXACT_NATIVE_RIP_STORE_FORM')
    S.need(store_rva+7+struct.unpack_from('<i',code,3)[0]==slot_rva,'EXACT_NATIVE_WATCHED_DESTINATION')
    source=GPRS[((code[2]>>3)&7)+(8 if code[0]&4 else 0)];value=registers[source]
    if code[1]==0x01:value=(old+value)&MASK
    return source,value

def validate_stack_initializer(function,source,opcode,value,kernel_stack):
    S.need(opcode==0x89,'NATIVE_FRAME_ADDRESS_INITIALIZER')
    if function in ('_dl_start','_dl_start_final'):S.need(source=='rbp','NATIVE_FRAME_ADDRESS_INITIALIZER')
    elif function=='_dl_sysdep_start':S.need(source=='rdi' and value==kernel_stack,'NATIVE_SYSDEP_STACK_EQUALS_KERNEL_EXEC_STACK')
    else:raise S.Hold('UNEXPECTED_STACK_INITIALIZER_FUNCTION')

class StartupTrace:
    def __init__(self,pid,owned,loader,main,analysis,end,tunable_rows):
        self.pid=pid;self.owned=owned;self.loader=loader;self.main=main;self.analysis=analysis;self.end=end;self.fn=api();self.exec_seen=False;self.fd=None;self.values={};self.events=[];self.loader_base=None;self.active=False;self.otherSignals=[];self.start_birth=owned['birth'];self.tunable_rows=tunable_rows;self.tunable_calls=[]
        for name,va in FIELDS.items():
            r=[x for x in analysis['symbols'] if x['name']==name];S.need(len(r)==1 and r[0]['RVA']==va and r[0]['size']==8 and r[0]['type']==1,'EXACT_DEBUG_WATCHED_OBJECT')
        self.allowed={}
        function_names={'start_time':('_dl_start','_dl_start_final'),'load_time':('dl_main',),'__libc_stack_end':('_dl_start','_dl_start_final','_dl_sysdep_start')}
        functions=[x for x in analysis['symbols'] if x['type']==2 and x['size']>0]
        for name,va in FIELDS.items():
            allowed=[]
            for f in functions:
                if f['name'] not in function_names[name]:continue
                for at in range(f['RVA'],f['RVA']+f['size']-6):
                    code=loader.body[at:at+7]
                    if len(code)==7 and code[0] in (0x48,0x4c) and code[1] in (0x89,0x01) and code[2]&0xc7==5 and at+7+struct.unpack_from('<i',code,3)[0]==va:allowed.append((at,code,f['name']))
            S.need(allowed,'DEBUG_BOUND_NATIVE_STORE_SITE_REQUIRED');self.allowed[name]=allowed
        setter=[s for s in analysis['symbols'] if s['name']=='__GI___tunable_set_val' and s['type']==2 and s['size']>0];S.need(len(setter)==1,'EXACT_NATIVE_TUNABLE_SETTER');self.setter=setter[0]
        S.need(len(tunable_rows)==41,'EXACT_COMPILED_TUNABLE_COUNT')
        self.tunable_state=[{'value':r['defaultValue'],'min':r['fileMin'],'max':r['fileMax'],'initialized':False} for r in tunable_rows]
        call(self.fn,0x4200,pid,0,0x1e|0x100000) # Detect unsupported fork/clone; TRACEEXEC/EXITKILL.
    def resume(self,sig=0):call(self.fn,7,self.pid,0,sig)
    def read(self,address,n):
        b=os.pread(self.fd,n,address);S.need(len(b)==n,'OWN_STARTUP_MEMORY_READ');return b
    def dr(self,index,value=None):
        S.need(index in (0,1,2,3,6,7),'ONLY_FOUR_SCOPED_DEBUG_REGISTERS')
        offset=848+8*index
        if value is None:return call(self.fn,3,self.pid,offset,0)
        return call(self.fn,6,self.pid,offset,value)
    def on_exec(self):
        S.need(not self.exec_seen,'SINGLE_OWN_NATIVE_EXEC');self.exec_seen=True
        proc=Path('/proc')/str(self.pid);S.need((proc/'stat').read_text().split(') ',1)[1].split()[19]==self.start_birth,'ORIGINAL_TRACED_CHILD_BIRTH')
        S.need((proc/'cgroup').read_text()==Path('/proc/self/cgroup').read_text(),'ORIGINAL_TRACED_OWN_CGROUP')
        aux=proc.joinpath('auxv').read_bytes();S.need(len(aux)<=16384 and len(aux)%16==0,'OWN_EXEC_AUXV_BOUND');self.auxv=dict(struct.iter_unpack('<QQ',aux));self.loader_base=self.auxv.get(7,0);S.need(self.loader_base and self.auxv.get(23)==0,'EXACT_NONSECURE_DYNAMIC_EXEC')
        ph=struct.unpack_from('<Q',self.main.body,32)[0];entry=struct.unpack_from('<Q',self.main.body,24)[0];pn=struct.unpack_from('<H',self.main.body,56)[0];self.main_base=self.auxv[3]-ph;S.need(self.auxv.get(5)==pn and self.auxv.get(9)==self.main_base+entry,'ACTUAL_EXEC_MAIN_AUXV')
        self.fd=os.open('/proc/'+str(self.pid)+'/mem',os.O_RDONLY|os.O_CLOEXEC);S.need(self.read(self.loader_base,64)==self.loader.body[:64],'ACTUAL_EXEC_LOADER_HEADER')
        registers=(ctypes.c_ulonglong*27)();call(self.fn,12,self.pid,0,ctypes.addressof(registers));self.execRegisters=dict(zip(REGISTERS,registers));self.kernelArgv=self.execRegisters['rsp']+8
        random_pointer=self.auxv.get(25,0);S.need(self.execRegisters['rsp']<=random_pointer and random_pointer+16<=self.execRegisters['rsp']+1048576,'KERNEL_RANDOM_IN_BOUNDED_INITIAL_STACK');self.kernelRandom=self.read(random_pointer,16)
        self.initialDR6=self.dr(6);S.need(self.initialDR6&15==0 and self.dr(7)==0 and all(self.dr(i)==0 for i in range(4)),'NO_FOREIGN_DEBUGGER_STATE')
        for i,(name,va) in enumerate(FIELDS.items()):
            S.need(self.loader.body[va:va+8]==bytes(8),'WATCHED_ZERO_FILE_INITIALIZER');initial=struct.unpack('<Q',self.read(self.loader_base+va,8))[0];S.need(initial==0,'WATCH_BEFORE_FIRST_NATIVE_INITIALIZER');self.values[name]=0;self.dr(i,self.loader_base+va)
        self.dr(3,self.loader_base+self.setter['RVA']);self.dr(6,self.initialDR6&~15);self.dr(7,0x09990055);self.active=True
    def on_watch(self):
        global LAST_EVENT
        bits=self.dr(6)&15;S.need(bits and self.active,'ONLY_EXPECTED_OWN_DATA_TRAPS')
        registers=(ctypes.c_ulonglong*27)();call(self.fn,12,self.pid,0,ctypes.addressof(registers));regs=dict(zip(REGISTERS,registers));at=regs['rip']-self.loader_base-7
        siginfo=ctypes.create_string_buffer(128);call(self.fn,0x4202,self.pid,0,ctypes.addressof(siginfo));si=siginfo.raw
        LAST_EVENT={'pid':self.pid,'birth':self.start_birth,'DR6LowBits':bits,'nativeRIP':regs['rip'],'loaderBase':self.loader_base,'nextRVA':regs['rip']-self.loader_base,'candidateStoreRVA':at,'signal':struct.unpack_from('<iii',si,0),'signalAddress':struct.unpack_from('<Q',si,16)[0],'knownStoreSites':{k:[x[0] for x in v] for k,v in self.allowed.items()},'completedStoreEvents':list(self.events),'completedNativeSetterCalls':list(self.tunable_calls),'admissionNotInferred':True}
        try:LAST_EVENT['instructionWindowBeforeRIP']=self.read(regs['rip']-24,32).hex()
        except OSError as e:LAST_EVENT['instructionWindowReadErrno']=e.errno
        if bits&8:self.on_tunable(regs)
        for i,(name,va) in enumerate(FIELDS.items()):
            if not bits&(1<<i):continue
            matches=[x for x in self.allowed[name] if x[0]==at];S.need(len(matches)==1,'EXACT_DEBUG_BOUND_NATIVE_STORE_SITE');where,code,function=matches[0];S.need(self.read(self.loader_base+where,7)==code,'NATIVE_EXECUTED_STORE_BYTES')
            source,expected=decode_store(code,where,va,regs,self.values[name]);actual=struct.unpack('<Q',self.read(self.loader_base+va,8))[0];S.need(actual==expected,'NATIVE_STORE_REGISTER_VALUE_MATCH')
            if name=='__libc_stack_end':validate_stack_initializer(function,source,code[1],expected,self.execRegisters['rsp'])
            self.values[name]=expected;self.events.append({'object':name,'objectRVA':va,'storeRVA':where,'function':function,'instruction':code.hex(),'sourceRegister':source,'expectedValue':expected,'actualValue':actual,'actualEqualsNativeRegisterStore':True})
        S.need(len(self.events)<=64,'NATIVE_STARTUP_EVENT_CAP');self.dr(6,self.initialDR6&~15)
    def on_tunable(self,regs):
        S.need(regs['rip']==self.loader_base+self.setter['RVA'] and self.read(regs['rip'],16)==self.loader.body[self.setter['RVA']:self.setter['RVA']+16],'ACTUAL_DEBUG_BOUND_TUNABLE_SETTER_ENTRY')
        index=regs['rdi']&0xffffffff;S.need(index<len(self.tunable_rows),'NATIVE_TUNABLE_ID');row=self.tunable_rows[index];current=self.tunable_state[index];S.need(row['typeCode'] in (0,1,2),'ONLY_NUMERIC_INTERNAL_CPU_TUNABLE_WRITES')
        def argument(pointer):
            S.need(pointer and pointer%8==0,'NATIVE_NUMERIC_TUNABLE_ARGUMENT_ALIGNMENT')
            if regs['rsp']+8<=pointer and pointer+8<=self.execRegisters['rsp']:
                S.need(self.execRegisters['rsp']-regs['rsp']<=1048576,'BOUNDED_NATIVE_INITIALIZER_FRAME');return struct.unpack('<Q',self.read(pointer,8))[0]
            matches=[x for x in self.loader.header['loads'] if not x['flags']&2 and self.loader_base+x['vaddr']<=pointer and pointer+8<=self.loader_base+x['vaddr']+x['filesz']]
            S.need(len(matches)==1,'ONLY_CURRENT_NATIVE_STACK_OR_HELD_CONSTANT_ARGUMENT');x=matches[0];off=x['offset']+pointer-self.loader_base-x['vaddr'];actual=self.read(pointer,8);S.need(actual==self.loader.body[off:off+8],'EXACT_HELD_NATIVE_BOUND_ARGUMENT');return struct.unpack('<Q',actual)[0]
        value=argument(regs['rsi']);minimum=argument(regs['rdx']) if regs['rdx'] else current['min'];maximum=argument(regs['rcx']) if regs['rcx'] else current['max']
        def typed(x):
            if row['typeCode']==0:
                x&=0xffffffff;return x-(1<<32) if x&(1<<31) else x
            return x&MASK
        lo=max(typed(minimum),typed(current['min']));hi=min(typed(maximum),typed(current['max']))
        if lo>hi:lo,hi=typed(current['min']),typed(current['max'])
        value=typed(value);updated=lo<=value<=hi
        if updated:current.update(value=value&MASK,min=lo&MASK,max=hi&MASK,initialized=True)
        self.tunable_calls.append({'index':index,'name':row['name'],'nativeSetterRVA':self.setter['RVA'],'inputValue':value,'inputMin':typed(minimum),'inputMax':typed(maximum),'nativeUpdatePredicate':updated,'result':dict(current),'noParentValueCopied':True});S.need(len(self.tunable_calls)<=128,'NATIVE_TUNABLE_CALL_CAP')
    def consume(self,holding=False):
        S.need(time.time()<self.end,'SIGNATURE_ROLE20');pid,status=os.waitpid(self.pid,os.WNOHANG|os.WUNTRACED)
        if not pid:return False
        S.need(pid==self.pid,'ONLY_OWN_WAITPID')
        if os.WIFEXITED(status) or os.WIFSIGNALED(status):
            self.owned.update(originalHandleTerminal=True,exitCode=os.waitstatus_to_exitcode(status));raise S.Hold('OWN_NATIVE_ENDED_BEFORE_STARTUP_ATTESTATION')
        S.need(os.WIFSTOPPED(status),'OWN_PTRACE_STOP');sig=os.WSTOPSIG(status);event=status>>16
        if sig==signal.SIGTRAP and event==4:self.on_exec();self.resume();return True
        if sig==signal.SIGTRAP and event==0:self.on_watch();self.resume();return True
        if holding and sig==signal.SIGSTOP:
            S.need(self.exec_seen and self.active,'OWN_EXEC_WATCHES_INSTALLED');self.dr(7,0)
            S.need(len(list((Path('/proc')/str(self.pid)/'task').iterdir()))==1,'ONLY_THE_ONE_OBSERVED_NATIVE_THREAD')
            for i in range(4):self.dr(i,0)
            self.dr(6,self.initialDR6);registers=(ctypes.c_ulonglong*27)();call(self.fn,12,self.pid,0,ctypes.addressof(registers));self.heldRegisters=dict(zip(REGISTERS,registers));self.active=False;return 'HELD'
        S.need(sig not in (signal.SIGTRAP,signal.SIGSTOP),'UNEXPECTED_NATIVE_TRACE_EVENT');self.otherSignals.append(sig);S.need(len(self.otherSignals)<=8,'NATIVE_SIGNAL_CAP');self.resume(sig);return True
    def hold(self):
        os.kill(self.pid,signal.SIGSTOP)
        while True:
            if self.consume(True)=='HELD':return
            time.sleep(.001)
    def proof_and_patches(self,path,base,read_memory,fd):
        S.need(self.exec_seen and not self.active,'OWN_NATIVE_STARTUP_HELD');patch={}
        for name,va in FIELDS.items():
            value=self.values[name];S.need(struct.unpack('<Q',read_memory(fd,base+va,8))[0]==value,'NATIVE_INITIALIZER_UNCHANGED_SINCE_OBSERVED_WRITE');patch[(path,base+va)]=struct.pack('<Q',value)
        S.need(struct.unpack('<Q',read_memory(fd,base+227960,8))[0]==self.kernelArgv,'NATIVE_ARGV_EQUALS_KERNEL_EXEC_STACK');patch[(path,base+227960)]=struct.pack('<Q',self.kernelArgv)
        return patch,{'schema':'tail11-native-initializer-transcript/v1','pid':self.pid,'birth':self.start_birth,'initialGlobalsWereExactZeroBeforeLoaderExecution':True,'operations':'TRACEME/TRACEEXEC/EXITKILL/GETREGS/PEEKUSER and three local data-write slots plus one native setter-entry slot; no POKEDATA/SETREGS/injected code','debugRegistersRestored':True,'events':self.events,'finalValues':self.values,'kernelExecArgv':self.kernelArgv,'nativeTunableCalls':self.tunable_calls,'otherNativeSignals':self.otherSignals,'auxv':{str(k):self.auxv[k] for k in (3,5,6,7,9,15,16,17,23,26,51) if k in self.auxv}}
    def detach_resume(self):call(self.fn,17,self.pid);os.kill(self.pid,signal.SIGCONT)
    def close(self):
        if self.fd is not None:os.close(self.fd);self.fd=None
