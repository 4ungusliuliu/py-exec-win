import time
class NtdllEmulator:
    def __init__(s,memory,api):
        s.memory=memory;s.api=api;s.handles={};s.next_handle_id=0x2000
        s.performance_frequency=10000000;s.critical_sections={};s.heaps={};s.default_heap=0x10000000
        s.heaps[s.default_heap]={'size':1024*1024,'allocations':{},'next_address':0x20000000}
    def RtlAllocateHeap(s,h,f,sz):
        if h not in s.heaps:h=s.default_heap
        hp=s.heaps[h];a=hp['next_address'];hp['next_address']+=sz;hp['allocations'][a]=sz;return a
    def RtlFreeHeap(s,h,f,a):
        if h not in s.heaps:h=s.default_heap
        if a in s.heaps[h]['allocations']:del s.heaps[h]['allocations'][a];return True
        return False
    def RtlReAllocateHeap(s,h,f,a,sz):
        if h not in s.heaps:h=s.default_heap
        if a in s.heaps[h]['allocations']:
            old=s.heaps[h]['allocations'][a]
            if sz<=old:return a
            n=s.RtlAllocateHeap(h,f,sz)
            if n:s.memory.write(n,s.memory.read(a,old));s.RtlFreeHeap(h,f,a);return n
        return 0
    def RtlSizeHeap(s,h,f,a):
        if h not in s.heaps:h=s.default_heap
        return s.heaps[h]['allocations'].get(a,0)
    def RtlZeroMemory(s,d,l):s.memory.write(d,b'\0'*l)
    def RtlMoveMemory(s,d,src,l):s.memory.write(d,s.memory.read(src,l))
    RtlCopyMemory=RtlMoveMemory
    def RtlFillMemory(s,d,l,f):s.memory.write(d,bytes([f&0xFF]*l))
    def RtlCompareMemory(s,a,b,l):
        da=s.memory.read(a,l);db=s.memory.read(b,l)
        for i in range(l):
            if da[i]!=db[i]:return i
        return l
    def RtlInitAnsiString(s,d,src):
        if not src:s.memory.write_dword(d,0);s.memory.write_dword(d+4,0);s.memory.write_dword(d+8,0);return
        st=s.memory.read_string(src);l=len(st)
        sa=s.RtlAllocateHeap(s.default_heap,0,l+1);s.memory.write(sa,st.encode('ascii','ignore')+b'\0')
        s.memory.write_dword(d,l+1);s.memory.write_dword(d+4,l);s.memory.write_qword(d+8,sa)
    def RtlInitUnicodeString(s,d,src):
        if not src:s.memory.write_dword(d,0);s.memory.write_dword(d+4,0);s.memory.write_qword(d+8,0);return
        st=s.memory.read_string(src);l=len(st)*2
        sa=s.RtlAllocateHeap(s.default_heap,0,l+2);s.memory.write(sa,st.encode('utf-16le')+b'\0\0')
        s.memory.write_dword(d,l+2);s.memory.write_dword(d+4,l);s.memory.write_qword(d+8,sa)
    def RtlEnterCriticalSection(s,cs):
        if cs not in s.critical_sections:s.critical_sections[cs]={'locked':False,'owner':0,'lock_count':0}
        c=s.critical_sections[cs];ct=0x1234
        if c['locked'] and c['owner']==ct:c['lock_count']+=1
        else:
            while c['locked']:pass
            c['locked']=True;c['owner']=ct;c['lock_count']=1
    def RtlLeaveCriticalSection(s,cs):
        if cs in s.critical_sections:
            c=s.critical_sections[cs]
            if c['locked']:
                c['lock_count']-=1
                if c['lock_count']==0:c['locked']=False;c['owner']=0
    def RtlInitializeCriticalSection(s,cs):
        s.memory.write(cs,b'\0'*32)
        s.memory.write_dword(cs+8,-1);s.memory.write_dword(cs+12,-1)
        s.critical_sections[cs]={'locked':False,'owner':0,'lock_count':0}
    def RtlDeleteCriticalSection(s,cs):
        if cs in s.critical_sections:del s.critical_sections[cs]
    def RtlGetLastWin32Error(s):return 0
    def RtlSetLastWin32Error(s,e):pass
    def RtlNtStatusToDosError(s,st):return{0:0,0xC0000005:5,0xC0000017:8,0xC000009A:8,0xC0000022:5,0xC000000D:87,0xC0000034:2,0xC0000035:3,0xC0000043:32,0xC0000120:6}.get(st&0xFFFFFFFF,317)
    def NtAllocateVirtualMemory(s,p,ba,zb,rs,at,pr):s.memory.write_qword(ba,0x30000000);return 0
    def NtFreeVirtualMemory(s,*a):return 0
    def NtProtectVirtualMemory(s,p,ba,rs,np,op):
        if op:s.memory.write_dword(op,0x40)
        return 0
    def NtQueryVirtualMemory(s,p,ba,mic,mi,mil,rl):
        if mic==0 and mil>=48:
            s.memory.write(mi,__import__('struct').pack('<QQQQQQ',0x2000,0x400000,0x40,0,0,0))
            if rl:s.memory.write_dword(rl,48)
            return 0
        return 0xC0000003
    def NtReadVirtualMemory(s,p,ba,buf,sz,nr):
        s.memory.write(buf,s.memory.read(ba,sz))
        if nr:s.memory.write_dword(nr,sz)
        return 0
    def NtWriteVirtualMemory(s,p,ba,buf,sz,nw):
        s.memory.write(ba,s.memory.read(buf,sz))
        if nw:s.memory.write_dword(nw,sz)
        return 0
    def NtCreateFile(s,fh,da,oa,iob,asz,fa,sa,cd,co,eb,el):
        h=s.next_handle_id;s.next_handle_id+=1
        s.handles[h]={'type':'file','position':0,'size':0,'data':bytearray()}
        s.memory.write_qword(fh,h);return 0
    def NtClose(s,h):
        if h in s.handles:del s.handles[h]
        return 0
    def NtQuerySystemInformation(s,sic,si,sil,rl):
        if sic==5 and sil>=56:
            s.memory.write(si,__import__('struct').pack('<QQQQQQQ',100,0,0,0,0,0,0))
            if rl:s.memory.write_dword(rl,56)
            return 0
        return 0xC0000003
    def NtQuerySystemTime(s,st):s.memory.write_qword(st,int(time.time()*10000000)+116444736000000000);return 0
    def NtQueryPerformanceCounter(s,pc,pf):
        c=int(time.time()*s.performance_frequency)
        if pc:s.memory.write_qword(pc,c)
        if pf:s.memory.write_qword(pf,s.performance_frequency)
        return 0
    def NtDelayExecution(s,al,di):
        if di:
            i=s.memory.read_qword(di);time.sleep(min(i/100,1.0))
        return 0
    def NtYieldExecution(s):return 0
    def NtGetContextThread(s,t,c):return 0
    def NtSetContextThread(s,t,c):return 0
    def NtQueryInformationProcess(s,*a):return 0xC0000003
    def NtSetInformationProcess(s,*a):return 0
    def NtQueryInformationThread(s,*a):return 0xC0000003
    def NtSetInformationThread(s,*a):return 0
    def NtCreateEvent(s,eh,da,oa,et,ist):
        h=s.next_handle_id;s.next_handle_id+=1
        s.handles[h]={'type':'event','signaled':ist,'event_type':et}
        s.memory.write_qword(eh,h);return 0
    def NtSetEvent(s,eh,ps):
        h=s.memory.read_qword(eh)
        if h in s.handles and s.handles[h]['type']=='event':
            old=1 if s.handles[h]['signaled'] else 0;s.handles[h]['signaled']=True
            if ps:s.memory.write_dword(ps,old)
            return 0
        return 0xC0000008
    def NtResetEvent(s,eh,ps):
        h=s.memory.read_qword(eh)
        if h in s.handles and s.handles[h]['type']=='event':
            old=1 if s.handles[h]['signaled'] else 0;s.handles[h]['signaled']=False
            if ps:s.memory.write_dword(ps,old)
            return 0
        return 0xC0000008
    def NtWaitForSingleObject(s,h,al,to):
        hv=s.memory.read_qword(h)
        if hv not in s.handles:return 0xC0000008
        o=s.handles[hv]
        if o['type']=='event':
            if o['signaled']:
                if not o['event_type']:o['signaled']=False
                return 0
        return 0x102
