import sys,time,struct
from ntdll import NtdllEmulator
from cpp import CPPLibrary
from crt import CRTLibrary
class APISimulator:
    def __init__(s,memory):
        s.memory=memory;s.functions={};s.func_name_map={};s.next_api_addr=0x50001000
        s.ntdll=NtdllEmulator(memory,s);s.cpp_lib=CPPLibrary(memory,s)
        s.crt=CRTLibrary(memory,s);s.executor=None;s.win_handles={};s.next_win_handle=0x70000000
        try:s.crt.set_arch(getattr(memory.pe_loader,'is_64bit',True))
        except:pass
        s.iob_base=memory.allocate(256);s.tls_base=memory.allocate(4096)
        s._reg();s._upgrade()
    def _upgrade(s):
        for a,n in list(s.func_name_map.items()):
            h=s.crt.resolve(n)
            if h:s.functions[a]=h

    STDCALL_ARGS = {"GetStdHandle":1,"WriteConsoleA":5,"WriteConsoleW":5,"ReadConsoleA":5,"ReadFile":5,
        "WriteFile":5,"ExitProcess":1,"ExitThread":1,"GetProcessHeap":0,"HeapAlloc":3,"HeapFree":3,
        "HeapReAlloc":4,"HeapSize":3,"HeapCreate":3,"HeapDestroy":1,"HeapValidate":3,"HeapSetInformation":4,
        "VirtualAlloc":4,"VirtualFree":3,"VirtualProtect":4,"VirtualQuery":3,"VirtualQueryEx":5,
        "CreateFileA":7,"CreateFileW":7,"CloseHandle":1,"SetFilePointer":4,"SetFilePointerEx":5,
        "GetFileSize":2,"GetFileSizeEx":2,"GetFileType":1,"DeleteFileA":1,"DeleteFileW":1,
        "GetModuleHandleA":1,"GetModuleHandleW":1,"GetModuleHandleExA":3,"GetProcAddress":2,
        "LoadLibraryA":1,"LoadLibraryW":1,"LoadLibraryExA":3,"FreeLibrary":1,"Sleep":1,
        "GetTickCount":0,"GetTickCount64":0,"QueryPerformanceCounter":1,"QueryPerformanceFrequency":1,
        "GetCommandLineA":0,"GetCommandLineW":0,"GetEnvironmentStringsA":0,"GetEnvironmentStringsW":0,
        "FreeEnvironmentStringsA":1,"FreeEnvironmentStringsW":1,"GetSystemTime":1,"GetLocalTime":1,
        "GetSystemTimeAsFileTime":1,"GetCurrentProcess":0,"GetCurrentProcessId":0,"GetCurrentThread":0,
        "GetCurrentThreadId":0,"TlsAlloc":0,"TlsGetValue":1,"TlsSetValue":2,"TlsFree":1,
        "EnterCriticalSection":1,"LeaveCriticalSection":1,"InitializeCriticalSection":1,
        "InitializeCriticalSectionAndSpinCount":2,"InitializeCriticalSectionEx":3,"DeleteCriticalSection":1,
        "GetLastError":0,"SetLastError":1,"MultiByteToWideChar":6,"WideCharToMultiByte":6,
        "GetModuleFileNameA":3,"GetModuleFileNameW":3,"GetStartupInfoA":1,"GetStartupInfoW":1,
        "GetVersion":0,"GetVersionExA":1,"GetVersionExW":1,"IsDebuggerPresent":0,
        "OutputDebugStringA":1,"OutputDebugStringW":1,"SetConsoleCtrlHandler":2,"GetConsoleMode":2,
        "SetConsoleMode":2,"CreateThread":6,"WaitForSingleObject":2,"WaitForMultipleObjects":4,
        "GetExitCodeThread":2,"InterlockedIncrement":1,"InterlockedDecrement":1,"InterlockedExchange":2,
        "InterlockedCompareExchange":3,"lstrlenA":1,"lstrlenW":1,"lstrcpyA":2,"lstrcpyW":2,
        "lstrcatA":2,"lstrcatW":2,"lstrcmpA":2,"lstrcmpW":2,"lstrcmpiA":2,"lstrcmpiW":2,"lstrcpynA":3,
        "GetSystemInfo":1,"GetNativeSystemInfo":1,"IsProcessorFeaturePresent":1,"GetACP":0,"GetOEMCP":0,
        "GetCPInfo":2,"GetTimeZoneInformation":1,"SetUnhandledExceptionFilter":1,"UnhandledExceptionFilter":1,
        "RaiseException":4,"SetErrorMode":1,"GetFullPathNameA":4,"GetCurrentDirectoryA":2,
        "SetCurrentDirectoryA":1,"CreateDirectoryA":2,"RemoveDirectoryA":1,"FindFirstFileA":2,
        "FindNextFileA":2,"FindClose":1,"GetWindowsDirectoryA":2,"GetSystemDirectoryA":2,
        "GetTempPathA":2,"GetTempFileNameA":4,"CopyFileA":3,"MoveFileA":2,"CreateMutexA":3,
        "ReleaseMutex":1,"CreateEventA":4,"SetEvent":1,"ResetEvent":1,"GetFileAttributesA":1,
        "SetFileAttributesA":2,"FlushFileBuffers":1,"SetEndOfFile":1,"GetProcessTimes":4,
        "GlobalAlloc":2,"GlobalFree":1,"GlobalLock":1,"GlobalUnlock":1,"LocalAlloc":2,"LocalFree":1,
        "MessageBoxA":4,"MessageBoxW":4,"GetDesktopWindow":0,"GetForegroundWindow":0,
        "IsValidCodePage":1,"GetLocaleInfoA":4,"GetUserDefaultLCID":0,"GetThreadLocale":0,
        "SetThreadLocale":1,"GetStringTypeA":4,"GetStringTypeW":4,"CompareStringA":6,"CompareStringW":6,
        "LCMapStringA":6,"LCMapStringW":6,"GetConsoleCP":0,"GetConsoleOutputCP":0,"SetConsoleCP":1,
        "SetConsoleOutputCP":1,"GetNumberOfConsoleInputEvents":2,"PeekConsoleInputA":4,
        "GetFileInformationByHandle":2,"DuplicateHandle":7,"SetHandleInformation":3,"CreatePipe":4,
        "GetConsoleScreenBufferInfo":2,"FillConsoleOutputCharacterA":5,"SetConsoleCursorPosition":2,
        "EncodePointer":1,"DecodePointer":1,"SetProcessMitigationPolicy":3,"GetProcessMitigationPolicy":4,
        "GetFileVersionInfoSizeA":2,"GetFileVersionInfoA":5,"VerQueryValueA":4}

    def _wopen(s,path,mode):
        if not s.crt:return 0
        h=s.crt.fs.open(path,mode)
        if not h:return 0xFFFFFFFFFFFFFFFF if s.memory.pe_loader.is_64bit else 0xFFFFFFFF
        w=s.next_win_handle;s.next_win_handle+=8
        s.win_handles[w]=h;return w
    def _wget(s,w):
        h=s.win_handles.get(w)
        return s.crt.fs.get(h) if h else None
    def _CreateFileA(s,*a):
        p=a[0] if a else 0
        if not p:return s._bad()
        path=s.memory.read_string(p,4096)
        acc=a[1] if len(a)>1 else 0x80000000
        w=True if acc&0xC0000000 else False
        return s._wopen(path,"r+b" if not w else "wb") if False else s._wopen(path,"wb" if w else "rb")
    _CreateFileW=_CreateFileA
    def _ReadFile(s,*a):
        if len(a)<4:return 0
        fh,lb,n,rp=a[0],a[1],a[2],a[3]
        if fh in(0x100,):
            d=sys.stdin.buffer.read(n) if n else b""
            if d:s.memory.write(lb,d)
            if rp:s.memory.write_dword(rp,len(d))
            return 1
        st=s._wget(fh)
        if not st:return 0
        d=st.read(n)
        if d:s.memory.write(lb,d)
        if rp:s.memory.write_dword(rp,len(d))
        return 1 if d else 0
    def _WriteFile2(s,*a):
        if len(a)<4:return 0
        fh,lb,n,wr=a[0],a[1],a[2],a[3]
        if fh in(0x101,0x102):
            d=s.memory.read(lb,n)
            (sys.stdout if fh==0x101 else sys.stderr).write(d.decode("utf-8","replace"))
            sys.stdout.flush()
            if wr:s.memory.write_dword(wr,n)
            return 1
        st=s._wget(fh)
        if not st:return 0
        st.write(s.memory.read(lb,n))
        if wr:s.memory.write_dword(wr,n)
        return 1
    def _CloseHandle(s,*a):
        w=a[0] if a else 0
        h=s.win_handles.pop(w,None)
        if h is not None and s.crt:s.crt.fs.close(h)
        return 1
    def _GetFileSize(s,*a):
        st=s._wget(a[0]) if a else None
        return len(st.data) if st else 0
    def _SetFilePointer(s,*a):
        st=s._wget(a[0]) if a else None
        if not st:return 0xFFFFFFFF
        return st.seek(a[1]&0xFFFFFFFF if len(a)>1 else 0,a[2] if len(a)>2 else 0)
    def _bad(s):return 0xFFFFFFFFFFFFFFFF if getattr(s.memory.pe_loader,"is_64bit",True) else 0xFFFFFFFF
    def _VirtualAlloc(s,*a):
        sz=a[2] if len(a)>2 else 0
        return s.memory.allocate(max(sz,0x1000))
    def _VirtualFree(s,*a):return 1
    def _HeapCreate(s,*a):return s.ntdll.default_heap
    def _HeapDestroy(s,*a):return 1
    def _HeapValidate(s,*a):return 1
    def _GetModuleFileNameA(s,*a):
        c="emulator.exe"
        if len(a)>2 and a[2]:
            ad=a[1];s.memory.write(ad,c.encode()+b"\0");return len(c)
        return len(c)
    def _GetModuleFileNameW(s,*a):
        c="emulator.exe"
        if len(a)>2 and a[2]:
            s.memory.write(a[1],c.encode("utf-16le")+b"\0\0");return len(c)
        return len(c)
    def _GetStartupInfoA(s,*a):
        if a and a[0]:s.memory.write(a[0],b"\0"*68)
        return 0
    _GetStartupInfoW=_GetStartupInfoA
    def _GetSystemInfo(s,*a):
        if a and a[0]:
            s.memory.write(a[0],struct.pack("<HHIIIIIIII",0,1,0x1000,0x10000,0xFFFF,0xFFFF,0,0,4,0xFFFF))
        return 0
    def _GetCurrentDirectoryA(s,*a):
        c="C:\\"
        if len(a)>1 and a[1]:s.memory.write(a[0],c.encode()+b"\0");return len(c)+1
        return len(c)+1
    def _IsProcessorFeaturePresent(s,*a):return 1
    def _lstrlenA(s,*a):return len(s.memory.read_string(a[0])) if a and a[0] else 0
    def _lstrlenW(s,*a):return s._wcslen(*a)
    def _lstrcpyA(s,*a):
        d,src=a[0] if a else 0,a[1] if len(a)>1 else 0
        if d and src:s.memory.write_string(d,s.memory.read_string(src,1<<16))
        return d
    def _lstrcatA(s,*a):
        d,src=a[0] if a else 0,a[1] if len(a)>1 else 0
        if d and src:s.memory.write_string(d,s.memory.read_string(d,1<<16)+s.memory.read_string(src,1<<16))
        return d
    def _lstrcmpA(s,*a):
        x,y=s.memory.read_string(a[0]) if a and a[0] else "",s.memory.read_string(a[1]) if len(a)>1 and a[1] else ""
        return -1 if x<y else(1 if x>y else 0)
    def _wsprintfA(s,*a):
        d,fmt=a[0] if a else 0,a[1] if len(a)>1 else 0
        if not d or not fmt:return 0
        fs=s.memory.read_string(fmt)
        args=list(a[2:])
        try:m=s.crt._format(fs,s.crt.fmt and __import__("crt").ListReader(args) or None)
        except Exception:m=fs
        s.memory.write(d,m.encode("utf-8")+b"\0")
        return len(m)
    def _MessageBoxA(s,*a):
        t=s.memory.read_string(a[1]) if len(a)>1 and a[1] else ""
        c=s.memory.read_string(a[2]) if len(a)>2 and a[2] else ""
        sys.stdout.write("[MessageBox] %s | %s\n"%(c,t));sys.stdout.flush();return 1
    _MessageBoxW=_MessageBoxA
    def _OutputDebugStringA(s,*a):return 0
    def _CreateThread(s,*a):return 0xF0000000
    def _WaitForSingleObject(s,*a):return 0
    def _GetExitCodeThread(s,*a):
        if len(a)>1 and a[1]:s.memory.write_dword(a[1],0)
        return 1
    def _IsDebuggerPresent(s,*a):return 0
    def _EncodePointer(s,*a):return a[0] if a else 0
    _DecodePointer=_EncodePointer
    def _GetACP(s,*a):return 1252
    def _GetOEMCP(s,*a):return 437
    def _GetConsoleMode(s,*a):
        if len(a)>1 and a[1]:s.memory.write_dword(a[1],3)
        return 1
    def _SetConsoleMode(s,*a):return 1
    def _GetVersion(s,*a):return 0x0A280105
    def _GetVersionExA(s,*a):
        if a and a[0]:s.memory.write_dword(a[0],148);s.memory.write_dword(a[0]+4,10);s.memory.write_dword(a[0]+8,0x1DB1)
        return 1
    _GetVersionExW=_GetVersionExA

    def heap_alloc(s,n):return s.ntdll.RtlAllocateHeap(s.ntdll.default_heap,0,n)
    def heap_free(s,p):return s.ntdll.RtlFreeHeap(s.ntdll.default_heap,0,p)
    def heap_size(s,p):return s.ntdll.RtlSizeHeap(s.ntdll.default_heap,0,p)
    def call_dynamic(s,f):return s.call(f) if False else (s.executor.call_user(f) if s.executor else 0)

    def stdcall_args(s, name):
        return s.STDCALL_ARGS.get(name, 0)

    VARARG_FUNCS = {"printf", "_printf", "printf_s", "fprintf", "fprintf_s", "vfprintf",
                    "vprintf", "sprintf", "sprintf_s", "snprintf", "_snprintf", "vsprintf",
                    "vsnprintf", "_vsnprintf", "_vsnprintf_s", "wsprintfA", "wprintf",
                    "printf_l", "fprintf_l", "sprintf_l", "snprintf_l", "_scprintf"}

    def is_varargs(s, name):
        return name in s.VARARG_FUNCS

    VARARG_FMT_SLOT = {"printf": 0, "_printf": 0, "printf_s": 0, "wprintf": 0,
                       "printf_l": 0, "wsprintfA": 0, "_scprintf": 0,
                       "fprintf": 1, "fprintf_s": 1, "fprintf_l": 1, "vfprintf": 1,
                       "vprintf": 0, "sprintf": 1, "sprintf_s": 2, "sprintf_l": 1,
                       "vsprintf": 1, "vsnprintf": 2, "_vsnprintf": 2, "_vsnprintf_s": 2,
                       "snprintf": 2, "_snprintf": 2, "snprintf_l": 2}

    def vararg_fmt_slot(s, name):
        return s.VARARG_FMT_SLOT.get(name, 0)

    def _reg(s):
        A={"VirtualProtect":s._VirtualProtect,"VirtualQuery":s._VirtualQuery,"TlsGetValue":s._TlsGetValue,"TlsSetValue":s._TlsSetValue,"ExitProcess":s._ExitProcess,"GetStdHandle":s._GetStdHandle,"WriteFile":s._WriteFile,"ReadFile":s._ReadFile,"WriteConsoleA":s._WriteConsoleA,"ReadConsoleA":s._ReadConsoleA,"__iob_func":s._iob_func_impl,"fwrite":s._fwrite_impl,"vfprintf":s._vfprintf_impl,"malloc":s._malloc,"free":s._free,"abort":s._abort_impl,"exit":s._exit_impl,"__getmainargs":s._getmainargs,"_initterm":s._initterm,"EnterCriticalSection":s.ntdll.RtlEnterCriticalSection,"LeaveCriticalSection":s.ntdll.RtlLeaveCriticalSection,"InitializeCriticalSection":s.ntdll.RtlInitializeCriticalSection,"DeleteCriticalSection":s.ntdll.RtlDeleteCriticalSection,"GetLastError":s.ntdll.RtlGetLastWin32Error,"SetLastError":s.ntdll.RtlSetLastWin32Error,"Sleep":s._Sleep,"GetTickCount":s._GetTickCount,"QueryPerformanceCounter":s._QueryPerformanceCounter,"QueryPerformanceFrequency":s._QueryPerformanceFrequency,"GetCommandLineA":s._GetCommandLineA,"GetCommandLineW":s._GetCommandLineW,"GetEnvironmentStringsA":s._GetEnvironmentStringsA,"GetEnvironmentStringsW":s._GetEnvironmentStringsW,"FreeEnvironmentStringsA":s._FreeEnvironmentStringsA,"FreeEnvironmentStringsW":s._FreeEnvironmentStringsW,"GetSystemTime":s._GetSystemTime,"GetLocalTime":s._GetLocalTime,"GetSystemTimeAsFileTime":s._GetSystemTimeAsFileTime,"GetCurrentProcess":s._GetCurrentProcess,"GetCurrentProcessId":s._GetCurrentProcessId,"GetCurrentThread":s._GetCurrentThread,"GetCurrentThreadId":s._GetCurrentThreadId,"GetProcessHeap":s._GetProcessHeap,"HeapAlloc":s._HeapAlloc,"HeapFree":s._HeapFree,"HeapReAlloc":s._HeapReAlloc,"HeapSize":s._HeapSize,"GetModuleHandleA":s._GetModuleHandleA,"GetModuleHandleW":s._GetModuleHandleW,"GetProcAddress":s._GetProcAddress,"LoadLibraryA":s._LoadLibraryA,"LoadLibraryW":s._LoadLibraryW,"FreeLibrary":s._FreeLibrary,"SetUnhandledExceptionFilter":s._SetUnhandledExceptionFilter,"MultiByteToWideChar":s._MultiByteToWideChar,"WideCharToMultiByte":s._WideCharToMultiByte,"IsDBCSLeadByteEx":s._IsDBCSLeadByteEx,"__C_specific_handler":s.__C_specific_handler,"___lc_codepage_func":s.___lc_codepage_func,"___mb_cur_max_func":s.___mb_cur_max_func,"__initenv":s.__initenv,"__set_app_type":s.__set_app_type,"__setusermatherr":s.__setusermatherr,"_amsg_exit":s._amsg_exit,"_cexit":s._cexit,"_commode":s._commode,"_errno":s._errno,"_fmode":s._fmode,"_lock":s._lock,"_onexit":s._onexit,"_unlock":s._unlock,"calloc":s._calloc,"fprintf":s._fprintf,"fputc":s._fputc,"localeconv":s._localeconv,"memcpy":s._memcpy,"memset":s._memset,"signal":s._signal,"strerror":s._strerror,"strlen":s._strlen,"strncmp":s._strncmp,"system":s._system,"wcslen":s._wcslen,
"CreateFileA":s._CreateFileA,"CreateFileW":s._CreateFileW,"CloseHandle":s._CloseHandle,
"GetFileSize":s._GetFileSize,"SetFilePointer":s._SetFilePointer,
"VirtualAlloc":s._VirtualAlloc,"VirtualFree":s._VirtualFree,
"HeapCreate":s._HeapCreate,"HeapDestroy":s._HeapDestroy,"HeapValidate":s._HeapValidate,
"GetModuleFileNameA":s._GetModuleFileNameA,"GetModuleFileNameW":s._GetModuleFileNameW,
"GetStartupInfoA":s._GetStartupInfoA,"GetStartupInfoW":s._GetStartupInfoW,
"GetSystemInfo":s._GetSystemInfo,"GetCurrentDirectoryA":s._GetCurrentDirectoryA,
"IsProcessorFeaturePresent":s._IsProcessorFeaturePresent,
"lstrlenA":s._lstrlenA,"lstrlenW":s._lstrlenW,"lstrcpyA":s._lstrcpyA,
"lstrcatA":s._lstrcatA,"lstrcmpA":s._lstrcmpA,"wsprintfA":s._wsprintfA,
"MessageBoxA":s._MessageBoxA,"MessageBoxW":s._MessageBoxW,
"OutputDebugStringA":s._OutputDebugStringA,
"CreateThread":s._CreateThread,"WaitForSingleObject":s._WaitForSingleObject,
"GetExitCodeThread":s._GetExitCodeThread,"IsDebuggerPresent":s._IsDebuggerPresent,
"EncodePointer":s._EncodePointer,"DecodePointer":s._DecodePointer,
"GetACP":s._GetACP,"GetOEMCP":s._GetOEMCP,"GetConsoleMode":s._GetConsoleMode,
"SetConsoleMode":s._SetConsoleMode,"GetVersion":s._GetVersion,
"GetVersionExA":s._GetVersionExA,"GetVersionExW":s._GetVersionExW}
        for n,h in A.items():
            a=s._na(n);s.functions[a]=h;s.func_name_map[a]=n
    def _na(s,n):a=s.next_api_addr;s.next_api_addr+=16;return a
    def get_api_address(s,dll,fn,ord=None):
        k=fn if fn else f"#{ord}"
        for a,n in s.func_name_map.items():
            if n==k:return a
        a=s._na(k);s.func_name_map[a]=k
        h=s._rh(dll,fn);s.functions[a]=h if h else(lambda *x:0)
        return a
    def _rh(s,dll,n):
        if not n:return None
        c=s.cpp_lib.resolve(n)
        if c:return c
        c=s.crt.resolve(n)
        if c:return c
        if hasattr(s,f"_{n}"):return getattr(s,f"_{n}")
        if hasattr(s.ntdll,n):return getattr(s.ntdll,n)
    def call(s,a,*args):
        if a in s.functions:
            try:return s.functions[a](*args)
            except SystemExit:raise
            except:return 0
        return 0
    def resolve_api_name(s,a):return s.func_name_map.get(a,f"Unk_{a:x}")
    def _vp(s,p):return p and 0x1000<p<0x7FFFFFFF0000
    def _ExitProcess(s,*a):raise SystemExit(a[0] if a else 0)
    def _GetStdHandle(s,*a):
        h=(a[0] if a else 0)&0xFFFFFFFF
        return{0xFFFFFFF5:0x101,0xFFFFFFF6:0x100,0xFFFFFFF4:0x102}.get(h,0)
    def _WriteFile(s,*a):
        if len(a)<4:return 0
        h,lb,n,wr=a[0],a[1],a[2],a[3]
        if h not in(0x101,0x102) and h in s.win_handles:return s._WriteFile2(*a)
        if h in(0x101,0x102):
            try:
                d=s.memory.read(lb,n);sys.stdout.write(d.decode('utf-8','replace'));sys.stdout.flush()
                if wr:s.memory.write_dword(wr,n)
                return 1
            except:return 0
        return 0
    def _WriteConsoleA(s,*a):
        if len(a)>=4:
            lb,n,wr=a[1],a[2],a[3]
            try:
                d=s.memory.read(lb,n);sys.stdout.write(d.decode('utf-8','replace'));sys.stdout.flush()
                if wr:s.memory.write_dword(wr,n)
                return 1
            except:return 0
        return 0
    def _ReadConsoleA(s,*a):
        if len(a)<4:return 0
        lb,n,rp=a[1],a[2],a[3]
        try:
            d=sys.stdin.readline()
            if d:
                e=d.encode('utf-8')[:n];s.memory.write(lb,e)
                if rp:s.memory.write_dword(rp,len(e))
            elif rp:s.memory.write_dword(rp,0)
            return 1
        except:return 0
    def _ReadFile(s,*a):
        if len(a)<4:return 0
        h,lb,n,rp=a[0],a[1],a[2],a[3]
        if h!=0x100 and h in s.win_handles:
            st=s._wget(h)
            if not st:return 0
            d=st.read(n)
            if d:s.memory.write(lb,d)
            if rp:s.memory.write_dword(rp,len(d))
            return 1 if d else 0
        if h==0x100:
            try:
                d=sys.stdin.readline().encode('utf-8')[:n]
                if d:
                    s.memory.write(lb,d)
                    if rp:s.memory.write_dword(rp,len(d))
                elif rp:s.memory.write_dword(rp,0)
                return 1
            except:return 0
        return 0
    def _fwrite_impl(s,*a):
        p,sz,c=a[0],a[1],a[2]
        if c==0:return 0
        t=sz*c
        if s._vp(p) and t>0:
            try:sys.stdout.write(s.memory.read(p,t).decode('utf-8','replace'));sys.stdout.flush();return c
            except:return 0
        return 0
    def _vfprintf_impl(s,st,fmt,ap,*a):
        try:
            fs=s.memory.read_string(fmt)
            a1=s.memory.read_qword(ap);a2=s.memory.read_qword(ap+8);a3=s.memory.read_qword(ap+16)
            try:
                if fs.count('%')==1:m=fs%(a1)
                elif fs.count('%')>1:m=fs%(a1,a2,a3)[:fs.count('%')]
                else:m=fs
            except:m=fs
            sys.stdout.write(m);sys.stdout.flush();return len(m)
        except:return 0
    def _iob_func_impl(s,*a):return s.iob_base
    def _malloc(s,*a):return s.ntdll.RtlAllocateHeap(0,0,a[0])
    def _free(s,*a):s.ntdll.RtlFreeHeap(0,0,a[0]);return 0
    def _initterm(s,*a):
        st,en=a[0],a[1]
        if not s._vp(st) or not s._vp(en):return 0
        c=st;i=0
        while c<en and i<1000:
            try:
                f=s.memory.read_qword(c)
                if f:s.call(f)
                c+=8;i+=1
            except:break
        return 0
    def _abort_impl(s,*a):raise SystemExit(1)
    def _exit_impl(s,*a):raise SystemExit(a[0] if a else 0)
    def _getmainargs(s,*a):
        if s._vp(a[0]):s.memory.write_dword(a[0],0)
        if s._vp(a[1]):s.memory.write_qword(a[1],0)
        return 0
    def _VirtualProtect(s,*a):return 1
    def _VirtualQuery(s,*a):return 0
    def _TlsGetValue(s,*a):return s.tls_base+(a[0]*8)
    def _TlsSetValue(s,*a):return 1
    def _Sleep(s,*a):time.sleep((a[0] if a else 0)/1000.0);return 0
    def _GetTickCount(s,*a):return int(time.time()*1000)&0xFFFFFFFF
    def _QueryPerformanceCounter(s,*a):
        c=int(time.time()*10000000)
        if a and a[0]:s.memory.write_qword(a[0],c)
        return 1
    def _QueryPerformanceFrequency(s,*a):
        if a and a[0]:s.memory.write_qword(a[0],10000000)
        return 1
    def _GetCommandLineA(s,*a):
        c="emulator.exe";ad=s.memory.allocate(len(c)+1);s.memory.write_string(ad,c);return ad
    def _GetCommandLineW(s,*a):
        c="emulator.exe";ad=s.memory.allocate((len(c)+1)*2);s.memory.write_string(ad,c,'utf-16le');return ad
    def _GetEnvironmentStringsA(s,*a):
        e=b"PATH=C:\\\0TEMP=C:\\Temp\0\0";ad=s.memory.allocate(len(e));s.memory.write(ad,e);return ad
    def _GetEnvironmentStringsW(s,*a):
        e=b"P\0A\0T\0H\0=\0C\0:\0\\\0\0\0T\0E\0M\0P\0=\0C\0:\0\\\0T\0e\0m\0p\0\0\0\0\0";ad=s.memory.allocate(len(e));s.memory.write(ad,e);return ad
    def _FreeEnvironmentStringsA(s,*a):return 1
    def _FreeEnvironmentStringsW(s,*a):return 1
    def _GetSystemTime(s,*a):
        import datetime;n=datetime.datetime.now()
        if a and a[0]:s.memory.write(a[0],struct.pack('<HHHHHHHH',n.year,n.month,n.day,n.weekday()+1,n.hour,n.minute,n.second,0))
        return 0
    _GetLocalTime=_GetSystemTime
    def _GetSystemTimeAsFileTime(s,*a):
        if a and a[0]:s.memory.write_qword(a[0],int(time.time()*10000000)+116444736000000000)
        return 0
    def _GetCurrentProcess(s,*a):return 0xFFFFFFFF
    def _GetCurrentProcessId(s,*a):return 1234
    def _GetCurrentThread(s,*a):return 0xFFFFFFFE
    def _GetCurrentThreadId(s,*a):return 5678
    def _GetProcessHeap(s,*a):return s.ntdll.default_heap
    def _HeapAlloc(s,*a):return s.ntdll.RtlAllocateHeap(a[0] if a else 0,a[1] if len(a)>1 else 0,a[2] if len(a)>2 else 0)
    def _HeapFree(s,*a):return s.ntdll.RtlFreeHeap(a[0] if a else 0,a[1] if len(a)>1 else 0,a[2] if len(a)>2 else 0)
    def _HeapReAlloc(s,*a):return s.ntdll.RtlReAllocateHeap(a[0] if a else 0,a[1] if len(a)>1 else 0,a[2] if len(a)>2 else 0,a[3] if len(a)>3 else 0)
    def _HeapSize(s,*a):return s.ntdll.RtlSizeHeap(a[0] if a else 0,a[1] if len(a)>1 else 0,a[2] if len(a)>2 else 0)
    def _GetModuleHandleA(s,*a):return 0x400000
    def _GetModuleHandleW(s,*a):return 0x400000
    def _GetProcAddress(s,*a):return 0
    def _LoadLibraryA(s,*a):return 0x10000000
    def _LoadLibraryW(s,*a):return 0x10000000
    def _FreeLibrary(s,*a):return 1
    def _SetUnhandledExceptionFilter(s,*a):return 0
    def _MultiByteToWideChar(s,*a):
        cp,fl,lp,cb,wc,cw=a[0] if a else 0,a[1] if len(a)>1 else 0,a[2] if len(a)>2 else 0,a[3] if len(a)>3 else 0,a[4] if len(a)>4 else 0,a[5] if len(a)>5 else 0
        if lp and cb>0:
            try:
                t=s.memory.read(lp,cb).decode('utf-8','ignore')
                if wc and cw>0:s.memory.write(wc,t.encode('utf-16le')[:cw*2])
                return len(t)
            except:pass
        return 0
    def _WideCharToMultiByte(s,*a):
        cp,fl,wp,cw,mb,cb=a[0] if a else 0,a[1] if len(a)>1 else 0,a[2] if len(a)>2 else 0,a[3] if len(a)>3 else 0,a[4] if len(a)>4 else 0,a[5] if len(a)>5 else 0
        if wp and cw>0:
            try:
                t=s.memory.read(wp,cw*2).decode('utf-16le','ignore')
                if mb and cb>0:s.memory.write(mb,t.encode('utf-8')[:cb])
                return len(t)
            except:pass
        return 0
    def _IsDBCSLeadByteEx(s,*a):return 0
    def __C_specific_handler(s,*a):return 0
    def ___lc_codepage_func(s,*a):ad=s.memory.allocate(4);s.memory.write_dword(ad,1252);return ad
    def ___mb_cur_max_func(s,*a):ad=s.memory.allocate(4);s.memory.write_dword(ad,1);return ad
    def __initenv(s,*a):ad=s.memory.allocate(8);s.memory.write_qword(ad,0);return ad
    def __set_app_type(s,*a):return 0
    def __setusermatherr(s,*a):return 0
    def _amsg_exit(s,*a):raise SystemExit(1)
    def _cexit(s,*a):return 0
    def _commode(s,*a):return 0
    def _errno(s,*a):ad=s.memory.allocate(4);s.memory.write_dword(ad,0);return ad
    def _fmode(s,*a):ad=s.memory.allocate(4);s.memory.write_dword(ad,0);return ad
    def _lock(s,*a):return 0
    def _onexit(s,*a):return 0
    def _unlock(s,*a):return 0
    def _calloc(s,*a):
        n,sz=a[0] if a else 0,a[1] if len(a)>1 else 0
        t=n*sz;ad=s.ntdll.RtlAllocateHeap(0,0,t)
        if ad:s.memory.write(ad,b'\0'*t)
        return ad
    def _fprintf(s,*a):return s._vfprintf_impl(a[0] if a else 0,a[1] if len(a)>1 else 0,a[2] if len(a)>2 else 0)
    def _fputc(s,*a):
        c=a[0] if a else 0;sys.stdout.write(chr(c));sys.stdout.flush();return c
    def _localeconv(s,*a):ad=s.memory.allocate(256);s.memory.write(ad,b'\0'*256);return ad
    def _memcpy(s,*a):
        d,src,c=a[0] if a else 0,a[1] if len(a)>1 else 0,a[2] if len(a)>2 else 0
        if d and src and c>0:s.memory.write(d,s.memory.read(src,c))
        return d
    def _memset(s,*a):
        d,v,c=a[0] if a else 0,a[1] if len(a)>1 else 0,a[2] if len(a)>2 else 0
        if d and c>0:s.memory.write(d,bytes([v&0xFF]*c))
        return d
    def _signal(s,*a):return 0
    def _strerror(s,*a):ad=s.memory.allocate(64);s.memory.write_string(ad,"Unknown error");return ad
    def _strlen(s,*a):return len(s.memory.read_string(a[0])) if a and a[0] else 0
    def _strncmp(s,*a):
        p1,p2,c=a[0] if a else 0,a[1] if len(a)>1 else 0,a[2] if len(a)>2 else 0
        if p1 and p2 and c>0:
            x=s.memory.read_string(p1,c);y=s.memory.read_string(p2,c)
            return -1 if x<y else(1 if x>y else 0)
        return 0
    def _system(s,*a):return 0
    def _wcslen(s,*a):
        p=a[0] if a else 0
        if p:
            d=s.memory.read(p,1024)
            for i in range(0,len(d),2):
                if d[i]==0 and d[i+1]==0:return i//2
            return 512
        return 0
