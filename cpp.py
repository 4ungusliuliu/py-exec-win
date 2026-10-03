import sys,struct
class CPPLibrary:
    def __init__(s,memory,api):
        s.memory=memory;s.api=api
        s.cout_addr=memory.allocate(256);s.cerr_addr=memory.allocate(256);s.cin_addr=memory.allocate(256);s.endl_addr=memory.allocate(8)
    def resolve(s,fn):
        m={"_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc":s._os_str,"_ZNSolsEPFRSoS_E":s._os_fn,"_ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_":s._os_endl,"_ZNSolsEi":s._os_num,"_ZNSolsEx":s._os_num,"_ZNSolsEy":s._os_num,"_ZNSolsEb":s._os_bool,"_ZNSolsEd":s._os_dbl,"_ZNSolsEf":s._os_flt,"_ZNSirsERi":s._is_int,"_ZStrsIcSt11char_traitsIcEERSt13basic_istreamIT_T0_ES6_PS3_":s._is_str,"_ZNSolsEPKc":s._os_str}
        for k,v in m.items():
            if fn.startswith(k):return v
    def get_symbol_address(s,sn):
        return{"_ZSt4cout":s.cout_addr,"_ZSt4cerr":s.cerr_addr,"_ZSt3cin":s.cin_addr,"_ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_":s.endl_addr}.get(sn)
    def _os_str(s,*a):
        sp=a[0] if a else 0;st=a[1] if len(a)>1 else 0
        if st>0:
            try:sys.stdout.write(s.memory.read_string(st));sys.stdout.flush()
            except:pass
        return sp
    def _os_endl(s,*a):sys.stdout.write("\n");sys.stdout.flush();return a[0] if a else 0
    def _os_fn(s,*a):
        sp=a[0] if a else 0;fp=a[1] if len(a)>1 else 0
        if fp==s.endl_addr:sys.stdout.write("\n");sys.stdout.flush()
        return sp
    def _os_dbl(s,*a):
        sp=a[0] if a else 0
        try:sys.stdout.write(str(struct.unpack('<d',struct.pack('<Q',a[1] if len(a)>1 else 0))[0]));sys.stdout.flush()
        except:pass
        return sp
    def _os_flt(s,*a):
        sp=a[0] if a else 0
        try:sys.stdout.write(str(struct.unpack('<f',struct.pack('<I',a[1] if len(a)>1 else 0))[0]));sys.stdout.flush()
        except:pass
        return sp
    def _os_num(s,*a):
        sp=a[0] if a else 0
        try:sys.stdout.write(str(a[1] if len(a)>1 else 0));sys.stdout.flush()
        except:pass
        return sp
    def _os_bool(s,*a):
        sp=a[0] if a else 0
        try:sys.stdout.write("true" if (a[1] if len(a)>1 else 0) else "false");sys.stdout.flush()
        except:pass
        return sp
    def _is_int(s,*a):
        sp=a[0] if a else 0;ip=a[1] if len(a)>1 else 0
        if ip>0:
            try:
                d=sys.stdin.readline().strip()
                if d:s.memory.write(ip,struct.pack('<I',int(d)))
            except:pass
        return sp
    def _is_str(s,*a):
        sp=a[0] if a else 0;p=a[1] if len(a)>1 else 0
        if p>0:
            try:
                d=sys.stdin.readline().strip()
                if d:s.memory.write(p,d.encode()+b'\0')
            except:pass
        return sp
