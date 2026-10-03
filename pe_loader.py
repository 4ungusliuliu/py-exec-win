import struct
class Section:
    def __init__(s,n,va,vs,rd,rs,ro,ch):s.name=n;s.virtual_address=va;s.virtual_size=vs;s.raw_data=rd;s.raw_size=rs;s.raw_offset=ro;s.characteristics=ch
class PELoader:
    def __init__(s,fp):
        s.filepath=fp;s.data=None;s.image_base=0;s.entry_point=0;s.sections=[];s.imports=[];s.iat={}
        for k in("machine_type","num_sections","optional_header_size","pe_offset","size_of_image","size_of_headers","size_of_code","size_of_initialized_data","size_of_uninitialized_data","subsystem","dll_characteristics"):setattr(s,k,0)
        s.is_64bit=False
    def load(s):
        try:
            with open(s.filepath,'rb') as f:s.data=bytearray(f.read())
            if len(s.data)<64 or s.data[:2]!=b'MZ':return False
            s.pe_offset=struct.unpack('<I',s.data[0x3C:0x40])[0]
            if s.pe_offset+4>=len(s.data) or s.data[s.pe_offset:s.pe_offset+4]!=b'PE\0\0':return False
            s._coff()
            if not s._opt():return False
            s._secs();s._imp();return True
        except Exception as e:print(f"Load: {e}");return False
    def _coff(s):
        s.machine_type=struct.unpack('<H',s.data[s.pe_offset+4:s.pe_offset+6])[0]
        s.num_sections=struct.unpack('<H',s.data[s.pe_offset+6:s.pe_offset+8])[0]
        s.optional_header_size=struct.unpack('<H',s.data[s.pe_offset+20:s.pe_offset+22])[0]
    def _opt(s):
        o=s.pe_offset+24
        if o+s.optional_header_size>len(s.data):return False
        m=struct.unpack('<H',s.data[o:o+2])[0]
        if m not in(0x10B,0x20B):return False
        s.is_64bit=m==0x20B
        s.size_of_code=struct.unpack('<I',s.data[o+4:o+8])[0]
        s.size_of_initialized_data=struct.unpack('<I',s.data[o+8:o+12])[0]
        s.size_of_uninitialized_data=struct.unpack('<I',s.data[o+12:o+16])[0]
        s.entry_point=struct.unpack('<I',s.data[o+16:o+20])[0]
        s.image_base=struct.unpack('<I' if m==0x10B else '<Q',s.data[o+(28 if m==0x10B else 24):o+(32 if m==0x10B else 32)])[0]
        s.size_of_image=struct.unpack('<I',s.data[o+56:o+60])[0]
        s.size_of_headers=struct.unpack('<I',s.data[o+60:o+64])[0]
        s.subsystem=struct.unpack('<H',s.data[o+68:o+70])[0]
        s.dll_characteristics=struct.unpack('<H',s.data[o+70:o+72])[0]
        return True
    def _secs(s):
        so=s.pe_offset+24+s.optional_header_size
        for i in range(s.num_sections):
            o=so+i*40
            if o+40>len(s.data):continue
            n=s.data[o:o+8].split(b'\0')[0].decode('ascii','ignore')
            vs,va,rs,ro=struct.unpack('<IIII',s.data[o+8:o+24]);ch=struct.unpack('<I',s.data[o+36:o+40])[0]
            if rs==0 and vs>0:rd=b'\0'*vs;rs=vs
            elif ro+rs>len(s.data):rs=len(s.data)-ro;rd=bytes(s.data[ro:ro+rs])
            else:rd=bytes(s.data[ro:ro+rs]) if rs>0 else b''
            if len(rd)<vs and vs>0:rd=rd+b'\0'*(vs-len(rd))
            s.sections.append(Section(n,va,vs,rd,rs,ro,ch))
    def _imp(s):
        try:
            dirs=s.pe_offset+24+(112 if s.is_64bit else 96)
            itr=struct.unpack('<I',s.data[dirs+8:dirs+12])[0]
            ito=s._r2o(itr) if itr else 0
            if not ito:s.imports=[];return
            s.imports=[];i=0
            while True:
                eo=ito+i*20
                if eo+20>len(s.data):break
                ie=struct.unpack('<IIIII',s.data[eo:eo+20])
                if not any(ie):break
                dno=s._r2o(ie[3])
                if not dno:break
                imp={'dll':s._cs(dno),'functions':[],'first_thunk':ie[4],'original_first_thunk':ie[0]}
                tr=imp['original_first_thunk'] or imp['first_thunk']
                to=s._r2o(tr)
                if not to:i+=1;continue
                j=0
                while True:
                    if s.is_64bit:
                        td=struct.unpack('<Q',s.data[to+j*8:to+j*8+8])[0]
                        if not td:break
                        is_ord=bool(td&0x8000000000000000)
                    else:
                        td=struct.unpack('<I',s.data[to+j*4:to+j*4+4])[0]
                        if not td:break
                        is_ord=bool(td&0x80000000)
                    if is_ord:imp['functions'].append({'ordinal':td&0xFFFF,'name':None})
                    else:
                        no=s._r2o(td+2)
                        if no:imp['functions'].append({'name':s._cs(no),'ordinal':None})
                    j+=1
                s.imports.append(imp);i+=1
        except Exception as e:print(f"Imp: {e}");s.imports=[]
    def _r2o(s,r):
        for sec in s.sections:
            if sec.virtual_address<=r<sec.virtual_address+sec.virtual_size:return sec.raw_offset+(r-sec.virtual_address)
        return r if r<s.size_of_headers else 0
    def _cs(s,o):
        e=o
        while e<len(s.data) and e-o<256 and s.data[e]:e+=1
        try:return s.data[o:e].decode('utf-8')
        except:return s.data[o:e].decode('latin-1','ignore')
    def get_section_by_va(s,va):
        for sec in s.sections:
            if sec.virtual_address<=va<sec.virtual_address+sec.virtual_size:return sec
    def get_architecture(s):return{0x014C:'x86',0x8664:'x64',0x01C0:'ARM',0xAA64:'ARM64',0x0200:'IA64'}.get(s.machine_type,'x64' if s.is_64bit else 'x86')
