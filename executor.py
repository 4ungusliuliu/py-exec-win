import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
from capstone.x86 import X86_OP_IMM, X86_OP_REG, X86_OP_MEM

PARITY = [1 if (bin(i).count("1") % 2 == 0) else 0 for i in range(256)]


def _regs_x64():
    m = {}
    top = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip"] + ["r%d" % i for i in range(8, 16)]
    for r in top:
        m[r] = (r, 0, 8)
    m32 = {"rax": "eax", "rbx": "ebx", "rcx": "ecx", "rdx": "edx", "rsi": "esi", "rdi": "edi",
           "rbp": "ebp", "rsp": "esp", "rip": "eip"}
    for i in range(8, 16):
        m32["r%d" % i] = "r%dd" % i
    for p, n in m32.items():
        m[n] = (p, 0, 4)
    m16 = {"rax": "ax", "rbx": "bx", "rcx": "cx", "rdx": "dx", "rsi": "si", "rdi": "di",
           "rbp": "bp", "rsp": "sp"}
    for i in range(8, 16):
        m16["r%d" % i] = "r%dw" % i
    for p, n in m16.items():
        m[n] = (p, 0, 2)
    m8 = {"rax": "al", "rbx": "bl", "rcx": "cl", "rdx": "dl", "rsi": "sil", "rdi": "dil",
          "rbp": "bpl", "rsp": "spl"}
    for i in range(8, 16):
        m8["r%d" % i] = "r%db" % i
    for p, n in m8.items():
        m[n] = (p, 0, 1)
    for p, n in (("rax", "ah"), ("rbx", "bh"), ("rcx", "ch"), ("rdx", "dh")):
        m[n] = (p, 1, 1)
    return m


def _regs_x86():
    m = {}
    for r in ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip"]:
        m[r] = (r, 0, 4)
    for p, n in (("eax", "ax"), ("ebx", "bx"), ("ecx", "cx"), ("edx", "dx"),
                 ("esi", "si"), ("edi", "di"), ("ebp", "bp"), ("esp", "sp")):
        m[n] = (p, 0, 2)
    for p, n in (("eax", "al"), ("ebx", "bl"), ("ecx", "cl"), ("edx", "dl")):
        m[n] = (p, 0, 1)
    for p, n in (("eax", "ah"), ("ebx", "bh"), ("ecx", "ch"), ("edx", "dh")):
        m[n] = (p, 1, 1)
    return m


REG_MAP = {"x64": _regs_x64(), "x86": _regs_x86()}

CC = {
    "e": lambda f: f["ZF"],
    "z": lambda f: f["ZF"],
    "ne": lambda f: not f["ZF"],
    "nz": lambda f: not f["ZF"],
    "a": lambda f: (not f["CF"]) and (not f["ZF"]),
    "ae": lambda f: not f["CF"],
    "nb": lambda f: not f["CF"],
    "nc": lambda f: not f["CF"],
    "b": lambda f: f["CF"],
    "c": lambda f: f["CF"],
    "nae": lambda f: f["CF"],
    "be": lambda f: f["CF"] or f["ZF"],
    "na": lambda f: f["CF"] or f["ZF"],
    "g": lambda f: (not f["ZF"]) and (f["SF"] == f["OF"]),
    "ge": lambda f: f["SF"] == f["OF"],
    "nl": lambda f: f["SF"] == f["OF"],
    "l": lambda f: f["SF"] != f["OF"],
    "nge": lambda f: f["SF"] != f["OF"],
    "le": lambda f: f["ZF"] or (f["SF"] != f["OF"]),
    "ng": lambda f: f["ZF"] or (f["SF"] != f["OF"]),
    "s": lambda f: f["SF"],
    "ns": lambda f: not f["SF"],
    "o": lambda f: f["OF"],
    "no": lambda f: not f["OF"],
    "p": lambda f: f["PF"],
    "pe": lambda f: f["PF"],
    "np": lambda f: not f["PF"],
    "po": lambda f: not f["PF"],
}


class UniversalExecutor:
    MAX_REP = 1 << 22

    def __init__(self, pe_loader, memory, api):
        self.pe_loader = pe_loader
        self.memory = memory
        self.api = api
        self.architecture = pe_loader.get_architecture()
        self.md = Cs(CS_ARCH_X86, CS_MODE_64 if self.architecture == "x64" else CS_MODE_32)
        self.md.detail = True
        self.running = False
        self.verbose = False
        self.debug = False
        self.trace = False
        self.instructions_executed = 0
        self.api_calls = 0
        self.unhandled = {}
        self.max_instructions = 100000000
        self.breakpoints = set()
        self.exit_code = None
        self._init_regs()

    def _init_regs(self):
        ep = self.pe_loader.image_base + self.pe_loader.entry_point
        st = self.memory.stack_top
        self.is64 = self.architecture == "x64"
        self.ptr_size = 8 if self.is64 else 4
        self.ptr_mask = 0xFFFFFFFFFFFFFFFF if self.is64 else 0xFFFFFFFF
        self.stack_step = self.ptr_size
        self.reg_map = REG_MAP["x64" if self.is64 else "x86"]
        if self.is64:
            self.registers = {"rax": 0, "rbx": 0, "rcx": 0, "rdx": 0, "rsi": 0, "rdi": 0,
                              "rsp": st, "rbp": st, "r8": 0, "r9": 0, "r10": 0, "r11": 0,
                              "r12": 0, "r13": 0, "r14": 0, "r15": 0, "rip": ep}
            self.ip_register = "rip"
            self.sp_register = "rsp"
            self.bp_register = "rbp"
            self.cx_register = "rcx"
            self.ax_register = "rax"
        else:
            self.registers = {"eax": 0, "ebx": 0, "ecx": 0, "edx": 0, "esi": 0, "edi": 0,
                              "esp": st, "ebp": st, "eip": ep}
            self.ip_register = "eip"
            self.sp_register = "esp"
            self.bp_register = "ebp"
            self.cx_register = "ecx"
            self.ax_register = "eax"
        self.flags = {"ZF": 0, "SF": 0, "CF": 0, "OF": 0, "DF": 0, "PF": 1, "AF": 0}
        self.xmm = [0] * 16
        self.st = [0.0] * 8
        self.ftop = 0
        self.fsw = 0
        self.fcw = 0x037F

    def run(self):
        self.running = True
        try:
            while self.running and self.instructions_executed < self.max_instructions:
                ip = self.registers[self.ip_register]
                if ip == 0 or ip < 0x1000 or ip in self.breakpoints:
                    break
                code = self.memory.read(ip, 16)
                if not code or code == b"\0" * 16:
                    break
                try:
                    insn = next(self.md.disasm(code, ip))
                except StopIteration:
                    break
                if self.trace:
                    self._trace(insn)
                try:
                    ni = self._exec(insn)
                except SystemExit:
                    raise
                except Exception as e:
                    if self.debug:
                        raise
                    sys.stderr.write("exec error @%x %s %s: %s\n" % (ip, insn.mnemonic, insn.op_str, e))
                    break
                self.registers[self.ip_register] = (ni if ni is not None
                                                    else self.registers[self.ip_register] + insn.size)
                self.instructions_executed += 1
        except KeyboardInterrupt:
            pass
        except SystemExit as e:
            self.exit_code = e.code
        self.running = False
        if self.verbose:
            self.report()
        return self.exit_code

    def report(self):
        sys.stderr.write("instructions=%d api_calls=%d\n" % (self.instructions_executed, self.api_calls))
        if self.unhandled:
            sys.stderr.write("unhandled: %s\n" % sorted(self.unhandled.items(), key=lambda x: -x[1])[:25])

    def _trace(self, insn):
        regs = " ".join("%s=%x" % (k, v) for k, v in list(self.registers.items())[:6])
        sys.stderr.write("%016x  %-24s %-28s %s\n" % (insn.address, insn.mnemonic + " " + insn.op_str,
                                                      "", regs))

    def _rr(self, name):
        if name in self.registers:
            return self.registers[name]
        e = self.reg_map.get(name)
        if e:
            parent, off, size = e
            v = self.registers.get(parent, 0)
            return (v >> (off * 8)) & ((1 << (size * 8)) - 1)
        return 0

    def _wr(self, name, value):
        value &= self.ptr_mask if self.reg_map[name][2] >= self.ptr_size else (1 << (self.reg_map[name][2] * 8)) - 1
        if name in self.registers:
            self.registers[name] = value & self.ptr_mask
            return
        e = self.reg_map.get(name)
        if not e:
            return
        parent, off, size = e
        bits = size * 8
        value &= (1 << bits) - 1
        cur = self.registers.get(parent, 0)
        if size >= 4 and self.is64:
            cur = 0
        mask = ((1 << bits) - 1) << (off * 8)
        self.registers[parent] = (cur & ~mask) | (value << (off * 8))
        self.registers[parent] &= self.ptr_mask

    def _mem_read(self, addr, size):
        size = size or self.ptr_size
        if size == 1:
            return self.memory.read_byte(addr)
        if size == 2:
            return self.memory.read_word(addr)
        if size == 4:
            return self.memory.read_dword(addr)
        if size == 8:
            return self.memory.read_qword(addr)
        if size == 16:
            return self.memory.read_qword(addr)
        return 0

    def _mem_write(self, addr, size, value):
        size = size or self.ptr_size
        if size == 1:
            return self.memory.write_byte(addr, value)
        if size == 2:
            return self.memory.write_word(addr, value)
        if size == 4:
            return self.memory.write_dword(addr, value)
        if size == 8:
            return self.memory.write_qword(addr, value)
        if size == 16:
            self.memory.write_qword(addr, value & 0xFFFFFFFFFFFFFFFF)
            self.memory.write_qword(addr + 8, (value >> 64) & 0xFFFFFFFFFFFFFFFF)
            return True
        return False

    def _gma(self, op, ia, isz=0):
        mm = op.mem
        a = 0
        if mm.segment != 0:
            sn = self.md.reg_name(mm.segment)
            if sn in ("gs",):
                return self.memory.TEB_BASE + mm.disp
            if sn in ("fs",):
                return self.memory.TEB_BASE + mm.disp
        if mm.base != 0:
            br = self.md.reg_name(mm.base)
            if br in ("rip", "eip"):
                a += (ia + isz)
            else:
                a += self._rr(br)
        if mm.index != 0:
            a += self._rr(self.md.reg_name(mm.index)) * mm.scale
        return (a + mm.disp) & self.ptr_mask

    def _gov(self, op, ia, size=None, isz=0):
        if op.type == X86_OP_IMM:
            return op.imm & self.ptr_mask
        if op.type == X86_OP_REG:
            name = self.md.reg_name(op.reg)
            if name.startswith(("xmm", "ymm")):
                return self._xmm_get(name)
            return self._rr(name)
        if op.type == X86_OP_MEM:
            addr = self._gma(op, ia, isz)
            if addr is None:
                return 0
            return self._mem_read(addr, size if size is not None else op.size)
        return 0

    def _sov(self, op, value, ia, size=None):
        value &= self.ptr_mask
        if op.type == X86_OP_REG:
            name = self.md.reg_name(op.reg)
            if name.startswith(("xmm", "ymm")):
                self._xmm_set(name, value)
                return
            self._wr(name, value)
        elif op.type == X86_OP_MEM:
            addr = self._gma(op, ia)
            if addr is None:
                return
            self._mem_write(addr, size if size is not None else op.size, value)

    def _xmm_index(self, name):
        try:
            return int(name[3:]) if name.startswith("xmm") else int(name[3:])
        except Exception:
            return 0

    def _xmm_get(self, name):
        return self.xmm[self._xmm_index(name)]

    def _xmm_set(self, name, v):
        self.xmm[self._xmm_index(name)] = v & ((1 << 128) - 1)

    @staticmethod
    def _f32(v):
        return struct.unpack("<f", struct.pack("<I", v & 0xFFFFFFFF))[0]

    @staticmethod
    def _p32(f):
        return struct.unpack("<I", struct.pack("<f", f))[0]

    @staticmethod
    def _f64(v):
        return struct.unpack("<d", struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF))[0]

    @staticmethod
    def _p64(f):
        return struct.unpack("<Q", struct.pack("<d", f))[0]

    def _fpush(self, v):
        self.ftop = (self.ftop - 1) & 7
        self.st[self.ftop] = float(v)

    def _fpop(self):
        v = self.st[self.ftop]
        self.ftop = (self.ftop + 1) & 7
        return v

    def _fst(self, i=0):
        return self.st[(self.ftop + i) & 7]

    def _fset(self, i, v):
        self.st[(self.ftop + i) & 7] = float(v)

    def _sz(self, insn):
        for o in insn.operands:
            if o.size:
                return o.size
        return self.ptr_size

    def _fl_logic(self, r, size):
        m = (1 << (size * 8)) - 1
        r &= m
        self.flags["ZF"] = int(r == 0)
        self.flags["SF"] = (r >> (size * 8 - 1)) & 1
        self.flags["CF"] = 0
        self.flags["OF"] = 0
        self.flags["PF"] = PARITY[r & 0xFF]

    def _fl_add(self, a, b, size, carry=0):
        m = (1 << (size * 8)) - 1
        a &= m
        b &= m
        r = (a + b + carry) & m
        sb = size * 8 - 1
        self.flags["ZF"] = int(r == 0)
        self.flags["SF"] = (r >> sb) & 1
        self.flags["CF"] = int((a + b + carry) > m)
        self.flags["OF"] = int((~(a ^ b) & (a ^ r) & (1 << sb)) != 0)
        self.flags["PF"] = PARITY[r & 0xFF]
        return r

    def _fl_sub(self, a, b, size, borrow=0):
        m = (1 << (size * 8)) - 1
        a &= m
        b &= m
        r = (a - b - borrow) & m
        sb = size * 8 - 1
        self.flags["ZF"] = int(r == 0)
        self.flags["SF"] = (r >> sb) & 1
        self.flags["CF"] = int((a & m) < ((b + borrow) & m))
        self.flags["OF"] = int(((a ^ b) & (a ^ r) & (1 << sb)) != 0)
        self.flags["PF"] = PARITY[r & 0xFF]
        return r

    def _exec(self, insn):
        m = insn.mnemonic
        if m.startswith("lock "):
            m = m[5:]
        prefix = None
        if m.startswith("repne ") or m.startswith("repnz "):
            prefix = "repne"
            m = m.split(" ", 1)[1]
        elif m.startswith("repe ") or m.startswith("repz ") or m.startswith("rep "):
            prefix = "rep"
            m = m.split(" ", 1)[1]
        if prefix:
            h = getattr(self, "_rep_%s" % m, None)
            if h:
                return h(insn, prefix)
        key = m.replace(".", "_").replace(" ", "_")
        h = getattr(self, "_handle_%s" % key, None)
        if h is None:
            self.unhandled[m] = self.unhandled.get(m, 0) + 1
            return None
        return h(insn)

    def _handle_unknown(self, insn):
        self.unhandled[insn.mnemonic] = self.unhandled.get(insn.mnemonic, 0) + 1
        return None

    def _handle_mov(self, insn):
        self._sov(insn.operands[0], self._gov(insn.operands[1], insn.address, isz=insn.size), insn.address)

    _handle_movabs = _handle_mov

    def _handle_lea(self, insn):
        self._sov(insn.operands[0], self._gma(insn.operands[1], insn.address, insn.size), insn.address)

    def _handle_movzx(self, insn):
        v = self._gov(insn.operands[1], insn.address, isz=insn.size)
        self._sov(insn.operands[0], v, insn.address)

    def _handle_movsx(self, insn):
        v = self._gov(insn.operands[1], insn.address, isz=insn.size)
        sz = insn.operands[1].size or 4
        if v & (1 << (sz * 8 - 1)):
            v = v | (~0 << (sz * 8))
        self._sov(insn.operands[0], v, insn.address)

    _handle_movsxd = _handle_movsx

    def _handle_xchg(self, insn):
        v1 = self._gov(insn.operands[0], insn.address, isz=insn.size)
        v2 = self._gov(insn.operands[1], insn.address, isz=insn.size)
        self._sov(insn.operands[0], v2, insn.address)
        self._sov(insn.operands[1], v1, insn.address)

    def _handle_xadd(self, insn):
        sz = self._sz(insn)
        d = self._gov(insn.operands[0], insn.address, isz=insn.size)
        x = self._gov(insn.operands[1], insn.address, isz=insn.size)
        r = self._fl_add(d, x, sz)
        self._sov(insn.operands[0], r, insn.address)
        self._sov(insn.operands[1], d, insn.address)

    def _handle_cmpxchg(self, insn):
        d, sr = insn.operands[0], insn.operands[1]
        sz = d.size or self.ptr_size
        dv = self._gov(d, insn.address, size=sz, isz=insn.size)
        fr = self.ax_register
        m = (1 << (sz * 8)) - 1
        av = self.registers[fr] & m
        if av == dv:
            self.flags["ZF"] = 1
            self._sov(d, self._gov(sr, insn.address, size=sz, isz=insn.size), insn.address, size=sz)
        else:
            self.flags["ZF"] = 0
            self.registers[fr] = (self.registers[fr] & ~m) | (dv & m)

    def _handle_bswap(self, insn):
        v = self._gov(insn.operands[0], insn.address)
        sz = insn.operands[0].size or 4
        out = 0
        for i in range(sz):
            out = (out << 8) | ((v >> (i * 8)) & 0xFF)
        self._sov(insn.operands[0], out, insn.address)

    def _push(self, v):
        sp = self.registers[self.sp_register] - self.stack_step
        self.registers[self.sp_register] = sp
        self._mem_write(sp, self.stack_step, v & self.ptr_mask)

    def _pop(self):
        sp = self.registers[self.sp_register]
        v = self._mem_read(sp, self.stack_step)
        self.registers[self.sp_register] = sp + self.stack_step
        return v

    def _handle_push(self, insn):
        self._push(self._gov(insn.operands[0], insn.address, isz=insn.size))

    def _handle_pop(self, insn):
        self._sov(insn.operands[0], self._pop(), insn.address)

    def _handle_pushf(self, insn):
        self._push(self._pack_flags())

    def _handle_pushfd(self, insn):
        self._push(self._pack_flags())

    def _handle_pushfq(self, insn):
        self._push(self._pack_flags())

    def _handle_popf(self, insn):
        self._unpack_flags(self._pop())

    _handle_popfd = _handle_popf
    _handle_popfq = _handle_popf

    def _pack_flags(self):
        v = 0x202
        if self.flags["CF"]:
            v |= 1
        if self.flags["PF"]:
            v |= 4
        if self.flags["AF"]:
            v |= 0x10
        if self.flags["ZF"]:
            v |= 0x40
        if self.flags["SF"]:
            v |= 0x80
        if self.flags["DF"]:
            v |= 0x400
        if self.flags["OF"]:
            v |= 0x800
        return v

    def _unpack_flags(self, v):
        self.flags["CF"] = v & 1
        self.flags["PF"] = (v >> 2) & 1
        self.flags["AF"] = (v >> 4) & 1
        self.flags["ZF"] = (v >> 6) & 1
        self.flags["SF"] = (v >> 7) & 1
        self.flags["DF"] = (v >> 10) & 1
        self.flags["OF"] = (v >> 11) & 1

    def _handle_enter(self, insn):
        ps = self._gov(insn.operands[0], insn.address) & 0xFFFF
        nl = self._gov(insn.operands[1], insn.address) & 0x1F
        self._push(self.registers[self.bp_register])
        bp = self.bp_register
        if nl > 0:
            for _ in range(1, nl):
                self.registers[bp] -= self.stack_step
                self._push(self._mem_read(self.registers[bp], self.stack_step))
        self.registers[bp] = self.registers[self.sp_register]
        self.registers[self.sp_register] -= ps

    def _handle_leave(self, insn):
        bp = self.bp_register
        self.registers[self.sp_register] = self.registers[bp]
        self.registers[bp] = self._pop()

    def _handle_call(self, insn):
        t = self._gov(insn.operands[0], insn.address, isz=insn.size)
        if self._is_api(t):
            return self._api_ret(t, insn)
        ra = self.registers[self.ip_register] + insn.size
        self._push(ra)
        return t

    def _handle_jmp(self, insn):
        t = self._gov(insn.operands[0], insn.address, isz=insn.size)
        if self._is_api(t):
            return self._api_noret(t)
        return t

    def _is_api(self, t):
        if self.api is None:
            return False
        return t in self.api.functions

    def _handle_ret(self, insn):
        ra = self._pop()
        if insn.operands:
            self.registers[self.sp_register] += self._gov(insn.operands[0], insn.address)
        return ra

    def _handle_loop(self, insn):
        c = (self._rr(self.cx_register) - 1) & self.ptr_mask
        self._wr(self.cx_register, c)
        if c != 0:
            return self._gov(insn.operands[0], insn.address, isz=insn.size)
        return None

    def _handle_loope(self, insn):
        c = (self._rr(self.cx_register) - 1) & self.ptr_mask
        self._wr(self.cx_register, c)
        if c != 0 and self.flags["ZF"]:
            return self._gov(insn.operands[0], insn.address, isz=insn.size)
        return None

    def _handle_loopne(self, insn):
        c = (self._rr(self.cx_register) - 1) & self.ptr_mask
        self._wr(self.cx_register, c)
        if c != 0 and not self.flags["ZF"]:
            return self._gov(insn.operands[0], insn.address, isz=insn.size)
        return None

    _handle_loopz = _handle_loope
    _handle_loopnz = _handle_loopne

    def _handle_jrcxz(self, insn):
        return self._gov(insn.operands[0], insn.address, isz=insn.size) if self._rr(self.cx_register) == 0 else None

    _handle_jecxz = _handle_jrcxz

    def _handle_iret(self, insn):
        raise SystemExit(0)

    def _handle_hlt(self, insn):
        self.running = False
        return None

    def _handle_ud2(self, insn):
        self.running = False
        return None

    def _handle_int3(self, insn):
        return None

    def _handle_int(self, insn):
        return None

    def _handle_int1(self, insn):
        return None

    def _handle_syscall(self, insn=None):
        return None

    def _handle_sysenter(self, insn=None):
        return None

    def _handle_nop(self, insn):
        return None

    _handle_nopw = _handle_nop
    _handle_nopl = _handle_nop
    _handle_endbr64 = _handle_nop
    _handle_endbr32 = _handle_nop
    _handle_cld = _handle_nop
    _handle_cli = _handle_nop
    _handle_sti = _handle_nop
    _handle_pause = _handle_nop
    _handle_mfence = _handle_nop
    _handle_lfence = _handle_nop
    _handle_sfence = _handle_nop
    _handle_cpuid = _handle_nop
    _handle_rdtsc = _handle_nop
    _handle_clc = _handle_nop

    def _handle_std(self, insn):
        self.flags["DF"] = 1

    def _handle_stc(self, insn):
        self.flags["CF"] = 1

    def _handle_cmc(self, insn):
        self.flags["CF"] = 1 - self.flags["CF"]

    def _handle_add(self, insn):
        sz = self._sz(insn)
        d = self._gov(insn.operands[0], insn.address, isz=insn.size)
        x = self._gov(insn.operands[1], insn.address, isz=insn.size)
        r = self._fl_add(d, x, sz)
        self._sov(insn.operands[0], r, insn.address)

    def _handle_sub(self, insn):
        sz = self._sz(insn)
        d = self._gov(insn.operands[0], insn.address, isz=insn.size)
        x = self._gov(insn.operands[1], insn.address, isz=insn.size)
        r = self._fl_sub(d, x, sz)
        self._sov(insn.operands[0], r, insn.address)

    def _handle_adc(self, insn):
        sz = self._sz(insn)
        d = self._gov(insn.operands[0], insn.address, isz=insn.size)
        x = self._gov(insn.operands[1], insn.address, isz=insn.size)
        r = self._fl_add(d, x, sz, self.flags["CF"])
        self._sov(insn.operands[0], r, insn.address)

    def _handle_sbb(self, insn):
        sz = self._sz(insn)
        d = self._gov(insn.operands[0], insn.address, isz=insn.size)
        x = self._gov(insn.operands[1], insn.address, isz=insn.size)
        r = self._fl_sub(d, x, sz, self.flags["CF"])
        self._sov(insn.operands[0], r, insn.address)

    def _handle_and(self, insn):
        sz = self._sz(insn)
        d = self._gov(insn.operands[0], insn.address, isz=insn.size)
        x = self._gov(insn.operands[1], insn.address, isz=insn.size)
        r = d & x
        self._fl_logic(r, sz)
        self._sov(insn.operands[0], r, insn.address)

    def _handle_or(self, insn):
        sz = self._sz(insn)
        d = self._gov(insn.operands[0], insn.address, isz=insn.size)
        x = self._gov(insn.operands[1], insn.address, isz=insn.size)
        r = d | x
        self._fl_logic(r, sz)
        self._sov(insn.operands[0], r, insn.address)

    def _handle_xor(self, insn):
        sz = self._sz(insn)
        d = self._gov(insn.operands[0], insn.address, isz=insn.size)
        x = self._gov(insn.operands[1], insn.address, isz=insn.size)
        r = d ^ x
        self._fl_logic(r, sz)
        self._sov(insn.operands[0], r, insn.address)

    def _handle_cmp(self, insn):
        sz = self._sz(insn)
        d = self._gov(insn.operands[0], insn.address, isz=insn.size)
        x = self._gov(insn.operands[1], insn.address, isz=insn.size)
        self._fl_sub(d, x, sz)

    def _handle_test(self, insn):
        sz = self._sz(insn)
        d = self._gov(insn.operands[0], insn.address, isz=insn.size)
        x = self._gov(insn.operands[1], insn.address, isz=insn.size)
        self._fl_logic(d & x, sz)

    def _handle_inc(self, insn):
        sz = self._sz(insn)
        d = self._gov(insn.operands[0], insn.address, isz=insn.size)
        cf = self.flags["CF"]
        r = self._fl_add(d, 1, sz)
        self.flags["CF"] = cf
        self._sov(insn.operands[0], r, insn.address)

    def _handle_dec(self, insn):
        sz = self._sz(insn)
        d = self._gov(insn.operands[0], insn.address, isz=insn.size)
        cf = self.flags["CF"]
        r = self._fl_sub(d, 1, sz)
        self.flags["CF"] = cf
        self._sov(insn.operands[0], r, insn.address)

    def _handle_neg(self, insn):
        sz = self._sz(insn)
        d = self._gov(insn.operands[0], insn.address, isz=insn.size)
        r = self._fl_sub(0, d, sz)
        self.flags["CF"] = int(d != 0)
        self._sov(insn.operands[0], r, insn.address)

    def _handle_not(self, insn):
        d = self._gov(insn.operands[0], insn.address, isz=insn.size)
        self._sov(insn.operands[0], ~d, insn.address)

    def _handle_mul(self, insn):
        sz = self._sz(insn)
        x = self._gov(insn.operands[0], insn.address, isz=insn.size)
        a = self._rr(self.ax_register) & ((1 << (sz * 8)) - 1)
        r = a * x
        self._wr(self.ax_register, r & ((1 << (sz * 8)) - 1))
        hi = (r >> (sz * 8)) & ((1 << (sz * 8)) - 1)
        dreg = "rdx" if self.is64 else "edx"
        self._wr(dreg, hi)
        self.flags["CF"] = int(hi != 0)
        self.flags["OF"] = self.flags["CF"]

    def _handle_imul(self, insn):
        if len(insn.operands) == 1:
            sz = self._sz(insn)
            x = self._gov(insn.operands[0], insn.address, isz=insn.size)
            bits = sz * 8
            a = self._rr(self.ax_register)
            a = a - (1 << bits) if a & (1 << (bits - 1)) else a
            xs = x - (1 << bits) if x & (1 << (bits - 1)) else x
            r = a * xs
            self._wr(self.ax_register, r & ((1 << bits) - 1))
            hi = (r >> bits) & ((1 << bits) - 1)
            self._wr("rdx" if self.is64 else "edx", hi)
            self.flags["CF"] = int(r < -(1 << (bits - 1)) or r >= (1 << (bits - 1)))
            self.flags["OF"] = self.flags["CF"]
            return None
        sz = self._sz(insn)
        d = self._gov(insn.operands[0], insn.address, isz=insn.size)
        x = self._gov(insn.operands[1], insn.address, isz=insn.size)
        r = d * x if len(insn.operands) == 2 else x * self._gov(insn.operands[2], insn.address, isz=insn.size)
        self._fl_logic(r & ((1 << (sz * 8)) - 1), sz)
        self.flags["CF"] = int(r < -(1 << (sz * 8 - 1)) or r >= (1 << (sz * 8 - 1)))
        self.flags["OF"] = self.flags["CF"]
        self._sov(insn.operands[0], r, insn.address)

    def _handle_div(self, insn):
        sz = self._sz(insn)
        x = self._gov(insn.operands[0], insn.address, isz=insn.size)
        if x == 0:
            raise ZeroDivisionError("div by zero")
        dreg = "rdx" if self.is64 else "edx"
        n = (self._rr(dreg) << (sz * 8)) | (self._rr(self.ax_register) & ((1 << (sz * 8)) - 1))
        q = (n // x) & ((1 << (sz * 8)) - 1)
        r = (n % x) & ((1 << (sz * 8)) - 1)
        self._wr(self.ax_register, q)
        self._wr(dreg, r)

    def _handle_idiv(self, insn):
        sz = self._sz(insn)
        bits = sz * 8
        x = self._gov(insn.operands[0], insn.address, isz=insn.size)
        if x == 0:
            raise ZeroDivisionError("idiv by zero")
        dreg = "rdx" if self.is64 else "edx"
        n = (self._rr(dreg) << bits) | (self._rr(self.ax_register) & ((1 << bits) - 1))
        xs = x - (1 << bits) if x & (1 << (bits - 1)) else x
        ns = n - (1 << (bits * 2)) if n & (1 << (bits * 2 - 1)) else n
        q = int(ns / xs) if xs else 0
        r = ns - q * xs
        self._wr(self.ax_register, q & ((1 << bits) - 1))
        self._wr(dreg, r & ((1 << bits) - 1))

    def _handle_cdq(self, insn):
        v = self._rr("eax")
        self._wr("edx", 0xFFFFFFFF if v & 0x80000000 else 0)

    def _handle_cqo(self, insn):
        v = self._rr("rax")
        self._wr("rdx", self.ptr_mask if v & (1 << 63) else 0)

    def _handle_cbw(self, insn):
        v = self._rr("al")
        self._wr("ax", v - 256 if v & 0x80 else v)

    def _handle_cwde(self, insn):
        v = self._rr("ax")
        self._wr("eax", v - 0x10000 if v & 0x8000 else v)

    def _handle_cdqe(self, insn):
        v = self._rr("eax")
        self._wr("rax", v - 0x100000000 if v & 0x80000000 else v)

    def _handle_sete(self, insn):
        self._setcc(insn, "e")

    def _shift(self, insn, fn):
        sz = self._sz(insn)
        d = self._gov(insn.operands[0], insn.address, isz=insn.size)
        sh = self._gov(insn.operands[1], insn.address, isz=insn.size) & 0x3F
        r = fn(d, sh, sz)
        self._sov(insn.operands[0], r, insn.address)
        self.flags["ZF"] = int((r & ((1 << (sz * 8)) - 1)) == 0)
        self.flags["SF"] = (r >> (sz * 8 - 1)) & 1
        self.flags["PF"] = PARITY[r & 0xFF]

    def _handle_shl(self, insn):
        def f(d, sh, sz):
            self.flags["CF"] = ((d >> (sz * 8 - sh)) & 1) if sh else self.flags["CF"]
            return (d << sh) & ((1 << (sz * 8)) - 1)
        self._shift(insn, f)

    def _handle_sal(self, insn):
        self._handle_shl(insn)

    def _handle_shr(self, insn):
        def f(d, sh, sz):
            self.flags["CF"] = ((d >> (sh - 1)) & 1) if sh else self.flags["CF"]
            return (d & ((1 << (sz * 8)) - 1)) >> sh
        self._shift(insn, f)

    def _handle_sar(self, insn):
        def f(d, sh, sz):
            self.flags["CF"] = ((d >> (sh - 1)) & 1) if sh else self.flags["CF"]
            bits = sz * 8
            if d & (1 << (bits - 1)):
                return ((d >> sh) | (~0 << (bits - sh))) & ((1 << bits) - 1)
            return d >> sh
        self._shift(insn, f)

    def _handle_rol(self, insn):
        def f(d, sh, sz):
            bits = sz * 8
            if sh:
                self.flags["CF"] = (d >> (bits - sh)) & 1
            return ((d << sh) | (d >> (bits - sh))) & ((1 << bits) - 1) if sh else d
        self._shift(insn, f)

    def _handle_ror(self, insn):
        def f(d, sh, sz):
            bits = sz * 8
            if sh:
                self.flags["CF"] = (d >> (sh - 1)) & 1
            return ((d >> sh) | (d << (bits - sh))) & ((1 << bits) - 1) if sh else d
        self._shift(insn, f)

    def _handle_rcl(self, insn):
        def f(d, sh, sz):
            bits = sz * 8
            r = d
            for _ in range(sh % (bits + 1)):
                cf = self.flags["CF"]
                self.flags["CF"] = (r >> (bits - 1)) & 1
                r = ((r << 1) | cf) & ((1 << bits) - 1)
            return r
        self._shift(insn, f)

    def _handle_rcr(self, insn):
        def f(d, sh, sz):
            bits = sz * 8
            r = d
            for _ in range(sh % (bits + 1)):
                cf = self.flags["CF"]
                self.flags["CF"] = r & 1
                r = (r >> 1) | (cf << (bits - 1))
            return r
        self._shift(insn, f)

    def _handle_shld(self, insn):
        sz = self._sz(insn)
        d = self._gov(insn.operands[0], insn.address, isz=insn.size)
        s = self._gov(insn.operands[1], insn.address, isz=insn.size)
        sh = self._gov(insn.operands[2], insn.address, isz=insn.size) & 0x3F if len(insn.operands) > 2 else 1
        bits = sz * 8
        r = ((d << sh) | (s >> (bits - sh))) & ((1 << bits) - 1) if sh else d
        self._sov(insn.operands[0], r, insn.address)
        self._fl_logic(r, sz)

    def _handle_shrd(self, insn):
        sz = self._sz(insn)
        d = self._gov(insn.operands[0], insn.address, isz=insn.size)
        s = self._gov(insn.operands[1], insn.address, isz=insn.size)
        sh = self._gov(insn.operands[2], insn.address, isz=insn.size) & 0x3F if len(insn.operands) > 2 else 1
        bits = sz * 8
        r = ((d >> sh) | (s << (bits - sh))) & ((1 << bits) - 1) if sh else d
        self._sov(insn.operands[0], r, insn.address)
        self._fl_logic(r, sz)

    def _handle_bt(self, insn):
        d = self._gov(insn.operands[0], insn.address, isz=insn.size)
        b = self._gov(insn.operands[1], insn.address, isz=insn.size)
        sz = self._sz(insn)
        b %= sz * 8
        self.flags["CF"] = (d >> b) & 1

    def _handle_bts(self, insn):
        self._handle_bt(insn)
        d = self._gov(insn.operands[0], insn.address, isz=insn.size)
        b = self._gov(insn.operands[1], insn.address, isz=insn.size) % (self._sz(insn) * 8)
        self._sov(insn.operands[0], d | (1 << b), insn.address)

    def _handle_btr(self, insn):
        self._handle_bt(insn)
        d = self._gov(insn.operands[0], insn.address, isz=insn.size)
        b = self._gov(insn.operands[1], insn.address, isz=insn.size) % (self._sz(insn) * 8)
        self._sov(insn.operands[0], d & ~(1 << b), insn.address)

    def _handle_btc(self, insn):
        self._handle_bt(insn)
        d = self._gov(insn.operands[0], insn.address, isz=insn.size)
        b = self._gov(insn.operands[1], insn.address, isz=insn.size) % (self._sz(insn) * 8)
        self._sov(insn.operands[0], d ^ (1 << b), insn.address)

    def _handle_bsf(self, insn):
        v = self._gov(insn.operands[1], insn.address, isz=insn.size)
        self.flags["ZF"] = int(v == 0)
        if v:
            r = (v & -v).bit_length() - 1
            self._sov(insn.operands[0], r, insn.address)

    def _handle_bsr(self, insn):
        v = self._gov(insn.operands[1], insn.address, isz=insn.size)
        self.flags["ZF"] = int(v == 0)
        if v:
            self._sov(insn.operands[0], v.bit_length() - 1, insn.address)

    def _handle_popcnt(self, insn):
        v = self._gov(insn.operands[1], insn.address, isz=insn.size)
        self._sov(insn.operands[0], bin(v).count("1"), insn.address)

    def _jcc(self, insn, cond):
        if CC[cond](self.flags):
            return self._gov(insn.operands[0], insn.address, isz=insn.size)
        return None

    def _setcc(self, insn, cond):
        self._sov(insn.operands[0], 1 if CC[cond](self.flags) else 0, insn.address)

    def _cmovcc(self, insn, cond):
        if CC[cond](self.flags):
            self._sov(insn.operands[0], self._gov(insn.operands[1], insn.address, isz=insn.size), insn.address)

    def _mkcc(self, name, cond):
        setattr(self, "_handle_j%s" % name, lambda insn, c=cond: self._jcc(insn, c))
        setattr(self, "_handle_set%s" % name, lambda insn, c=cond: self._setcc(insn, c))
        setattr(self, "_handle_cmov%s" % name, lambda insn, c=cond: self._cmovcc(insn, c))

    def _str_dir(self):
        return -1 if self.flags["DF"] else 1

    def _str_addr(self):
        return ("rsi", "rdi") if self.is64 else ("esi", "edi")

    def _rep_stosb(self, insn, prefix):
        self._rep_stos(insn, 1)

    def _rep_stosw(self, insn, prefix):
        self._rep_stos(insn, 2)

    def _rep_stosd(self, insn, prefix):
        self._rep_stos(insn, 4)

    def _rep_stosq(self, insn, prefix):
        self._rep_stos(insn, 8)

    def _rep_stos(self, insn, size):
        si, di = self._str_addr()
        cnt = self._rr(self.cx_register)
        dst = self._rr(di)
        val = self._rr(self.ax_register)
        step = self._str_dir() * size
        n = 0
        while cnt and n < self.MAX_REP:
            self._mem_write(dst, size, val)
            dst = (dst + step) & self.ptr_mask
            cnt -= 1
            n += 1
        self._wr(self.cx_register, cnt)
        self._wr(di, dst)

    def _rep_movsb(self, insn, prefix):
        self._rep_movs(insn, 1)

    def _rep_movsw(self, insn, prefix):
        self._rep_movs(insn, 2)

    def _rep_movsd(self, insn, prefix):
        self._rep_movs(insn, 4)

    def _rep_movsq(self, insn, prefix):
        self._rep_movs(insn, 8)

    def _rep_movs(self, insn, size):
        si, di = self._str_addr()
        cnt = self._rr(self.cx_register)
        src = self._rr(si)
        dst = self._rr(di)
        step = self._str_dir() * size
        n = 0
        while cnt and n < self.MAX_REP:
            self._mem_write(dst, size, self._mem_read(src, size))
            src = (src + step) & self.ptr_mask
            dst = (dst + step) & self.ptr_mask
            cnt -= 1
            n += 1
        self._wr(self.cx_register, cnt)
        self._wr(si, src)
        self._wr(di, dst)

    def _rep_scasb(self, insn, prefix):
        self._rep_scas(insn, 1, prefix)

    def _rep_scasw(self, insn, prefix):
        self._rep_scas(insn, 2, prefix)

    def _rep_scasd(self, insn, prefix):
        self._rep_scas(insn, 4, prefix)

    def _rep_scasq(self, insn, prefix):
        self._rep_scas(insn, 8, prefix)

    def _rep_scas(self, insn, size, prefix):
        si, di = self._str_addr()
        cnt = self._rr(self.cx_register)
        dst = self._rr(di)
        val = self._rr(self.ax_register) & ((1 << (size * 8)) - 1)
        step = self._str_dir() * size
        n = 0
        while cnt and n < self.MAX_REP:
            v = self._mem_read(dst, size) & ((1 << (size * 8)) - 1)
            self._fl_sub(val, v, size)
            dst = (dst + step) & self.ptr_mask
            cnt -= 1
            n += 1
            if prefix == "repne" and self.flags["ZF"]:
                break
            if prefix == "rep" and not self.flags["ZF"]:
                break
        self._wr(self.cx_register, cnt)
        self._wr(di, dst)

    def _rep_cmpsb(self, insn, prefix):
        self._rep_cmps(insn, 1, prefix)

    def _rep_cmpsw(self, insn, prefix):
        self._rep_cmps(insn, 2, prefix)

    def _rep_cmpsd(self, insn, prefix):
        self._rep_cmps(insn, 4, prefix)

    def _rep_cmpsq(self, insn, prefix):
        self._rep_cmps(insn, 8, prefix)

    def _rep_cmps(self, insn, size, prefix):
        si, di = self._str_addr()
        cnt = self._rr(self.cx_register)
        src = self._rr(si)
        dst = self._rr(di)
        step = self._str_dir() * size
        n = 0
        while cnt and n < self.MAX_REP:
            a = self._mem_read(src, size)
            b = self._mem_read(dst, size)
            self._fl_sub(a, b, size)
            src = (src + step) & self.ptr_mask
            dst = (dst + step) & self.ptr_mask
            cnt -= 1
            n += 1
            if prefix == "repne" and self.flags["ZF"]:
                break
            if prefix == "rep" and not self.flags["ZF"]:
                break
        self._wr(self.cx_register, cnt)
        self._wr(si, src)
        self._wr(di, dst)

    def _rep_lodsb(self, insn, prefix):
        self._rep_lods(insn, 1)

    def _rep_lodsd(self, insn, prefix):
        self._rep_lods(insn, 4)

    def _rep_lods(self, insn, size):
        si, di = self._str_addr()
        cnt = self._rr(self.cx_register)
        src = self._rr(si)
        val = self._mem_read(src, size)
        self._wr(self.ax_register, val)
        if cnt:
            src = (src + self._str_dir() * size) & self.ptr_mask
            cnt -= 1
        self._wr(self.cx_register, cnt)
        self._wr(si, src)

    def _sse_val(self, op, insn, size):
        if op.type == X86_OP_REG:
            n = self.md.reg_name(op.reg)
            if n.startswith(("xmm", "ymm")):
                return self._xmm_get(n) & ((1 << (size * 8)) - 1)
            return self._rr(n) & ((1 << (size * 8)) - 1)
        if op.type == X86_OP_MEM:
            return self._mem_read(self._gma(op, insn.address, insn.size), size)
        return op.imm

    def _sse_store(self, op, insn, size, val, keep_high=False):
        if op.type == X86_OP_REG:
            n = self.md.reg_name(op.reg)
            if n.startswith(("xmm", "ymm")):
                old = self._xmm_get(n) if keep_high else 0
                mask = ((1 << 128) - 1) ^ ((1 << (size * 8)) - 1)
                self._xmm_set(n, (old & mask) | (val & ((1 << (size * 8)) - 1)))
            else:
                self._wr(n, val)
        elif op.type == X86_OP_MEM:
            self._mem_write(self._gma(op, insn.address), size, val)

    def _handle_movss(self, insn):
        d, s = insn.operands
        v = self._sse_val(s, insn, 4)
        self._sse_store(d, insn, 4, v, keep_high=(s.type == X86_OP_REG))

    def _handle_movsd(self, insn):
        d, s = insn.operands
        names = [self.md.reg_name(o.reg) if o.type == X86_OP_REG else "" for o in insn.operands]
        if any(n.startswith("xmm") for n in names):
            v = self._sse_val(s, insn, 8)
            self._sse_store(d, insn, 8, v, keep_high=(s.type == X86_OP_REG))
        else:
            self._rep_movs(insn, 4)

    def _handle_movaps(self, insn):
        self._handle_movups(insn)

    def _handle_movups(self, insn):
        d, s = insn.operands
        if s.type == X86_OP_MEM:
            a = self._gma(s, insn.address, insn.size)
            v = self._mem_read(a, 8) | (self._mem_read(a + 8, 8) << 64)
        else:
            v = self._xmm_get(self.md.reg_name(s.reg))
        self._sse_store(d, insn, 16, v)

    _handle_movapd = _handle_movups
    _handle_movupd = _handle_movups
    _handle_movdqa = _handle_movups
    _handle_movdqu = _handle_movups

    def _handle_movd(self, insn):
        d, s = insn.operands
        v = self._sse_val(s, insn, 4)
        if d.type == X86_OP_REG and self.md.reg_name(d.reg).startswith("xmm"):
            self._xmm_set(self.md.reg_name(d.reg), v)
        else:
            self._sse_store(d, insn, 4, v)

    def _handle_movq(self, insn):
        d, s = insn.operands
        v = self._sse_val(s, insn, 8)
        if d.type == X86_OP_REG and self.md.reg_name(d.reg).startswith("xmm"):
            self._xmm_set(self.md.reg_name(d.reg), v)
        else:
            self._sse_store(d, insn, 8, v)

    def _handle_xorps(self, insn):
        d, s = insn.operands
        a = self._xmm_get(self.md.reg_name(d.reg)) if d.type == X86_OP_REG else 0
        b = self._sse_val(s, insn, 16)
        self._sse_store(d, insn, 16, (a ^ b) & ((1 << 128) - 1))

    _handle_pxor = _handle_xorps
    _handle_xorpd = _handle_xorps

    def _sse_arith(self, insn, size, fn):
        d, s = insn.operands
        dn = self.md.reg_name(d.reg)
        a = self._xmm_get(dn)
        b = self._sse_val(s, insn, size)
        if size == 4:
            r = self._p32(fn(self._f32(a), self._f32(b)))
        else:
            r = self._p64(fn(self._f64(a), self._f64(b)))
        self._xmm_set(dn, (a & (((1 << 128) - 1) ^ ((1 << (size * 8)) - 1))) | r)

    def _handle_addss(self, insn):
        self._sse_arith(insn, 4, lambda a, b: a + b)

    def _handle_subss(self, insn):
        self._sse_arith(insn, 4, lambda a, b: a - b)

    def _handle_mulss(self, insn):
        self._sse_arith(insn, 4, lambda a, b: a * b)

    def _handle_divss(self, insn):
        self._sse_arith(insn, 4, lambda a, b: a / b if b else float("inf"))

    def _handle_sqrtss(self, insn):
        d, s = insn.operands
        dn = self.md.reg_name(d.reg)
        v = self._f32(self._sse_val(s, insn, 4))
        self._xmm_set(dn, self._p32(v ** 0.5 if v >= 0 else float("nan")))

    def _handle_addsd(self, insn):
        self._sse_arith(insn, 8, lambda a, b: a + b)

    def _handle_subsd(self, insn):
        self._sse_arith(insn, 8, lambda a, b: a - b)

    def _handle_mulsd(self, insn):
        self._sse_arith(insn, 8, lambda a, b: a * b)

    def _handle_divsd(self, insn):
        self._sse_arith(insn, 8, lambda a, b: a / b if b else float("inf"))

    def _handle_sqrtsd(self, insn):
        d, s = insn.operands
        dn = self.md.reg_name(d.reg)
        v = self._f64(self._sse_val(s, insn, 8))
        self._xmm_set(dn, self._p64(v ** 0.5 if v >= 0 else float("nan")))

    def _handle_maxss(self, insn):
        self._sse_arith(insn, 4, max)

    def _handle_minss(self, insn):
        self._sse_arith(insn, 4, min)

    def _handle_maxsd(self, insn):
        self._sse_arith(insn, 8, max)

    def _handle_minsd(self, insn):
        self._sse_arith(insn, 8, min)

    def _handle_ucomiss(self, insn):
        d, s = insn.operands
        a = self._f32(self._xmm_get(self.md.reg_name(d.reg)))
        b = self._f32(self._sse_val(s, insn, 4))
        self.flags["ZF"] = int(a == b)
        self.flags["CF"] = int(a < b)
        self.flags["PF"] = int(a != a or b != b)
        self.flags["OF"] = 0
        self.flags["SF"] = 0

    _handle_comiss = _handle_ucomiss

    def _handle_ucomisd(self, insn):
        d, s = insn.operands
        a = self._f64(self._xmm_get(self.md.reg_name(d.reg)))
        b = self._f64(self._sse_val(s, insn, 8))
        self.flags["ZF"] = int(a == b)
        self.flags["CF"] = int(a < b)
        self.flags["PF"] = int(a != a or b != b)
        self.flags["OF"] = 0
        self.flags["SF"] = 0

    _handle_comisd = _handle_ucomisd

    def _handle_cvtsi2ss(self, insn):
        d, s = insn.operands
        v = self._sse_val(s, insn, s.size or 4)
        if s.size == 8:
            v = v - (1 << 64) if v & (1 << 63) else v
        elif s.size == 4:
            v = v - (1 << 32) if v & (1 << 31) else v
        elif s.size == 2:
            v = v - (1 << 16) if v & (1 << 15) else v
        dn = self.md.reg_name(d.reg)
        old = self._xmm_get(dn)
        self._xmm_set(dn, (old & (((1 << 128) - 1) ^ 0xFFFFFFFF)) | self._p32(float(v)))

    def _handle_cvtsi2sd(self, insn):
        d, s = insn.operands
        v = self._sse_val(s, insn, s.size or 4)
        if s.size == 8:
            v = v - (1 << 64) if v & (1 << 63) else v
        elif s.size == 4:
            v = v - (1 << 32) if v & (1 << 31) else v
        dn = self.md.reg_name(d.reg)
        old = self._xmm_get(dn)
        self._xmm_set(dn, (old & (((1 << 128) - 1) ^ 0xFFFFFFFFFFFFFFFF)) | self._p64(float(v)))

    def _handle_cvttss2si(self, insn):
        d, s = insn.operands
        f = self._f32(self._sse_val(s, insn, 4))
        try:
            v = int(f)
        except (ValueError, OverflowError):
            v = 0
        self._sov(d, v, insn.address)

    def _handle_cvttsd2si(self, insn):
        d, s = insn.operands
        f = self._f64(self._sse_val(s, insn, 8))
        try:
            v = int(f)
        except (ValueError, OverflowError):
            v = 0
        self._sov(d, v, insn.address)

    def _handle_cvtss2sd(self, insn):
        d, s = insn.operands
        dn = self.md.reg_name(d.reg)
        self._xmm_set(dn, self._p64(self._f32(self._sse_val(s, insn, 4))))

    def _handle_cvtsd2ss(self, insn):
        d, s = insn.operands
        dn = self.md.reg_name(d.reg)
        old = self._xmm_get(dn)
        self._xmm_set(dn, (old & (((1 << 128) - 1) ^ 0xFFFFFFFF)) | self._p32(self._f64(self._sse_val(s, insn, 8))))

    def _handle_cvtps2pd(self, insn):
        d, s = insn.operands
        dn = self.md.reg_name(d.reg)
        a = self._f32(self._sse_val(s, insn, 16) & 0xFFFFFFFF)
        b = self._f32((self._sse_val(s, insn, 16) >> 32) & 0xFFFFFFFF)
        self._xmm_set(dn, self._p64(a) | (self._p64(b) << 64))

    def _handle_cvtpd2ps(self, insn):
        d, s = insn.operands
        dn = self.md.reg_name(d.reg)
        v = self._sse_val(s, insn, 16)
        a = self._f64(v & 0xFFFFFFFFFFFFFFFF)
        b = self._f64((v >> 64) & 0xFFFFFFFFFFFFFFFF)
        self._xmm_set(dn, self._p32(a) | (self._p32(b) << 32))

    def _handle_movsxd(self, insn):
        self._handle_movsx(insn)

    def _fld_mem(self, insn, size):
        if size == 4:
            return self._f32(self._mem_read(self._gma(insn.operands[0], insn.address, insn.size), 4))
        if size == 8:
            return self._f64(self._mem_read(self._gma(insn.operands[0], insn.address, insn.size), 8))
        return struct.unpack("<e", self._mem_read(self._gma(insn.operands[0], insn.address, insn.size), 10)[:10])[0]

    def _handle_fld(self, insn):
        op = insn.operands[0]
        if op.type == X86_OP_REG:
            self._fpush(self._fst(self._st_index(op)))
        else:
            self._fpush(self._fld_mem(insn, op.size))

    def _st_index(self, op):
        n = self.md.reg_name(op.reg)
        return int(n[2:]) if n.startswith("st") else 0

    def _handle_fild(self, insn):
        op = insn.operands[0]
        a = self._gma(op, insn.address, insn.size)
        if op.size == 2:
            v = self._mem_read(a, 2)
            v = v - 0x10000 if v & 0x8000 else v
        elif op.size == 4:
            v = self._mem_read(a, 4)
            v = v - 0x100000000 if v & 0x80000000 else v
        else:
            v = self._mem_read(a, 8)
            v = v - (1 << 64) if v & (1 << 63) else v
        self._fpush(float(v))

    def _handle_fstp(self, insn):
        op = insn.operands[0]
        v = self._fpop()
        if op.type == X86_OP_REG:
            self._fset(self._st_index(op), v)
        else:
            a = self._gma(op, insn.address, insn.size)
            if op.size == 4:
                self._mem_write(a, 4, self._p32(v))
            elif op.size == 8:
                self._mem_write(a, 8, self._p64(v))

    def _handle_fst(self, insn):
        op = insn.operands[0]
        v = self._fst(0)
        if op.type == X86_OP_REG:
            self._fset(self._st_index(op), v)
        else:
            a = self._gma(op, insn.address, insn.size)
            if op.size == 4:
                self._mem_write(a, 4, self._p32(v))
            elif op.size == 8:
                self._mem_write(a, 8, self._p64(v))

    def _handle_fistp(self, insn):
        op = insn.operands[0]
        v = int(self._fpop())
        a = self._gma(op, insn.address, insn.size)
        self._mem_write(a, op.size, v & ((1 << (op.size * 8)) - 1))

    def _handle_fist(self, insn):
        op = insn.operands[0]
        v = int(self._fst(0))
        a = self._gma(op, insn.address, insn.size)
        self._mem_write(a, op.size, v & ((1 << (op.size * 8)) - 1))

    def _fbin(self, insn, fn):
        op = insn.operands[0]
        if op.type == X86_OP_REG:
            i = self._st_index(op)
            self._fset(0, fn(self._fst(0), self._fst(i)))
        else:
            self._fset(0, fn(self._fst(0), self._fld_mem(insn, op.size)))

    def _fbinr(self, insn, fn):
        op = insn.operands[0]
        if op.type == X86_OP_REG:
            i = self._st_index(op)
            self._fset(0, fn(self._fst(i), self._fst(0)))
        else:
            self._fset(0, fn(self._fld_mem(insn, op.size), self._fst(0)))

    def _fbinp(self, insn, fn):
        op = insn.operands[0]
        i = self._st_index(op) if op.type == X86_OP_REG else 0
        self._fset(i, fn(self._fst(i), self._fst(0)))
        self._fpop()

    def _fbinrp(self, insn, fn):
        op = insn.operands[0]
        i = self._st_index(op) if op.type == X86_OP_REG else 0
        self._fset(i, fn(self._fst(0), self._fst(i)))
        self._fpop()

    def _handle_fadd(self, insn):
        self._fbin(insn, lambda a, b: a + b)

    def _handle_faddp(self, insn):
        self._fbinp(insn, lambda a, b: a + b)

    def _handle_fsub(self, insn):
        self._fbin(insn, lambda a, b: a - b)

    def _handle_fsubp(self, insn):
        self._fbinp(insn, lambda a, b: a - b)

    def _handle_fsubr(self, insn):
        self._fbinr(insn, lambda a, b: a - b)

    def _handle_fsubrp(self, insn):
        self._fbinrp(insn, lambda a, b: a - b)

    def _handle_fmul(self, insn):
        self._fbin(insn, lambda a, b: a * b)

    def _handle_fmulp(self, insn):
        self._fbinp(insn, lambda a, b: a * b)

    def _handle_fdiv(self, insn):
        self._fbin(insn, lambda a, b: a / b if b else float("inf"))

    def _handle_fdivp(self, insn):
        self._fbinp(insn, lambda a, b: a / b if b else float("inf"))

    def _handle_fdivr(self, insn):
        self._fbinr(insn, lambda a, b: a / b if b else float("inf"))

    def _handle_fdivrp(self, insn):
        self._fbinrp(insn, lambda a, b: a / b if b else float("inf"))

    def _handle_fabs(self, insn):
        self._fset(0, abs(self._fst(0)))

    def _handle_fchs(self, insn):
        self._fset(0, -self._fst(0))

    def _handle_fsqrt(self, insn):
        self._fset(0, self._fst(0) ** 0.5)

    def _handle_fldz(self, insn):
        self._fpush(0.0)

    def _handle_fld1(self, insn):
        self._fpush(1.0)

    def _handle_fldl2e(self, insn):
        import math
        self._fpush(math.log2(math.e))

    def _handle_fldpi(self, insn):
        import math
        self._fpush(math.pi)

    def _handle_fprem(self, insn):
        import math
        self._fset(0, math.fmod(self._fst(0), self._fst(1)))

    def _handle_fscale(self, insn):
        self._fset(0, self._fst(0) * (2.0 ** int(self._fst(1))))

    def _handle_fxch(self, insn):
        i = self._st_index(insn.operands[0]) if insn.operands else 1
        a, b = self._fst(0), self._fst(i)
        self._fset(0, b)
        self._fset(i, a)

    def _handle_ffree(self, insn):
        pass

    def _handle_fninit(self, insn):
        self.ftop = 0
        self.fsw = 0
        self.fcw = 0x037F
        self.st = [0.0] * 8

    def _handle_fclex(self, insn):
        self.fsw = 0

    def _handle_fdecstp(self, insn):
        self.ftop = (self.ftop - 1) & 7

    def _handle_fincstp(self, insn):
        self.ftop = (self.ftop + 1) & 7

    def _handle_emms(self, insn):
        pass

    def _handle_femms(self, insn):
        pass

    def _handle_fldenv(self, insn):
        pass

    def _handle_fnstenv(self, insn):
        op = insn.operands[0]
        if op.type == X86_OP_MEM:
            a = self._gma(op, insn.address, insn.size)
            self._mem_write(a, 4, self.fcw)

    def _handle_fstenv(self, insn):
        self._handle_fnstenv(insn)

    def _handle_frstor(self, insn):
        pass

    def _handle_fsave(self, insn):
        self._handle_fnstenv(insn)

    def _handle_fnsave(self, insn):
        self._handle_fnstenv(insn)

    def _handle_fxsave(self, insn):
        op = insn.operands[0]
        if op.type == X86_OP_MEM:
            a = self._gma(op, insn.address, insn.size)
            self._mem_write(a, 2, self.fcw)
            self._mem_write(a + 2, 2, self.fsw)

    def _handle_fxsave64(self, insn):
        self._handle_fxsave(insn)

    def _handle_fxrstor(self, insn):
        pass

    def _handle_fxrstor64(self, insn):
        pass

    def _handle_fldlg2(self, insn):
        import math
        self._fpush(math.log10(2))

    def _handle_fldln2(self, insn):
        import math
        self._fpush(math.log(2))

    def _handle_fprem1(self, insn):
        self._handle_fprem(insn)

    def _handle_fxtract(self, insn):
        import math
        v = self._fst(0)
        if v == 0:
            self._fset(0, 0.0)
            self._fpush(0.0)
        else:
            e = math.floor(math.log(abs(v), 2))
            self._fset(0, float(e))
            self._fpush(v / (2.0 ** e))

    def _handle_fucompp(self, insn):
        self._fcom_common(insn, True)
        self._fpop()

    def _handle_fstpnce(self, insn):
        self._handle_fstp(insn)

    def _handle_fnop(self, insn):
        pass

    def _handle_fwait(self, insn):
        pass

    def _handle_fxam(self, insn):
        v = self._fst(0)
        self.fsw = 0
        if v == 0:
            self.fsw |= 0x4000
        self.flags["ZF"] = 0

    def _handle_ftst(self, insn):
        v = self._fst(0)
        self.flags["ZF"] = int(v == 0.0)
        self.flags["CF"] = int(v < 0.0)
        self.flags["PF"] = 0
        self.fsw = 0
        if v == 0.0:
            self.fsw |= 0x4000
        elif v < 0:
            self.fsw |= 0x100

    def _fcom_common(self, insn, pop):
        op = insn.operands[0]
        a = self._fst(0)
        if op.type == X86_OP_REG:
            b = self._fst(self._st_index(op))
        else:
            b = self._fld_mem(insn, op.size)
        self.flags["ZF"] = int(a == b)
        self.flags["CF"] = int(a < b)
        self.flags["PF"] = int(a > b)
        self.flags["OF"] = 0
        self.flags["SF"] = 0
        self.fsw = 0
        if a == b:
            self.fsw |= 0x4000
        elif a < b:
            self.fsw |= 0x100
        if pop:
            self._fpop()

    def _handle_fcom(self, insn):
        self._fcom_common(insn, False)

    def _handle_fcomp(self, insn):
        self._fcom_common(insn, True)

    def _handle_fcompp(self, insn):
        self._fcom_common(insn, True)
        self._fpop()

    def _handle_fucom(self, insn):
        self._fcom_common(insn, False)

    def _handle_fucomp(self, insn):
        self._fcom_common(insn, True)

    def _handle_fucompp(self, insn):
        self._fcom_common(insn, True)
        self._fpop()

    def _handle_fcomi(self, insn):
        self._fcom_common(insn, False)

    def _handle_fcomip(self, insn):
        self._fcom_common(insn, True)

    def _handle_fucomi(self, insn):
        self._fcom_common(insn, False)

    def _handle_fucomip(self, insn):
        self._fcom_common(insn, True)

    def _handle_fnstsw(self, insn):
        v = self.fsw | (self.flags["CF"] << 8) | (self.flags["PF"] << 2) | (self.flags["ZF"] << 14)
        op = insn.operands[0]
        if op.type == X86_OP_REG:
            self._wr(self.md.reg_name(op.reg), v & 0xFFFF)
        else:
            self._mem_write(self._gma(op, insn.address, insn.size), 2, v & 0xFFFF)

    _handle_fstsw = _handle_fnstsw

    def _handle_fnstcw(self, insn):
        op = insn.operands[0]
        self._mem_write(self._gma(op, insn.address, insn.size), 2, self.fcw)

    def _handle_fldcw(self, insn):
        op = insn.operands[0]
        self.fcw = self._mem_read(self._gma(op, insn.address, insn.size), 2)

    def _handle_fstcw(self, insn):
        self._handle_fnstcw(insn)

    def _handle_fsin(self, insn):
        import math
        self._fset(0, math.sin(self._fst(0)))

    def _handle_fcos(self, insn):
        import math
        self._fset(0, math.cos(self._fst(0)))

    def _handle_fpatan(self, insn):
        import math
        self._fset(1, math.atan2(self._fst(1), self._fst(0)))
        self._fpop()

    def _handle_fptan(self, insn):
        import math
        self._fpush(1.0)
        self._fset(0, math.tan(self._fst(1) if False else self._fst(0)))

    def _handle_fyl2x(self, insn):
        import math
        y = self._fst(1)
        x = self._fst(0)
        self._fset(1, y * math.log2(x) if x > 0 else 0.0)
        self._fpop()

    def _handle_frndint(self, insn):
        self._fset(0, float(round(self._fst(0))))

    def _api_args(self):
        a = []
        sp = self.registers[self.sp_register]
        if self.is64:
            for r in ("rcx", "rdx", "r8", "r9"):
                a.append(self.registers.get(r, 0))
            for i in range(4, 24):
                a.append(self.memory.read_qword(sp + i * 8))
        else:
            for i in range(24):
                a.append(self.memory.read_dword(sp + i * 4))
        return a

    def call_user(self, func_addr, *args):
        if not func_addr:
            return 0
        saved_ip = self.registers[self.ip_register]
        saved_sp = self.registers[self.sp_register]
        saved = dict(self.registers)
        sp = (self.registers[self.sp_register] - 0x80) & self.ptr_mask
        self.registers[self.sp_register] = sp
        if self.is64:
            for i, r in enumerate(("rcx", "rdx", "r8", "r9")):
                self.registers[r] = args[i] if i < len(args) else 0
        else:
            for i in range(min(len(args), 8)):
                self.memory.write_dword(sp + i * 4, args[i] & 0xFFFFFFFF)
        sentinel = saved_ip
        self.registers[self.sp_register] -= self.stack_step
        self._mem_write(self.registers[self.sp_register], self.stack_step, sentinel)
        self.registers[self.ip_register] = func_addr
        depth = 0
        limit = 200000
        steps = 0
        try:
            while steps < limit:
                ip = self.registers[self.ip_register]
                if not (0x1000 <= ip < 0xF0000000000):
                    break
                code = self.memory.read(ip, 16)
                if not code or code == b"\0" * 16:
                    break
                try:
                    insn = next(self.md.disasm(code, ip))
                except StopIteration:
                    break
                ni = self._exec(insn)
                if ni is None:
                    self.registers[self.ip_register] = ip + insn.size
                else:
                    self.registers[self.ip_register] = ni
                steps += 1
                m = insn.mnemonic
                if m == "call":
                    depth += 1
                elif m in ("ret", "retn"):
                    depth -= 1
                    if depth < 0:
                        break
        except SystemExit:
            raise
        except Exception:
            pass
        result = self.registers[self.ax_register]
        self.registers = saved
        return result

    def _api_cleanup(self, target):
        if self.is64 or self.api is None:
            return
        fn = getattr(self.api, "stdcall_args", None)
        if fn is None:
            return
        n = fn(self.api.resolve_api_name(target))
        if n:
            self.registers[self.sp_register] += n * 4

    def _api_ret(self, target, insn):
        self.api_calls += 1
        r = self.api.call(target, *self._api_args())
        self.registers[self.ax_register] = (r or 0) & self.ptr_mask
        self._api_cleanup(target)
        return self.registers[self.ip_register] + insn.size

    def _api_noret(self, target):
        self.api_calls += 1
        r = self.api.call(target, *self._api_args())
        self.registers[self.ax_register] = (r or 0) & self.ptr_mask
        self._api_cleanup(target)
        return self._pop()


for _name, _cond in CC.items():
    def _mk(name, cond):
        def _j(self, insn, c=cond):
            return self._jcc(insn, c)

        def _s(self, insn, c=cond):
            return self._setcc(insn, c)

        def _c(self, insn, c=cond):
            return self._cmovcc(insn, c)

        setattr(UniversalExecutor, "_handle_j%s" % name, _j)
        setattr(UniversalExecutor, "_handle_set%s" % name, _s)
        setattr(UniversalExecutor, "_handle_cmov%s" % name, _c)

    _mk(_name, _name)
