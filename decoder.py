X86_OP_INVALID = 0
X86_OP_REG = 1
X86_OP_IMM = 2
X86_OP_MEM = 3

_R8 = ["al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"]
_R8R = ["al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil"]
_R16 = ["ax", "cx", "dx", "bx", "sp", "bp", "si", "di"]
_R32 = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
_R64 = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"]
_X8 = ["r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"]
_X16 = ["r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"]
_X32 = ["r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"]
_X64 = ["r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
_SEG = ["es", "cs", "ss", "ds", "fs", "gs"]
_SEGP = {0x2E: "cs", 0x36: "ss", 0x3E: "ds", 0x26: "es", 0x64: "fs", 0x65: "gs"}


def gpr(idx, size, rex=0):
    if size == 1:
        if idx < 8:
            return (_R8R if rex else _R8)[idx]
        return _X8[idx - 8]
    if size == 2:
        return _R16[idx] if idx < 8 else _X16[idx - 8]
    if size == 4:
        return _R32[idx] if idx < 8 else _X32[idx - 8]
    return _R64[idx] if idx < 8 else _X64[idx - 8]


def xmm(idx):
    return "xmm%d" % idx


def mm(idx):
    return "mm%d" % idx


class Mem(object):
    __slots__ = ("base", "index", "scale", "disp", "segment")

    def __init__(self, base="", index="", scale=1, disp=0, segment=""):
        self.base = base
        self.index = index
        self.scale = scale
        self.disp = disp
        self.segment = segment


class Operand(object):
    __slots__ = ("type", "reg", "imm", "mem", "size", "rel")

    def __init__(self, type=X86_OP_INVALID, reg="", imm=0, mem=None, size=0, rel=False):
        self.type = type
        self.reg = reg
        self.imm = imm
        self.mem = mem
        self.size = size
        self.rel = rel

    def __repr__(self):
        if self.type == X86_OP_REG:
            return self.reg
        if self.type == X86_OP_IMM:
            return "0x%x" % (self.imm & 0xFFFFFFFFFFFFFFFF)
        m = self.mem
        p = []
        if m.segment:
            p.append(m.segment + ":")
        if m.base:
            p.append(m.base)
        if m.index:
            p.append("+%s*%d" % (m.index, m.scale) if m.base else "%s*%d" % (m.index, m.scale))
        if m.disp or not p:
            p.append("%+d" % m.disp if m.disp else "0")
        return "[%s]" % "".join(p)


class Insn(object):
    __slots__ = ("address", "size", "mnemonic", "op_str", "operands")

    def __init__(self, address=0, size=0, mnemonic="", op_str="", operands=None):
        self.address = address
        self.size = size
        self.mnemonic = mnemonic
        self.op_str = op_str
        self.operands = operands or []

    def __repr__(self):
        return "%08x: %s %s" % (self.address, self.mnemonic, self.op_str)


class _Ctx(object):
    __slots__ = ("bits", "opsize", "addrsize", "rex", "seg", "rep", "lock", "code", "pos",
                 "start", "insn", "operands", "rel_ops", "seen66", "seen67", "modrm")

    def __init__(self, code, start, bits):
        self.code = code
        self.pos = 0
        self.start = start
        self.bits = bits
        self.opsize = 4
        self.addrsize = 32
        self.rex = 0
        self.seg = ""
        self.rep = None
        self.lock = False
        self.seen66 = False
        self.seen67 = False
        self.operands = []
        self.rel_ops = []
        self.modrm = None

    def read(self, n):
        v = int.from_bytes(self.code[self.pos:self.pos + n], "little")
        self.pos += n
        return v

    def simm(self, n):
        v = self.read(n)
        if v & (1 << (n * 8 - 1)):
            v -= 1 << (n * 8)
        return v

    def finish(self, mnemonic, ops=None):
        insn = Insn(self.start, self.pos, mnemonic, "", ops if ops is not None else self.operands)
        end = self.start + self.pos
        for op in insn.operands:
            if op.rel:
                op.imm = (end + op.imm) & 0xFFFFFFFFFFFFFFFF
                op.rel = False
            if op.type == X86_OP_MEM and op.mem is not None:
                m = op.mem
                if m.base == "rip":
                    m.base = ""
                    m.disp = (end + m.disp) & 0xFFFFFFFFFFFFFFFF
                elif m.base == "abs":
                    m.base = ""
        insn.op_str = ", ".join(str(o) for o in insn.operands)
        return insn


_A16_BASE = [
    ["bx", "si"], ["bx", "di"], ["bp", "si"], ["bp", "di"],
    ["si", ""], ["di", ""], ["bp", ""], ["bx", ""],
]


def _modrm(ctx):
    if ctx.modrm is None:
        m = ctx.read(1)
        ctx.modrm = (m >> 6, ((m >> 3) & 7) | (((ctx.rex >> 2) & 1) << 3), m & 7)
    return ctx.modrm


def _mem(ctx, mod, rm, size):
    seg = ctx.seg
    if ctx.addrsize == 16:
        if mod == 0 and rm == 6:
            d = ctx.read(2)
            return Mem("", "", 1, d, seg)
        b, i = _A16_BASE[rm]
        if mod == 1:
            d = ctx.simm(1)
        elif mod == 2:
            d = ctx.simm(2)
        else:
            d = 0
        return Mem(b, i, 1, d, seg)
    bb = (ctx.rex & 1) << 3
    if rm == 4:
        s = ctx.read(1)
        scale = 1 << (s >> 6)
        idx = ((s >> 3) & 7) | (((ctx.rex >> 1) & 1) << 3)
        bas = (s & 7) | bb
        if (idx & 7) == 4 and not (ctx.rex & 2):
            idx = None
        has_base = not ((s & 7) == 5 and mod == 0)
        if mod == 0:
            d = ctx.simm(4) if not has_base else 0
        elif mod == 1:
            d = ctx.simm(1)
        else:
            d = ctx.simm(4)
        base = gpr(bas, 8 if ctx.bits == 64 else 4, ctx.rex) if has_base else ""
        idxname = "" if idx is None else gpr(idx, 8 if ctx.bits == 64 else 4, ctx.rex)
        return Mem(base, idxname, scale, d, seg)
    if mod == 0 and rm == 5:
        d = ctx.simm(4)
        base = "rip" if ctx.bits == 64 else "abs"
        return Mem(base, "", 1, d, seg)
    base = gpr(rm | bb, 8 if ctx.bits == 64 else 4, ctx.rex)
    if mod == 1:
        d = ctx.simm(1)
    elif mod == 2:
        d = ctx.simm(4)
    else:
        d = 0
    return Mem(base, "", 1, d, seg)


def _rm_op(ctx, size):
    mod, reg, rm = _modrm(ctx)
    if mod == 3:
        return Operand(X86_OP_REG, gpr(rm | ((ctx.rex & 1) << 3), size, ctx.rex), 0, None, size)
    return Operand(X86_OP_MEM, "", 0, _mem(ctx, mod, rm, size), size)


SZ = {"b": 1, "w": 2, "d": 4, "q": 8}


def _szof(tok, ctx):
    c = tok[1] if len(tok) > 1 else "v"
    if c == "v":
        return ctx.opsize
    if c == "p":
        return 8 if ctx.bits == 64 else 4
    if c == "z":
        return 2 if ctx.opsize == 2 else 4
    return SZ.get(c, ctx.opsize)


def _fixed(name, size):
    return Operand(X86_OP_REG, name, 0, None, size)


def _imm_op(ctx, size, val=None, rel=False):
    return Operand(X86_OP_IMM, "", val if val is not None else ctx.read(size), None, size, rel)


def _tok(ctx, tok, op=None):
    c = tok[0]
    if tok in ("AL", "CL", "DL", "BL", "AH", "CH", "DH", "BH"):
        return _fixed(tok.lower(), 1)
    if tok in ("AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI"):
        return _fixed(tok.lower(), 2)
    if tok in ("rAX", "rCX", "rDX", "rBX"):
        idx = {"rAX": 0, "rCX": 1, "rDX": 2, "rBX": 3}[tok]
        if tok == "rCX":
            sz = 8 if ctx.bits == 64 else 4
            return _fixed(gpr(idx, sz, ctx.rex), sz)
        return _fixed(gpr(idx, ctx.opsize, ctx.rex), ctx.opsize)
    if tok in ("ST0", "ST1"):
        return _fixed(tok.lower(), 0)
    if c == "E" or c == "M":
        return _rm_op(ctx, _szof("E" + tok[1:], ctx))
    if c == "G":
        mod, reg, rm = _modrm(ctx)
        s = _szof(tok, ctx)
        return Operand(X86_OP_REG, gpr(reg, s, ctx.rex), 0, None, s)
    if c == "I":
        if tok[1:] == "z":
            w = 2 if ctx.opsize == 2 else 4
            return Operand(X86_OP_IMM, "", ctx.simm(w), None, ctx.opsize)
        s = _szof(tok, ctx)
        return Operand(X86_OP_IMM, "", ctx.simm(s), None, s)
    if c == "J":
        s = _szof("J" + tok[1:], ctx)
        return Operand(X86_OP_IMM, "", ctx.simm(s), None, s, True)
    if c == "O":
        w = 8 if ctx.bits == 64 else 4
        if ctx.opsize == 2:
            w = 2
        return Operand(X86_OP_MEM, "", 0, Mem("abs", "", 1, ctx.read(w), ctx.seg), ctx.opsize)
    if c == "X":
        s = ctx.opsize
        return Operand(X86_OP_MEM, "", 0, Mem(_ptr(ctx, "si"), "", 1, 0, ctx.seg), s)
    if c == "Y":
        s = ctx.opsize
        return Operand(X86_OP_MEM, "", 0, Mem(_ptr(ctx, "di"), "", 1, 0, ctx.seg), s)
    if c == "V":
        mod, reg, rm = _modrm(ctx)
        return Operand(X86_OP_REG, xmm(reg), 0, None, {"s": 4, "d": 8}.get(tok[1:], 16))
    if c == "W":
        mod, reg, rm = _modrm(ctx)
        sz = {"s": 4, "d": 8}.get(tok[1:], 16)
        if mod == 3:
            return Operand(X86_OP_REG, xmm(rm | ((ctx.rex & 1) << 3)), 0, None, sz)
        return Operand(X86_OP_MEM, "", 0, _mem(ctx, mod, rm, sz), sz)
    if c == "P":
        mod, reg, rm = _modrm(ctx)
        return Operand(X86_OP_REG, mm(reg & 7), 0, None, 8)
    if c == "Q":
        mod, reg, rm = _modrm(ctx)
        if mod == 3:
            return Operand(X86_OP_REG, mm(rm & 7), 0, None, 8)
        return Operand(X86_OP_MEM, "", 0, _mem(ctx, mod, rm, 8), 8)
    if c == "Z":
        s = _szof(tok, ctx)
        return Operand(X86_OP_REG, gpr((op & 7) | ((ctx.rex & 1) << 3), s, ctx.rex), 0, None, s)
    if c == "S":
        mod, reg, rm = _modrm(ctx)
        return Operand(X86_OP_REG, _SEG[reg & 7], 0, None, 2)
    if c == "R":
        mod, reg, rm = _modrm(ctx)
        if mod == 3:
            return Operand(X86_OP_REG, gpr(rm | ((ctx.rex & 1) << 3), _szof("E" + tok[1:], ctx), ctx.rex),
                           0, None, _szof("E" + tok[1:], ctx))
        return _rm_op(ctx, _szof("E" + tok[1:], ctx))
    if c == "A":
        if tok == "AL":
            return _fixed("al", 1)
        if tok == "CL":
            return _fixed("cl", 1)
        if tok == "DL":
            return _fixed("dl", 1)
        if tok == "AX":
            return _fixed("ax", 2)
        if tok == "DX":
            return _fixed("dx", 2)
        if tok == "rAX":
            return _fixed(gpr(0, ctx.opsize, ctx.rex), ctx.opsize)
        if tok == "rCX":
            return _fixed(gpr(1, ctx.bits == 64 and 8 or 4, ctx.rex), ctx.bits == 64 and 8 or 4)
        if tok == "rDX":
            return _fixed(gpr(2, ctx.opsize, ctx.rex), ctx.opsize)
        if tok == "ST0":
            return _fixed("st0", 0)
        if tok == "STi":
            mod, reg, rm = _modrm(ctx)
            return _fixed("st%d" % (rm & 7), 0)
    if c == "F":
        mod, reg, rm = _modrm(ctx)
        s = _szof("E" + tok[1:], ctx)
        if mod == 3:
            return Operand(X86_OP_REG, gpr(rm | ((ctx.rex & 1) << 3), s, ctx.rex), 0, None, s)
        return Operand(X86_OP_MEM, "", 0, _mem(ctx, mod, rm, s), s)
    if tok == "1":
        return Operand(X86_OP_IMM, "", 1, None, 1)
    if tok == "CL":
        return _fixed("cl", 1)
    if tok == "ST0":
        return _fixed("st0", 0)
    if tok == "ST1":
        return _fixed("st1", 0)
    if tok.startswith("st"):
        return _fixed(tok, 0)
    return Operand(X86_OP_IMM, "", 0, None, 1)


def _ptr(ctx, which):
    if which == "si":
        return gpr(6, 8 if ctx.bits == 64 else 4)
    return gpr(7, 8 if ctx.bits == 64 else 4)


def _ops(ctx, fmt, op=None):
    out = []
    for tok in fmt.split(","):
        tok = tok.strip()
        if not tok:
            continue
        out.append(_tok(ctx, tok, op))
    return out


ARITH = ["add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"]
CC = ["o", "no", "b", "ae", "e", "ne", "be", "a", "s", "ns", "p", "np", "l", "ge", "le", "g"]
SHIFT = ["rol", "ror", "rcl", "rcr", "shl", "shr", "shl", "sar"]
GRP3 = ["test", "test", "not", "neg", "mul", "imul", "div", "idiv"]


def _reg(ctx, name, size):
    return Operand(X86_OP_REG, name, 0, None, size)


def _ssuf(ctx):
    return {1: "b", 2: "w", 4: "d", 8: "q"}.get(ctx.opsize, "d")


def _one(ctx):
    op = ctx.read(1)
    if op == 0x0F:
        return _two(ctx)
    if op < 0x40:
        k = (op >> 3) & 7
        r = op & 7
        if r < 6:
            mn = ARITH[k]
            if r == 0:
                return ctx.finish(mn, _ops(ctx, "Eb,Gb", op))
            if r == 1:
                return ctx.finish(mn, _ops(ctx, "Ev,Gv", op))
            if r == 2:
                return ctx.finish(mn, _ops(ctx, "Gb,Eb", op))
            if r == 3:
                return ctx.finish(mn, _ops(ctx, "Gv,Ev", op))
            if r == 4:
                return ctx.finish(mn, _ops(ctx, "AL,Ib", op))
            return ctx.finish(mn, _ops(ctx, "rAX,Iz", op))
        if r == 6:
            if k < 4:
                return ctx.finish("push", [_reg(ctx, _SEG[k], 2)])
            return None
        if k in (0, 2, 3):
            return ctx.finish("pop", [_reg(ctx, _SEG[k], 2)])
        if k == 4:
            return ctx.finish("daa")
        if k == 5:
            return ctx.finish("das")
        if k == 6:
            return ctx.finish("aaa")
        return ctx.finish("aas")
    if op < 0x50:
        if ctx.bits == 64:
            return None
        return ctx.finish("inc" if op < 0x48 else "dec", _ops(ctx, "Zv", op))
    if op < 0x60:
        return ctx.finish("push" if op < 0x58 else "pop", _ops(ctx, "Zp", op))
    if op == 0x60:
        return ctx.finish("pushal" if ctx.opsize == 2 else "pushad")
    if op == 0x61:
        return ctx.finish("popal" if ctx.opsize == 2 else "popad")
    if op == 0x62:
        return None
    if op == 0x63:
        if ctx.bits == 64:
            return ctx.finish("movsxd", _ops(ctx, "Gq,Ed", op))
        return ctx.finish("arpl", _ops(ctx, "Ew,Gw", op))
    if op == 0x68:
        return ctx.finish("push", _ops(ctx, "Iz", op))
    if op == 0x69:
        return ctx.finish("imul", _ops(ctx, "Gv,Ev,Iz", op))
    if op == 0x6A:
        return ctx.finish("push", _ops(ctx, "Ib", op))
    if op == 0x6B:
        return ctx.finish("imul", _ops(ctx, "Gv,Ev,Ib", op))
    if 0x70 <= op <= 0x7F:
        return ctx.finish("j" + CC[op & 0xF], _ops(ctx, "Jb", op))
    if 0x80 <= op <= 0x83:
        mod, reg, rm = _modrm(ctx)
        mn = ARITH[reg & 7]
        if op == 0x80:
            return ctx.finish(mn, _ops(ctx, "Eb,Ib", op))
        if op == 0x81:
            return ctx.finish(mn, _ops(ctx, "Ev,Iz", op))
        return ctx.finish(mn, _ops(ctx, "Ev,Ib", op))
    if op == 0x84:
        return ctx.finish("test", _ops(ctx, "Eb,Gb", op))
    if op == 0x85:
        return ctx.finish("test", _ops(ctx, "Ev,Gv", op))
    if op in (0x86, 0x87):
        return ctx.finish("xchg", _ops(ctx, "Eb,Gb" if op == 0x86 else "Ev,Gv", op))
    if op == 0x88:
        return ctx.finish("mov", _ops(ctx, "Eb,Gb", op))
    if op == 0x89:
        return ctx.finish("mov", _ops(ctx, "Ev,Gv", op))
    if op == 0x8A:
        return ctx.finish("mov", _ops(ctx, "Gb,Eb", op))
    if op == 0x8B:
        return ctx.finish("mov", _ops(ctx, "Gv,Ev", op))
    if op == 0x8C:
        return ctx.finish("mov", _ops(ctx, "Ew,S", op))
    if op == 0x8D:
        return ctx.finish("lea", _ops(ctx, "Gv,M", op))
    if op == 0x8E:
        return ctx.finish("mov", _ops(ctx, "S,Ew", op))
    if op == 0x8F:
        return ctx.finish("pop", _ops(ctx, "Ev", op))
    if op == 0x90:
        if ctx.rep == "rep":
            return ctx.finish("pause")
        return ctx.finish("nop")
    if 0x91 <= op <= 0x97:
        return ctx.finish("xchg", _ops(ctx, "Zv,rAX", op))
    if op == 0x98:
        return ctx.finish("cbw" if ctx.opsize == 2 else ("cwde" if ctx.opsize == 4 else "cdqe"))
    if op == 0x99:
        return ctx.finish("cwd" if ctx.opsize == 2 else ("cdq" if ctx.opsize == 4 else "cqo"))
    if op == 0x9A:
        return None
    if op == 0x9B:
        return ctx.finish("fwait")
    if op == 0x9C:
        return ctx.finish("pushfq" if ctx.bits == 64 else ("pushfw" if ctx.opsize == 2 else "pushfd"))
    if op == 0x9D:
        return ctx.finish("popfq" if ctx.bits == 64 else ("popfw" if ctx.opsize == 2 else "popfd"))
    if op == 0x9E:
        return ctx.finish("sahf")
    if op == 0x9F:
        return ctx.finish("lahf")
    if 0xA0 <= op <= 0xA3:
        if op <= 0xA1:
            return ctx.finish("mov", _ops(ctx, "AL,O" if op == 0xA0 else "rAX,O", op))
        return ctx.finish("mov", _ops(ctx, "O,AL" if op == 0xA2 else "O,rAX", op))
    if op in (0xA4, 0xA5):
        return ctx.finish("movs" + _ssuf(ctx), _ops(ctx, "Y,X", op))
    if op in (0xA6, 0xA7):
        return ctx.finish("cmps" + _ssuf(ctx), _ops(ctx, "X,Y", op))
    if op == 0xA8:
        return ctx.finish("test", _ops(ctx, "AL,Ib", op))
    if op == 0xA9:
        return ctx.finish("test", _ops(ctx, "rAX,Iz", op))
    if op in (0xAA, 0xAB):
        return ctx.finish("stos" + _ssuf(ctx), _ops(ctx, "Y,rAX", op))
    if op in (0xAC, 0xAD):
        return ctx.finish("lods" + _ssuf(ctx), _ops(ctx, "rAX,X", op))
    if op in (0xAE, 0xAF):
        return ctx.finish("scas" + _ssuf(ctx), _ops(ctx, "rAX,Y", op))
    if 0xB0 <= op <= 0xB7:
        return ctx.finish("mov", _ops(ctx, "Zb,Ib", op))
    if 0xB8 <= op <= 0xBF:
        if ctx.opsize == 8:
            return ctx.finish("movabs", _ops(ctx, "Zq,Iq", op))
        if ctx.opsize == 2:
            return ctx.finish("mov", _ops(ctx, "Zw,Iw", op))
        return ctx.finish("mov", _ops(ctx, "Zv,Iz", op))
    if op in (0xC0, 0xC1):
        mod, reg, rm = _modrm(ctx)
        return ctx.finish(SHIFT[reg & 7], _ops(ctx, "Eb,Ib" if op == 0xC0 else "Ev,Ib", op))
    if op in (0xD0, 0xD1):
        mod, reg, rm = _modrm(ctx)
        return ctx.finish(SHIFT[reg & 7], _ops(ctx, "Eb,1" if op == 0xD0 else "Ev,1", op))
    if op in (0xD2, 0xD3):
        mod, reg, rm = _modrm(ctx)
        return ctx.finish(SHIFT[reg & 7], _ops(ctx, "Eb,CL" if op == 0xD2 else "Ev,CL", op))
    if op == 0xC2:
        return ctx.finish("ret", _ops(ctx, "Iw", op))
    if op == 0xC3:
        return ctx.finish("ret")
    if op in (0xC4, 0xC5):
        return None
    if op == 0xC6:
        return ctx.finish("mov", _ops(ctx, "Eb,Ib", op))
    if op == 0xC7:
        return ctx.finish("mov", _ops(ctx, "Ev,Iz", op))
    if op == 0xC8:
        return ctx.finish("enter", _ops(ctx, "Iw,Ib", op))
    if op == 0xC9:
        return ctx.finish("leave")
    if op in (0xCA, 0xCB):
        return ctx.finish("retf", _ops(ctx, "Iw", op) if op == 0xCA else [])
    if op == 0xCC:
        return ctx.finish("int3")
    if op == 0xCD:
        return ctx.finish("int", _ops(ctx, "Ib", op))
    if op == 0xCE:
        return ctx.finish("into")
    if op == 0xCF:
        return ctx.finish("iretd")
    if op == 0xD4:
        return ctx.finish("aam", _ops(ctx, "Ib", op))
    if op == 0xD5:
        return ctx.finish("aad", _ops(ctx, "Ib", op))
    if op == 0xD6:
        return None
    if op == 0xD7:
        return ctx.finish("xlatb")
    if 0xD8 <= op <= 0xDF:
        return _x87(ctx, op)
    if op == 0xE0:
        return ctx.finish("loopne", _ops(ctx, "Jb", op))
    if op == 0xE1:
        return ctx.finish("loope", _ops(ctx, "Jb", op))
    if op == 0xE2:
        return ctx.finish("loop", _ops(ctx, "Jb", op))
    if op == 0xE3:
        return ctx.finish("jrcxz" if ctx.bits == 64 else "jecxz", _ops(ctx, "Jb", op))
    if op in (0xE4, 0xE5):
        return ctx.finish("in", _ops(ctx, "AL,Ib" if op == 0xE4 else "rAX,Ib", op))
    if op in (0xE6, 0xE7):
        return ctx.finish("out", _ops(ctx, "Ib,AL" if op == 0xE6 else "Ib,rAX", op))
    if op == 0xE8:
        return ctx.finish("call", _ops(ctx, "Jz", op))
    if op == 0xE9:
        return ctx.finish("jmp", _ops(ctx, "Jz", op))
    if op == 0xEA:
        return None
    if op == 0xEB:
        return ctx.finish("jmp", _ops(ctx, "Jb", op))
    if op in (0xEC, 0xED):
        return ctx.finish("in", _ops(ctx, "AL,DX" if op == 0xEC else "rAX,DX", op))
    if op in (0xEE, 0xEF):
        return ctx.finish("out", _ops(ctx, "DX,AL" if op == 0xEE else "DX,rAX", op))
    if op == 0xF1:
        return ctx.finish("int1")
    if op == 0xF4:
        return ctx.finish("hlt")
    if op == 0xF5:
        return ctx.finish("cmc")
    if op in (0xF6, 0xF7):
        mod, reg, rm = _modrm(ctx)
        g = reg & 7
        mn = GRP3[g]
        if op == 0xF6:
            return ctx.finish(mn, _ops(ctx, "Eb" + (",Ib" if g < 2 else ""), op))
        return ctx.finish(mn, _ops(ctx, "Ev" + (",Iz" if g < 2 else ""), op))
    if op in (0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD):
        return ctx.finish(["clc", "stc", "cli", "sti", "cld", "std"][op - 0xF8])
    if op == 0xFE:
        mod, reg, rm = _modrm(ctx)
        return ctx.finish("inc" if (reg & 7) == 0 else "dec", _ops(ctx, "Eb", op))
    if op == 0xFF:
        mod, reg, rm = _modrm(ctx)
        g = reg & 7
        if g == 0:
            return ctx.finish("inc", _ops(ctx, "Ev", op))
        if g == 1:
            return ctx.finish("dec", _ops(ctx, "Ev", op))
        if g == 2:
            return ctx.finish("call", _ops(ctx, "Ev", op))
        if g == 3:
            return None
        if g == 4:
            return ctx.finish("jmp", _ops(ctx, "Ev", op))
        if g == 5:
            return None
        if g == 6:
            return ctx.finish("push", _ops(ctx, "Ev", op))
        return None
    return None


def _two(ctx):
    op = ctx.read(1)
    mp = ctx.rep
    ctx.rep = None
    p66 = ctx.seen66

    def sse(none, n66=None, f2=None, f3=None):
        if p66 and n66:
            return n66
        if mp == "repne" and f2:
            return f2
        if mp == "rep" and f3:
            return f3
        return none

    def pf2f3(f2name, f3name, nonename):
        if mp == "repne":
            return f2name
        if mp == "rep":
            return f3name
        return nonename

    if op in (0x10, 0x11):
        mn = sse("movups", "movupd", "movsd", "movss")
        return ctx.finish(mn, _ops(ctx, "V,W" if op == 0x10 else "W,V"))
    if op in (0x12, 0x13):
        mn = sse("movlps", "movlpd", "movddup", "movsldup")
        return ctx.finish(mn, _ops(ctx, "V,W" if op == 0x12 else "W,V"))
    if op == 0x14:
        return ctx.finish(sse("unpcklps", "unpcklpd"), _ops(ctx, "V,W"))
    if op == 0x15:
        return ctx.finish(sse("unpckhps", "unpckhpd"), _ops(ctx, "V,W"))
    if op in (0x16, 0x17):
        mn = sse("movhps", "movhpd", None, "movshdup")
        return ctx.finish(mn, _ops(ctx, "V,W" if op == 0x16 else "W,V"))
    if op in (0x28, 0x29):
        mn = sse("movaps", "movapd")
        return ctx.finish(mn, _ops(ctx, "V,W" if op == 0x28 else "W,V"))
    if op == 0x2A:
        mn = sse("cvtsi2ps", None, "cvtsi2sd", "cvtsi2ss")
        return ctx.finish(mn, _ops(ctx, "V,Ev"))
    if op == 0x2C:
        if mp == "repne":
            return ctx.finish("cvttsd2si", _ops(ctx, "Gv,Wd"))
        if mp == "rep":
            return ctx.finish("cvttss2si", _ops(ctx, "Gv,Ws"))
        return ctx.finish(sse("cvttps2dq", "cvttpd2dq"), _ops(ctx, "V,W"))
    if op == 0x2D:
        if mp == "repne":
            return ctx.finish("cvtsd2si", _ops(ctx, "Gv,Wd"))
        if mp == "rep":
            return ctx.finish("cvtss2si", _ops(ctx, "Gv,Ws"))
        return ctx.finish(sse("cvtps2dq", "cvtpd2dq"), _ops(ctx, "V,W"))
    if op == 0x2E:
        return ctx.finish(sse("ucomiss", "ucomisd"), _ops(ctx, "Vd,Wd" if p66 else "Vs,Ws"))
    if op == 0x2F:
        return ctx.finish(sse("comiss", "comisd"), _ops(ctx, "Vd,Wd" if p66 else "Vs,Ws"))
    if op == 0x51:
        mn = pf2f3("sqrtsd", "sqrtss", None)
        if mn is None:
            mn = "sqrtpd" if p66 else "sqrtps"
            return ctx.finish(mn, _ops(ctx, "V,W"))
        return ctx.finish(mn, _ops(ctx, "Vd,Wd" if mn == "sqrtsd" else "Vs,Ws"))
    if op in (0x54, 0x55, 0x56, 0x57):
        mn = {0x54: "andps", 0x55: "andnps", 0x56: "orps", 0x57: "xorps"}[op]
        if p66:
            mn = mn[:-2] + "pd"
        return ctx.finish(mn, _ops(ctx, "V,W"))
    if op == 0x58:
        mn = pf2f3("addsd", "addss", "addpd" if p66 else "addps")
        return ctx.finish(mn, _ops(ctx, "Vd,Wd" if mn.endswith("sd") else ("Vs,Ws" if mn.endswith("ss") else "V,W")))
    if op == 0x59:
        mn = pf2f3("mulsd", "mulss", "mulpd" if p66 else "mulps")
        return ctx.finish(mn, _ops(ctx, "Vd,Wd" if mn.endswith("sd") else ("Vs,Ws" if mn.endswith("ss") else "V,W")))
    if op == 0x5A:
        mn = sse("cvtps2pd", "cvtpd2ps", "cvtsd2ss", "cvtss2sd")
        return ctx.finish(mn, _ops(ctx, "V,W"))
    if op == 0x5C:
        mn = pf2f3("subsd", "subss", "subpd" if p66 else "subps")
        return ctx.finish(mn, _ops(ctx, "Vd,Wd" if mn.endswith("sd") else ("Vs,Ws" if mn.endswith("ss") else "V,W")))
    if op == 0x5D:
        mn = pf2f3("minsd", "minss", "minpd" if p66 else "minps")
        return ctx.finish(mn, _ops(ctx, "Vd,Wd" if mn.endswith("sd") else ("Vs,Ws" if mn.endswith("ss") else "V,W")))
    if op == 0x5F:
        mn = pf2f3("maxsd", "maxss", "maxpd" if p66 else "maxps")
        return ctx.finish(mn, _ops(ctx, "Vd,Wd" if mn.endswith("sd") else ("Vs,Ws" if mn.endswith("ss") else "V,W")))
    if op == 0x6F:
        if p66:
            return ctx.finish("movdqa", _ops(ctx, "V,W"))
        if mp == "rep":
            return ctx.finish("movdqu", _ops(ctx, "V,W"))
        return ctx.finish("movq", _ops(ctx, "P,Q"))
    if op == 0xEF:
        return ctx.finish("pxor" if p66 else "pxor", _ops(ctx, "V,W"))
    if op == 0x6E:
        if p66:
            return ctx.finish("movd", _ops(ctx, "V,Ev"))
        return ctx.finish("movd", _ops(ctx, "P,Ed"))
    if op == 0x7E:
        if mp == "rep":
            return ctx.finish("movq", _ops(ctx, "Vd,Wd"))
        if p66:
            return ctx.finish("movd", _ops(ctx, "Ed,V"))
        return ctx.finish("movd", _ops(ctx, "Ed,P"))
    if op == 0x7F:
        if p66:
            return ctx.finish("movdqa", _ops(ctx, "W,V"))
        if mp == "rep":
            return ctx.finish("movdqu", _ops(ctx, "W,V"))
        return ctx.finish("movq", _ops(ctx, "Q,P"))
    if op == 0xD6:
        return ctx.finish("movq", _ops(ctx, "Wd,Vd"))
    if op in (0x70, 0xC2):
        ctx.read(1)
        if op == 0x70:
            mn = "pshufd" if p66 else ("pshufhw" if mp == "rep" else ("pshuflw" if mp == "repne" else "pshufw"))
        else:
            mn = sse("cmpps", "cmppd", "cmpsd", "cmpss")
        return ctx.finish(mn, _ops(ctx, "V,W,Ib"))
    if op in (0x71, 0x72, 0x73):
        return ctx.finish("pshift", _ops(ctx, "W,Ib"))
    if 0x74 <= op <= 0x76 or 0xC4 <= op <= 0xC6 or 0xD1 <= op <= 0xDF or 0xE0 <= op <= 0xF7 or 0xF8 <= op <= 0xFE:
        return ctx.finish("sse%02x" % op, _ops(ctx, "P,Q"))
    if op == 0x00:
        mod, reg, rm = _modrm(ctx)
        names = ["sldt", "str", "lldt", "ltr", "verr", "verw"]
        if (reg & 7) < 6:
            return ctx.finish(names[reg & 7], _ops(ctx, "Ew"))
        return ctx.finish("(bad)", _ops(ctx, "Ew"))
    if op == 0x01:
        mod, reg, rm = _modrm(ctx)
        g = reg & 7
        if g == 7:
            return ctx.finish("swapgs")
        names = ["sgdt", "sidt", "lgdt", "lidt", "smsw", "lmsw", "invlpg"]
        return ctx.finish(names[g], _ops(ctx, "M"))
    if op == 0x05:
        return ctx.finish("syscall")
    if op == 0x07:
        return ctx.finish("sysret")
    if op == 0x08:
        return ctx.finish("invd")
    if op == 0x09:
        return ctx.finish("wbinvd")
    if op == 0x0B:
        return ctx.finish("ud2")
    if op == 0x0D:
        return ctx.finish("prefetch", _ops(ctx, "Mb"))
    if op == 0x0E:
        return ctx.finish("femms")
    if op == 0x1E:
        if mp == "rep":
            return ctx.finish("endbr64" if ctx.bits == 64 else "endbr32")
        return ctx.finish("nop", _ops(ctx, "Ev"))
    if op == 0x1F:
        return ctx.finish("nop", _ops(ctx, "Ev"))
    if 0x20 <= op <= 0x23:
        return ctx.finish("mov", _ops(ctx, "Gv,Ev"))
    if op == 0x30:
        return ctx.finish("wrmsr")
    if op == 0x31:
        return ctx.finish("rdtsc")
    if op == 0x32:
        return ctx.finish("rdmsr")
    if op == 0x33:
        return ctx.finish("rdpmc")
    if op == 0x34:
        return ctx.finish("sysenter")
    if op == 0x35:
        return ctx.finish("sysexit")
    if op == 0x38:
        ctx.read(1)
        return ctx.finish("(bad)", _ops(ctx, "P,Q"))
    if op == 0x3A:
        ctx.read(1)
        return ctx.finish("(bad)", _ops(ctx, "V,W,Ib"))
    if 0x40 <= op <= 0x4F:
        return ctx.finish("cmov" + CC[op & 0xF], _ops(ctx, "Gv,Ev"))
    if op == 0x77:
        return ctx.finish("emms")
    if 0x80 <= op <= 0x8F:
        return ctx.finish("j" + CC[op & 0xF], _ops(ctx, "Jz"))
    if 0x90 <= op <= 0x9F:
        return ctx.finish("set" + CC[op & 0xF], _ops(ctx, "Eb"))
    if op == 0xA2:
        return ctx.finish("cpuid")
    if op == 0xA3:
        return ctx.finish("bt", _ops(ctx, "Ev,Gv"))
    if op == 0xA4:
        return ctx.finish("shld", _ops(ctx, "Ev,Gv,Ib"))
    if op == 0xA5:
        return ctx.finish("shld", _ops(ctx, "Ev,Gv,CL"))
    if op == 0xAB:
        return ctx.finish("bts", _ops(ctx, "Ev,Gv"))
    if op == 0xAC:
        return ctx.finish("shrd", _ops(ctx, "Ev,Gv,Ib"))
    if op == 0xAD:
        return ctx.finish("shrd", _ops(ctx, "Ev,Gv,CL"))
    if op == 0xAE:
        mod, reg, rm = _modrm(ctx)
        g = reg & 7
        names = ["fxsave", "fxrstor", "ldmxcsr", "stmxcsr", "xsave", "lfence", "mfence", "sfence"]
        return ctx.finish(names[g], _ops(ctx, "M"))
    if op == 0xAF:
        return ctx.finish("imul", _ops(ctx, "Gv,Ev"))
    if op == 0xB0:
        return ctx.finish("cmpxchg", _ops(ctx, "Eb,Gb"))
    if op == 0xB1:
        return ctx.finish("cmpxchg", _ops(ctx, "Ev,Gv"))
    if op == 0xB3:
        return ctx.finish("btr", _ops(ctx, "Ev,Gv"))
    if op == 0xB6:
        return ctx.finish("movzx", _ops(ctx, "Gv,Eb"))
    if op == 0xB7:
        return ctx.finish("movzx", _ops(ctx, "Gv,Ew"))
    if op == 0xB8:
        return ctx.finish("popcnt", _ops(ctx, "Gv,Ev"))
    if op == 0xBA:
        mod, reg, rm = _modrm(ctx)
        g = reg & 7
        if g >= 4:
            return ctx.finish(["bt", "bts", "btr", "btc"][g - 4], _ops(ctx, "Ev,Ib"))
        return ctx.finish("(bad)", _ops(ctx, "Ev,Ib"))
    if op == 0xBB:
        return ctx.finish("btc", _ops(ctx, "Ev,Gv"))
    if op == 0xBC:
        return ctx.finish("bsf", _ops(ctx, "Gv,Ev"))
    if op == 0xBD:
        return ctx.finish("bsr", _ops(ctx, "Gv,Ev"))
    if op == 0xBE:
        return ctx.finish("movsx", _ops(ctx, "Gv,Eb"))
    if op == 0xBF:
        return ctx.finish("movsx", _ops(ctx, "Gv,Ew"))
    if op == 0xC0:
        return ctx.finish("xadd", _ops(ctx, "Eb,Gb"))
    if op == 0xC1:
        return ctx.finish("xadd", _ops(ctx, "Ev,Gv"))
    if 0xC8 <= op <= 0xCF:
        return ctx.finish("bswap", _ops(ctx, "Zp", op))
    if op == 0xFF:
        return ctx.finish("ud0", _ops(ctx, "Gv,Ev"))
    return ctx.finish("(bad)")


_X87_MEM = {
    0xD8: (["fadd", "fmul", "fcom", "fcomp", "fsub", "fsubr", "fdiv", "fdivr"],
           [4, 4, 4, 4, 4, 4, 4, 4]),
    0xD9: (["fld", "fld", "fst", "fstp", "fldenv", "fldcw", "fnstenv", "fnstcw"],
           [4, 4, 4, 4, 28, 2, 28, 2]),
    0xDA: (["fiadd", "fimul", "ficom", "ficomp", "fisub", "fisubr", "fidiv", "fidivr"],
           [4, 4, 4, 4, 4, 4, 4, 4]),
    0xDB: (["fild", "fisttp", "fist", "fistp", "(bad)", "fld", "(bad)", "fstp"],
           [4, 4, 4, 4, 4, 10, 4, 10]),
    0xDC: (["fadd", "fmul", "fcom", "fcomp", "fsubr", "fsub", "fdivr", "fdiv"],
           [8, 8, 8, 8, 8, 8, 8, 8]),
    0xDD: (["fld", "fisttp", "fst", "fstp", "frstor", "(bad)", "fnsave", "fnstsw"],
           [8, 8, 8, 8, 28, 8, 28, 2]),
    0xDE: (["fiadd", "fimul", "ficom", "ficomp", "fisub", "fisubr", "fidiv", "fidivr"],
           [2, 2, 2, 2, 2, 2, 2, 2]),
    0xDF: (["fild", "fisttp", "fist", "fistp", "fbld", "fild", "fbstp", "fistp"],
           [2, 2, 2, 2, 10, 8, 10, 8]),
}

_X87_REG = {
    0xD8: ["fadd", "fmul", "fcom", "fcomp", "fsub", "fsubr", "fdiv", "fdivr"],
    0xDC: ["fadd", "fmul", "fcom", "fcomp", "fsubr", "fsub", "fdivr", "fdiv"],
    0xDE: ["faddp", "fmulp", "(bad)", "(bad)", "fsubrp", "fsubp", "fdivrp", "fdivp"],
}

_D9_REGS = [
    ["fchs", "fabs", "(bad)", "(bad)", "ftst", "fxam", "(bad)", "(bad)"],
    ["fld1", "fldl2t", "fldl2e", "fldpi", "fldlg2", "fldln2", "fldz", "(bad)"],
    ["f2xm1", "fyl2x", "fptan", "fpatan", "fxtract", "fprem1", "fdecstp", "fincstp"],
    ["fprem", "fyl2xp1", "fsqrt", "fsincos", "frndint", "fscale", "fsin", "fcos"],
]


def _st(i):
    return _fixed("st%d" % (i & 7), 0)


def _x87(ctx, op):
    mod, reg, rm = _modrm(ctx)
    i = rm & 7
    g = reg & 7
    if mod == 3:
        if op == 0xD9:
            if g == 0:
                return ctx.finish("fld", [_st(i)])
            if g == 1:
                return ctx.finish("fxch", [_st(i)])
            if g == 2:
                return ctx.finish("fnop")
            if g == 3:
                return ctx.finish("fstp", [_st(i)])
            if g == 4:
                return ctx.finish(_D9_REGS[0][i])
            if g == 5:
                return ctx.finish(_D9_REGS[1][i])
            if g == 6:
                return ctx.finish(_D9_REGS[2][i])
            return ctx.finish(_D9_REGS[3][i])
        if op == 0xDA:
            if g == 0:
                return ctx.finish("fcmovb", [_st(0), _st(i)])
            if g == 1:
                return ctx.finish("fcmove", [_st(0), _st(i)])
            if g == 2:
                return ctx.finish("fcmovbe", [_st(0), _st(i)])
            if g == 3:
                return ctx.finish("fcmovu", [_st(0), _st(i)])
            if g == 5 and i == 1:
                return ctx.finish("fucompp")
            return ctx.finish("(bad)")
        if op == 0xDB:
            if g == 0:
                return ctx.finish("fcmovnb", [_st(0), _st(i)])
            if g == 1:
                return ctx.finish("fcmovne", [_st(0), _st(i)])
            if g == 2:
                return ctx.finish("fcmovnbe", [_st(0), _st(i)])
            if g == 3:
                return ctx.finish("fcmovnu", [_st(0), _st(i)])
            if g == 5:
                return ctx.finish("fucomi", [_st(0), _st(i)])
            if g == 6:
                return ctx.finish("fcomi", [_st(0), _st(i)])
            return ctx.finish("fnop")
        if op == 0xDD:
            if g == 0:
                return ctx.finish("ffree", [_st(i)])
            if g == 1:
                return ctx.finish("fxch", [_st(i)])
            if g == 2:
                return ctx.finish("fst", [_st(i)])
            if g == 3:
                return ctx.finish("fstp", [_st(i)])
            if g == 4:
                return ctx.finish("fucom", [_st(i)])
            if g == 5:
                return ctx.finish("fucomp", [_st(i)])
            return ctx.finish("(bad)")
        if op == 0xDF:
            if g == 0:
                return ctx.finish("ffree", [_st(i)])
            if g == 1:
                return ctx.finish("fxch", [_st(i)])
            if g == 2:
                return ctx.finish("fst", [_st(i)])
            if g == 3:
                return ctx.finish("fstp", [_st(i)])
            if g == 4:
                return ctx.finish("fnstsw", [_fixed("ax", 2)])
            if g == 5:
                return ctx.finish("fucomip", [_st(0), _st(i)])
            if g == 6:
                return ctx.finish("fcomip", [_st(0), _st(i)])
            return ctx.finish("(bad)")
        if op == 0xDE and g == 3:
            return ctx.finish("fcompp" if i == 1 else "(bad)")
        mn = _X87_REG.get(op, ["(bad)"] * 8)[g]
        return ctx.finish(mn, [_st(i), _st(0)])
    names, sizes = _X87_MEM[op]
    mn = names[g]
    sz = sizes[g]
    mem = Operand(X86_OP_MEM, "", 0, _mem(ctx, mod, rm, sz), sz)
    return ctx.finish(mn, [mem])


def decode(code, addr=0, bits=64):
    ctx = _Ctx(bytes(code), addr, bits)
    n = len(ctx.code)
    while ctx.pos < n:
        b = ctx.code[ctx.pos]
        if b == 0x66:
            ctx.seen66 = True
            ctx.pos += 1
            continue
        if b == 0x67:
            ctx.addrsize = 16
            ctx.pos += 1
            continue
        if b == 0xF0:
            ctx.lock = True
            ctx.pos += 1
            continue
        if b == 0xF2:
            ctx.rep = "repne"
            ctx.pos += 1
            continue
        if b == 0xF3:
            ctx.rep = "rep"
            ctx.pos += 1
            continue
        if b in _SEGP:
            ctx.seg = _SEGP[b]
            ctx.pos += 1
            continue
        if bits == 64 and 0x40 <= b <= 0x4F:
            ctx.rex = b
            ctx.pos += 1
            continue
        break
    if bits == 64:
        ctx.opsize = 8 if (ctx.rex & 8) else (2 if ctx.seen66 else 4)
    else:
        ctx.opsize = 2 if ctx.seen66 else 4
    insn = _one(ctx)
    if insn is None:
        insn = Insn(addr, max(ctx.pos, 1), "(bad)", "", [])
    if ctx.lock:
        insn.mnemonic = "lock " + insn.mnemonic
    if ctx.rep:
        insn.mnemonic = ("repne " if ctx.rep == "repne" else "rep ") + insn.mnemonic
    return insn


class Decoder(object):

    def __init__(self, mode=64):
        self.mode = mode
        self.detail = False

    def disasm(self, code, addr=0):
        yield decode(code, addr, 64 if self.mode == 64 else 32)

    def reg_name(self, reg):
        return reg if isinstance(reg, str) else ""


CS_ARCH_X86 = 0
CS_MODE_64 = 64
CS_MODE_32 = 32


class Cs(Decoder):
    def __init__(self, arch=0, mode=64):
        Decoder.__init__(self, mode)
