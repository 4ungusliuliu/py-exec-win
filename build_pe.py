import struct

FILE_ALIGN = 0x200
SECT_ALIGN = 0x1000


def align(v, a):
    return (v + a - 1) & ~(a - 1)


class Builder(object):
    def __init__(self, bits, image_base):
        self.bits = bits
        self.image_base = image_base
        self.text_rva = 0x1000
        self.data_rva = 0x2000
        self.code = bytearray()
        self.data = bytearray()
        self.strings = []
        self.thunks = {}
        self.descs = []

    def add_str(self, s):
        off = len(self.data)
        self.data += s.encode() + b"\0"
        return self.data_rva + off

    def add_hint_name(self, name):
        off = len(self.data)
        self.data += struct.pack("<H", 0)
        self.data += name.encode() + b"\0"
        return self.data_rva + off

    def add_ptr(self, v):
        off = len(self.data)
        self.data += struct.pack("<Q", v) if self.bits == 64 else struct.pack("<I", v & 0xFFFFFFFF)
        return self.data_rva + off

    def add_zeros(self, n):
        self.data += b"\0" * n

    def code_va(self, off):
        return self.image_base + self.text_rva + off

    def emit(self, b):
        self.code += bytes(b)

    def _rel32(self, target_va, after_off):
        return (target_va - self.code_va(after_off)) & 0xFFFFFFFF

    def lea_rcx_rip(self, target_va):
        self.emit([0x48, 0x8D, 0x0D])
        self.emit(struct.pack("<I", self._rel32(target_va, len(self.code) + 4)))

    def call_rip(self, target_va):
        self.emit([0xFF, 0x15])
        self.emit(struct.pack("<I", self._rel32(target_va, len(self.code) + 4)))

    def mov_edx(self, v):
        self.emit([0xBA] + list(struct.pack("<I", v & 0xFFFFFFFF)))

    def mov_r8d(self, v):
        self.emit([0x41, 0xB8] + list(struct.pack("<I", v & 0xFFFFFFFF)))

    def sub_rsp(self, n):
        self.emit([0x48, 0x83, 0xEC, n & 0xFF])

    def xor_ecx(self):
        self.emit([0x33, 0xC9])

    def push_imm32(self, v):
        self.emit([0x68] + list(struct.pack("<I", v & 0xFFFFFFFF)))

    def call_abs(self, va):
        self.emit([0xFF, 0x15] + list(struct.pack("<I", va & 0xFFFFFFFF)))

    def add_esp(self, n):
        self.emit([0x83, 0xC4, n & 0xFF])

    def xor_eax(self):
        self.emit([0x31, 0xC0])

    def ret(self):
        self.emit([0xC3])

    def push_ebp_mov(self):
        self.emit([0x55, 0x89, 0xE5])

    def declare_imports(self, imports):
        psz = 8 if self.bits == 64 else 4
        for dll, funcs in imports:
            dll_rva = self.add_str(dll)
            names = [self.add_hint_name(f) for f in funcs]
            base = self.data_rva + len(self.data)
            for n in names:
                self.add_ptr(n)
            self.add_zeros(psz)
            for f, i in zip(funcs, range(len(funcs))):
                self.thunks[(dll, f)] = base + i * psz
            self.descs.append((base, dll_rva, base))

    def finalize(self):
        desc_rva = self.data_rva + len(self.data)
        for thunk, dll, iat in self.descs:
            self.data += struct.pack("<IIIII", thunk, 0, 0, dll, iat)
        self.data += struct.pack("<IIIII", 0, 0, 0, 0, 0)
        return desc_rva

    def build(self):
        desc_rva = self.finalize()
        code_raw = bytes(self.code)
        data_raw = bytes(self.data)
        text_file = FILE_ALIGN
        data_file = text_file + align(max(len(code_raw), 1), FILE_ALIGN)
        nsec = 2
        opt_size = 240 if self.bits == 64 else 224
        pe_off = 0x40
        sect_off = pe_off + 4 + 20 + opt_size
        size_of_headers = align(sect_off + nsec * 40, FILE_ALIGN)
        size_of_image = align(self.data_rva + align(len(data_raw), SECT_ALIGN), SECT_ALIGN)

        dos = bytearray(0x40)
        dos[0:2] = b"MZ"
        struct.pack_into("<I", dos, 0x3C, pe_off)
        coff = struct.pack("<HHIIIHH",
                           0x8664 if self.bits == 64 else 0x014C,
                           nsec, 0, 0, 0, opt_size, 0x2022)
        if self.bits == 64:
            opt = bytearray(240)
            struct.pack_into("<H", opt, 0, 0x20B)
            struct.pack_into("<I", opt, 4, len(code_raw))
            struct.pack_into("<I", opt, 8, len(data_raw))
            struct.pack_into("<I", opt, 16, self.text_rva)
            struct.pack_into("<I", opt, 20, self.text_rva)
            struct.pack_into("<Q", opt, 24, self.image_base)
            struct.pack_into("<I", opt, 32, SECT_ALIGN)
            struct.pack_into("<I", opt, 36, FILE_ALIGN)
            struct.pack_into("<I", opt, 56, size_of_image)
            struct.pack_into("<I", opt, 60, size_of_headers)
            struct.pack_into("<H", opt, 68, 3)
            struct.pack_into("<I", opt, 108, 16)
            dd = 112
        else:
            opt = bytearray(224)
            struct.pack_into("<H", opt, 0, 0x10B)
            struct.pack_into("<I", opt, 4, len(code_raw))
            struct.pack_into("<I", opt, 8, len(data_raw))
            struct.pack_into("<I", opt, 16, self.text_rva)
            struct.pack_into("<I", opt, 20, self.text_rva)
            struct.pack_into("<I", opt, 24, self.data_rva)
            struct.pack_into("<I", opt, 28, self.image_base)
            struct.pack_into("<I", opt, 32, SECT_ALIGN)
            struct.pack_into("<I", opt, 36, FILE_ALIGN)
            struct.pack_into("<I", opt, 56, size_of_image)
            struct.pack_into("<I", opt, 60, size_of_headers)
            struct.pack_into("<H", opt, 68, 3)
            struct.pack_into("<I", opt, 92, 16)
            dd = 96
        struct.pack_into("<II", opt, dd + 8, desc_rva, 20 * (len(self.descs) + 1))

        secs = self._section(b".text", self.text_rva, len(code_raw), text_file, 0x60000020)
        secs += self._section(b".rdata", self.data_rva, len(data_raw), data_file, 0x40000040)

        buf = bytearray(b"\0" * size_of_headers)
        buf[0:0x40] = dos
        hdr = b"PE\0\0" + coff + bytes(opt) + secs
        buf[pe_off:pe_off + len(hdr)] = hdr
        buf += b"\0" * (text_file - len(buf))
        buf += code_raw + b"\0" * (align(max(len(code_raw), 1), FILE_ALIGN) - len(code_raw))
        buf += data_raw + b"\0" * (align(max(len(data_raw), 1), FILE_ALIGN) - len(data_raw))
        return bytes(buf)

    def _section(self, name, rva, vsize, raw_off, chars):
        return (name + b"\0" * (8 - len(name)) +
                struct.pack("<IIII", vsize, rva, align(max(vsize, 1), FILE_ALIGN), raw_off) +
                struct.pack("<II", 0, 0) + struct.pack("<HH", 0, 0) +
                struct.pack("<I", chars))
