import struct


class VirtualMemory:

    LOW_SIZE = 96 * 1024 * 1024
    HEAP_BASE = 0x20000000
    HEAP_SIZE = 64 * 1024 * 1024
    STACK_SIZE = 4 * 1024 * 1024
    STACK_BASE = 0x05000000
    TEB_BASE = 0x06000000
    PEB_BASE = 0x06002000

    def __init__(self, pe_loader):
        self.pe_loader = pe_loader
        self.image_base = pe_loader.image_base
        self.image_size = max(
            (x.virtual_address + max(x.virtual_size, x.raw_size) for x in pe_loader.sections),
            default=0,
        ) + 0x2000
        self.image_size = max(self.image_size, pe_loader.size_of_image or 0)
        self.image_size = (self.image_size + 0xFFF) & ~0xFFF

        total = self.image_size + self.LOW_SIZE + self.HEAP_SIZE + 0x100000
        self.memory = bytearray(total)
        self.regions = []
        off = 0
        self.regions.append((self.image_base, self.image_size, off)); off += self.image_size
        self.regions.append((0, self.LOW_SIZE, off)); off += self.LOW_SIZE
        self.regions.append((self.HEAP_BASE, self.HEAP_SIZE, off)); off += self.HEAP_SIZE

        self.allocated_blocks = {}
        self.heap_next = self.HEAP_BASE + 0x10000
        self.stack_base = self.STACK_BASE
        self.stack_top = self.STACK_BASE + self.STACK_SIZE
        self._load()
        self._init_stack()
        self._init_teb_peb()

    def _vi(self, va):
        if va is None:
            return None
        va &= 0xFFFFFFFFFFFFFFFF
        for start, size, off in self.regions:
            if start <= va < start + size:
                return off + (va - start)
        return None

    def is_valid(self, va):
        return self._vi(va) is not None

    def _load(self):
        for sec in self.pe_loader.sections:
            d = sec.raw_data
            sz = max(len(d), sec.virtual_size)
            if sz == 0:
                continue
            if len(d) < sz:
                d = d + b"\0" * (sz - len(d))
            off = self._vi(self.image_base + sec.virtual_address)
            if off is None:
                continue
            if off + sz > len(self.memory):
                sz = len(self.memory) - off
            self.memory[off:off + sz] = d[:sz]

    def _init_stack(self):
        self.stack_size = self.STACK_SIZE
        self.stack_base = self.STACK_BASE
        self.stack_top = self.STACK_BASE + self.STACK_SIZE

    def _init_teb_peb(self):
        teb = self.TEB_BASE
        peb = self.PEB_BASE
        self.write_qword(teb + 0x30, peb)
        self.write_qword(teb + 0x60, peb)
        self.write_qword(peb + 0x08, self.image_base)
        self.write_dword(peb + 0x08, self.image_base) if False else None
        self.write_dword(peb + 0x04, self.image_base)
        self.write_dword(peb + 0x0C, 0)
        self.write_dword(peb + 0x10, 0)
        self.write_dword(peb + 0x18, self.HEAP_BASE)
        self.write_qword(peb + 0x18, self.HEAP_BASE)
        self.write_dword(peb + 0xA4, 6)
        self.write_dword(peb + 0xA8, 1)
        self.write_dword(peb + 0xAC, 1)
        self.teb_base = teb
        self.peb_base = peb

    def load_imports(self, api_layer):
        ps = 8 if self.pe_loader.is_64bit else 4
        for m in self.pe_loader.imports:
            iat = m.get("first_thunk")
            if not iat:
                continue
            for i, f in enumerate(m["functions"]):
                addr = api_layer.get_api_address(m["dll"], f.get("name"), f.get("ordinal"))
                tv = self.image_base + iat + i * ps
                if ps == 8:
                    self.write_qword(tv, addr)
                else:
                    self.write_dword(tv, addr)

    def read(self, va, size):
        off = self._vi(va)
        if size <= 0:
            return b""
        if off is None or off + size > len(self.memory):
            return b"\0" * size
        return bytes(self.memory[off:off + size])

    def write(self, va, data):
        off = self._vi(va)
        if off is None:
            return False
        data = bytes(data)
        if off + len(data) > len(self.memory):
            data = data[:len(self.memory) - off]
        self.memory[off:off + len(data)] = data
        return True

    def read_byte(self, va):
        d = self.read(va, 1)
        return d[0] if d else 0

    def read_word(self, va):
        return struct.unpack("<H", self.read(va, 2))[0]

    def read_dword(self, va):
        return struct.unpack("<I", self.read(va, 4))[0]

    def read_qword(self, va):
        return struct.unpack("<Q", self.read(va, 8))[0]

    def read_string(self, va, maxlen=4096):
        r = bytearray()
        for i in range(maxlen):
            b = self.read(va + i, 1)
            if not b or b == b"\0":
                break
            r.extend(b)
        try:
            return r.decode("utf-8")
        except Exception:
            return r.decode("latin-1", "ignore")

    def read_wstring(self, va, maxlen=2048):
        r = []
        for _ in range(maxlen):
            c = self.read_word(va)
            if c == 0:
                break
            r.append(chr(c))
            va += 2
        return "".join(r)

    def write_byte(self, va, v):
        return self.write(va, bytes([v & 0xFF]))

    def write_word(self, va, v):
        return self.write(va, struct.pack("<H", v & 0xFFFF))

    def write_dword(self, va, v):
        return self.write(va, struct.pack("<I", v & 0xFFFFFFFF))

    def write_qword(self, va, v):
        return self.write(va, struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF))

    def write_string(self, va, s, enc="utf-8"):
        try:
            return self.write(va, s.encode(enc) + b"\0")
        except Exception:
            return False

    def write_wstring(self, va, s):
        return self.write(va, s.encode("utf-16le") + b"\0\0")

    def allocate(self, size, align=0x10):
        size = max(size, 1)
        base = self.heap_next
        if align:
            base = (base + align - 1) & ~(align - 1)
        self.allocated_blocks[base] = size
        self.heap_next = base + ((size + 0xFFF) & ~0xFFF)
        if self.heap_next >= self.HEAP_BASE + self.HEAP_SIZE:
            self.heap_next = self.HEAP_BASE + 0x10000
        return base

    def free(self, va):
        if va in self.allocated_blocks:
            del self.allocated_blocks[va]
            return True
        return False

    def __len__(self):
        return len(self.memory)
