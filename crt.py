import math
import os
import struct
import sys
class VAReader:

    def __init__(self, memory, addr, is64):
        self.memory = memory
        self.addr = addr
        self.is64 = is64
        self.step = 8 if is64 else 4

    def raw(self, size=None):
        if self.is64:
            v = self.memory.read_qword(self.addr)
            self.addr += 8
        else:
            v = self.memory.read_dword(self.addr)
            self.addr += 4
        return v

    def dword(self):
        if self.is64:
            v = self.memory.read_qword(self.addr)
            self.addr += 8
            return v & 0xFFFFFFFF
        v = self.memory.read_dword(self.addr)
        self.addr += 4
        return v

    def qword(self):
        if self.is64:
            v = self.memory.read_qword(self.addr)
            self.addr += 8
            return v
        lo = self.memory.read_dword(self.addr)
        hi = self.memory.read_dword(self.addr + 4)
        self.addr += 8
        return (hi << 32) | lo

    def double(self):
        return self._as_double(self.qword())

    def float_(self):
        return self._as_float(self.dword())

    @staticmethod
    def _as_double(v):
        try:
            return struct.unpack("<d", struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF))[0]
        except Exception:
            return 0.0

    @staticmethod
    def _as_float(v):
        try:
            return struct.unpack("<f", struct.pack("<I", v & 0xFFFFFFFF))[0]
        except Exception:
            return 0.0

    def ptr(self):
        return self.qword() if self.is64 else self.dword()


class ListReader:

    def __init__(self, values):
        self.values = list(values)
        self.i = 0

    def _next(self):
        if self.i < len(self.values):
            v = self.values[self.i]
            self.i += 1
            return v
        return 0

    def dword(self):
        return self._next() & 0xFFFFFFFF

    def qword(self):
        return self._next()

    def ptr(self):
        return self._next()

    def double(self):
        return VAReader._as_double(self._next())

    def float_(self):
        return VAReader._as_float(self._next())

class FormatEngine:
    LEN_FLAGS = "-+ #0"

    def __init__(self, memory, is64):
        self.memory = memory
        self.is64 = is64

    def vsnprintf(self, fmt, va, maxlen=-1, wide=False):
        out = []
        i = 0
        n = len(fmt)
        while i < n:
            c = fmt[i]
            if c != "%":
                out.append(c)
                i += 1
                continue
            i += 1
            if i >= n:
                break
            if fmt[i] == "%":
                out.append("%")
                i += 1
                continue
            i, piece = self._one(fmt, i, va, wide)
            out.append(piece)
        text = "".join(out)
        if maxlen >= 0:
            text = text[:maxlen]
        return text

    def _rd_str(self, ptr, wide, prec=None):
        if not ptr:
            return "(null)"
        if wide:
            s = self.memory.read_wstring(ptr)
        else:
            s = self.memory.read_string(ptr, 65536)
        if prec is not None:
            s = s[:prec]
        return s

    def _int_size(self, length, conv):
        signed = conv in "di"
        if length in ("hh",):
            return 1, signed
        if length in ("h",):
            return 2, signed
        if length in ("ll", "I64", "q", "L"):
            return 8, signed
        if length in ("I32",):
            return 4, signed
        if length in ("z", "t", "j"):
            return 8 if self.is64 else 4, False if length == "z" else signed
        return 4, signed

    @staticmethod
    def _sign_extend(v, size, signed):
        if not signed:
            return v & ((1 << (size * 8)) - 1)
        if v & (1 << (size * 8 - 1)):
            v -= (1 << (size * 8))
        return v

    def _fmt_float(self, conv, value, width, prec, flags):
        if conv in ("f", "F"):
            if prec is None:
                prec = 6
            body = "%.*f" % (prec, value)
        elif conv in ("e", "E"):
            if prec is None:
                prec = 6
            body = "%.*e" % (prec, value)
        elif conv in ("g", "G"):
            if prec is None:
                prec = 6
            body = "%.*g" % (prec, value)
        elif conv in ("a", "A"):
            body = float.hex(value)
        else:
            body = str(value)
        if flags and "#" in flags and "." not in body and "e" not in body and "n" not in body:
            if prec == 0:
                body += "."
        if conv.isupper():
            body = body.upper()
        return self._pad(body, width, flags, numeric=True, negative=body.startswith("-"))

    def _pad(self, body, width, flags, numeric=False, negative=False):
        left = "-" in flags
        zeropad = "0" in flags and numeric and not left
        if width is None:
            return body
        need = width - len(body)
        if need <= 0:
            return body
        if left:
            return body + " " * need
        if zeropad:
            if negative:
                return "-" + "0" * need + body[1:]
            return "0" * need + body
        return " " * need + body

    def _one(self, fmt, i, va, wide_fmt):
        n = len(fmt)
        flags = ""
        while i < n and fmt[i] in self.LEN_FLAGS:
            flags += fmt[i]
            i += 1
        if i >= n:
            return i, ""

        width = None
        if fmt[i] == "*":
            width = self._to_py_int(va.dword(), 4, True)
            i += 1
        else:
            j = i
            while i < n and fmt[i].isdigit():
                i += 1
            if i > j:
                width = int(fmt[j:i])

        prec = None
        if i < n and fmt[i] == ".":
            i += 1
            if i < n and fmt[i] == "*":
                prec = self._to_py_int(va.dword(), 4, True)
                i += 1
            else:
                j = i
                while i < n and fmt[i].isdigit():
                    i += 1
                prec = int(fmt[j:i]) if i > j else 0

        length = ""
        if i < n:
            for cand in ("I64", "I32", "hh", "ll", "h", "l", "L", "q", "j", "z", "t", "w"):
                if fmt.startswith(cand, i):
                    length = cand
                    i += len(cand)
                    break

        if i >= n:
            return i, ""
        conv = fmt[i]
        i += 1

        if conv in ("s", "c") and length == "l":
            conv = "S" if conv == "s" else "C"

        if conv == "n":
            size, signed = self._int_size(length, "d")
            if size == 8:
                v = va.qword()
            elif size == 2:
                v = va.dword() & 0xFFFF
            elif size == 1:
                v = va.dword() & 0xFF
            else:
                v = va.dword()
            ptr = va.ptr()
            written = 0
            return i, ""

        if conv == "p":
            v = va.ptr()
            return i, self._pad("0x%x" % v, width, flags, numeric=True)

        if conv in ("d", "i", "u", "o", "x", "X", "b"):
            size, signed = self._int_size(length, conv)
            if size == 8:
                raw = va.qword()
            else:
                raw = va.dword()
            val = self._sign_extend(raw, size, signed)
            if conv in ("o", "x", "X", "b") and not signed:
                val = raw & ((1 << (size * 8)) - 1)
            if conv == "d" or conv == "i":
                body = str(val)
            elif conv == "u":
                body = str(val & ((1 << (size * 8)) - 1))
            elif conv == "x":
                body = "%x" % (val & ((1 << (size * 8)) - 1))
            elif conv == "X":
                body = "%X" % (val & ((1 << (size * 8)) - 1))
            elif conv == "o":
                body = "%o" % (val & ((1 << (size * 8)) - 1))
            else:
                body = format(val & ((1 << (size * 8)) - 1), "b")
            if "#" in flags and conv == "o" and body[0] != "0":
                body = "0" + body
            return i, self._pad(body, width, flags, numeric=True, negative=body.startswith("-"))

        if conv == "c" or conv == "C":
            v = va.dword()
            if conv == "C" or wide_fmt:
                ch = chr(v & 0xFFFF) if v else "\0"
            else:
                ch = chr(v & 0xFF)
            return i, self._pad(ch, width, flags)

        if conv == "s" or conv == "S":
            ptr = va.ptr()
            is_wide = (conv == "S") or wide_fmt
            s = self._rd_str(ptr, is_wide, prec)
            return i, self._pad(s, width, flags)

        if conv in ("f", "F", "e", "E", "g", "G", "a", "A"):
            if length == "L":
                value = va.double()
            else:
                value = va.double()
            return i, self._fmt_float(conv, value, width, prec, flags)

        if conv == "%":
            return i, "%"
        return i, ""

    @staticmethod
    def _to_py_int(v, size, signed):
        if signed and v & (1 << (size * 8 - 1)):
            v -= (1 << (size * 8))
        return v
class FileStream:

    def __init__(self, path, mode, data):
        self.path = path
        self.mode = mode
        self.data = bytearray(data)
        self.pos = len(self.data) if "a" in mode else 0
        self.writable = any(c in mode for c in "wax+")
        self.eof_flag = False

    def read(self, size):
        if self.pos >= len(self.data):
            self.eof_flag = True
            return b""
        d = bytes(self.data[self.pos:self.pos + size])
        self.pos += len(d)
        return d

    def read_line(self, maxlen):
        if self.pos >= len(self.data):
            self.eof_flag = True
            return b""
        end = self.data.find(b"\n", self.pos)
        if end < 0:
            end = len(self.data)
        else:
            end += 1
        limit = min(end, self.pos + maxlen)
        d = bytes(self.data[self.pos:limit])
        self.pos += len(d)
        return d

    def write(self, data):
        if self.pos + len(data) > len(self.data):
            self.data.extend(b"\0" * (self.pos + len(data) - len(self.data)))
        self.data[self.pos:self.pos + len(data)] = data
        self.pos += len(data)
        return len(data)

    def seek(self, off, whence=0):
        if whence == 0:
            self.pos = off
        elif whence == 1:
            self.pos += off
        else:
            self.pos = len(self.data) + off
        self.pos = max(0, min(self.pos, len(self.data)))
        self.eof_flag = False
        return self.pos

    def tell(self):
        return self.pos

    def at_eof(self):
        return self.pos >= len(self.data)


class FileSystem:
    STDIN = 0x61000000
    STDOUT = 0x61000008
    STDERR = 0x61000010
    NEXT = 0x62000000

    def __init__(self, memory):
        self.memory = memory
        self.streams = {}
        self.counter = 0
        self.stdin_data = b""
        self.stdin_pos = 0
        self.disk = {}

    def open(self, path, mode):
        if not path:
            return 0
        data = b""
        if path in self.disk:
            data = self.disk[path]
        elif "r" in mode or "a" in mode:
            try:
                with open(path, "rb") as f:
                    data = f.read()
            except Exception:
                data = b""
        elif "w" in mode:
            data = b""
        st = FileStream(path, mode, data)
        h = self.NEXT + self.counter * 8
        self.counter += 1
        self.streams[h] = st
        return h

    def get(self, h):
        return self.streams.get(h)

    def close(self, h):
        st = self.streams.pop(h, None)
        if not st:
            return -1
        if st.writable:
            self.disk[st.path] = bytes(st.data)
            try:
                with open(st.path, "wb") as f:
                    f.write(bytes(st.data))
            except Exception:
                pass
        return 0

    def write(self, h, data):
        if h == self.STDOUT:
            sys.stdout.write(data.decode("utf-8", "replace"))
            sys.stdout.flush()
            return len(data)
        if h == self.STDERR:
            sys.stderr.write(data.decode("utf-8", "replace"))
            sys.stderr.flush()
            return len(data)
        st = self.get(h)
        if not st:
            return 0
        return st.write(data)

    def read(self, h, size):
        if h == self.STDIN:
            if self.stdin_pos >= len(self.stdin_data):
                try:
                    line = sys.stdin.readline()
                except Exception:
                    line = ""
                if not line:
                    return b""
                self.stdin_data = line.encode()
                self.stdin_pos = 0
            d = self.stdin_data[self.stdin_pos:self.stdin_pos + size]
            self.stdin_pos += len(d)
            return d
        st = self.get(h)
        if not st:
            return b""
        return st.read(size)

    def read_line(self, h, maxlen):
        if h == self.STDIN:
            buf = bytearray()
            while len(buf) < maxlen:
                d = self.read(h, 1)
                if not d:
                    break
                buf += d
                if d == b"\n":
                    break
            return bytes(buf)
        st = self.get(h)
        if not st:
            return b""
        return st.read_line(maxlen)

    def eof(self, h):
        st = self.get(h)
        if not st:
            return 1
        return 1 if st.at_eof() else 0

    def seek(self, h, off, whence):
        st = self.get(h)
        if not st:
            return -1
        return st.seek(off, whence)

    def tell(self, h):
        st = self.get(h)
        return st.tell() if st else -1

class CRTLibrary:
    def __init__(self, memory, api):
        self.memory = memory
        self.api = api
        self.is64 = True
        self.fs = FileSystem(memory)
        self.fmt = FormatEngine(memory, True)
        self._build_table()

    def set_arch(self, is64):
        self.is64 = is64
        self.fmt.is64 = is64

    def _build_table(self):
        t = {
            "printf": self.printf,
            "_printf": self.printf,
            "printf_s": self.printf,
            "fprintf": self.fprintf,
            "fprintf_s": self.fprintf,
            "vfprintf": self.vfprintf,
            "vsprintf": self.vsprintf,
            "vsnprintf": self.vsnprintf,
            "sprintf": self.sprintf,
            "sprintf_s": self.sprintf,
            "snprintf": self.snprintf,
            "_snprintf": self.snprintf,
            "_vsnprintf": self.vsnprintf,
            "_vsnprintf_s": self.vsnprintf,
            "vprintf": self.vfprintf,
            "puts": self.puts,
            "_putws": self.puts,
            "putchar": self.putchar,
            "putc": self.fputc,
            "fputc": self.fputc,
            "fputs": self.fputs,
            "getchar": self.getchar,
            "getc": self.fgetc,
            "fgetc": self.fgetc,
            "fgets": self.fgets,
            "gets_s": self.gets_s,
            "fwrite": self.fwrite,
            "fread": self.fread,
            "fopen": self.fopen,
            "fopen_s": self.fopen_s,
            "fclose": self.fclose,
            "fflush": self.fflush,
            "fseek": self.fseek,
            "ftell": self.ftell,
            "rewind": self.rewind,
            "feof": self.feof,
            "ferror": self.ferror,
            "clearerr": self.clearerr,
            "remove": self.remove,
            "rename": self.rename,
            "tmpfile": self.tmpfile,
            "setvbuf": self.setvbuf,
            "setbuf": self.setvbuf,
            "__stdio_common_vfprintf": self.stdio_common_vfprintf,
            "__stdio_common_vfwprintf": self.stdio_common_vfprintf,
            "__stdio_common_vsprintf": self.stdio_common_vsprintf,
            "__stdio_common_vsnprintf_s": self.stdio_common_vsprintf,
            "__acrt_iob_func": self.acrt_iob_func,
            "__iob_func": self.acrt_iob_func,
            "_iob": self.acrt_iob_func,
            "strlen": self.strlen,
            "wcslen": self.wcslen,
            "strcmp": self.strcmp,
            "wcscmp": self.strcmp,
            "strncmp": self.strncmp,
            "wcsncmp": self.strncmp,
            "stricmp": self.strcasecmp,
            "_stricmp": self.strcasecmp,
            "strcasecmp": self.strcasecmp,
            "strcmpi": self.strcasecmp,
            "_strcmpi": self.strcasecmp,
            "strcpy": self.strcpy,
            "wcscpy": self.strcpy,
            "strcpy_s": self.strcpy_s,
            "strncpy": self.strncpy,
            "strcat": self.strcat,
            "strncat": self.strncat,
            "strchr": self.strchr,
            "strrchr": self.strrchr,
            "strstr": self.strstr,
            "strtok": self.strtok,
            "strtok_s": self.strtok,
            "strspn": self.strspn,
            "strcspn": self.strcspn,
            "strpbrk": self.strpbrk,
            "strerror": self.strerror,
            "strtol": self.strtol,
            "strtoul": self.strtoul,
            "strtod": self.strtod,
            "atoi": self.atoi,
            "atol": self.atol,
            "atof": self.atof,
            "_atoi64": self.atoi,
            "memcpy": self.memcpy,
            "memmove": self.memmove,
            "memset": self.memset,
            "memcmp": self.memcmp,
            "memchr": self.memchr,
            "wmemcpy": self.memcpy,
            "wmemset": self.memset,
            "toupper": self.toupper,
            "tolower": self.tolower,
            "isdigit": self.isdigit,
            "isalpha": self.isalpha,
            "isspace": self.isspace,
            "isalnum": self.isalnum,
            "isupper": self.isupper,
            "islower": self.islower,
            "isprint": self.isprint,
            "ispunct": self.ispunct,
            "malloc": self.malloc,
            "calloc": self.calloc,
            "realloc": self.realloc,
            "free": self.free,
            "_msize": self.msize,
            "abort": self.abort,
            "exit": self.exit,
            "_exit": self.exit,
            "qsort": self.qsort,
            "bsearch": self.bsearch,
            "rand": self.rand,
            "srand": self.srand,
            "abs": self.abs,
            "labs": self.abs,
            "llabs": self.abs,
            "div": self.div,
            "getenv": self.getenv,
            "_getenv": self.getenv,
            "putenv": self.putenv,
            "system": self.system,
            "sqrt": self.sqrt,
            "sqrtf": self.sqrt,
            "pow": self.pow,
            "powf": self.pow,
            "sin": self.sin,
            "cos": self.cos,
            "tan": self.tan,
            "asin": self.asin,
            "acos": self.acos,
            "atan": self.atan,
            "atan2": self.atan2,
            "exp": self.exp,
            "log": self.log,
            "log10": self.log10,
            "log2": self.log2,
            "fabs": self.fabs,
            "floor": self.floor,
            "ceil": self.ceil,
            "fmod": self.fmod,
            "hypot": self.hypot,
            "sinh": self.sinh,
            "cosh": self.cosh,
            "tanh": self.tanh,
            "frexp": self.frexp,
            "ldexp": self.ldexp,
            "modf": self.modf,
            "time": self.time,
            "clock": self.clock,
            "difftime": self.difftime,
            "_initterm": self.initterm,
            "_initterm_e": self.initterm,
            "__p___argc": self.p_argc,
            "__p___argv": self.p_argv,
            "__p___wargv": self.p_argv,
            "__p__environ": self.p_environ,
            "__p__wenviron": self.p_environ,
            "_set_invalid_parameter_handler": self.ret0,
            "_crt_atexit": self.ret0,
            "_configure_narrow_argv": self.ret0,
            "_configure_wide_argv": self.ret0,
            "_initialize_narrow_environment": self.ret0,
            "_initialize_wide_environment": self.ret0,
            "__p__commode": self.p_int_zero,
            "__p__fmode": self.p_int_zero,
            "_set_new_mode": self.ret1,
            "_lock": self.ret0,
            "_unlock": self.ret0,
            "_lock_file": self.ret0,
            "_unlock_file": self.ret0,
            "puts_no_lock": self.puts,
        }
        self.table = t

    def resolve(self, name):
        if not name:
            return None
        h = self.table.get(name)
        if h:
            return h
        base = name.lstrip("@_")
        base = base.split("@")[0]
        return self.table.get(base)

    def _iob(self, idx):
        return [FileSystem.STDIN, FileSystem.STDOUT, FileSystem.STDERR][idx] if 0 <= idx <= 2 else 0

    def acrt_iob_func(self, idx=0, *a):
        return self._iob(idx if isinstance(idx, int) else 0)

    def _std_stream(self, h):
        return h in (FileSystem.STDOUT, FileSystem.STDERR, FileSystem.STDIN)

    def _emit(self, h, text):
        self.fs.write(h, text.encode("utf-8", "replace"))
        return len(text)

    def printf(self, fmt_ptr, *args):
        fmt = self.memory.read_string(fmt_ptr, 65536)
        va = ListReader(args)
        text = self._format(fmt, va)
        return self._emit(FileSystem.STDOUT, text)

    def fprintf(self, stream, fmt_ptr, *args):
        fmt = self.memory.read_string(fmt_ptr, 65536)
        va = ListReader(args[1:] if not self.is64 else args)
        text = self._format(fmt, va)
        return self._emit(stream, text)

    def vfprintf(self, stream, fmt_ptr, ap, *a):
        fmt = self.memory.read_string(fmt_ptr, 65536)
        va = VAReader(self.memory, ap, self.is64)
        text = self._format(fmt, va)
        return self._emit(stream, text)

    def stdio_common_vfprintf(self, options, stream, fmt_ptr, locale, ap, *a):
        return self.vfprintf(stream, fmt_ptr, ap)

    def sprintf(self, dst, fmt_ptr, *args):
        fmt = self.memory.read_string(fmt_ptr, 65536)
        va = ListReader(args)
        text = self._format(fmt, va)
        self.memory.write(dst, text.encode("utf-8") + b"\0")
        return len(text)

    def snprintf(self, dst, size, fmt_ptr, *args):
        fmt = self.memory.read_string(fmt_ptr, 65536)
        va = ListReader(args)
        text = self._format(fmt, va)
        if size > 0:
            data = text.encode("utf-8")[:size - 1] + b"\0"
            self.memory.write(dst, data)
        return len(text)

    def vsprintf(self, dst, fmt_ptr, ap, *a):
        fmt = self.memory.read_string(fmt_ptr, 65536)
        text = self._format(fmt, VAReader(self.memory, ap, self.is64))
        self.memory.write(dst, text.encode("utf-8") + b"\0")
        return len(text)

    def vsnprintf(self, dst, size, fmt_ptr, ap, *a):
        fmt = self.memory.read_string(fmt_ptr, 65536)
        text = self._format(fmt, VAReader(self.memory, ap, self.is64))
        if size > 0:
            self.memory.write(dst, text.encode("utf-8")[:size - 1] + b"\0")
        return len(text)

    def stdio_common_vsprintf(self, options, dst, size, fmt_ptr, locale, ap, *a):
        return self.vsnprintf(dst, size, fmt_ptr, ap)

    def puts(self, s, *a):
        if not s:
            return 0
        text = self.memory.read_string(s, 65536)
        self._emit(FileSystem.STDOUT, text + "\n")
        return len(text) + 1

    def putchar(self, c, *a):
        self._emit(FileSystem.STDOUT, chr(c & 0xFF))
        return c & 0xFF

    def fputc(self, c, stream, *a):
        self.fs.write(stream, bytes([c & 0xFF]))
        return c & 0xFF

    def fputs(self, s, stream, *a):
        if not s:
            return -1
        text = self.memory.read_string(s, 65536)
        self.fs.write(stream, text.encode("utf-8"))
        return len(text)

    def getchar(self, *a):
        d = self.fs.read(FileSystem.STDIN, 1)
        return d[0] if d else -1

    def fgetc(self, stream, *a):
        d = self.fs.read(stream, 1)
        return d[0] if d else -1

    def fgets(self, buf, n, stream, *a):
        if n <= 0:
            return 0
        data = self.fs.read_line(stream, n - 1)
        if not data:
            return 0
        self.memory.write(buf, data + b"\0")
        return buf

    def gets_s(self, buf, n, *a):
        return self.fgets(buf, n, FileSystem.STDIN)

    def fwrite(self, ptr, size, count, stream, *a):
        total = size * count
        if total <= 0:
            return 0
        data = self.memory.read(ptr, total)
        self.fs.write(stream, data)
        return count

    def fread(self, ptr, size, count, stream, *a):
        total = size * count
        if total <= 0:
            return 0
        data = self.fs.read(stream, total)
        if not data:
            return 0
        self.memory.write(ptr, data + b"\0" * (total - len(data)))
        return len(data) // size if size else 0

    def fopen(self, path_ptr, mode_ptr, *a):
        if not path_ptr:
            return 0
        path = self.memory.read_string(path_ptr, 4096)
        mode = self.memory.read_string(mode_ptr, 64) if mode_ptr else "r"
        return self.fs.open(path, mode)

    def fopen_s(self, out, path_ptr, mode_ptr, *a):
        h = self.fopen(path_ptr, mode_ptr)
        if out:
            self.memory.write_qword(out, h)
        return 0 if h else 1

    def fclose(self, h, *a):
        return self.fs.close(h)

    def fflush(self, h=0, *a):
        return 0

    def fseek(self, h, off, origin, *a):
        return 0 if self.fs.seek(h, off, origin) >= 0 else -1

    def ftell(self, h, *a):
        v = self.fs.tell(h)
        return v if v >= 0 else -1

    def rewind(self, h, *a):
        return self.fseek(h, 0, 0)

    def feof(self, h, *a):
        return self.fs.eof(h)

    def ferror(self, h, *a):
        return 0

    def clearerr(self, h, *a):
        return 0

    def remove(self, p, *a):
        try:
            os.remove(self.memory.read_string(p, 4096))
            return 0
        except Exception:
            return -1

    def rename(self, a1, a2, *a):
        try:
            os.rename(self.memory.read_string(a1, 4096), self.memory.read_string(a2, 4096))
            return 0
        except Exception:
            return -1

    def tmpfile(self, *a):
        return 0

    def setvbuf(self, *a):
        return 0

    def _format(self, fmt, va):
        out = []
        i = 0
        n = len(fmt)
        written = 0
        while i < n:
            c = fmt[i]
            if c != "%":
                out.append(c)
                i += 1
                continue
            i += 1
            if i >= n:
                break
            if fmt[i] == "%":
                out.append("%")
                i += 1
                continue
            start = i
            j = i
            while j < n and fmt[j] not in "diouxXeEfgGacspnCSb%":
                j += 1
            conv = fmt[j] if j < n else ""
            if conv == "n":
                spec = fmt[i:j + 1]
                self._do_n(spec, va, VAWriter(self.memory, va))
                i = j + 1
                continue
            i, piece = self.fmt._one(fmt, i, va, False)
            out.append(piece)
        return "".join(out)

    def _do_n(self, spec, va, writer):
        length = ""
        for cand in ("hh", "ll", "h", "l", "I64"):
            if spec.startswith(cand):
                length = cand
                break
        ptr = va.ptr()
        return ptr

    def strlen(self, p, *a):
        if not p:
            return 0
        d = self.memory.read(p, 1 << 20)
        for i, b in enumerate(d):
            if b == 0:
                return i
        return len(d)

    def wcslen(self, p, *a):
        if not p:
            return 0
        i = 0
        while i < 4096:
            if self.memory.read_word(p + i * 2) == 0:
                return i
            i += 1
        return i

    def _s(self, p, wide=False):
        return self.memory.read_wstring(p) if wide else self.memory.read_string(p, 1 << 16)

    def strcmp(self, a, b, *a_):
        x, y = self._s(a), self._s(b)
        return -1 if x < y else (1 if x > y else 0)

    def strncmp(self, a, b, n, *a_):
        x, y = self._s(a)[:n], self._s(b)[:n]
        return -1 if x < y else (1 if x > y else 0)

    def strcasecmp(self, a, b, *a_):
        x, y = self._s(a).lower(), self._s(b).lower()
        return -1 if x < y else (1 if x > y else 0)

    def strcpy(self, d, s, *a):
        if not d or not s:
            return d
        t = self._s(s)
        self.memory.write(d, t.encode("utf-8") + b"\0")
        return d

    def strcpy_s(self, d, sz, s, *a):
        if not d or not s:
            return 1
        t = self._s(s)
        if len(t) + 1 > sz:
            return 1
        self.memory.write(d, t.encode("utf-8") + b"\0")
        return 0

    def strncpy(self, d, s, n, *a):
        if not d:
            return d
        t = self._s(s)[:n]
        self.memory.write(d, t.encode("utf-8"))
        if len(t) < n:
            self.memory.write(d + len(t), b"\0" * (n - len(t)))
        return d

    def strcat(self, d, s, *a):
        if not d or not s:
            return d
        cur = self._s(d)
        t = cur + self._s(s)
        self.memory.write(d, t.encode("utf-8") + b"\0")
        return d

    def strncat(self, d, s, n, *a):
        if not d or not s:
            return d
        t = self._s(d) + self._s(s)[:n]
        self.memory.write(d, t.encode("utf-8") + b"\0")
        return d

    def strchr(self, p, c, *a):
        if not p:
            return 0
        s = self._s(p)
        i = s.find(chr(c & 0xFF))
        return p + i if i >= 0 else 0

    def strrchr(self, p, c, *a):
        if not p:
            return 0
        s = self._s(p)
        i = s.rfind(chr(c & 0xFF))
        return p + i if i >= 0 else 0

    def strstr(self, p, sub, *a):
        if not p or not sub:
            return 0
        s = self._s(p)
        i = s.find(self._s(sub))
        return p + i if i >= 0 else 0

    def strtok(self, p, delim, *a):
        return 0

    def strspn(self, p, acc, *a):
        s, a2 = self._s(p), set(self._s(acc))
        i = 0
        while i < len(s) and s[i] in a2:
            i += 1
        return i

    def strcspn(self, p, rej, *a):
        s, a2 = self._s(p), set(self._s(rej))
        i = 0
        while i < len(s) and s[i] not in a2:
            i += 1
        return i

    def strpbrk(self, p, acc, *a):
        s, a2 = self._s(p), set(self._s(acc))
        for i, ch in enumerate(s):
            if ch in a2:
                return p + i
        return 0

    def strerror(self, n, *a):
        p = self.memory.allocate(64)
        self.memory.write_string(p, "error %d" % n)
        return p

    def strtol(self, p, end, base, *a):
        return self._strto(p, end, base, False)

    def strtoul(self, p, end, base, *a):
        return self._strto(p, end, base, True)

    def _strto(self, p, end, base, unsigned):
        if not p:
            return 0
        s = self._s(p).strip()
        b = base if base else 10
        try:
            v = int(s, b)
        except Exception:
            v = 0
        return v & 0xFFFFFFFFFFFFFFFF

    def strtod(self, p, end, *a):
        try:
            return float(self._s(p).strip())
        except Exception:
            return 0.0

    def atoi(self, p, *a):
        try:
            return int(self._s(p).strip())
        except Exception:
            return 0

    atol = atoi

    def atof(self, p, *a):
        try:
            return float(self._s(p).strip())
        except Exception:
            return 0.0

    def memcpy(self, d, s, n, *a):
        if not d or not s or n <= 0:
            return d
        self.memory.write(d, self.memory.read(s, n))
        return d

    memmove = memcpy

    def memset(self, d, v, n, *a):
        if not d or n <= 0:
            return d
        self.memory.write(d, bytes([v & 0xFF]) * n)
        return d

    def memcmp(self, p1, p2, n, *a):
        if n <= 0:
            return 0
        a1, b1 = self.memory.read(p1, n), self.memory.read(p2, n)
        return -1 if a1 < b1 else (1 if a1 > b1 else 0)

    def memchr(self, p, c, n, *a):
        d = self.memory.read(p, n)
        i = d.find(bytes([c & 0xFF]))
        return p + i if i >= 0 else 0

    def toupper(self, c, *a):
        return ord(chr(c & 0xFF).upper())

    def tolower(self, c, *a):
        return ord(chr(c & 0xFF).lower())

    def isdigit(self, c, *a):
        return int(chr(c & 0xFF).isdigit())

    def isalpha(self, c, *a):
        return int(chr(c & 0xFF).isalpha())

    def isspace(self, c, *a):
        return int(chr(c & 0xFF).isspace())

    def isalnum(self, c, *a):
        return int(chr(c & 0xFF).isalnum())

    def isupper(self, c, *a):
        return int(chr(c & 0xFF).isupper())

    def islower(self, c, *a):
        return int(chr(c & 0xFF).islower())

    def isprint(self, c, *a):
        return int(32 <= (c & 0xFF) < 127)

    def ispunct(self, c, *a):
        ch = chr(c & 0xFF)
        return int(ch.isalnum() is False and ch.isspace() is False and 32 <= (c & 0xFF) < 127)

    def malloc(self, n, *a):
        return self.api.heap_alloc(max(n or 0, 1))

    def calloc(self, n, sz, *a):
        total = (n or 0) * (sz or 0)
        p = self.api.heap_alloc(max(total, 1))
        if p:
            self.memory.write(p, b"\0" * max(total, 1))
        return p

    def realloc(self, p, n, *a):
        if not p:
            return self.malloc(n)
        if n == 0:
            self.api.heap_free(p)
            return 0
        newp = self.api.heap_alloc(n)
        if newp:
            old = self.api.heap_size(p)
            self.memory.write(newp, self.memory.read(p, min(old, n)))
            self.api.heap_free(p)
        return newp

    def free(self, p, *a):
        if p:
            self.api.heap_free(p)
        return 0

    def msize(self, p, *a):
        return self.api.heap_size(p)

    def abort(self, *a):
        raise SystemExit(3)

    def exit(self, code=0, *a):
        raise SystemExit(code)

    def qsort(self, base, n, size, cmp_fn, *a):
        if not base or n <= 0 or not size or not cmp_fn:
            return
        elems = [self.memory.read(base + i * size, size) for i in range(n)]

        def key(e):
            return e

        import functools
        try:
            def cmp_wrapper(x, y):
                self.memory.write(base, x)
                self.memory.write(base + size, y)
                r = self.api.executor.call_user(cmp_fn, base, base + size)
                return -1 if r < 0 else (1 if r > 0 else 0)
            elems.sort(key=functools.cmp_to_key(cmp_wrapper))
        except Exception:
            elems.sort()
        for i, e in enumerate(elems):
            self.memory.write(base + i * size, e)

    def bsearch(self, key, base, n, size, cmp_fn, *a):
        if not base or not cmp_fn:
            return 0
        for i in range(n or 0):
            addr = base + i * size
            try:
                if self.api.executor.call_user(cmp_fn, key, addr) == 0:
                    return addr
            except Exception:
                break
        return 0

    def rand(self, *a):
        import random
        return random.randint(0, 0x7FFF)

    def srand(self, seed, *a):
        import random
        random.seed(seed)
        return 0

    def abs(self, v, *a):
        return -v if v < 0 else v

    def div(self, num, den, *a):
        return 0

    def getenv(self, name_ptr, *a):
        if not name_ptr:
            return 0
        name = self.memory.read_string(name_ptr, 256)
        val = os.environ.get(name)
        if val is None:
            return 0
        p = self.memory.allocate(len(val) + 8)
        self.memory.write_string(p, val)
        return p

    def putenv(self, s, *a):
        return 0

    def system(self, cmd, *a):
        return 0

    def _dbl(self, v):
        try:
            return struct.unpack("<d", struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF))[0]
        except Exception:
            return 0.0

    def _bits(self, d):
        return struct.unpack("<Q", struct.pack("<d", float(d)))[0]

    def sqrt(self, v, *a):
        x = self._dbl(v)
        return self._bits(math.sqrt(x) if x >= 0 else float("nan"))

    def pow(self, x, y, *a):
        try:
            return self._bits(math.pow(self._dbl(x), self._dbl(y)))
        except Exception:
            return 0

    def sin(self, v, *a):
        return self._bits(math.sin(self._dbl(v)))

    def cos(self, v, *a):
        return self._bits(math.cos(self._dbl(v)))

    def tan(self, v, *a):
        return self._bits(math.tan(self._dbl(v)))

    def asin(self, v, *a):
        return self._bits(math.asin(self._dbl(v)))

    def acos(self, v, *a):
        return self._bits(math.acos(self._dbl(v)))

    def atan(self, v, *a):
        return self._bits(math.atan(self._dbl(v)))

    def atan2(self, y, x, *a):
        return self._bits(math.atan2(self._dbl(y), self._dbl(x)))

    def exp(self, v, *a):
        return self._bits(math.exp(self._dbl(v)))

    def log(self, v, *a):
        return self._bits(math.log(self._dbl(v)))

    def log10(self, v, *a):
        return self._bits(math.log10(self._dbl(v)))

    def log2(self, v, *a):
        return self._bits(math.log2(self._dbl(v)))

    def fabs(self, v, *a):
        return self._bits(abs(self._dbl(v)))

    def floor(self, v, *a):
        return self._bits(float(math.floor(self._dbl(v))))

    def ceil(self, v, *a):
        return self._bits(float(math.ceil(self._dbl(v))))

    def fmod(self, x, y, *a):
        try:
            return self._bits(math.fmod(self._dbl(x), self._dbl(y)))
        except Exception:
            return 0

    def hypot(self, x, y, *a):
        return self._bits(math.hypot(self._dbl(x), self._dbl(y)))

    def sinh(self, v, *a):
        return self._bits(math.sinh(self._dbl(v)))

    def cosh(self, v, *a):
        return self._bits(math.cosh(self._dbl(v)))

    def tanh(self, v, *a):
        return self._bits(math.tanh(self._dbl(v)))

    def frexp(self, v, exp_ptr, *a):
        m, e = math.frexp(self._dbl(v))
        if exp_ptr:
            self.memory.write_dword(exp_ptr, e & 0xFFFFFFFF)
        return self._bits(m)

    def ldexp(self, v, e, *a):
        return self._bits(math.ldexp(self._dbl(v), e))

    def modf(self, v, iptr, *a):
        x = self._dbl(v)
        f, i = math.modf(x)
        if iptr:
            self.memory.write_qword(iptr, self._bits(i))
        return self._bits(f)

    def time(self, out, *a):
        import time as _t
        v = int(_t.time())
        if out:
            if self.is64:
                self.memory.write_qword(out, v)
            else:
                self.memory.write_dword(out, v & 0xFFFFFFFF)
        return v

    def clock(self, *a):
        import time as _t
        return int((_t.time() % 1) * 1000)

    def difftime(self, a1, a2, *a):
        return self._dbl(a1) - self._dbl(a2)

    def initterm(self, start, end, *a):
        if not start or not end:
            return 0
        step = 8 if self.is64 else 4
        cur = start
        guard = 0
        while cur < end and guard < 4096:
            f = self.memory.read_qword(cur) if self.is64 else self.memory.read_dword(cur)
            cur += step
            guard += 1
            if not f:
                continue
            try:
                r = self.api.call_dynamic(f)
                if r:
                    return r
            except SystemExit:
                raise
            except Exception:
                pass
        return 0

    def p_argc(self, *a):
        p = self.memory.allocate(8)
        self.memory.write_dword(p, 1)
        return p

    def p_argv(self, *a):
        p = self.memory.allocate(64)
        s = self.memory.allocate(64)
        self.memory.write_string(s, "emulator.exe")
        if self.is64:
            self.memory.write_qword(p, s)
            self.memory.write_qword(p + 8, 0)
        else:
            self.memory.write_dword(p, s)
            self.memory.write_dword(p + 4, 0)
        return p

    def p_environ(self, *a):
        p = self.memory.allocate(32)
        if self.is64:
            self.memory.write_qword(p, 0)
        else:
            self.memory.write_dword(p, 0)
        return p

    def p_int_zero(self, *a):
        p = self.memory.allocate(8)
        self.memory.write_dword(p, 0)
        return p

    def ret0(self, *a):
        return 0

    def ret1(self, *a):
        return 1


class VAWriter:

    def __init__(self, memory, va):
        self.memory = memory
        self.va = va
