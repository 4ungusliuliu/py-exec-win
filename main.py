import sys
import argparse

from pe_loader import PELoader
from memory import VirtualMemory
from api_layer import APISimulator
from executor import UniversalExecutor


def main():
    p = argparse.ArgumentParser(description="x86/x64 Windows PE emulator")
    p.add_argument("exe_file")
    p.add_argument("--verbose", "-v", action="store_true", help="print run statistics")
    p.add_argument("--debug", "-d", action="store_true", help="don't swallow exceptions")
    p.add_argument("--trace", "-t", action="store_true", help="trace every instruction")
    p.add_argument("--max-instructions", "-m", type=int, default=100000000)
    a = p.parse_args()
    try:
        loader = PELoader(a.exe_file)
        if not loader.load():
            print("Failed to load %s" % a.exe_file)
            return 1
        mem = VirtualMemory(loader)
        api = APISimulator(mem)
        mem.load_imports(api)
        exe = UniversalExecutor(loader, mem, api)
        api.executor = exe
        exe.verbose = a.verbose
        exe.debug = a.debug
        exe.trace = a.trace
        exe.max_instructions = a.max_instructions
        code = exe.run()
        if a.verbose and code is not None:
            sys.stderr.write("exit code: %s\n" % code)
        return 0
    except FileNotFoundError:
        print("Not found: %s" % a.exe_file)
        return 1
    except KeyboardInterrupt:
        return 0
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 0
    except Exception as e:
        print("Error: %s" % e)
        if a.debug:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
