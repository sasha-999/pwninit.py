#!/usr/bin/python3
from pwn import *
from sys import argv

{bindings}

if len(argv) > 1:
    ip, port = argv[1:3] if len(argv) >= 3 else argv[1].split(":")
    REMOTE = True
else:
    REMOTE = False

attach = lambda p: gdb.attach(p) if not REMOTE else None
def conn(level=None):
    if REMOTE:
        return remote(ip, port, level=level)
    ARGS = []
    if args.GDB:
        gdbscript = """
        continue
        """
        return e.debug(argv=ARGS, gdbscript=gdbscript, level=level)
    return e.process(argv=ARGS, level=level)

p = conn()

p.interactive()
