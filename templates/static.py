#!/usr/bin/python3
from pwn import *

{bindings}

REMOTE = args.REMOTE

attach = lambda p: gdb.attach(p) if not REMOTE else None
def conn(level=None):
    if REMOTE:
        return remote("", 1337, level=level)
    ARGS = []
    if args.GDB:
        gdbscript = """
        continue
        """
        return e.debug(argv=ARGS, gdbscript=gdbscript, level=level)
    return e.process(argv=ARGS, level=level)

p = conn()

p.interactive()
