#!/usr/bin/python3
from pwn import *

{bindings}

def conn(level=None):
    if args.REMOTE:
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
