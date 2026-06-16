#!/usr/bin/python3
from pwn import *
from sys import argv

{bindings}

def conn(level=None):
    if len(argv) > 1:
        ip, port = argv[1:3] if len(argv) >= 3 else argv[1].split(":")
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
