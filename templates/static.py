#!/usr/bin/python3
from pwn import *

{bindings}
if args.REMOTE:
    conn = lambda: remote("", )
else:
    conn = lambda: e.process()

p = conn()

p.interactive()
