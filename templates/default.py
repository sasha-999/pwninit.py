#!/usr/bin/python3
from pwn import *
from sys import argv

{bindings}
if len(argv) > 1:
    ip, port = argv[1].split(":")
    conn = lambda: remote(ip, port)
else:
    conn = lambda: e.process()

p = conn()

p.interactive()
